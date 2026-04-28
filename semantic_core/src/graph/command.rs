use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticCommand {
    RegisterHart {
        hart: HartId,
        hardware_id: u32,
        label: String,
        boot: bool,
        note: String,
    },
    SetHartState {
        hart: HartId,
        hart_generation: Generation,
        state: HartState,
        reason: String,
        note: String,
    },
    BindHartCurrentActivation {
        hart: HartId,
        hart_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        note: String,
    },
    ClearHartCurrentActivation {
        hart: HartId,
        hart_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        reason: String,
        note: String,
    },
    CreateRuntimeActivation {
        activation: ActivationId,
        owner_task: TaskId,
        owner_task_generation: Generation,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        code_object: Option<ContractObjectRef>,
    },
    CreateRunnableQueue {
        queue: RunnableQueueId,
        label: String,
    },
    BindRunnableQueueOwner {
        queue: RunnableQueueId,
        queue_generation: Generation,
        hart: HartId,
        hart_generation: Generation,
        note: String,
    },
    EnqueueRunnable {
        queue: RunnableQueueId,
        activation: ActivationId,
        activation_generation: Generation,
    },
    DequeueRunnable {
        queue: RunnableQueueId,
        activation: ActivationId,
    },
    CreateActivationContext {
        context: ActivationContextId,
        activation: ActivationId,
        activation_generation: Generation,
    },
    CaptureSavedContext {
        saved_context: SavedContextId,
        context: ActivationContextId,
        context_generation: Generation,
        reason: SavedContextReason,
        pc: u64,
        sp: u64,
        flags: u64,
        note: String,
    },
    SavePreemptedContext {
        context: ActivationContextId,
        saved_context: SavedContextId,
        preemption: PreemptionId,
        preemption_generation: Generation,
        pc: u64,
        sp: u64,
        flags: u64,
        note: String,
    },
    RecordTimerInterrupt {
        interrupt: TimerInterruptId,
        timer_epoch: u64,
        hart: HartId,
        hart_generation: Generation,
        target_activation: Option<ActivationId>,
        target_activation_generation: Option<Generation>,
        note: String,
    },
    RecordIpiEvent {
        ipi: IpiEventId,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        kind: IpiEventKind,
        reason: String,
        note: String,
    },
    RemotePreemptActivation {
        remote_preempt: RemotePreemptId,
        ipi: IpiEventId,
        ipi_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        queue: RunnableQueueId,
        note: String,
    },
    RemoteParkHart {
        remote_park: RemoteParkId,
        ipi: IpiEventId,
        ipi_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        reason: String,
        note: String,
    },
    PreemptActivation {
        preemption: PreemptionId,
        activation: ActivationId,
        activation_generation: Generation,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        queue: RunnableQueueId,
        note: String,
    },
    RecordSchedulerDecision {
        decision: SchedulerDecisionId,
        queue: RunnableQueueId,
        queue_generation: Generation,
        selected_activation: ActivationId,
        selected_activation_generation: Generation,
        reason: String,
        note: String,
    },
    RecordCrossHartSchedulerDecision {
        cross_decision: CrossHartSchedulerDecisionId,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        deciding_hart: HartId,
        deciding_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        reason: String,
        note: String,
    },
    MigrateRunnableActivation {
        migration: ActivationMigrationId,
        activation: ActivationId,
        activation_generation: Generation,
        source_queue: RunnableQueueId,
        source_queue_generation: Generation,
        target_queue: RunnableQueueId,
        target_queue_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        reason: String,
        note: String,
    },
    RecordSmpSafePoint {
        safe_point: SmpSafePointId,
        coordinator_hart: HartId,
        coordinator_hart_generation: Generation,
        participants: Vec<(HartId, Generation)>,
        reason: String,
        note: String,
    },
    CompleteStopTheWorldRendezvous {
        rendezvous: StopTheWorldRendezvousId,
        epoch: u64,
        safe_point: SmpSafePointId,
        safe_point_generation: Generation,
        stop_new_activations: bool,
        reason: String,
        note: String,
    },
    ValidateSmpCodePublishBarrier {
        barrier: SmpCodePublishBarrierId,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        code_publish_epoch_before: u64,
        code_publish_epoch_after: u64,
        remote_icache_sync_required: bool,
        code_publish_executed: bool,
        reason: String,
        note: String,
    },
    ValidateSmpCleanupQuiescence {
        quiescence: SmpCleanupQuiescenceId,
        cleanup: ActivationCleanupId,
        cleanup_generation: Generation,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        store: StoreId,
        target_store_generation: Generation,
        result_store_generation: Generation,
        reason: String,
        note: String,
    },
    ValidateSmpSnapshotBarrier {
        barrier: SmpSnapshotBarrierId,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        snapshot_state: SnapshotBarrierValidationState,
        reason: String,
        note: String,
    },
    RecordSmpStressRun {
        run: SmpStressRunId,
        scenario: String,
        iterations: u32,
        invariant_checks: u32,
        reason: String,
        note: String,
    },
    RecordSmpScalingBenchmark {
        benchmark: SmpScalingBenchmarkId,
        scenario: String,
        stress_run: SmpStressRunId,
        stress_run_generation: Generation,
        workload_units: u64,
        baseline_single_hart_nanos: u64,
        measured_smp_nanos: u64,
        budget_nanos: u64,
        note: String,
    },
    RecordDeviceObject {
        device: DeviceObjectId,
        name: String,
        class: String,
        resource: ResourceId,
        resource_generation: Generation,
        backend: String,
        bus: String,
        vendor: String,
        model: String,
        note: String,
    },
    RecordPacketDeviceObject {
        packet_device: PacketDeviceObjectId,
        name: String,
        device: DeviceObjectId,
        device_generation: Generation,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        mac: [u8; 6],
        frame_format_version: u32,
        max_payload_len: u32,
        note: String,
    },
    RecordPacketBufferObject {
        packet_buffer: PacketBufferObjectId,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        direction: PacketBufferDirection,
        frame_format_version: u32,
        capacity: u32,
        payload_len: u32,
        sequence: u64,
        state: PacketBufferObjectState,
        note: String,
    },
    RecordPacketQueueObject {
        packet_queue: PacketQueueObjectId,
        name: String,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        role: PacketQueueRole,
        queue_index: u16,
        depth: u32,
        note: String,
    },
    RecordPacketDescriptorObject {
        packet_descriptor: PacketDescriptorObjectId,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        packet_buffer: PacketBufferObjectId,
        packet_buffer_generation: Generation,
        slot: u16,
        length: u32,
        note: String,
    },
    RecordFakeNetBackendObject {
        fake_net_backend: FakeNetBackendObjectId,
        name: String,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        provider: String,
        profile: String,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        mac: [u8; 6],
        frame_format_version: u32,
        max_payload_len: u32,
        deterministic_seed: u64,
        note: String,
    },
    RecordFakeBlockBackendObject {
        fake_block_backend: FakeBlockBackendObjectId,
        name: String,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        provider: String,
        profile: String,
        sector_size: u32,
        sector_count: u64,
        read_only: bool,
        max_transfer_sectors: u32,
        deterministic_seed: u64,
        note: String,
    },
    RecordVirtioBlkBackendObject {
        virtio_blk_backend: VirtioBlkBackendObjectId,
        name: String,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        provider: String,
        profile: String,
        model: String,
        sector_size: u32,
        sector_count: u64,
        read_only: bool,
        max_transfer_sectors: u32,
        device_features: u64,
        driver_features: u64,
        negotiated_features: u64,
        request_queue_index: u16,
        queue_size: u16,
        irq_vector: u16,
        note: String,
    },
    RecordBlockReadPath {
        read_path: BlockReadPathId,
        backend: ContractObjectRef,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        data_digest: u64,
        note: String,
    },
    RecordBlockWritePath {
        write_path: BlockWritePathId,
        backend: ContractObjectRef,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        payload_digest: u64,
        note: String,
    },
    RecordBlockRequestQueue {
        queue: BlockRequestQueueId,
        backend: ContractObjectRef,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        depth: u32,
        entries: Vec<BlockRequestQueueEntryRef>,
        note: String,
    },
    RecordBlockDmaBuffer {
        block_dma_buffer: BlockDmaBufferId,
        backend: ContractObjectRef,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        dma_buffer: DmaBufferObjectId,
        dma_buffer_generation: Generation,
        buffer_digest: u64,
        note: String,
    },
    RecordBlockPageObject {
        block_page_object: BlockPageObjectId,
        block_dma_buffer: BlockDmaBufferId,
        block_dma_buffer_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        aspace: ContractObjectRef,
        vma_region: ContractObjectRef,
        page: ContractObjectRef,
        page_dirty_generation: Generation,
        page_backing: PageBacking,
        cow_state: CowState,
        page_state: PageObjectState,
        page_offset: u64,
        byte_len: u64,
        note: String,
    },
    RecordBufferCacheObject {
        buffer_cache_object: BufferCacheObjectId,
        block_page_object: BlockPageObjectId,
        block_page_object_generation: Generation,
        page: ContractObjectRef,
        page_dirty_generation: Generation,
        block_offset: u64,
        byte_len: u64,
        cache_state: BufferCacheObjectState,
        coherency_epoch: u64,
        note: String,
    },
    RecordFileObject {
        file_object: FileObjectId,
        buffer_cache_object: BufferCacheObjectId,
        buffer_cache_object_generation: Generation,
        namespace: String,
        file_key: String,
        path: String,
        file_offset: u64,
        byte_len: u64,
        file_size: u64,
        content_digest: u64,
        state: FileObjectState,
        note: String,
    },
    RecordDirectoryObject {
        directory_object: DirectoryObjectId,
        file_object: FileObjectId,
        file_object_generation: Generation,
        namespace: String,
        directory_key: String,
        directory_path: String,
        entry_name: String,
        child_file_key: String,
        child_path: String,
        entry_kind: DirectoryEntryKind,
        file_size: u64,
        content_digest: u64,
        state: DirectoryObjectState,
        note: String,
    },
    RecordFatAdapterObject {
        fat_adapter_object: FatAdapterObjectId,
        directory_object: DirectoryObjectId,
        directory_object_generation: Generation,
        file_object: FileObjectId,
        file_object_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        implementation: String,
        version: String,
        profile: String,
        volume_label: String,
        image_bytes: u64,
        adapter_path: String,
        semantic_path: String,
        bytes_written: u64,
        bytes_read: u64,
        write_digest: u64,
        read_digest: u64,
        file_content_digest: u64,
        state: FatAdapterObjectState,
        note: String,
    },
    RecordExt4AdapterObject {
        ext4_adapter_object: Ext4AdapterObjectId,
        directory_object: DirectoryObjectId,
        directory_object_generation: Generation,
        file_object: FileObjectId,
        file_object_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        implementation: String,
        version: String,
        profile: String,
        volume_label: String,
        image_bytes: u64,
        adapter_path: String,
        semantic_path: String,
        bytes_read: u64,
        read_digest: u64,
        file_content_digest: u64,
        directory_entries: u64,
        read_only_enforced: bool,
        state: Ext4AdapterObjectState,
        note: String,
    },
    RecordFileHandleCapability {
        file_handle_capability: FileHandleCapabilityId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        file_object: FileObjectId,
        file_object_generation: Generation,
        directory_object: DirectoryObjectId,
        directory_object_generation: Generation,
        capability: CapabilityId,
        capability_generation: Generation,
        handle: CapabilityHandle,
        operation: String,
        file_offset: u64,
        byte_len: u64,
        content_digest: u64,
        note: String,
    },
    RecordFsWait {
        fs_wait: FsWaitId,
        wait: WaitId,
        wait_generation: Generation,
        file_handle_capability: FileHandleCapabilityId,
        file_handle_capability_generation: Generation,
        operation: String,
        sequence: u64,
        note: String,
    },
    ResolveFsWait {
        fs_wait: FsWaitId,
        fs_wait_generation: Generation,
        note: String,
    },
    CancelFsWait {
        fs_wait: FsWaitId,
        fs_wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: String,
    },
    CleanupBlockDriver {
        cleanup: BlockDriverCleanupId,
        io_cleanup: IoCleanupId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        backend: ContractObjectRef,
        reason: String,
        note: String,
    },
    RecordVirtioNetBackendObject {
        virtio_net_backend: VirtioNetBackendObjectId,
        name: String,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        provider: String,
        profile: String,
        model: String,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        mac: [u8; 6],
        frame_format_version: u32,
        max_payload_len: u32,
        device_features: u64,
        driver_features: u64,
        negotiated_features: u64,
        rx_queue_index: u16,
        tx_queue_index: u16,
        queue_size: u16,
        irq_vector: u16,
        note: String,
    },
    RecordNetworkRxInterrupt {
        rx_interrupt: NetworkRxInterruptId,
        virtio_net_backend: VirtioNetBackendObjectId,
        virtio_net_backend_generation: Generation,
        irq_event: IrqEventId,
        irq_event_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        ready_descriptors: u16,
        sequence: u64,
        note: String,
    },
    ResolveNetworkRxWait {
        resolution: NetworkRxWaitResolutionId,
        io_wait: IoWaitId,
        io_wait_generation: Generation,
        rx_interrupt: NetworkRxInterruptId,
        rx_interrupt_generation: Generation,
        note: String,
    },
    RecordNetworkTxCapabilityGate {
        tx_gate: NetworkTxCapabilityGateId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        packet_descriptor: PacketDescriptorObjectId,
        packet_descriptor_generation: Generation,
        device_capability: DeviceCapabilityId,
        device_capability_generation: Generation,
        handle: CapabilityHandle,
        note: String,
    },
    RecordNetworkTxCompletion {
        completion: NetworkTxCompletionId,
        tx_gate: NetworkTxCapabilityGateId,
        tx_gate_generation: Generation,
        backend: ContractObjectRef,
        completion_sequence: u64,
        note: String,
    },
    RecordNetworkStackAdapter {
        adapter: NetworkStackAdapterId,
        backend: ContractObjectRef,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        tx_queue: PacketQueueObjectId,
        tx_queue_generation: Generation,
        implementation: String,
        implementation_version: String,
        profile: String,
        medium: String,
        mac: [u8; 6],
        ipv4_addr: [u8; 4],
        ipv4_prefix_len: u8,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        max_payload_len: u32,
        socket_capacity: u16,
        note: String,
    },
    RecordSocketObject {
        socket: SocketObjectId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        owner_store: StoreId,
        owner_store_generation: Generation,
        domain: u32,
        socket_type: u32,
        protocol: u32,
        note: String,
    },
    RecordEndpointObject {
        endpoint: EndpointObjectId,
        socket: SocketObjectId,
        socket_generation: Generation,
        local_addr: [u8; 4],
        local_port: u16,
        remote_addr: [u8; 4],
        remote_port: u16,
        note: String,
    },
    BindSocketEndpoint {
        operation_id: SocketOperationId,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        local_addr: [u8; 4],
        local_port: u16,
        sequence: u64,
        note: String,
    },
    ListenSocketEndpoint {
        operation_id: SocketOperationId,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        backlog: u16,
        sequence: u64,
        note: String,
    },
    ConnectSocketEndpoint {
        operation_id: SocketOperationId,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        remote_addr: [u8; 4],
        remote_port: u16,
        sequence: u64,
        note: String,
    },
    SendSocket {
        operation_id: SocketOperationId,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        byte_len: u32,
        sequence: u64,
        note: String,
    },
    RecvSocket {
        operation_id: SocketOperationId,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        byte_len: u32,
        sequence: u64,
        note: String,
    },
    RecordSocketWait {
        socket_wait: SocketWaitId,
        wait: WaitId,
        wait_generation: Generation,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        wait_kind: SemanticWaitKind,
        blocker: ContractObjectRef,
        note: String,
    },
    ResolveSocketWait {
        socket_wait: SocketWaitId,
        socket_wait_generation: Generation,
        ready_sequence: u64,
        byte_len: u32,
        note: String,
    },
    CancelSocketWait {
        socket_wait: SocketWaitId,
        socket_wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: String,
    },
    RecordNetworkBackpressure {
        backpressure: NetworkBackpressureId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        endpoint: Option<EndpointObjectId>,
        endpoint_generation: Option<Generation>,
        direction: PacketBufferDirection,
        reason: NetworkBackpressureReason,
        action: NetworkBackpressureAction,
        queue_depth: u32,
        queue_limit: u32,
        dropped_packets: u32,
        dropped_bytes: u32,
        sequence: u64,
        note: String,
    },
    CleanupNetworkDriver {
        cleanup: NetworkDriverCleanupId,
        io_cleanup: IoCleanupId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        backend: ContractObjectRef,
        reason: String,
        note: String,
    },
    RecordNetworkGenerationAudit {
        audit: NetworkGenerationAuditId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        packet_descriptor: PacketDescriptorObjectId,
        packet_descriptor_generation: Generation,
        packet_buffer: PacketBufferObjectId,
        packet_buffer_generation: Generation,
        dma_buffer: ContractObjectRef,
        device_capability: ContractObjectRef,
        rejected_packet_generation_probes: u32,
        rejected_dma_generation_probes: u32,
        note: String,
    },
    RecordNetworkFaultInjection {
        injection: NetworkFaultInjectionId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        packet_descriptor: Option<PacketDescriptorObjectId>,
        packet_descriptor_generation: Option<Generation>,
        packet_buffer: Option<PacketBufferObjectId>,
        packet_buffer_generation: Option<Generation>,
        endpoint: Option<EndpointObjectId>,
        endpoint_generation: Option<Generation>,
        direction: PacketBufferDirection,
        kind: NetworkFaultInjectionKind,
        effect: NetworkFaultInjectionEffect,
        injected_packets: u32,
        dropped_packets: u32,
        error_packets: u32,
        error_code: String,
        sequence: u64,
        note: String,
    },
    RecordNetworkBenchmark {
        benchmark: NetworkBenchmarkId,
        scenario: String,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        tx_queue: PacketQueueObjectId,
        tx_queue_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        tx_completion: NetworkTxCompletionId,
        tx_completion_generation: Generation,
        rx_wait_resolution: NetworkRxWaitResolutionId,
        rx_wait_resolution_generation: Generation,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        backpressure: Option<NetworkBackpressureId>,
        backpressure_generation: Option<Generation>,
        sample_packets: u32,
        sample_bytes: u64,
        tx_completed_packets: u32,
        rx_resolved_packets: u32,
        dropped_packets: u32,
        measured_nanos: u64,
        budget_nanos: u64,
        p50_latency_nanos: u64,
        p99_latency_nanos: u64,
        note: String,
    },
    RecordNetworkRecoveryBenchmark {
        benchmark: NetworkRecoveryBenchmarkId,
        scenario: String,
        cleanup: NetworkDriverCleanupId,
        cleanup_generation: Generation,
        io_cleanup: IoCleanupId,
        io_cleanup_generation: Generation,
        fault_injection: Option<NetworkFaultInjectionId>,
        fault_injection_generation: Option<Generation>,
        recovery_start_event: EventId,
        recovery_complete_event: EventId,
        cancelled_socket_waits: u32,
        revoked_packet_capabilities: u32,
        recovery_nanos: u64,
        budget_nanos: u64,
        note: String,
    },
    RecordBlockDeviceObject {
        block_device: BlockDeviceObjectId,
        name: String,
        device: DeviceObjectId,
        device_generation: Generation,
        sector_size: u32,
        sector_count: u64,
        read_only: bool,
        max_transfer_sectors: u32,
        note: String,
    },
    RecordBlockRangeObject {
        block_range: BlockRangeObjectId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        start_sector: u64,
        sector_count: u64,
        note: String,
    },
    RecordBlockRequestObject {
        block_request: BlockRequestObjectId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        operation: BlockRequestOperation,
        sequence: u64,
        note: String,
    },
    RecordBlockCompletionObject {
        block_completion: BlockCompletionObjectId,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        sequence: u64,
        completed_bytes: u64,
        status: BlockCompletionStatus,
        note: String,
    },
    RecordBlockWait {
        block_wait: BlockWaitId,
        wait: WaitId,
        wait_generation: Generation,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        note: String,
    },
    ResolveBlockWait {
        block_wait: BlockWaitId,
        block_wait_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        note: String,
    },
    CancelBlockWait {
        block_wait: BlockWaitId,
        block_wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: String,
    },
    ApplyBlockPendingIoPolicy {
        policy: BlockPendingIoPolicyId,
        block_wait: BlockWaitId,
        block_wait_generation: Generation,
        action: BlockPendingIoAction,
        retry_request: Option<BlockRequestObjectId>,
        retry_request_generation: Option<Generation>,
        errno: i32,
        retry_attempt: u32,
        max_retries: u32,
        note: String,
    },
    RecordBlockRequestGenerationAudit {
        audit: BlockRequestGenerationAuditId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        backend: ContractObjectRef,
        dma_buffer: ContractObjectRef,
        rejected_completion_generation_probes: u32,
        rejected_wait_generation_probes: u32,
        rejected_dma_generation_probes: u32,
        rejected_queue_generation_probes: u32,
        note: String,
    },
    RecordBlockBenchmark {
        benchmark: BlockBenchmarkId,
        scenario: String,
        backend: ContractObjectRef,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        read_path: BlockReadPathId,
        read_path_generation: Generation,
        write_path: BlockWritePathId,
        write_path_generation: Generation,
        request_queue: BlockRequestQueueId,
        request_queue_generation: Generation,
        block_dma_buffer: BlockDmaBufferId,
        block_dma_buffer_generation: Generation,
        sample_requests: u32,
        sample_bytes: u64,
        read_completed_requests: u32,
        write_completed_requests: u32,
        queue_completed_requests: u32,
        measured_nanos: u64,
        budget_nanos: u64,
        p50_latency_nanos: u64,
        p99_latency_nanos: u64,
        note: String,
    },
    RecordBlockRecoveryBenchmark {
        benchmark: BlockRecoveryBenchmarkId,
        scenario: String,
        cleanup: BlockDriverCleanupId,
        cleanup_generation: Generation,
        io_cleanup: IoCleanupId,
        io_cleanup_generation: Generation,
        recovery_start_event: EventId,
        recovery_complete_event: EventId,
        cancelled_block_waits: u32,
        cancelled_wait_tokens: u32,
        released_dma_buffers: u32,
        revoked_device_capabilities: u32,
        recovery_nanos: u64,
        budget_nanos: u64,
        note: String,
    },
    RecordTargetFeatureSet {
        feature_set: TargetFeatureSetId,
        name: String,
        discovery_source: String,
        target_profile: String,
        target_arch: String,
        base_isa: String,
        simd_abi: String,
        simd_supported: bool,
        vector_register_count: u16,
        vector_register_bits: u16,
        scalar_fallback: bool,
        unsupported_reason: String,
        note: String,
    },
    RecordVectorState {
        vector_state: VectorStateId,
        owner_activation: ContractObjectRef,
        owner_store: ContractObjectRef,
        code_object: ContractObjectRef,
        target_feature_set: ContractObjectRef,
        simd_abi: String,
        vector_register_count: u16,
        vector_register_bits: u16,
        register_bytes: u32,
        state: VectorStateState,
        note: String,
    },
    RecordQueueObject {
        queue: QueueObjectId,
        name: String,
        role: QueueObjectRole,
        queue_index: u16,
        depth: u32,
        device: DeviceObjectId,
        device_generation: Generation,
        note: String,
    },
    RecordDescriptorObject {
        descriptor: DescriptorObjectId,
        queue: QueueObjectId,
        queue_generation: Generation,
        slot: u16,
        access: DescriptorObjectAccess,
        length: u32,
        note: String,
    },
    RecordDmaBufferObject {
        dma_buffer: DmaBufferObjectId,
        descriptor: DescriptorObjectId,
        descriptor_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        access: DmaBufferObjectAccess,
        length: u32,
        note: String,
    },
    RecordMmioRegionObject {
        mmio_region: MmioRegionObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        region_index: u16,
        offset: u64,
        length: u64,
        access: MmioRegionObjectAccess,
        note: String,
    },
    RecordIrqLineObject {
        irq_line: IrqLineObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        irq_number: u32,
        trigger: IrqLineTrigger,
        polarity: IrqLinePolarity,
        note: String,
    },
    RecordIrqEvent {
        irq_event: IrqEventId,
        irq_line: IrqLineObjectId,
        irq_line_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_store: StoreId,
        driver_store_generation: Generation,
        sequence: u64,
        note: String,
    },
    RecordDeviceCapability {
        device_capability: DeviceCapabilityId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        target: ContractObjectRef,
        class: CapabilityClass,
        operation: String,
        handle: CapabilityHandle,
        note: String,
    },
    BindDriverStore {
        binding: DriverStoreBindingId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        device_capability: DeviceCapabilityId,
        device_capability_generation: Generation,
        note: String,
    },
    RecordIoWait {
        io_wait: IoWaitId,
        wait: WaitId,
        wait_generation: Generation,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        blocker: ContractObjectRef,
        note: String,
    },
    ResolveIoWait {
        io_wait: IoWaitId,
        io_wait_generation: Generation,
        irq_event: IrqEventId,
        irq_event_generation: Generation,
        note: String,
    },
    CancelIoWait {
        io_wait: IoWaitId,
        io_wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: String,
    },
    CleanupIoDriver {
        cleanup: IoCleanupId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        reason: String,
        note: String,
    },
    InjectIoFault {
        fault: IoFaultInjectionId,
        cleanup: IoCleanupId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        target: ContractObjectRef,
        kind: IoFaultInjectionKind,
        note: String,
    },
    ValidateIoRuntime {
        report: IoValidationReportId,
        note: String,
    },
    ResumeActivation {
        resume: ActivationResumeId,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        note: String,
    },
    RecordPreemptionLatencySample {
        sample: PreemptionLatencySampleId,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        preemption: PreemptionId,
        preemption_generation: Generation,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        activation_resume: ActivationResumeId,
        activation_resume_generation: Generation,
        measured_nanos: u64,
        budget_nanos: u64,
        note: String,
    },
    BlockActivationOnWait {
        activation_wait: ActivationWaitId,
        activation: ActivationId,
        activation_generation: Generation,
        wait: WaitId,
        kind: SemanticWaitKind,
        blockers: Vec<ContractObjectRef>,
        deadline: Option<u64>,
        restart_policy: RestartPolicy,
        note: String,
    },
    CancelActivationWait {
        activation_wait: ActivationWaitId,
        activation_wait_generation: Generation,
        wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: String,
    },
    CleanupActivationForStoreFault {
        cleanup: ActivationCleanupId,
        store: StoreId,
        store_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        wait: Option<WaitId>,
        wait_generation: Option<Generation>,
        reason: String,
        note: String,
    },
    GrantCapability {
        subject: String,
        debug_object_label: String,
        object_ref: AuthorityObjectRef,
        operations: Vec<String>,
        lifetime: String,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        owner_task: Option<TaskId>,
        source: String,
        manifest_decl: bool,
    },
    RevokeCapability {
        cap: CapabilityId,
    },
    CreateWait {
        wait: WaitId,
        owner_task: Option<TaskId>,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        kind: SemanticWaitKind,
        generation: Generation,
        blockers: Vec<ContractObjectRef>,
        deadline: Option<u64>,
        restart_policy: RestartPolicy,
        saved_context: Option<String>,
    },
    ResolveWait {
        wait: WaitId,
        reason: String,
    },
    CancelWait {
        wait: WaitId,
        errno: i32,
        reason: WaitCancelReason,
    },
    RecordTrap {
        store: Option<StoreId>,
        task: Option<TaskId>,
        trap: TrapClass,
        detail: String,
    },
    BeginCleanup {
        cleanup: TransactionId,
        store: StoreId,
        generation: Generation,
        reason: String,
    },
    ApplyCleanupStep {
        cleanup: TransactionId,
        step: CleanupStep,
        target: ContractObjectRef,
        observed_generation: Generation,
    },
    CommitCleanup {
        cleanup: TransactionId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandEnvelope {
    pub command_id: CommandId,
    pub issuer: String,
    pub expected_epoch: Option<u64>,
    pub command: SemanticCommand,
}

impl CommandEnvelope {
    pub fn new(command_id: CommandId, issuer: &str, command: SemanticCommand) -> Self {
        Self {
            command_id,
            issuer: issuer.to_string(),
            expected_epoch: None,
            command,
        }
    }

    pub fn with_expected_epoch(mut self, expected_epoch: u64) -> Self {
        self.expected_epoch = Some(expected_epoch);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStatus {
    Applied,
    Noop,
    Rejected,
}

impl CommandStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Noop => "noop",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandEffect {
    pub kind: String,
    pub target: Option<ContractObjectRef>,
}

impl CommandEffect {
    pub fn new(kind: &str, target: Option<ContractObjectRef>) -> Self {
        Self {
            kind: kind.to_string(),
            target,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandResult {
    pub command_id: CommandId,
    pub issuer: String,
    pub command: &'static str,
    pub status: CommandStatus,
    pub events: Vec<EventId>,
    pub effects: Vec<CommandEffect>,
    pub violations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutcome {
    pub command: &'static str,
    pub event_count_before: usize,
    pub event_count_after: usize,
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandError {
    PreconditionFailed(String),
}

impl CommandError {
    pub fn precondition(detail: &str) -> Self {
        Self::PreconditionFailed(detail.to_string())
    }
}

impl SemanticCommand {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::RegisterHart { .. } => "register-hart",
            Self::SetHartState { .. } => "set-hart-state",
            Self::BindHartCurrentActivation { .. } => "bind-hart-current-activation",
            Self::ClearHartCurrentActivation { .. } => "clear-hart-current-activation",
            Self::CreateRuntimeActivation { .. } => "create-runtime-activation",
            Self::CreateRunnableQueue { .. } => "create-runnable-queue",
            Self::BindRunnableQueueOwner { .. } => "bind-runnable-queue-owner",
            Self::EnqueueRunnable { .. } => "enqueue-runnable",
            Self::DequeueRunnable { .. } => "dequeue-runnable",
            Self::CreateActivationContext { .. } => "create-activation-context",
            Self::CaptureSavedContext { .. } => "capture-saved-context",
            Self::SavePreemptedContext { .. } => "save-preempted-context",
            Self::RecordTimerInterrupt { .. } => "record-timer-interrupt",
            Self::RecordIpiEvent { .. } => "record-ipi-event",
            Self::RemotePreemptActivation { .. } => "remote-preempt-activation",
            Self::RemoteParkHart { .. } => "remote-park-hart",
            Self::PreemptActivation { .. } => "preempt-activation",
            Self::RecordSchedulerDecision { .. } => "record-scheduler-decision",
            Self::RecordCrossHartSchedulerDecision { .. } => "record-cross-hart-scheduler-decision",
            Self::MigrateRunnableActivation { .. } => "migrate-runnable-activation",
            Self::RecordSmpSafePoint { .. } => "record-smp-safe-point",
            Self::CompleteStopTheWorldRendezvous { .. } => "complete-stop-the-world-rendezvous",
            Self::ValidateSmpCodePublishBarrier { .. } => "validate-smp-code-publish-barrier",
            Self::ValidateSmpCleanupQuiescence { .. } => "validate-smp-cleanup-quiescence",
            Self::ValidateSmpSnapshotBarrier { .. } => "validate-smp-snapshot-barrier",
            Self::RecordSmpStressRun { .. } => "record-smp-stress-run",
            Self::RecordSmpScalingBenchmark { .. } => "record-smp-scaling-benchmark",
            Self::RecordDeviceObject { .. } => "record-device-object",
            Self::RecordPacketDeviceObject { .. } => "record-packet-device-object",
            Self::RecordPacketBufferObject { .. } => "record-packet-buffer-object",
            Self::RecordPacketQueueObject { .. } => "record-packet-queue-object",
            Self::RecordPacketDescriptorObject { .. } => "record-packet-descriptor-object",
            Self::RecordFakeNetBackendObject { .. } => "record-fake-net-backend-object",
            Self::RecordFakeBlockBackendObject { .. } => "record-fake-block-backend-object",
            Self::RecordVirtioBlkBackendObject { .. } => "record-virtio-blk-backend-object",
            Self::RecordBlockReadPath { .. } => "record-block-read-path",
            Self::RecordBlockWritePath { .. } => "record-block-write-path",
            Self::RecordBlockRequestQueue { .. } => "record-block-request-queue",
            Self::RecordBlockDmaBuffer { .. } => "record-block-dma-buffer",
            Self::RecordBlockPageObject { .. } => "record-block-page-object",
            Self::RecordBufferCacheObject { .. } => "record-buffer-cache-object",
            Self::RecordFileObject { .. } => "record-file-object",
            Self::RecordDirectoryObject { .. } => "record-directory-object",
            Self::RecordFatAdapterObject { .. } => "record-fat-adapter-object",
            Self::RecordExt4AdapterObject { .. } => "record-ext4-adapter-object",
            Self::RecordFileHandleCapability { .. } => "record-file-handle-capability",
            Self::RecordFsWait { .. } => "record-fs-wait",
            Self::ResolveFsWait { .. } => "resolve-fs-wait",
            Self::CancelFsWait { .. } => "cancel-fs-wait",
            Self::CleanupBlockDriver { .. } => "cleanup-block-driver",
            Self::RecordVirtioNetBackendObject { .. } => "record-virtio-net-backend-object",
            Self::RecordNetworkRxInterrupt { .. } => "record-network-rx-interrupt",
            Self::ResolveNetworkRxWait { .. } => "resolve-network-rx-wait",
            Self::RecordNetworkTxCapabilityGate { .. } => "record-network-tx-capability-gate",
            Self::RecordNetworkTxCompletion { .. } => "record-network-tx-completion",
            Self::RecordNetworkStackAdapter { .. } => "record-network-stack-adapter",
            Self::RecordSocketObject { .. } => "record-socket-object",
            Self::RecordEndpointObject { .. } => "record-endpoint-object",
            Self::BindSocketEndpoint { .. } => "bind-socket-endpoint",
            Self::ListenSocketEndpoint { .. } => "listen-socket-endpoint",
            Self::ConnectSocketEndpoint { .. } => "connect-socket-endpoint",
            Self::SendSocket { .. } => "send-socket",
            Self::RecvSocket { .. } => "recv-socket",
            Self::RecordSocketWait { .. } => "record-socket-wait",
            Self::ResolveSocketWait { .. } => "resolve-socket-wait",
            Self::CancelSocketWait { .. } => "cancel-socket-wait",
            Self::RecordNetworkBackpressure { .. } => "record-network-backpressure",
            Self::CleanupNetworkDriver { .. } => "cleanup-network-driver",
            Self::RecordNetworkGenerationAudit { .. } => "record-network-generation-audit",
            Self::RecordNetworkFaultInjection { .. } => "record-network-fault-injection",
            Self::RecordNetworkBenchmark { .. } => "record-network-benchmark",
            Self::RecordNetworkRecoveryBenchmark { .. } => "record-network-recovery-benchmark",
            Self::RecordBlockDeviceObject { .. } => "record-block-device-object",
            Self::RecordBlockRangeObject { .. } => "record-block-range-object",
            Self::RecordBlockRequestObject { .. } => "record-block-request-object",
            Self::RecordBlockCompletionObject { .. } => "record-block-completion-object",
            Self::RecordBlockWait { .. } => "record-block-wait",
            Self::ResolveBlockWait { .. } => "resolve-block-wait",
            Self::CancelBlockWait { .. } => "cancel-block-wait",
            Self::ApplyBlockPendingIoPolicy { .. } => "apply-block-pending-io-policy",
            Self::RecordBlockRequestGenerationAudit { .. } => {
                "record-block-request-generation-audit"
            }
            Self::RecordBlockBenchmark { .. } => "record-block-benchmark",
            Self::RecordBlockRecoveryBenchmark { .. } => "record-block-recovery-benchmark",
            Self::RecordTargetFeatureSet { .. } => "record-target-feature-set",
            Self::RecordVectorState { .. } => "record-vector-state",
            Self::RecordQueueObject { .. } => "record-queue-object",
            Self::RecordDescriptorObject { .. } => "record-descriptor-object",
            Self::RecordDmaBufferObject { .. } => "record-dma-buffer-object",
            Self::RecordMmioRegionObject { .. } => "record-mmio-region-object",
            Self::RecordIrqLineObject { .. } => "record-irq-line-object",
            Self::RecordIrqEvent { .. } => "record-irq-event",
            Self::RecordDeviceCapability { .. } => "record-device-capability",
            Self::BindDriverStore { .. } => "bind-driver-store",
            Self::RecordIoWait { .. } => "record-io-wait",
            Self::ResolveIoWait { .. } => "resolve-io-wait",
            Self::CancelIoWait { .. } => "cancel-io-wait",
            Self::CleanupIoDriver { .. } => "cleanup-io-driver",
            Self::InjectIoFault { .. } => "inject-io-fault",
            Self::ValidateIoRuntime { .. } => "validate-io-runtime",
            Self::ResumeActivation { .. } => "resume-activation",
            Self::RecordPreemptionLatencySample { .. } => "record-preemption-latency-sample",
            Self::BlockActivationOnWait { .. } => "block-activation-on-wait",
            Self::CancelActivationWait { .. } => "cancel-activation-wait",
            Self::CleanupActivationForStoreFault { .. } => "cleanup-activation-for-store-fault",
            Self::GrantCapability { .. } => "grant-capability",
            Self::RevokeCapability { .. } => "revoke-capability",
            Self::CreateWait { .. } => "create-wait",
            Self::ResolveWait { .. } => "resolve-wait",
            Self::CancelWait { .. } => "cancel-wait",
            Self::RecordTrap { .. } => "record-trap",
            Self::BeginCleanup { .. } => "begin-cleanup",
            Self::ApplyCleanupStep { .. } => "apply-cleanup-step",
            Self::CommitCleanup { .. } => "commit-cleanup",
        }
    }
}

impl SemanticGraph {
    pub fn apply_envelope(&mut self, envelope: CommandEnvelope) -> CommandResult {
        let command_name = envelope.command.name();
        let result = if envelope.command_id == 0 {
            rejected_command_result(
                envelope.command_id,
                envelope.issuer,
                command_name,
                "command id=0 is invalid",
            )
        } else if let Some(expected_epoch) = envelope.expected_epoch {
            let actual_epoch = self.event_count() as u64;
            if expected_epoch != actual_epoch {
                rejected_command_result(
                    envelope.command_id,
                    envelope.issuer,
                    command_name,
                    "expected epoch mismatch",
                )
            } else {
                self.apply_envelope_prechecked(envelope, command_name)
            }
        } else {
            self.apply_envelope_prechecked(envelope, command_name)
        };
        self.command_results.push(result.clone());
        result
    }

    fn apply_envelope_prechecked(
        &mut self,
        envelope: CommandEnvelope,
        command_name: &'static str,
    ) -> CommandResult {
        match self.apply(envelope.command) {
            Ok(outcome) => CommandResult {
                command_id: envelope.command_id,
                issuer: envelope.issuer,
                command: outcome.command,
                status: if outcome.changed {
                    CommandStatus::Applied
                } else {
                    CommandStatus::Noop
                },
                events: event_refs_between(outcome.event_count_before, outcome.event_count_after),
                effects: command_effects(&outcome),
                violations: Vec::new(),
            },
            Err(CommandError::PreconditionFailed(detail)) => CommandResult {
                command_id: envelope.command_id,
                issuer: envelope.issuer,
                command: command_name,
                status: CommandStatus::Rejected,
                events: Vec::new(),
                effects: Vec::new(),
                violations: {
                    let mut violations = Vec::new();
                    violations.push(detail);
                    violations
                },
            },
        }
    }

    pub fn apply(&mut self, command: SemanticCommand) -> Result<CommandOutcome, CommandError> {
        self.preflight_command(&command)?;
        let event_count_before = self.event_count();
        let command_name = command.name();
        let changed = self.apply_prechecked_command(command);
        Ok(CommandOutcome {
            command: command_name,
            event_count_before,
            event_count_after: self.event_count(),
            changed,
        })
    }

    fn preflight_command(&self, command: &SemanticCommand) -> Result<(), CommandError> {
        match command {
            SemanticCommand::RegisterHart {
                hart,
                hardware_id,
                label,
                boot,
                ..
            } => {
                if *hart == 0 {
                    Err(CommandError::precondition("hart id=0 is invalid"))
                } else if label.is_empty() {
                    Err(CommandError::precondition("hart label is empty"))
                } else if self.harts.iter().any(|record| record.id == *hart) {
                    Err(CommandError::precondition("hart already exists"))
                } else if self
                    .harts
                    .iter()
                    .any(|record| record.hardware_id == *hardware_id)
                {
                    Err(CommandError::precondition("hardware hart already exists"))
                } else if *boot && self.harts.iter().any(|record| record.boot) {
                    Err(CommandError::precondition("boot hart already exists"))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::SetHartState {
                hart,
                hart_generation,
                reason,
                ..
            } => {
                if reason.is_empty() {
                    Err(CommandError::precondition("hart state reason is empty"))
                } else if self
                    .harts
                    .iter()
                    .any(|record| record.id == *hart && record.generation == *hart_generation)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("hart generation is missing"))
                }
            }
            SemanticCommand::BindHartCurrentActivation {
                hart,
                hart_generation,
                activation,
                activation_generation,
                ..
            } => {
                let Some(hart_record) = self
                    .harts
                    .iter()
                    .find(|record| record.id == *hart && record.generation == *hart_generation)
                else {
                    return Err(CommandError::precondition("hart generation is missing"));
                };
                if hart_record.state != HartState::Idle {
                    return Err(CommandError::precondition("hart is not idle"));
                }
                if hart_record.current_activation.is_some() {
                    return Err(CommandError::precondition(
                        "hart already has current activation",
                    ));
                }
                if self.harts.iter().any(|record| {
                    record.id != *hart
                        && record.current_activation == Some(*activation)
                        && record.current_activation_generation == Some(*activation_generation)
                }) {
                    return Err(CommandError::precondition(
                        "activation is already current on another hart",
                    ));
                }
                let Some(activation_record) = self.runtime_activations.iter().find(|record| {
                    record.id == *activation
                        && record.generation == *activation_generation
                        && record.state == RuntimeActivationState::Running
                }) else {
                    return Err(CommandError::precondition(
                        "current activation generation is missing or not running",
                    ));
                };
                if !self.tasks.iter().any(|task| {
                    task.id == activation_record.owner_task
                        && task.generation == activation_record.owner_task_generation
                }) {
                    return Err(CommandError::precondition(
                        "current activation owner task generation is missing",
                    ));
                }
                if let Some(store) = activation_record.owner_store {
                    let Some(generation) = activation_record.owner_store_generation else {
                        return Err(CommandError::precondition(
                            "current activation owner store generation is required",
                        ));
                    };
                    if !self.stores.iter().any(|store_record| {
                        store_record.id == store
                            && store_record.generation == generation
                            && store_record.state != StoreState::Dead
                    }) {
                        return Err(CommandError::precondition(
                            "current activation owner store generation is missing or dead",
                        ));
                    }
                }
                Ok(())
            }
            SemanticCommand::ClearHartCurrentActivation {
                hart,
                hart_generation,
                activation,
                activation_generation,
                reason,
                ..
            } => {
                if reason.is_empty() {
                    return Err(CommandError::precondition(
                        "clear hart current activation reason is empty",
                    ));
                }
                let Some(hart_record) = self
                    .harts
                    .iter()
                    .find(|record| record.id == *hart && record.generation == *hart_generation)
                else {
                    return Err(CommandError::precondition("hart generation is missing"));
                };
                if hart_record.current_activation == Some(*activation)
                    && hart_record.current_activation_generation == Some(*activation_generation)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "hart current activation generation mismatch",
                    ))
                }
            }
            SemanticCommand::CreateRuntimeActivation {
                activation,
                owner_task,
                owner_task_generation,
                owner_store,
                owner_store_generation,
                code_object,
            } => {
                if *activation == 0 {
                    Err(CommandError::precondition("activation id=0 is invalid"))
                } else if self
                    .runtime_activations
                    .iter()
                    .any(|record| record.id == *activation)
                {
                    Err(CommandError::precondition("activation already exists"))
                } else if !self
                    .tasks
                    .iter()
                    .any(|task| task.id == *owner_task && task.generation == *owner_task_generation)
                {
                    Err(CommandError::precondition(
                        "activation owner task generation is missing",
                    ))
                } else if let Some(code) = code_object
                    && code.kind != ContractObjectKind::CodeObject
                {
                    Err(CommandError::precondition(
                        "activation code reference must be a code object",
                    ))
                } else if let Some(store) = owner_store {
                    if let Some(generation) = owner_store_generation {
                        if self.stores.iter().any(|record| {
                            record.id == *store
                                && record.generation == *generation
                                && record.state != StoreState::Dead
                        }) {
                            Ok(())
                        } else {
                            Err(CommandError::precondition(
                                "activation owner store generation is missing or dead",
                            ))
                        }
                    } else {
                        Err(CommandError::precondition(
                            "activation owner store generation is required",
                        ))
                    }
                } else {
                    Ok(())
                }
            }
            SemanticCommand::CreateRunnableQueue { queue, label } => {
                if *queue == 0 {
                    Err(CommandError::precondition("runnable queue id=0 is invalid"))
                } else if label.is_empty() {
                    Err(CommandError::precondition("runnable queue label is empty"))
                } else if self
                    .runnable_queues
                    .iter()
                    .any(|record| record.id == *queue)
                {
                    Err(CommandError::precondition("runnable queue already exists"))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::BindRunnableQueueOwner {
                queue,
                queue_generation,
                hart,
                hart_generation,
                ..
            } => {
                let Some(queue_record) = self.runnable_queues.iter().find(|record| {
                    record.id == *queue
                        && record.generation == *queue_generation
                        && record.state == RunnableQueueState::Active
                }) else {
                    return Err(CommandError::precondition(
                        "runnable queue generation is missing or inactive",
                    ));
                };
                if queue_record.owner_hart == Some(*hart)
                    && queue_record.owner_hart_generation == Some(*hart_generation)
                {
                    return Err(CommandError::precondition(
                        "runnable queue owner is already bound",
                    ));
                }
                if !queue_record.entries.is_empty() {
                    return Err(CommandError::precondition(
                        "runnable queue owner cannot change while entries are live",
                    ));
                }
                let Some(_hart_record) = self.harts.iter().find(|record| {
                    record.id == *hart
                        && record.generation == *hart_generation
                        && !matches!(record.state, HartState::Offline | HartState::Faulted)
                }) else {
                    return Err(CommandError::precondition(
                        "runnable queue owner hart generation is missing or unavailable",
                    ));
                };
                Ok(())
            }
            SemanticCommand::EnqueueRunnable {
                queue,
                activation,
                activation_generation,
            } => {
                let Some(queue_record) = self
                    .runnable_queues
                    .iter()
                    .find(|record| record.id == *queue)
                else {
                    return Err(CommandError::precondition("runnable queue is missing"));
                };
                if queue_record.state != RunnableQueueState::Active {
                    return Err(CommandError::precondition("runnable queue is not active"));
                }
                if self.runnable_queues.iter().any(|record| {
                    record
                        .entries
                        .iter()
                        .any(|entry| entry.activation == *activation)
                }) {
                    return Err(CommandError::precondition("activation already queued"));
                }
                let Some(activation_record) = self
                    .runtime_activations
                    .iter()
                    .find(|record| record.id == *activation)
                else {
                    return Err(CommandError::precondition("activation is missing"));
                };
                if activation_record.generation != *activation_generation {
                    return Err(CommandError::precondition("activation generation mismatch"));
                }
                if !matches!(
                    activation_record.state,
                    RuntimeActivationState::Created | RuntimeActivationState::Blocked
                ) {
                    return Err(CommandError::precondition("activation is not enqueueable"));
                }
                if activation_record.runnable_queue.is_some() {
                    return Err(CommandError::precondition("activation already queued"));
                }
                let Some(owner_task) = self.tasks.iter().find(|task| {
                    task.id == activation_record.owner_task
                        && task.generation == activation_record.owner_task_generation
                }) else {
                    return Err(CommandError::precondition(
                        "activation owner task generation is missing",
                    ));
                };
                if owner_task.state == TaskState::Pending {
                    return Err(CommandError::precondition(
                        "pending wait task cannot be enqueued",
                    ));
                }
                if let Some(store) = activation_record.owner_store {
                    let Some(generation) = activation_record.owner_store_generation else {
                        return Err(CommandError::precondition(
                            "activation owner store generation is required",
                        ));
                    };
                    if !self.stores.iter().any(|record| {
                        record.id == store
                            && record.generation == generation
                            && record.state != StoreState::Dead
                    }) {
                        return Err(CommandError::precondition(
                            "dead or missing store activation cannot be enqueued",
                        ));
                    }
                }
                Ok(())
            }
            SemanticCommand::DequeueRunnable { queue, activation } => {
                let Some(queue_record) = self
                    .runnable_queues
                    .iter()
                    .find(|record| record.id == *queue)
                else {
                    return Err(CommandError::precondition("runnable queue is missing"));
                };
                if queue_record.state != RunnableQueueState::Active {
                    return Err(CommandError::precondition("runnable queue is not active"));
                }
                if !queue_record
                    .entries
                    .iter()
                    .any(|entry| entry.activation == *activation)
                {
                    return Err(CommandError::precondition("activation is not queued"));
                }
                Ok(())
            }
            SemanticCommand::CreateActivationContext {
                context,
                activation,
                activation_generation,
            } => {
                if *context == 0 {
                    Err(CommandError::precondition(
                        "activation context id=0 is invalid",
                    ))
                } else if self
                    .activation_contexts
                    .iter()
                    .any(|record| record.id == *context)
                {
                    Err(CommandError::precondition(
                        "activation context already exists",
                    ))
                } else if self.activation_contexts.iter().any(|record| {
                    record.activation == *activation
                        && record.state != ActivationContextState::Dropped
                }) {
                    Err(CommandError::precondition(
                        "activation already has a live context",
                    ))
                } else if self.runtime_activations.iter().any(|record| {
                    record.id == *activation
                        && record.generation == *activation_generation
                        && !matches!(
                            record.state,
                            RuntimeActivationState::Dead | RuntimeActivationState::Exited
                        )
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "activation generation is missing or inactive",
                    ))
                }
            }
            SemanticCommand::CaptureSavedContext {
                saved_context,
                context,
                context_generation,
                pc,
                sp,
                ..
            } => {
                if *saved_context == 0 {
                    Err(CommandError::precondition("saved context id=0 is invalid"))
                } else if *pc == 0 || *sp == 0 {
                    Err(CommandError::precondition(
                        "saved context requires nonzero pc and sp",
                    ))
                } else if self
                    .saved_contexts
                    .iter()
                    .any(|record| record.id == *saved_context)
                {
                    Err(CommandError::precondition("saved context already exists"))
                } else {
                    let Some(context_record) = self.activation_contexts.iter().find(|record| {
                        record.id == *context
                            && record.generation == *context_generation
                            && record.state != ActivationContextState::Dropped
                    }) else {
                        return Err(CommandError::precondition(
                            "activation context generation is missing or dropped",
                        ));
                    };
                    if context_record.current_saved_context.is_some() {
                        Err(CommandError::precondition(
                            "activation context already has saved context",
                        ))
                    } else {
                        Ok(())
                    }
                }
            }
            SemanticCommand::SavePreemptedContext {
                context,
                saved_context,
                preemption,
                preemption_generation,
                pc,
                sp,
                ..
            } => {
                if *context == 0 || *saved_context == 0 {
                    Err(CommandError::precondition(
                        "preempted context requires nonzero context ids",
                    ))
                } else if *pc == 0 || *sp == 0 {
                    Err(CommandError::precondition(
                        "preempted context requires nonzero pc and sp",
                    ))
                } else if self
                    .activation_contexts
                    .iter()
                    .any(|record| record.id == *context)
                {
                    Err(CommandError::precondition(
                        "activation context already exists",
                    ))
                } else if self
                    .saved_contexts
                    .iter()
                    .any(|record| record.id == *saved_context)
                {
                    Err(CommandError::precondition("saved context already exists"))
                } else {
                    let Some(preemption_record) = self.preemptions.iter().find(|record| {
                        record.id == *preemption
                            && record.generation == *preemption_generation
                            && record.state == PreemptionState::Applied
                    }) else {
                        return Err(CommandError::precondition(
                            "preemption generation is missing",
                        ));
                    };
                    let Some(activation) = self.runtime_activations.iter().find(|record| {
                        record.id == preemption_record.activation
                            && record.generation == preemption_record.activation_generation_after
                            && !matches!(
                                record.state,
                                RuntimeActivationState::Dead | RuntimeActivationState::Exited
                            )
                    }) else {
                        return Err(CommandError::precondition(
                            "preempted activation generation is missing or dead",
                        ));
                    };
                    if self.activation_contexts.iter().any(|record| {
                        record.activation == activation.id
                            && record.state != ActivationContextState::Dropped
                    }) {
                        Err(CommandError::precondition(
                            "activation already has live context",
                        ))
                    } else if !self.tasks.iter().any(|task| {
                        task.id == activation.owner_task
                            && task.generation == activation.owner_task_generation
                    }) {
                        Err(CommandError::precondition(
                            "preempted activation owner task generation is missing",
                        ))
                    } else if let Some(store) = activation.owner_store {
                        if let Some(generation) = activation.owner_store_generation {
                            if self.stores.iter().any(|record| {
                                record.id == store
                                    && record.generation == generation
                                    && record.state != StoreState::Dead
                            }) {
                                Ok(())
                            } else {
                                Err(CommandError::precondition(
                                    "preempted activation owner store generation is missing or dead",
                                ))
                            }
                        } else {
                            Err(CommandError::precondition(
                                "preempted activation owner store generation is required",
                            ))
                        }
                    } else {
                        Ok(())
                    }
                }
            }
            SemanticCommand::RecordTimerInterrupt {
                interrupt,
                timer_epoch,
                hart,
                hart_generation,
                target_activation,
                target_activation_generation,
                ..
            } => {
                if *interrupt == 0 {
                    Err(CommandError::precondition(
                        "timer interrupt id=0 is invalid",
                    ))
                } else if *timer_epoch == 0 {
                    Err(CommandError::precondition(
                        "timer interrupt epoch=0 is invalid",
                    ))
                } else if self
                    .timer_interrupts
                    .iter()
                    .any(|record| record.id == *interrupt || record.timer_epoch == *timer_epoch)
                {
                    Err(CommandError::precondition("timer interrupt already exists"))
                } else if let Some(previous) = self
                    .timer_interrupts
                    .iter()
                    .map(|record| record.timer_epoch)
                    .max()
                    && *timer_epoch <= previous
                {
                    Err(CommandError::precondition(
                        "timer interrupt epoch must be monotonic",
                    ))
                } else if !self.harts.iter().any(|record| {
                    record.id == *hart
                        && record.generation == *hart_generation
                        && !matches!(record.state, HartState::Offline | HartState::Faulted)
                }) {
                    Err(CommandError::precondition(
                        "timer interrupt hart generation is missing or inactive",
                    ))
                } else if let Some(activation) = target_activation {
                    let Some(generation) = target_activation_generation else {
                        return Err(CommandError::precondition(
                            "timer interrupt target activation generation is required",
                        ));
                    };
                    if self.runtime_activations.iter().any(|record| {
                        record.id == *activation
                            && record.generation == *generation
                            && !matches!(
                                record.state,
                                RuntimeActivationState::Dead | RuntimeActivationState::Exited
                            )
                    }) {
                        Ok(())
                    } else {
                        Err(CommandError::precondition(
                            "timer interrupt target activation generation is missing or inactive",
                        ))
                    }
                } else if target_activation_generation.is_some() {
                    Err(CommandError::precondition(
                        "timer interrupt target activation is required",
                    ))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::RecordIpiEvent {
                ipi,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                reason,
                ..
            } => {
                if *ipi == 0 {
                    Err(CommandError::precondition("ipi event id=0 is invalid"))
                } else if reason.is_empty() {
                    Err(CommandError::precondition("ipi event reason is empty"))
                } else if source_hart == target_hart {
                    Err(CommandError::precondition(
                        "ipi source and target harts must differ",
                    ))
                } else if self.ipi_events.iter().any(|record| record.id == *ipi) {
                    Err(CommandError::precondition("ipi event already exists"))
                } else if !self.harts.iter().any(|record| {
                    record.id == *source_hart
                        && record.generation == *source_hart_generation
                        && !matches!(record.state, HartState::Offline | HartState::Faulted)
                }) {
                    Err(CommandError::precondition(
                        "ipi source hart generation is missing or inactive",
                    ))
                } else if !self.harts.iter().any(|record| {
                    record.id == *target_hart
                        && record.generation == *target_hart_generation
                        && !matches!(record.state, HartState::Offline | HartState::Faulted)
                }) {
                    Err(CommandError::precondition(
                        "ipi target hart generation is missing or inactive",
                    ))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::RemotePreemptActivation {
                remote_preempt,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                activation,
                activation_generation,
                queue,
                ..
            } => self
                .validate_remote_preempt_activation(
                    *remote_preempt,
                    *ipi,
                    *ipi_generation,
                    *source_hart,
                    *source_hart_generation,
                    *target_hart,
                    *target_hart_generation,
                    *activation,
                    *activation_generation,
                    *queue,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RemoteParkHart {
                remote_park,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                ..
            } => self
                .validate_remote_park_hart(
                    *remote_park,
                    *ipi,
                    *ipi_generation,
                    *source_hart,
                    *source_hart_generation,
                    *target_hart,
                    *target_hart_generation,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::PreemptActivation {
                preemption,
                activation,
                activation_generation,
                timer_interrupt,
                timer_interrupt_generation,
                queue,
                ..
            } => {
                if *preemption == 0 {
                    Err(CommandError::precondition("preemption id=0 is invalid"))
                } else if self
                    .preemptions
                    .iter()
                    .any(|record| record.id == *preemption)
                {
                    Err(CommandError::precondition("preemption already exists"))
                } else if !self
                    .runnable_queues
                    .iter()
                    .any(|record| record.id == *queue && record.state == RunnableQueueState::Active)
                {
                    Err(CommandError::precondition(
                        "preemption queue is missing or inactive",
                    ))
                } else if self.runnable_queues.iter().any(|record| {
                    record
                        .entries
                        .iter()
                        .any(|entry| entry.activation == *activation)
                }) {
                    Err(CommandError::precondition("activation already queued"))
                } else {
                    let Some(timer) = self.timer_interrupts.iter().find(|record| {
                        record.id == *timer_interrupt
                            && record.generation == *timer_interrupt_generation
                    }) else {
                        return Err(CommandError::precondition(
                            "preemption timer interrupt generation is missing",
                        ));
                    };
                    if timer.target_activation != Some(*activation)
                        || timer.target_activation_generation != Some(*activation_generation)
                    {
                        return Err(CommandError::precondition(
                            "preemption timer target does not match activation generation",
                        ));
                    }
                    let Some(record) = self.runtime_activations.iter().find(|record| {
                        record.id == *activation
                            && record.generation == *activation_generation
                            && record.state == RuntimeActivationState::Running
                            && record.runnable_queue.is_none()
                            && record.runnable_queue_generation.is_none()
                    }) else {
                        return Err(CommandError::precondition(
                            "preemption target activation generation is not running",
                        ));
                    };
                    let Some(owner_task) = self.tasks.iter().find(|task| {
                        task.id == record.owner_task
                            && task.generation == record.owner_task_generation
                    }) else {
                        return Err(CommandError::precondition(
                            "preemption owner task generation is missing",
                        ));
                    };
                    if matches!(
                        owner_task.state,
                        TaskState::Pending
                            | TaskState::Cancelled
                            | TaskState::Faulted
                            | TaskState::Exited
                    ) {
                        return Err(CommandError::precondition(
                            "preemption owner task is not runnable",
                        ));
                    }
                    if let Some(store) = record.owner_store {
                        let Some(generation) = record.owner_store_generation else {
                            return Err(CommandError::precondition(
                                "preemption owner store generation is required",
                            ));
                        };
                        if !self.stores.iter().any(|store_record| {
                            store_record.id == store
                                && store_record.generation == generation
                                && store_record.state != StoreState::Dead
                        }) {
                            return Err(CommandError::precondition(
                                "preemption owner store generation is missing or dead",
                            ));
                        }
                    }
                    Ok(())
                }
            }
            SemanticCommand::RecordSchedulerDecision {
                decision,
                queue,
                queue_generation,
                selected_activation,
                selected_activation_generation,
                reason,
                ..
            } => {
                if *decision == 0 {
                    Err(CommandError::precondition(
                        "scheduler decision id=0 is invalid",
                    ))
                } else if reason.is_empty() {
                    Err(CommandError::precondition(
                        "scheduler decision reason is empty",
                    ))
                } else if self
                    .scheduler_decisions
                    .iter()
                    .any(|record| record.id == *decision)
                {
                    Err(CommandError::precondition(
                        "scheduler decision already exists",
                    ))
                } else {
                    let Some(queue_record) = self.runnable_queues.iter().find(|record| {
                        record.id == *queue
                            && record.generation == *queue_generation
                            && record.state == RunnableQueueState::Active
                    }) else {
                        return Err(CommandError::precondition(
                            "scheduler decision queue generation is missing or inactive",
                        ));
                    };
                    if !queue_record.entries.iter().any(|entry| {
                        entry.activation == *selected_activation
                            && entry.activation_generation == *selected_activation_generation
                    }) {
                        return Err(CommandError::precondition(
                            "scheduler decision activation is not queued",
                        ));
                    }
                    let Some(activation) = self.runtime_activations.iter().find(|record| {
                        record.id == *selected_activation
                            && record.generation == *selected_activation_generation
                            && record.state == RuntimeActivationState::Runnable
                            && record.runnable_queue == Some(*queue)
                            && record.runnable_queue_generation == Some(*queue_generation)
                    }) else {
                        return Err(CommandError::precondition(
                            "scheduler decision activation generation is not runnable",
                        ));
                    };
                    if self.tasks.iter().any(|task| {
                        task.id == activation.owner_task
                            && task.generation == activation.owner_task_generation
                    }) {
                        Ok(())
                    } else {
                        Err(CommandError::precondition(
                            "scheduler decision owner task generation is missing",
                        ))
                    }
                }
            }
            SemanticCommand::RecordCrossHartSchedulerDecision {
                cross_decision,
                scheduler_decision,
                scheduler_decision_generation,
                deciding_hart,
                deciding_hart_generation,
                target_hart,
                target_hart_generation,
                reason,
                ..
            } => self
                .validate_cross_hart_scheduler_decision(
                    *cross_decision,
                    *scheduler_decision,
                    *scheduler_decision_generation,
                    *deciding_hart,
                    *deciding_hart_generation,
                    *target_hart,
                    *target_hart_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::MigrateRunnableActivation {
                migration,
                activation,
                activation_generation,
                source_queue,
                source_queue_generation,
                target_queue,
                target_queue_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                reason,
                ..
            } => self
                .validate_runnable_activation_migration(
                    *migration,
                    *activation,
                    *activation_generation,
                    *source_queue,
                    *source_queue_generation,
                    *target_queue,
                    *target_queue_generation,
                    *source_hart,
                    *source_hart_generation,
                    *target_hart,
                    *target_hart_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSmpSafePoint {
                safe_point,
                coordinator_hart,
                coordinator_hart_generation,
                participants,
                reason,
                ..
            } => self
                .validate_smp_safe_point(
                    *safe_point,
                    *coordinator_hart,
                    *coordinator_hart_generation,
                    participants,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::CompleteStopTheWorldRendezvous {
                rendezvous,
                epoch,
                safe_point,
                safe_point_generation,
                stop_new_activations,
                reason,
                ..
            } => self
                .validate_stop_the_world_rendezvous(
                    *rendezvous,
                    *epoch,
                    *safe_point,
                    *safe_point_generation,
                    *stop_new_activations,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ValidateSmpCodePublishBarrier {
                barrier,
                rendezvous,
                rendezvous_generation,
                code_publish_epoch_before,
                code_publish_epoch_after,
                remote_icache_sync_required,
                code_publish_executed,
                reason,
                ..
            } => self
                .validate_smp_code_publish_barrier(
                    *barrier,
                    *rendezvous,
                    *rendezvous_generation,
                    *code_publish_epoch_before,
                    *code_publish_epoch_after,
                    *remote_icache_sync_required,
                    *code_publish_executed,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ValidateSmpCleanupQuiescence {
                quiescence,
                cleanup,
                cleanup_generation,
                rendezvous,
                rendezvous_generation,
                store,
                target_store_generation,
                result_store_generation,
                reason,
                ..
            } => self
                .validate_smp_cleanup_quiescence(
                    *quiescence,
                    *cleanup,
                    *cleanup_generation,
                    *rendezvous,
                    *rendezvous_generation,
                    *store,
                    *target_store_generation,
                    *result_store_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ValidateSmpSnapshotBarrier {
                barrier,
                rendezvous,
                rendezvous_generation,
                snapshot_state,
                reason,
                ..
            } => self
                .validate_smp_snapshot_barrier(
                    *barrier,
                    *rendezvous,
                    *rendezvous_generation,
                    snapshot_state,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSmpStressRun {
                run,
                scenario,
                iterations,
                invariant_checks,
                reason,
                ..
            } => self
                .validate_smp_stress_run(*run, scenario, *iterations, *invariant_checks, reason)
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSmpScalingBenchmark {
                benchmark,
                scenario,
                stress_run,
                stress_run_generation,
                workload_units,
                baseline_single_hart_nanos,
                measured_smp_nanos,
                budget_nanos,
                ..
            } => self
                .validate_smp_scaling_benchmark(
                    *benchmark,
                    scenario,
                    *stress_run,
                    *stress_run_generation,
                    *workload_units,
                    *baseline_single_hart_nanos,
                    *measured_smp_nanos,
                    *budget_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDeviceObject {
                device,
                name,
                class,
                resource,
                resource_generation,
                backend,
                ..
            } => self
                .validate_device_object(
                    *device,
                    name,
                    class,
                    *resource,
                    *resource_generation,
                    backend,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketDeviceObject {
                packet_device,
                name,
                device,
                device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                frame_format_version,
                max_payload_len,
                ..
            } => self
                .validate_packet_device_object(
                    *packet_device,
                    name,
                    *device,
                    *device_generation,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *frame_format_version,
                    *max_payload_len,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketBufferObject {
                packet_buffer,
                packet_device,
                packet_device_generation,
                direction,
                frame_format_version,
                capacity,
                payload_len,
                sequence,
                state,
                ..
            } => self
                .validate_packet_buffer_object(
                    *packet_buffer,
                    *packet_device,
                    *packet_device_generation,
                    *direction,
                    *frame_format_version,
                    *capacity,
                    *payload_len,
                    *sequence,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketQueueObject {
                packet_queue,
                name,
                packet_device,
                packet_device_generation,
                role,
                queue_index,
                depth,
                ..
            } => self
                .validate_packet_queue_object(
                    *packet_queue,
                    name,
                    *packet_device,
                    *packet_device_generation,
                    *role,
                    *queue_index,
                    *depth,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketDescriptorObject {
                packet_descriptor,
                packet_queue,
                packet_queue_generation,
                packet_buffer,
                packet_buffer_generation,
                slot,
                length,
                ..
            } => self
                .validate_packet_descriptor_object(
                    *packet_descriptor,
                    *packet_queue,
                    *packet_queue_generation,
                    *packet_buffer,
                    *packet_buffer_generation,
                    *slot,
                    *length,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFakeNetBackendObject {
                fake_net_backend,
                name,
                packet_device,
                packet_device_generation,
                provider,
                profile,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                deterministic_seed,
                ..
            } => self
                .validate_fake_net_backend_object(
                    *fake_net_backend,
                    name,
                    *packet_device,
                    *packet_device_generation,
                    provider,
                    profile,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *mac,
                    *frame_format_version,
                    *max_payload_len,
                    *deterministic_seed,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFakeBlockBackendObject {
                fake_block_backend,
                name,
                block_device,
                block_device_generation,
                provider,
                profile,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                deterministic_seed,
                ..
            } => self
                .validate_fake_block_backend_object(
                    *fake_block_backend,
                    name,
                    *block_device,
                    *block_device_generation,
                    provider,
                    profile,
                    *sector_size,
                    *sector_count,
                    *read_only,
                    *max_transfer_sectors,
                    *deterministic_seed,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordVirtioBlkBackendObject {
                virtio_blk_backend,
                name,
                block_device,
                block_device_generation,
                driver_binding,
                driver_binding_generation,
                provider,
                profile,
                model,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                device_features,
                driver_features,
                negotiated_features,
                request_queue_index,
                queue_size,
                irq_vector,
                ..
            } => self
                .validate_virtio_blk_backend_object(
                    *virtio_blk_backend,
                    name,
                    *block_device,
                    *block_device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    provider,
                    profile,
                    model,
                    *sector_size,
                    *sector_count,
                    *read_only,
                    *max_transfer_sectors,
                    *device_features,
                    *driver_features,
                    *negotiated_features,
                    *request_queue_index,
                    *queue_size,
                    *irq_vector,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockReadPath {
                read_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                data_digest,
                ..
            } => self
                .validate_block_read_path(
                    *read_path,
                    *backend,
                    *block_request,
                    *block_request_generation,
                    *block_completion,
                    *block_completion_generation,
                    *data_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockWritePath {
                write_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                payload_digest,
                ..
            } => self
                .validate_block_write_path(
                    *write_path,
                    *backend,
                    *block_request,
                    *block_request_generation,
                    *block_completion,
                    *block_completion_generation,
                    *payload_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRequestQueue {
                queue,
                backend,
                block_device,
                block_device_generation,
                depth,
                entries,
                ..
            } => self
                .validate_block_request_queue(
                    *queue,
                    *backend,
                    *block_device,
                    *block_device_generation,
                    *depth,
                    entries,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockDmaBuffer {
                block_dma_buffer,
                backend,
                block_request,
                block_request_generation,
                dma_buffer,
                dma_buffer_generation,
                buffer_digest,
                ..
            } => self
                .validate_block_dma_buffer(
                    *block_dma_buffer,
                    *backend,
                    *block_request,
                    *block_request_generation,
                    *dma_buffer,
                    *dma_buffer_generation,
                    *buffer_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockPageObject {
                block_page_object,
                block_dma_buffer,
                block_dma_buffer_generation,
                block_completion,
                block_completion_generation,
                aspace,
                vma_region,
                page,
                page_dirty_generation,
                page_backing,
                cow_state,
                page_state,
                page_offset,
                byte_len,
                ..
            } => self
                .validate_block_page_object(
                    *block_page_object,
                    *block_dma_buffer,
                    *block_dma_buffer_generation,
                    *block_completion,
                    *block_completion_generation,
                    *aspace,
                    *vma_region,
                    *page,
                    *page_dirty_generation,
                    *page_backing,
                    *cow_state,
                    *page_state,
                    *page_offset,
                    *byte_len,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBufferCacheObject {
                buffer_cache_object,
                block_page_object,
                block_page_object_generation,
                page,
                page_dirty_generation,
                block_offset,
                byte_len,
                cache_state,
                coherency_epoch,
                ..
            } => self
                .validate_buffer_cache_object(
                    *buffer_cache_object,
                    *block_page_object,
                    *block_page_object_generation,
                    *page,
                    *page_dirty_generation,
                    *block_offset,
                    *byte_len,
                    *cache_state,
                    *coherency_epoch,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFileObject {
                file_object,
                buffer_cache_object,
                buffer_cache_object_generation,
                namespace,
                file_key,
                path,
                file_offset,
                byte_len,
                file_size,
                content_digest,
                state,
                ..
            } => self
                .validate_file_object(
                    *file_object,
                    *buffer_cache_object,
                    *buffer_cache_object_generation,
                    namespace,
                    file_key,
                    path,
                    *file_offset,
                    *byte_len,
                    *file_size,
                    *content_digest,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDirectoryObject {
                directory_object,
                file_object,
                file_object_generation,
                namespace,
                directory_key,
                directory_path,
                entry_name,
                child_file_key,
                child_path,
                entry_kind,
                file_size,
                content_digest,
                state,
                ..
            } => self
                .validate_directory_object(
                    *directory_object,
                    *file_object,
                    *file_object_generation,
                    namespace,
                    directory_key,
                    directory_path,
                    entry_name,
                    child_file_key,
                    child_path,
                    *entry_kind,
                    *file_size,
                    *content_digest,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFatAdapterObject {
                fat_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation,
                version,
                profile,
                volume_label,
                image_bytes,
                adapter_path,
                semantic_path,
                bytes_written,
                bytes_read,
                write_digest,
                read_digest,
                file_content_digest,
                state,
                ..
            } => self
                .validate_fat_adapter_object(
                    *fat_adapter_object,
                    *directory_object,
                    *directory_object_generation,
                    *file_object,
                    *file_object_generation,
                    *block_device,
                    *block_device_generation,
                    implementation,
                    version,
                    profile,
                    volume_label,
                    *image_bytes,
                    adapter_path,
                    semantic_path,
                    *bytes_written,
                    *bytes_read,
                    *write_digest,
                    *read_digest,
                    *file_content_digest,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordExt4AdapterObject {
                ext4_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation,
                version,
                profile,
                volume_label,
                image_bytes,
                adapter_path,
                semantic_path,
                bytes_read,
                read_digest,
                file_content_digest,
                directory_entries,
                read_only_enforced,
                state,
                ..
            } => self
                .validate_ext4_adapter_object(
                    *ext4_adapter_object,
                    *directory_object,
                    *directory_object_generation,
                    *file_object,
                    *file_object_generation,
                    *block_device,
                    *block_device_generation,
                    implementation,
                    version,
                    profile,
                    volume_label,
                    *image_bytes,
                    adapter_path,
                    semantic_path,
                    *bytes_read,
                    *read_digest,
                    *file_content_digest,
                    *directory_entries,
                    *read_only_enforced,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFileHandleCapability {
                file_handle_capability,
                owner_store,
                owner_store_generation,
                file_object,
                file_object_generation,
                directory_object,
                directory_object_generation,
                capability,
                capability_generation,
                handle,
                operation,
                file_offset,
                byte_len,
                content_digest,
                ..
            } => self
                .validate_file_handle_capability(
                    *file_handle_capability,
                    *owner_store,
                    *owner_store_generation,
                    *file_object,
                    *file_object_generation,
                    *directory_object,
                    *directory_object_generation,
                    *capability,
                    *capability_generation,
                    handle,
                    operation,
                    *file_offset,
                    *byte_len,
                    *content_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFsWait {
                fs_wait,
                wait,
                wait_generation,
                file_handle_capability,
                file_handle_capability_generation,
                operation,
                sequence,
                ..
            } => self
                .validate_fs_wait(
                    *fs_wait,
                    *wait,
                    *wait_generation,
                    *file_handle_capability,
                    *file_handle_capability_generation,
                    operation,
                    *sequence,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveFsWait {
                fs_wait,
                fs_wait_generation,
                ..
            } => {
                if self.fs_waits.iter().any(|record| {
                    record.id == *fs_wait
                        && record.generation == *fs_wait_generation
                        && record.state == FsWaitState::Pending
                        && self.waits.iter().any(|wait| {
                            wait.id == record.wait
                                && wait.generation == record.wait_generation
                                && wait.state == WaitState::Pending
                        })
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "fs wait generation is missing or not pending",
                    ))
                }
            }
            SemanticCommand::CancelFsWait {
                fs_wait,
                fs_wait_generation,
                reason,
                ..
            } => {
                if !matches!(
                    reason,
                    WaitCancelReason::CloseFd
                        | WaitCancelReason::StoreFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    return Err(CommandError::precondition(
                        "fs wait cancellation reason is not a filesystem reason",
                    ));
                }
                if self.fs_waits.iter().any(|record| {
                    record.id == *fs_wait
                        && record.generation == *fs_wait_generation
                        && record.state == FsWaitState::Pending
                        && self.waits.iter().any(|wait| {
                            wait.id == record.wait
                                && wait.generation == record.wait_generation
                                && wait.state == WaitState::Pending
                        })
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "fs wait generation is missing or not pending",
                    ))
                }
            }
            SemanticCommand::CleanupBlockDriver {
                cleanup,
                io_cleanup,
                block_device,
                block_device_generation,
                backend,
                reason,
                ..
            } => self
                .validate_block_driver_cleanup(
                    *cleanup,
                    *io_cleanup,
                    *block_device,
                    *block_device_generation,
                    *backend,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordVirtioNetBackendObject {
                virtio_net_backend,
                name,
                packet_device,
                packet_device_generation,
                driver_binding,
                driver_binding_generation,
                provider,
                profile,
                model,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                device_features,
                driver_features,
                negotiated_features,
                rx_queue_index,
                tx_queue_index,
                queue_size,
                irq_vector,
                ..
            } => self
                .validate_virtio_net_backend_object(
                    *virtio_net_backend,
                    name,
                    *packet_device,
                    *packet_device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    provider,
                    profile,
                    model,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *mac,
                    *frame_format_version,
                    *max_payload_len,
                    *device_features,
                    *driver_features,
                    *negotiated_features,
                    *rx_queue_index,
                    *tx_queue_index,
                    *queue_size,
                    *irq_vector,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkRxInterrupt {
                rx_interrupt,
                virtio_net_backend,
                virtio_net_backend_generation,
                irq_event,
                irq_event_generation,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                ready_descriptors,
                sequence,
                ..
            } => self
                .validate_network_rx_interrupt(
                    *rx_interrupt,
                    *virtio_net_backend,
                    *virtio_net_backend_generation,
                    *irq_event,
                    *irq_event_generation,
                    *packet_device,
                    *packet_device_generation,
                    *rx_queue,
                    *rx_queue_generation,
                    *ready_descriptors,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveNetworkRxWait {
                resolution,
                io_wait,
                io_wait_generation,
                rx_interrupt,
                rx_interrupt_generation,
                ..
            } => self
                .validate_network_rx_wait_resolution(
                    *resolution,
                    *io_wait,
                    *io_wait_generation,
                    *rx_interrupt,
                    *rx_interrupt_generation,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkTxCapabilityGate {
                tx_gate,
                driver_store,
                driver_store_generation,
                packet_descriptor,
                packet_descriptor_generation,
                device_capability,
                device_capability_generation,
                handle,
                ..
            } => self
                .validate_network_tx_capability_gate(
                    *tx_gate,
                    *driver_store,
                    *driver_store_generation,
                    *packet_descriptor,
                    *packet_descriptor_generation,
                    *device_capability,
                    *device_capability_generation,
                    handle,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkTxCompletion {
                completion,
                tx_gate,
                tx_gate_generation,
                backend,
                completion_sequence,
                ..
            } => self
                .validate_network_tx_completion(
                    *completion,
                    *tx_gate,
                    *tx_gate_generation,
                    *backend,
                    *completion_sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkStackAdapter {
                adapter,
                backend,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                tx_queue,
                tx_queue_generation,
                implementation,
                implementation_version,
                profile,
                medium,
                mac,
                ipv4_addr,
                ipv4_prefix_len,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                max_payload_len,
                socket_capacity,
                ..
            } => self
                .validate_network_stack_adapter(
                    *adapter,
                    *backend,
                    *packet_device,
                    *packet_device_generation,
                    *rx_queue,
                    *rx_queue_generation,
                    *tx_queue,
                    *tx_queue_generation,
                    implementation,
                    implementation_version,
                    profile,
                    medium,
                    *mac,
                    *ipv4_addr,
                    *ipv4_prefix_len,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *max_payload_len,
                    *socket_capacity,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSocketObject {
                socket,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                domain,
                socket_type,
                protocol,
                ..
            } => self
                .validate_socket_object(
                    *socket,
                    *adapter,
                    *adapter_generation,
                    *owner_store,
                    *owner_store_generation,
                    *domain,
                    *socket_type,
                    *protocol,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordEndpointObject {
                endpoint,
                socket,
                socket_generation,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                ..
            } => self
                .validate_endpoint_object(
                    *endpoint,
                    *socket,
                    *socket_generation,
                    *local_addr,
                    *local_port,
                    *remote_addr,
                    *remote_port,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::BindSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                local_addr,
                local_port,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Bind,
                    *local_addr,
                    *local_port,
                    [0, 0, 0, 0],
                    0,
                    0,
                    0,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ListenSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                backlog,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Listen,
                    [0, 0, 0, 0],
                    0,
                    [0, 0, 0, 0],
                    0,
                    *backlog,
                    0,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ConnectSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                remote_addr,
                remote_port,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Connect,
                    [0, 0, 0, 0],
                    0,
                    *remote_addr,
                    *remote_port,
                    0,
                    0,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::SendSocket {
                operation_id,
                endpoint,
                endpoint_generation,
                byte_len,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Send,
                    [0, 0, 0, 0],
                    0,
                    [0, 0, 0, 0],
                    0,
                    0,
                    *byte_len,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecvSocket {
                operation_id,
                endpoint,
                endpoint_generation,
                byte_len,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Recv,
                    [0, 0, 0, 0],
                    0,
                    [0, 0, 0, 0],
                    0,
                    0,
                    *byte_len,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSocketWait {
                socket_wait,
                wait,
                wait_generation,
                endpoint,
                endpoint_generation,
                wait_kind,
                blocker,
                ..
            } => self
                .validate_socket_wait(
                    *socket_wait,
                    *wait,
                    *wait_generation,
                    *endpoint,
                    *endpoint_generation,
                    *wait_kind,
                    *blocker,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveSocketWait {
                socket_wait,
                socket_wait_generation,
                ready_sequence,
                byte_len,
                ..
            } => {
                if self.socket_waits.iter().any(|record| {
                    record.id == *socket_wait
                        && record.generation == *socket_wait_generation
                        && record.state == SocketWaitState::Pending
                        && *ready_sequence > 0
                        && (!matches!(record.wait_kind, SemanticWaitKind::SocketReadable)
                            || *byte_len > 0)
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "socket wait is not pending or readiness is empty",
                    ))
                }
            }
            SemanticCommand::CancelSocketWait {
                socket_wait,
                socket_wait_generation,
                reason,
                ..
            } => {
                if self.socket_waits.iter().any(|record| {
                    record.id == *socket_wait
                        && record.generation == *socket_wait_generation
                        && record.state == SocketWaitState::Pending
                }) && matches!(
                    reason,
                    WaitCancelReason::CloseFd
                        | WaitCancelReason::StoreFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::DeviceFault
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "socket wait is not pending or cancel reason is not socket-visible",
                    ))
                }
            }
            SemanticCommand::RecordNetworkBackpressure {
                backpressure,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                endpoint,
                endpoint_generation,
                direction,
                reason,
                action,
                queue_depth,
                queue_limit,
                dropped_packets,
                dropped_bytes,
                sequence,
                ..
            } => self
                .validate_network_backpressure(
                    *backpressure,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *packet_queue,
                    *packet_queue_generation,
                    *endpoint,
                    *endpoint_generation,
                    *direction,
                    *reason,
                    *action,
                    *queue_depth,
                    *queue_limit,
                    *dropped_packets,
                    *dropped_bytes,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::CleanupNetworkDriver {
                cleanup,
                io_cleanup,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                backend,
                reason,
                ..
            } => self
                .validate_network_driver_cleanup(
                    *cleanup,
                    *io_cleanup,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *backend,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkGenerationAudit {
                audit,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                dma_buffer,
                device_capability,
                rejected_packet_generation_probes,
                rejected_dma_generation_probes,
                ..
            } => self
                .validate_network_generation_audit(
                    *audit,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *packet_queue,
                    *packet_queue_generation,
                    *packet_descriptor,
                    *packet_descriptor_generation,
                    *packet_buffer,
                    *packet_buffer_generation,
                    *dma_buffer,
                    *device_capability,
                    *rejected_packet_generation_probes,
                    *rejected_dma_generation_probes,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkFaultInjection {
                injection,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                endpoint,
                endpoint_generation,
                direction,
                kind,
                effect,
                injected_packets,
                dropped_packets,
                error_packets,
                error_code,
                sequence,
                ..
            } => self
                .validate_network_fault_injection(
                    *injection,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *packet_queue,
                    *packet_queue_generation,
                    *packet_descriptor,
                    *packet_descriptor_generation,
                    *packet_buffer,
                    *packet_buffer_generation,
                    *endpoint,
                    *endpoint_generation,
                    *direction,
                    *kind,
                    *effect,
                    *injected_packets,
                    *dropped_packets,
                    *error_packets,
                    error_code,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkBenchmark {
                benchmark,
                scenario,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                rx_queue,
                rx_queue_generation,
                tx_completion,
                tx_completion_generation,
                rx_wait_resolution,
                rx_wait_resolution_generation,
                endpoint,
                endpoint_generation,
                backpressure,
                backpressure_generation,
                sample_packets,
                sample_bytes,
                tx_completed_packets,
                rx_resolved_packets,
                dropped_packets,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                ..
            } => self
                .validate_network_benchmark(
                    *benchmark,
                    scenario,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *tx_queue,
                    *tx_queue_generation,
                    *rx_queue,
                    *rx_queue_generation,
                    *tx_completion,
                    *tx_completion_generation,
                    *rx_wait_resolution,
                    *rx_wait_resolution_generation,
                    *endpoint,
                    *endpoint_generation,
                    *backpressure,
                    *backpressure_generation,
                    *sample_packets,
                    *sample_bytes,
                    *tx_completed_packets,
                    *rx_resolved_packets,
                    *dropped_packets,
                    *measured_nanos,
                    *budget_nanos,
                    *p50_latency_nanos,
                    *p99_latency_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkRecoveryBenchmark {
                benchmark,
                scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                fault_injection,
                fault_injection_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                recovery_nanos,
                budget_nanos,
                ..
            } => self
                .validate_network_recovery_benchmark(
                    *benchmark,
                    scenario,
                    *cleanup,
                    *cleanup_generation,
                    *io_cleanup,
                    *io_cleanup_generation,
                    *fault_injection,
                    *fault_injection_generation,
                    *recovery_start_event,
                    *recovery_complete_event,
                    *cancelled_socket_waits,
                    *revoked_packet_capabilities,
                    *recovery_nanos,
                    *budget_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockDeviceObject {
                block_device,
                name,
                device,
                device_generation,
                sector_size,
                sector_count,
                max_transfer_sectors,
                ..
            } => self
                .validate_block_device_object(
                    *block_device,
                    name,
                    *device,
                    *device_generation,
                    *sector_size,
                    *sector_count,
                    *max_transfer_sectors,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRangeObject {
                block_range,
                block_device,
                block_device_generation,
                start_sector,
                sector_count,
                ..
            } => self
                .validate_block_range_object(
                    *block_range,
                    *block_device,
                    *block_device_generation,
                    *start_sector,
                    *sector_count,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRequestObject {
                block_request,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                operation,
                sequence,
                ..
            } => self
                .validate_block_request_object(
                    *block_request,
                    *block_device,
                    *block_device_generation,
                    *block_range,
                    *block_range_generation,
                    *operation,
                    *sequence,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockCompletionObject {
                block_completion,
                block_request,
                block_request_generation,
                sequence,
                completed_bytes,
                status,
                ..
            } => self
                .validate_block_completion_object(
                    *block_completion,
                    *block_request,
                    *block_request_generation,
                    *sequence,
                    *completed_bytes,
                    *status,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockWait {
                block_wait,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
                ..
            } => self
                .validate_block_wait(
                    *block_wait,
                    *wait,
                    *wait_generation,
                    *block_request,
                    *block_request_generation,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveBlockWait {
                block_wait,
                block_wait_generation,
                block_completion,
                block_completion_generation,
                ..
            } => {
                let Some(record) = self.block_waits.iter().find(|record| {
                    record.id == *block_wait
                        && record.generation == *block_wait_generation
                        && record.state == BlockWaitState::Pending
                }) else {
                    return Err(CommandError::precondition(
                        "block wait generation is missing or not pending",
                    ));
                };
                let Some(completion) = self.block_completion_objects.iter().find(|completion| {
                    completion.id == *block_completion
                        && completion.generation == *block_completion_generation
                        && completion.state == BlockCompletionObjectState::Recorded
                }) else {
                    return Err(CommandError::precondition(
                        "block wait completion generation is missing",
                    ));
                };
                if completion.block_request == record.block_request
                    && completion.block_request_generation == record.block_request_generation
                    && completion.block_device == record.block_device
                    && completion.block_device_generation == record.block_device_generation
                    && completion.block_range == record.block_range
                    && completion.block_range_generation == record.block_range_generation
                    && completion.sequence == record.sequence
                    && completion.status == BlockCompletionStatus::Success
                    && completion.completed_bytes == record.byte_len
                    && self.waits.iter().any(|wait| {
                        wait.id == record.wait
                            && wait.generation == record.wait_generation
                            && wait.state == WaitState::Pending
                    })
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "block wait completion attribution mismatch",
                    ))
                }
            }
            SemanticCommand::CancelBlockWait {
                block_wait,
                block_wait_generation,
                reason,
                ..
            } => {
                if !matches!(
                    reason,
                    WaitCancelReason::DeviceFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    return Err(CommandError::precondition(
                        "block wait cancellation reason is not a block io reason",
                    ));
                }
                if self.block_waits.iter().any(|record| {
                    record.id == *block_wait
                        && record.generation == *block_wait_generation
                        && record.state == BlockWaitState::Pending
                        && self.waits.iter().any(|wait| {
                            wait.id == record.wait
                                && wait.generation == record.wait_generation
                                && wait.state == WaitState::Pending
                        })
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "block wait generation is missing or not pending",
                    ))
                }
            }
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy,
                block_wait,
                block_wait_generation,
                action,
                retry_request,
                retry_request_generation,
                errno,
                retry_attempt,
                max_retries,
                ..
            } => self
                .validate_block_pending_io_policy(
                    *policy,
                    *block_wait,
                    *block_wait_generation,
                    *action,
                    *retry_request,
                    *retry_request_generation,
                    *errno,
                    *retry_attempt,
                    *max_retries,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRequestGenerationAudit {
                audit,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                block_request,
                block_request_generation,
                backend,
                dma_buffer,
                rejected_completion_generation_probes,
                rejected_wait_generation_probes,
                rejected_dma_generation_probes,
                rejected_queue_generation_probes,
                ..
            } => self
                .validate_block_request_generation_audit(
                    *audit,
                    *block_device,
                    *block_device_generation,
                    *block_range,
                    *block_range_generation,
                    *block_request,
                    *block_request_generation,
                    *backend,
                    *dma_buffer,
                    *rejected_completion_generation_probes,
                    *rejected_wait_generation_probes,
                    *rejected_dma_generation_probes,
                    *rejected_queue_generation_probes,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockBenchmark {
                benchmark,
                scenario,
                backend,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                read_path,
                read_path_generation,
                write_path,
                write_path_generation,
                request_queue,
                request_queue_generation,
                block_dma_buffer,
                block_dma_buffer_generation,
                sample_requests,
                sample_bytes,
                read_completed_requests,
                write_completed_requests,
                queue_completed_requests,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                ..
            } => self
                .validate_block_benchmark(
                    *benchmark,
                    scenario,
                    *backend,
                    *block_device,
                    *block_device_generation,
                    *block_range,
                    *block_range_generation,
                    *read_path,
                    *read_path_generation,
                    *write_path,
                    *write_path_generation,
                    *request_queue,
                    *request_queue_generation,
                    *block_dma_buffer,
                    *block_dma_buffer_generation,
                    *sample_requests,
                    *sample_bytes,
                    *read_completed_requests,
                    *write_completed_requests,
                    *queue_completed_requests,
                    *measured_nanos,
                    *budget_nanos,
                    *p50_latency_nanos,
                    *p99_latency_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRecoveryBenchmark {
                benchmark,
                scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_block_waits,
                cancelled_wait_tokens,
                released_dma_buffers,
                revoked_device_capabilities,
                recovery_nanos,
                budget_nanos,
                ..
            } => self
                .validate_block_recovery_benchmark(
                    *benchmark,
                    scenario,
                    *cleanup,
                    *cleanup_generation,
                    *io_cleanup,
                    *io_cleanup_generation,
                    *recovery_start_event,
                    *recovery_complete_event,
                    *cancelled_block_waits,
                    *cancelled_wait_tokens,
                    *released_dma_buffers,
                    *revoked_device_capabilities,
                    *recovery_nanos,
                    *budget_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordTargetFeatureSet {
                feature_set,
                name,
                discovery_source,
                target_profile,
                target_arch,
                base_isa,
                simd_abi,
                simd_supported,
                vector_register_count,
                vector_register_bits,
                scalar_fallback,
                unsupported_reason,
                ..
            } => self
                .validate_target_feature_set(
                    *feature_set,
                    name,
                    discovery_source,
                    target_profile,
                    target_arch,
                    base_isa,
                    simd_abi,
                    *simd_supported,
                    *vector_register_count,
                    *vector_register_bits,
                    *scalar_fallback,
                    unsupported_reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordVectorState {
                vector_state,
                owner_activation,
                owner_store,
                code_object,
                target_feature_set,
                simd_abi,
                vector_register_count,
                vector_register_bits,
                register_bytes,
                state,
                ..
            } => self
                .validate_vector_state(
                    *vector_state,
                    *owner_activation,
                    *owner_store,
                    *code_object,
                    *target_feature_set,
                    simd_abi,
                    *vector_register_count,
                    *vector_register_bits,
                    *register_bytes,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordQueueObject {
                queue,
                name,
                role,
                queue_index,
                depth,
                device,
                device_generation,
                ..
            } => self
                .validate_queue_object(
                    *queue,
                    name,
                    *role,
                    *queue_index,
                    *depth,
                    *device,
                    *device_generation,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDescriptorObject {
                descriptor,
                queue,
                queue_generation,
                slot,
                access,
                length,
                ..
            } => self
                .validate_descriptor_object(
                    *descriptor,
                    *queue,
                    *queue_generation,
                    *slot,
                    *access,
                    *length,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDmaBufferObject {
                dma_buffer,
                descriptor,
                descriptor_generation,
                resource,
                resource_generation,
                access,
                length,
                ..
            } => self
                .validate_dma_buffer_object(
                    *dma_buffer,
                    *descriptor,
                    *descriptor_generation,
                    *resource,
                    *resource_generation,
                    *access,
                    *length,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordMmioRegionObject {
                mmio_region,
                device,
                device_generation,
                resource,
                resource_generation,
                region_index,
                offset,
                length,
                access,
                ..
            } => self
                .validate_mmio_region_object(
                    *mmio_region,
                    *device,
                    *device_generation,
                    *resource,
                    *resource_generation,
                    *region_index,
                    *offset,
                    *length,
                    *access,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIrqLineObject {
                irq_line,
                device,
                device_generation,
                resource,
                resource_generation,
                irq_number,
                trigger,
                polarity,
                ..
            } => self
                .validate_irq_line_object(
                    *irq_line,
                    *device,
                    *device_generation,
                    *resource,
                    *resource_generation,
                    *irq_number,
                    *trigger,
                    *polarity,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIrqEvent {
                irq_event,
                irq_line,
                irq_line_generation,
                device,
                device_generation,
                driver_store,
                driver_store_generation,
                sequence,
                ..
            } => self
                .validate_irq_event(
                    *irq_event,
                    *irq_line,
                    *irq_line_generation,
                    *device,
                    *device_generation,
                    *driver_store,
                    *driver_store_generation,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDeviceCapability {
                device_capability,
                driver_store,
                driver_store_generation,
                target,
                class,
                operation,
                handle,
                ..
            } => self
                .validate_device_capability(
                    *device_capability,
                    *driver_store,
                    *driver_store_generation,
                    *target,
                    *class,
                    operation,
                    handle,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::BindDriverStore {
                binding,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                device_capability,
                device_capability_generation,
                ..
            } => self
                .validate_driver_store_binding(
                    *binding,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *device_capability,
                    *device_capability_generation,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIoWait {
                io_wait,
                wait,
                wait_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                blocker,
                ..
            } => self
                .validate_io_wait(
                    *io_wait,
                    *wait,
                    *wait_generation,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    *blocker,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveIoWait {
                io_wait,
                io_wait_generation,
                irq_event,
                irq_event_generation,
                ..
            } => {
                let Some(record) = self.io_waits.iter().find(|record| {
                    record.id == *io_wait
                        && record.generation == *io_wait_generation
                        && record.state == IoWaitState::Pending
                }) else {
                    return Err(CommandError::precondition(
                        "io wait generation is missing or not pending",
                    ));
                };
                let Some(irq_record) = self.irq_events.iter().find(|irq| {
                    irq.id == *irq_event
                        && irq.generation == *irq_event_generation
                        && irq.state == IrqEventState::Recorded
                }) else {
                    return Err(CommandError::precondition(
                        "io wait irq event generation is missing",
                    ));
                };
                if record.blocker.kind == ContractObjectKind::IrqLineObject
                    && (record.blocker.id != irq_record.irq_line
                        || record.blocker.generation != irq_record.irq_line_generation)
                {
                    return Err(CommandError::precondition(
                        "io wait irq line attribution mismatch",
                    ));
                }
                if !self.waits.iter().any(|wait| {
                    wait.id == record.wait
                        && wait.generation == record.wait_generation
                        && wait.state == WaitState::Pending
                }) {
                    return Err(CommandError::precondition(
                        "io wait token generation is missing or not pending",
                    ));
                }
                if irq_record.device == record.device
                    && irq_record.device_generation == record.device_generation
                    && irq_record.driver_store == record.driver_store
                    && irq_record.driver_store_generation == record.driver_store_generation
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "io wait irq event attribution mismatch",
                    ))
                }
            }
            SemanticCommand::CancelIoWait {
                io_wait,
                io_wait_generation,
                reason,
                ..
            } => {
                if !matches!(
                    reason,
                    WaitCancelReason::DeviceFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    return Err(CommandError::precondition(
                        "io wait cancellation reason is not an io reason",
                    ));
                }
                if self.io_waits.iter().any(|record| {
                    record.id == *io_wait
                        && record.generation == *io_wait_generation
                        && record.state == IoWaitState::Pending
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "io wait generation is missing or not pending",
                    ))
                }
            }
            SemanticCommand::CleanupIoDriver {
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                reason,
                ..
            } => self
                .validate_io_cleanup(
                    *cleanup,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::InjectIoFault {
                fault,
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                target,
                kind,
                ..
            } => self
                .validate_io_fault_injection(
                    *fault,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    *target,
                    *cleanup,
                    *kind,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ValidateIoRuntime { report, .. } => self
                .validate_io_validation_report(*report)
                .map_err(CommandError::precondition),
            SemanticCommand::ResumeActivation {
                resume,
                scheduler_decision,
                scheduler_decision_generation,
                activation,
                activation_generation,
                ..
            } => {
                if *resume == 0 {
                    Err(CommandError::precondition(
                        "activation resume id=0 is invalid",
                    ))
                } else if self
                    .activation_resumes
                    .iter()
                    .any(|record| record.id == *resume)
                {
                    Err(CommandError::precondition(
                        "activation resume already exists",
                    ))
                } else {
                    let Some(decision) = self.scheduler_decisions.iter().find(|record| {
                        record.id == *scheduler_decision
                            && record.generation == *scheduler_decision_generation
                            && record.state == SchedulerDecisionState::Recorded
                            && record.selected_activation == *activation
                            && record.selected_activation_generation == *activation_generation
                    }) else {
                        return Err(CommandError::precondition(
                            "resume scheduler decision generation is missing or consumed",
                        ));
                    };
                    let Some(queue) = self.runnable_queues.iter().find(|record| {
                        record.id == decision.queue
                            && record.generation == decision.queue_generation
                            && record.state == RunnableQueueState::Active
                    }) else {
                        return Err(CommandError::precondition(
                            "resume queue generation is missing or inactive",
                        ));
                    };
                    if !queue.entries.iter().any(|entry| {
                        entry.activation == *activation
                            && entry.activation_generation == *activation_generation
                    }) {
                        return Err(CommandError::precondition(
                            "resume activation is not queued",
                        ));
                    }
                    let Some(record) = self.runtime_activations.iter().find(|record| {
                        record.id == *activation
                            && record.generation == *activation_generation
                            && record.state == RuntimeActivationState::Runnable
                            && record.runnable_queue == Some(decision.queue)
                            && record.runnable_queue_generation == Some(decision.queue_generation)
                    }) else {
                        return Err(CommandError::precondition(
                            "resume activation generation is not runnable",
                        ));
                    };
                    if !self.tasks.iter().any(|task| {
                        task.id == record.owner_task
                            && task.generation == record.owner_task_generation
                            && matches!(task.state, TaskState::Runnable | TaskState::Running)
                    }) {
                        return Err(CommandError::precondition(
                            "resume owner task generation is missing or not runnable",
                        ));
                    }
                    if let Some(store) = record.owner_store {
                        let Some(generation) = record.owner_store_generation else {
                            return Err(CommandError::precondition(
                                "resume owner store generation is required",
                            ));
                        };
                        if !self.stores.iter().any(|store_record| {
                            store_record.id == store
                                && store_record.generation == generation
                                && store_record.state != StoreState::Dead
                        }) {
                            return Err(CommandError::precondition(
                                "resume owner store generation is missing or dead",
                            ));
                        }
                    }
                    if let Some(code) = record.code_object
                        && (code.kind != ContractObjectKind::CodeObject || code.generation == 0)
                    {
                        return Err(CommandError::precondition(
                            "resume code object reference is invalid",
                        ));
                    }
                    if let Some(context) = self.activation_contexts.iter().find(|context| {
                        context.activation == *activation
                            && context.activation_generation == *activation_generation
                            && context.state != ActivationContextState::Dropped
                    }) {
                        if context.state != ActivationContextState::Saved {
                            return Err(CommandError::precondition(
                                "resume activation context is not saved",
                            ));
                        }
                        match (
                            context.current_saved_context,
                            context.current_saved_context_generation,
                        ) {
                            (Some(saved), Some(saved_generation)) => {
                                if !self.saved_contexts.iter().any(|saved_record| {
                                    saved_record.id == saved
                                        && saved_record.generation == saved_generation
                                        && saved_record.context == context.id
                                        && saved_record.context_generation == context.generation
                                        && saved_record.activation == *activation
                                        && saved_record.activation_generation
                                            == *activation_generation
                                        && saved_record.state == SavedContextState::Captured
                                }) {
                                    return Err(CommandError::precondition(
                                        "resume saved context generation is missing",
                                    ));
                                }
                            }
                            (None, None) => {}
                            _ => {
                                return Err(CommandError::precondition(
                                    "resume saved context generation is required",
                                ));
                            }
                        }
                    }
                    Ok(())
                }
            }
            SemanticCommand::RecordPreemptionLatencySample {
                sample,
                timer_interrupt,
                timer_interrupt_generation,
                preemption,
                preemption_generation,
                scheduler_decision,
                scheduler_decision_generation,
                activation_resume,
                activation_resume_generation,
                measured_nanos,
                budget_nanos,
                ..
            } => self
                .validate_preemption_latency_sample(
                    *sample,
                    *timer_interrupt,
                    *timer_interrupt_generation,
                    *preemption,
                    *preemption_generation,
                    *scheduler_decision,
                    *scheduler_decision_generation,
                    *activation_resume,
                    *activation_resume_generation,
                    *measured_nanos,
                    *budget_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::BlockActivationOnWait {
                activation_wait,
                activation,
                activation_generation,
                wait,
                blockers,
                deadline,
                ..
            } => {
                if *activation_wait == 0 {
                    Err(CommandError::precondition(
                        "activation wait id=0 is invalid",
                    ))
                } else if *wait == 0 {
                    Err(CommandError::precondition("wait id=0 is invalid"))
                } else if blockers.is_empty() && deadline.is_none() {
                    Err(CommandError::precondition(
                        "activation wait requires blocker or deadline",
                    ))
                } else if self
                    .activation_waits
                    .iter()
                    .any(|record| record.id == *activation_wait)
                {
                    Err(CommandError::precondition("activation wait already exists"))
                } else if self.waits.iter().any(|record| record.id == *wait) {
                    Err(CommandError::precondition("wait already exists"))
                } else {
                    let Some(record) = self.runtime_activations.iter().find(|record| {
                        record.id == *activation
                            && record.generation == *activation_generation
                            && record.state == RuntimeActivationState::Running
                            && record.runnable_queue.is_none()
                            && record.runnable_queue_generation.is_none()
                    }) else {
                        return Err(CommandError::precondition(
                            "activation wait target generation is not running",
                        ));
                    };
                    if !self.tasks.iter().any(|task| {
                        task.id == record.owner_task
                            && task.generation == record.owner_task_generation
                            && matches!(task.state, TaskState::Runnable | TaskState::Running)
                    }) {
                        return Err(CommandError::precondition(
                            "activation wait owner task generation is missing or not runnable",
                        ));
                    }
                    if let Some(store) = record.owner_store {
                        let Some(generation) = record.owner_store_generation else {
                            return Err(CommandError::precondition(
                                "activation wait owner store generation is required",
                            ));
                        };
                        if !self.stores.iter().any(|store_record| {
                            store_record.id == store
                                && store_record.generation == generation
                                && store_record.state != StoreState::Dead
                        }) {
                            return Err(CommandError::precondition(
                                "activation wait owner store generation is missing or dead",
                            ));
                        }
                    }
                    Ok(())
                }
            }
            SemanticCommand::CancelActivationWait {
                activation_wait,
                activation_wait_generation,
                wait_generation,
                ..
            } => {
                let Some(record) = self.activation_waits.iter().find(|record| {
                    record.id == *activation_wait
                        && record.generation == *activation_wait_generation
                        && record.wait_generation == *wait_generation
                        && record.state == ActivationWaitState::Pending
                }) else {
                    return Err(CommandError::precondition(
                        "activation wait generation is missing or not pending",
                    ));
                };
                if self.waits.iter().any(|wait| {
                    wait.id == record.wait
                        && wait.generation == *wait_generation
                        && wait.state == WaitState::Pending
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "activation wait token generation is missing or not pending",
                    ))
                }
            }
            SemanticCommand::CleanupActivationForStoreFault {
                cleanup,
                store,
                store_generation,
                activation,
                activation_generation,
                wait,
                wait_generation,
                reason,
                ..
            } => {
                if *cleanup == 0 {
                    return Err(CommandError::precondition(
                        "activation cleanup id=0 is invalid",
                    ));
                }
                if reason.is_empty() {
                    return Err(CommandError::precondition(
                        "activation cleanup reason is empty",
                    ));
                }
                if self
                    .activation_cleanups
                    .iter()
                    .any(|record| record.id == *cleanup)
                {
                    return Err(CommandError::precondition(
                        "activation cleanup already exists",
                    ));
                }
                if !self.stores.iter().any(|record| {
                    record.id == *store
                        && record.generation == *store_generation
                        && record.state != StoreState::Dead
                }) {
                    return Err(CommandError::precondition(
                        "cleanup target store generation is missing or dead",
                    ));
                }
                if !self.runtime_activations.iter().any(|record| {
                    record.id == *activation
                        && record.generation == *activation_generation
                        && record.owner_store == Some(*store)
                        && record.owner_store_generation == Some(*store_generation)
                        && !matches!(
                            record.state,
                            RuntimeActivationState::Dead | RuntimeActivationState::Exited
                        )
                }) {
                    return Err(CommandError::precondition(
                        "cleanup target activation generation is missing or not store-owned",
                    ));
                }
                match (*wait, *wait_generation) {
                    (Some(wait), Some(generation)) => {
                        if self.waits.iter().any(|record| {
                            record.id == wait
                                && record.generation == generation
                                && record.state == WaitState::Pending
                                && record.owner_store == Some(*store)
                                && record.owner_store_generation == Some(*store_generation)
                        }) {
                            Ok(())
                        } else {
                            Err(CommandError::precondition(
                                "cleanup wait generation is missing or not pending",
                            ))
                        }
                    }
                    (Some(_), None) | (None, Some(_)) => Err(CommandError::precondition(
                        "cleanup wait and wait generation must be paired",
                    )),
                    (None, None) => Ok(()),
                }
            }
            SemanticCommand::GrantCapability { operations, .. } if operations.is_empty() => Err(
                CommandError::precondition("grant-capability requires at least one operation"),
            ),
            SemanticCommand::GrantCapability {
                owner_store: Some(store),
                owner_store_generation,
                ..
            } => {
                if let Some(generation) = owner_store_generation {
                    if self
                        .stores
                        .iter()
                        .any(|record| record.id == *store && record.generation == *generation)
                    {
                        Ok(())
                    } else {
                        Err(CommandError::precondition(
                            "owner store generation is missing",
                        ))
                    }
                } else {
                    Err(CommandError::precondition(
                        "owner store generation is required",
                    ))
                }
            }
            SemanticCommand::RevokeCapability { cap } => {
                if self
                    .capabilities
                    .records()
                    .iter()
                    .any(|record| record.id == *cap)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("capability does not exist"))
                }
            }
            SemanticCommand::CreateWait {
                owner_task,
                owner_store,
                owner_store_generation,
                blockers,
                deadline,
                ..
            } => {
                if owner_task.is_none() && owner_store.is_none() {
                    Err(CommandError::precondition(
                        "create-wait requires owner task or owner store",
                    ))
                } else if blockers.is_empty() && deadline.is_none() {
                    Err(CommandError::precondition(
                        "create-wait requires blocker or deadline",
                    ))
                } else {
                    if let Some(task) = owner_task
                        && !self.tasks.iter().any(|record| record.id == *task)
                    {
                        return Err(CommandError::precondition("owner task is missing"));
                    }
                    if let Some(store) = owner_store {
                        if let Some(generation) = owner_store_generation {
                            if self.stores.iter().any(|record| {
                                record.id == *store && record.generation == *generation
                            }) {
                                Ok(())
                            } else {
                                Err(CommandError::precondition(
                                    "owner store generation is missing",
                                ))
                            }
                        } else {
                            Err(CommandError::precondition(
                                "owner store generation is required",
                            ))
                        }
                    } else {
                        Ok(())
                    }
                }
            }
            SemanticCommand::ResolveWait { wait, .. }
            | SemanticCommand::CancelWait { wait, .. } => {
                if self
                    .waits
                    .iter()
                    .any(|record| record.id == *wait && record.state == WaitState::Pending)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("wait is not pending"))
                }
            }
            SemanticCommand::BeginCleanup {
                cleanup,
                store,
                generation,
                ..
            } => {
                if self.transactions.iter().any(|record| record.id == *cleanup) {
                    Err(CommandError::precondition(
                        "cleanup transaction id already exists",
                    ))
                } else if self
                    .stores
                    .iter()
                    .any(|record| record.id == *store && record.generation == *generation)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "cleanup target store generation is missing",
                    ))
                }
            }
            SemanticCommand::ApplyCleanupStep { cleanup, .. }
            | SemanticCommand::CommitCleanup { cleanup } => {
                if self
                    .transactions
                    .iter()
                    .any(|record| record.id == *cleanup && record.state == TransactionState::Begun)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "cleanup transaction is not active",
                    ))
                }
            }
            SemanticCommand::GrantCapability { .. } | SemanticCommand::RecordTrap { .. } => Ok(()),
        }
    }

    fn apply_prechecked_command(&mut self, command: SemanticCommand) -> bool {
        match command {
            SemanticCommand::RegisterHart {
                hart,
                hardware_id,
                label,
                boot,
                note,
            } => self.register_hart_with_id(hart, hardware_id, &label, boot, &note),
            SemanticCommand::SetHartState {
                hart,
                hart_generation,
                state,
                reason,
                note,
            } => self.set_hart_state(hart, hart_generation, state, &reason, &note),
            SemanticCommand::BindHartCurrentActivation {
                hart,
                hart_generation,
                activation,
                activation_generation,
                note,
            } => self.bind_hart_current_activation(
                hart,
                hart_generation,
                activation,
                activation_generation,
                &note,
            ),
            SemanticCommand::ClearHartCurrentActivation {
                hart,
                hart_generation,
                activation,
                activation_generation,
                reason,
                note,
            } => self.clear_hart_current_activation(
                hart,
                hart_generation,
                activation,
                activation_generation,
                &reason,
                &note,
            ),
            SemanticCommand::CreateRuntimeActivation {
                activation,
                owner_task,
                owner_task_generation,
                owner_store,
                owner_store_generation,
                code_object,
            } => self.create_runtime_activation_with_id(
                activation,
                owner_task,
                owner_task_generation,
                owner_store,
                owner_store_generation,
                code_object,
            ),
            SemanticCommand::CreateRunnableQueue { queue, label } => {
                self.create_runnable_queue_with_id(queue, &label)
            }
            SemanticCommand::BindRunnableQueueOwner {
                queue,
                queue_generation,
                hart,
                hart_generation,
                note,
            } => self.bind_runnable_queue_owner(
                queue,
                queue_generation,
                hart,
                hart_generation,
                &note,
            ),
            SemanticCommand::EnqueueRunnable {
                queue,
                activation,
                activation_generation,
            } => self.enqueue_runnable_activation(queue, activation, activation_generation),
            SemanticCommand::DequeueRunnable { queue, activation } => {
                self.dequeue_runnable_activation(queue, activation)
            }
            SemanticCommand::CreateActivationContext {
                context,
                activation,
                activation_generation,
            } => self.create_activation_context_with_id(context, activation, activation_generation),
            SemanticCommand::CaptureSavedContext {
                saved_context,
                context,
                context_generation,
                reason,
                pc,
                sp,
                flags,
                note,
            } => self.capture_saved_context_with_id(
                saved_context,
                context,
                context_generation,
                reason,
                pc,
                sp,
                flags,
                &note,
            ),
            SemanticCommand::SavePreemptedContext {
                context,
                saved_context,
                preemption,
                preemption_generation,
                pc,
                sp,
                flags,
                note,
            } => self.save_preempted_context_with_ids(
                context,
                saved_context,
                preemption,
                preemption_generation,
                pc,
                sp,
                flags,
                &note,
            ),
            SemanticCommand::RecordTimerInterrupt {
                interrupt,
                timer_epoch,
                hart,
                hart_generation,
                target_activation,
                target_activation_generation,
                note,
            } => self.record_timer_interrupt_with_id(
                interrupt,
                timer_epoch,
                hart,
                hart_generation,
                target_activation,
                target_activation_generation,
                &note,
            ),
            SemanticCommand::RecordIpiEvent {
                ipi,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                kind,
                reason,
                note,
            } => self.record_ipi_event_with_id(
                ipi,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                kind,
                &reason,
                &note,
            ),
            SemanticCommand::RemotePreemptActivation {
                remote_preempt,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                activation,
                activation_generation,
                queue,
                note,
            } => self.remote_preempt_activation_with_id(
                remote_preempt,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                activation,
                activation_generation,
                queue,
                &note,
            ),
            SemanticCommand::RemoteParkHart {
                remote_park,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                reason,
                note,
            } => self.remote_park_hart_with_id(
                remote_park,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                &reason,
                &note,
            ),
            SemanticCommand::PreemptActivation {
                preemption,
                activation,
                activation_generation,
                timer_interrupt,
                timer_interrupt_generation,
                queue,
                note,
            } => self.preempt_running_activation_with_id(
                preemption,
                activation,
                activation_generation,
                timer_interrupt,
                timer_interrupt_generation,
                queue,
                &note,
            ),
            SemanticCommand::RecordSchedulerDecision {
                decision,
                queue,
                queue_generation,
                selected_activation,
                selected_activation_generation,
                reason,
                note,
            } => self.record_scheduler_decision_with_id(
                decision,
                queue,
                queue_generation,
                selected_activation,
                selected_activation_generation,
                &reason,
                &note,
            ),
            SemanticCommand::RecordCrossHartSchedulerDecision {
                cross_decision,
                scheduler_decision,
                scheduler_decision_generation,
                deciding_hart,
                deciding_hart_generation,
                target_hart,
                target_hart_generation,
                reason,
                note,
            } => self.record_cross_hart_scheduler_decision_with_id(
                cross_decision,
                scheduler_decision,
                scheduler_decision_generation,
                deciding_hart,
                deciding_hart_generation,
                target_hart,
                target_hart_generation,
                &reason,
                &note,
            ),
            SemanticCommand::MigrateRunnableActivation {
                migration,
                activation,
                activation_generation,
                source_queue,
                source_queue_generation,
                target_queue,
                target_queue_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                reason,
                note,
            } => self.migrate_runnable_activation_with_id(
                migration,
                activation,
                activation_generation,
                source_queue,
                source_queue_generation,
                target_queue,
                target_queue_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                &reason,
                &note,
            ),
            SemanticCommand::RecordSmpSafePoint {
                safe_point,
                coordinator_hart,
                coordinator_hart_generation,
                participants,
                reason,
                note,
            } => self.record_smp_safe_point_with_id(
                safe_point,
                coordinator_hart,
                coordinator_hart_generation,
                participants,
                &reason,
                &note,
            ),
            SemanticCommand::CompleteStopTheWorldRendezvous {
                rendezvous,
                epoch,
                safe_point,
                safe_point_generation,
                stop_new_activations,
                reason,
                note,
            } => self.complete_stop_the_world_rendezvous_with_id(
                rendezvous,
                epoch,
                safe_point,
                safe_point_generation,
                stop_new_activations,
                &reason,
                &note,
            ),
            SemanticCommand::ValidateSmpCodePublishBarrier {
                barrier,
                rendezvous,
                rendezvous_generation,
                code_publish_epoch_before,
                code_publish_epoch_after,
                remote_icache_sync_required,
                code_publish_executed,
                reason,
                note,
            } => self.validate_smp_code_publish_barrier_with_id(
                barrier,
                rendezvous,
                rendezvous_generation,
                code_publish_epoch_before,
                code_publish_epoch_after,
                remote_icache_sync_required,
                code_publish_executed,
                &reason,
                &note,
            ),
            SemanticCommand::ValidateSmpCleanupQuiescence {
                quiescence,
                cleanup,
                cleanup_generation,
                rendezvous,
                rendezvous_generation,
                store,
                target_store_generation,
                result_store_generation,
                reason,
                note,
            } => self.validate_smp_cleanup_quiescence_with_id(
                quiescence,
                cleanup,
                cleanup_generation,
                rendezvous,
                rendezvous_generation,
                store,
                target_store_generation,
                result_store_generation,
                &reason,
                &note,
            ),
            SemanticCommand::ValidateSmpSnapshotBarrier {
                barrier,
                rendezvous,
                rendezvous_generation,
                snapshot_state,
                reason,
                note,
            } => self.validate_smp_snapshot_barrier_with_id(
                barrier,
                rendezvous,
                rendezvous_generation,
                snapshot_state,
                &reason,
                &note,
            ),
            SemanticCommand::RecordSmpStressRun {
                run,
                scenario,
                iterations,
                invariant_checks,
                reason,
                note,
            } => self.record_smp_stress_run_with_id(
                run,
                &scenario,
                iterations,
                invariant_checks,
                &reason,
                &note,
            ),
            SemanticCommand::RecordSmpScalingBenchmark {
                benchmark,
                scenario,
                stress_run,
                stress_run_generation,
                workload_units,
                baseline_single_hart_nanos,
                measured_smp_nanos,
                budget_nanos,
                note,
            } => self.record_smp_scaling_benchmark_with_id(
                benchmark,
                &scenario,
                stress_run,
                stress_run_generation,
                workload_units,
                baseline_single_hart_nanos,
                measured_smp_nanos,
                budget_nanos,
                &note,
            ),
            SemanticCommand::RecordDeviceObject {
                device,
                name,
                class,
                resource,
                resource_generation,
                backend,
                bus,
                vendor,
                model,
                note,
            } => self.record_device_object_with_id(
                device,
                &name,
                &class,
                resource,
                resource_generation,
                &backend,
                &bus,
                &vendor,
                &model,
                &note,
            ),
            SemanticCommand::RecordPacketDeviceObject {
                packet_device,
                name,
                device,
                device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                note,
            } => self.record_packet_device_object_with_id(
                packet_device,
                &name,
                device,
                device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                &note,
            ),
            SemanticCommand::RecordPacketBufferObject {
                packet_buffer,
                packet_device,
                packet_device_generation,
                direction,
                frame_format_version,
                capacity,
                payload_len,
                sequence,
                state,
                note,
            } => self.record_packet_buffer_object_with_id(
                packet_buffer,
                packet_device,
                packet_device_generation,
                direction,
                frame_format_version,
                capacity,
                payload_len,
                sequence,
                state,
                &note,
            ),
            SemanticCommand::RecordPacketQueueObject {
                packet_queue,
                name,
                packet_device,
                packet_device_generation,
                role,
                queue_index,
                depth,
                note,
            } => self.record_packet_queue_object_with_id(
                packet_queue,
                &name,
                packet_device,
                packet_device_generation,
                role,
                queue_index,
                depth,
                &note,
            ),
            SemanticCommand::RecordPacketDescriptorObject {
                packet_descriptor,
                packet_queue,
                packet_queue_generation,
                packet_buffer,
                packet_buffer_generation,
                slot,
                length,
                note,
            } => self.record_packet_descriptor_object_with_id(
                packet_descriptor,
                packet_queue,
                packet_queue_generation,
                packet_buffer,
                packet_buffer_generation,
                slot,
                length,
                &note,
            ),
            SemanticCommand::RecordFakeNetBackendObject {
                fake_net_backend,
                name,
                packet_device,
                packet_device_generation,
                provider,
                profile,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                deterministic_seed,
                note,
            } => self.record_fake_net_backend_object_with_id(
                fake_net_backend,
                &name,
                packet_device,
                packet_device_generation,
                &provider,
                &profile,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                deterministic_seed,
                &note,
            ),
            SemanticCommand::RecordFakeBlockBackendObject {
                fake_block_backend,
                name,
                block_device,
                block_device_generation,
                provider,
                profile,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                deterministic_seed,
                note,
            } => self.record_fake_block_backend_object_with_id(
                fake_block_backend,
                &name,
                block_device,
                block_device_generation,
                &provider,
                &profile,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                deterministic_seed,
                &note,
            ),
            SemanticCommand::RecordVirtioBlkBackendObject {
                virtio_blk_backend,
                name,
                block_device,
                block_device_generation,
                driver_binding,
                driver_binding_generation,
                provider,
                profile,
                model,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                device_features,
                driver_features,
                negotiated_features,
                request_queue_index,
                queue_size,
                irq_vector,
                note,
            } => self.record_virtio_blk_backend_object_with_id(
                virtio_blk_backend,
                &name,
                block_device,
                block_device_generation,
                driver_binding,
                driver_binding_generation,
                &provider,
                &profile,
                &model,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                device_features,
                driver_features,
                negotiated_features,
                request_queue_index,
                queue_size,
                irq_vector,
                &note,
            ),
            SemanticCommand::RecordBlockReadPath {
                read_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                data_digest,
                note,
            } => self.record_block_read_path_with_id(
                read_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                data_digest,
                &note,
            ),
            SemanticCommand::RecordBlockWritePath {
                write_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                payload_digest,
                note,
            } => self.record_block_write_path_with_id(
                write_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                payload_digest,
                &note,
            ),
            SemanticCommand::RecordBlockRequestQueue {
                queue,
                backend,
                block_device,
                block_device_generation,
                depth,
                entries,
                note,
            } => self.record_block_request_queue_with_id(
                queue,
                backend,
                block_device,
                block_device_generation,
                depth,
                &entries,
                &note,
            ),
            SemanticCommand::RecordBlockDmaBuffer {
                block_dma_buffer,
                backend,
                block_request,
                block_request_generation,
                dma_buffer,
                dma_buffer_generation,
                buffer_digest,
                note,
            } => self.record_block_dma_buffer_with_id(
                block_dma_buffer,
                backend,
                block_request,
                block_request_generation,
                dma_buffer,
                dma_buffer_generation,
                buffer_digest,
                &note,
            ),
            SemanticCommand::RecordBlockPageObject {
                block_page_object,
                block_dma_buffer,
                block_dma_buffer_generation,
                block_completion,
                block_completion_generation,
                aspace,
                vma_region,
                page,
                page_dirty_generation,
                page_backing,
                cow_state,
                page_state,
                page_offset,
                byte_len,
                note,
            } => self.record_block_page_object_with_id(
                block_page_object,
                block_dma_buffer,
                block_dma_buffer_generation,
                block_completion,
                block_completion_generation,
                aspace,
                vma_region,
                page,
                page_dirty_generation,
                page_backing,
                cow_state,
                page_state,
                page_offset,
                byte_len,
                &note,
            ),
            SemanticCommand::RecordBufferCacheObject {
                buffer_cache_object,
                block_page_object,
                block_page_object_generation,
                page,
                page_dirty_generation,
                block_offset,
                byte_len,
                cache_state,
                coherency_epoch,
                note,
            } => self.record_buffer_cache_object_with_id(
                buffer_cache_object,
                block_page_object,
                block_page_object_generation,
                page,
                page_dirty_generation,
                block_offset,
                byte_len,
                cache_state,
                coherency_epoch,
                &note,
            ),
            SemanticCommand::RecordFileObject {
                file_object,
                buffer_cache_object,
                buffer_cache_object_generation,
                namespace,
                file_key,
                path,
                file_offset,
                byte_len,
                file_size,
                content_digest,
                state,
                note,
            } => self.record_file_object_with_id(
                file_object,
                buffer_cache_object,
                buffer_cache_object_generation,
                &namespace,
                &file_key,
                &path,
                file_offset,
                byte_len,
                file_size,
                content_digest,
                state,
                &note,
            ),
            SemanticCommand::RecordDirectoryObject {
                directory_object,
                file_object,
                file_object_generation,
                namespace,
                directory_key,
                directory_path,
                entry_name,
                child_file_key,
                child_path,
                entry_kind,
                file_size,
                content_digest,
                state,
                note,
            } => self.record_directory_object_with_id(
                directory_object,
                file_object,
                file_object_generation,
                &namespace,
                &directory_key,
                &directory_path,
                &entry_name,
                &child_file_key,
                &child_path,
                entry_kind,
                file_size,
                content_digest,
                state,
                &note,
            ),
            SemanticCommand::RecordFatAdapterObject {
                fat_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation,
                version,
                profile,
                volume_label,
                image_bytes,
                adapter_path,
                semantic_path,
                bytes_written,
                bytes_read,
                write_digest,
                read_digest,
                file_content_digest,
                state,
                note,
            } => self.record_fat_adapter_object_with_id(
                fat_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                &implementation,
                &version,
                &profile,
                &volume_label,
                image_bytes,
                &adapter_path,
                &semantic_path,
                bytes_written,
                bytes_read,
                write_digest,
                read_digest,
                file_content_digest,
                state,
                &note,
            ),
            SemanticCommand::RecordExt4AdapterObject {
                ext4_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation,
                version,
                profile,
                volume_label,
                image_bytes,
                adapter_path,
                semantic_path,
                bytes_read,
                read_digest,
                file_content_digest,
                directory_entries,
                read_only_enforced,
                state,
                note,
            } => self.record_ext4_adapter_object_with_id(
                ext4_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                &implementation,
                &version,
                &profile,
                &volume_label,
                image_bytes,
                &adapter_path,
                &semantic_path,
                bytes_read,
                read_digest,
                file_content_digest,
                directory_entries,
                read_only_enforced,
                state,
                &note,
            ),
            SemanticCommand::RecordFileHandleCapability {
                file_handle_capability,
                owner_store,
                owner_store_generation,
                file_object,
                file_object_generation,
                directory_object,
                directory_object_generation,
                capability,
                capability_generation,
                handle,
                operation,
                file_offset,
                byte_len,
                content_digest,
                note,
            } => self.record_file_handle_capability_with_id(
                file_handle_capability,
                owner_store,
                owner_store_generation,
                file_object,
                file_object_generation,
                directory_object,
                directory_object_generation,
                capability,
                capability_generation,
                handle,
                &operation,
                file_offset,
                byte_len,
                content_digest,
                &note,
            ),
            SemanticCommand::RecordFsWait {
                fs_wait,
                wait,
                wait_generation,
                file_handle_capability,
                file_handle_capability_generation,
                operation,
                sequence,
                note,
            } => self.record_fs_wait_with_id(
                fs_wait,
                wait,
                wait_generation,
                file_handle_capability,
                file_handle_capability_generation,
                &operation,
                sequence,
                &note,
            ),
            SemanticCommand::ResolveFsWait {
                fs_wait,
                fs_wait_generation,
                note,
            } => self.resolve_fs_wait(fs_wait, fs_wait_generation, &note),
            SemanticCommand::CancelFsWait {
                fs_wait,
                fs_wait_generation,
                errno,
                reason,
                note,
            } => self.cancel_fs_wait(fs_wait, fs_wait_generation, errno, reason, &note),
            SemanticCommand::CleanupBlockDriver {
                cleanup,
                io_cleanup,
                block_device,
                block_device_generation,
                backend,
                reason,
                note,
            } => self.cleanup_block_driver_with_id(
                cleanup,
                io_cleanup,
                block_device,
                block_device_generation,
                backend,
                &reason,
                &note,
            ),
            SemanticCommand::RecordVirtioNetBackendObject {
                virtio_net_backend,
                name,
                packet_device,
                packet_device_generation,
                driver_binding,
                driver_binding_generation,
                provider,
                profile,
                model,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                device_features,
                driver_features,
                negotiated_features,
                rx_queue_index,
                tx_queue_index,
                queue_size,
                irq_vector,
                note,
            } => self.record_virtio_net_backend_object_with_id(
                virtio_net_backend,
                &name,
                packet_device,
                packet_device_generation,
                driver_binding,
                driver_binding_generation,
                &provider,
                &profile,
                &model,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                device_features,
                driver_features,
                negotiated_features,
                rx_queue_index,
                tx_queue_index,
                queue_size,
                irq_vector,
                &note,
            ),
            SemanticCommand::RecordNetworkRxInterrupt {
                rx_interrupt,
                virtio_net_backend,
                virtio_net_backend_generation,
                irq_event,
                irq_event_generation,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                ready_descriptors,
                sequence,
                note,
            } => self.record_network_rx_interrupt_with_id(
                rx_interrupt,
                virtio_net_backend,
                virtio_net_backend_generation,
                irq_event,
                irq_event_generation,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                ready_descriptors,
                sequence,
                &note,
            ),
            SemanticCommand::ResolveNetworkRxWait {
                resolution,
                io_wait,
                io_wait_generation,
                rx_interrupt,
                rx_interrupt_generation,
                note,
            } => self.resolve_network_rx_wait_with_id(
                resolution,
                io_wait,
                io_wait_generation,
                rx_interrupt,
                rx_interrupt_generation,
                &note,
            ),
            SemanticCommand::RecordNetworkTxCapabilityGate {
                tx_gate,
                driver_store,
                driver_store_generation,
                packet_descriptor,
                packet_descriptor_generation,
                device_capability,
                device_capability_generation,
                handle,
                note,
            } => self.record_network_tx_capability_gate_with_id(
                tx_gate,
                driver_store,
                driver_store_generation,
                packet_descriptor,
                packet_descriptor_generation,
                device_capability,
                device_capability_generation,
                handle,
                &note,
            ),
            SemanticCommand::RecordNetworkTxCompletion {
                completion,
                tx_gate,
                tx_gate_generation,
                backend,
                completion_sequence,
                note,
            } => self.record_network_tx_completion_with_id(
                completion,
                tx_gate,
                tx_gate_generation,
                backend,
                completion_sequence,
                &note,
            ),
            SemanticCommand::RecordNetworkStackAdapter {
                adapter,
                backend,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                tx_queue,
                tx_queue_generation,
                implementation,
                implementation_version,
                profile,
                medium,
                mac,
                ipv4_addr,
                ipv4_prefix_len,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                max_payload_len,
                socket_capacity,
                note,
            } => self.record_network_stack_adapter_with_id(
                adapter,
                backend,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                tx_queue,
                tx_queue_generation,
                &implementation,
                &implementation_version,
                &profile,
                &medium,
                mac,
                ipv4_addr,
                ipv4_prefix_len,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                max_payload_len,
                socket_capacity,
                &note,
            ),
            SemanticCommand::RecordSocketObject {
                socket,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                domain,
                socket_type,
                protocol,
                note,
            } => self.record_socket_object_with_id(
                socket,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                domain,
                socket_type,
                protocol,
                &note,
            ),
            SemanticCommand::RecordEndpointObject {
                endpoint,
                socket,
                socket_generation,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                note,
            } => self.record_endpoint_object_with_id(
                endpoint,
                socket,
                socket_generation,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                &note,
            ),
            SemanticCommand::BindSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                local_addr,
                local_port,
                sequence,
                note,
            } => self.record_socket_operation_with_id(
                operation_id,
                endpoint,
                endpoint_generation,
                SocketOperationKind::Bind,
                local_addr,
                local_port,
                [0, 0, 0, 0],
                0,
                0,
                0,
                sequence,
                &note,
            ),
            SemanticCommand::ListenSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                backlog,
                sequence,
                note,
            } => self.record_socket_operation_with_id(
                operation_id,
                endpoint,
                endpoint_generation,
                SocketOperationKind::Listen,
                [0, 0, 0, 0],
                0,
                [0, 0, 0, 0],
                0,
                backlog,
                0,
                sequence,
                &note,
            ),
            SemanticCommand::ConnectSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                remote_addr,
                remote_port,
                sequence,
                note,
            } => self.record_socket_operation_with_id(
                operation_id,
                endpoint,
                endpoint_generation,
                SocketOperationKind::Connect,
                [0, 0, 0, 0],
                0,
                remote_addr,
                remote_port,
                0,
                0,
                sequence,
                &note,
            ),
            SemanticCommand::SendSocket {
                operation_id,
                endpoint,
                endpoint_generation,
                byte_len,
                sequence,
                note,
            } => self.record_socket_operation_with_id(
                operation_id,
                endpoint,
                endpoint_generation,
                SocketOperationKind::Send,
                [0, 0, 0, 0],
                0,
                [0, 0, 0, 0],
                0,
                0,
                byte_len,
                sequence,
                &note,
            ),
            SemanticCommand::RecvSocket {
                operation_id,
                endpoint,
                endpoint_generation,
                byte_len,
                sequence,
                note,
            } => self.record_socket_operation_with_id(
                operation_id,
                endpoint,
                endpoint_generation,
                SocketOperationKind::Recv,
                [0, 0, 0, 0],
                0,
                [0, 0, 0, 0],
                0,
                0,
                byte_len,
                sequence,
                &note,
            ),
            SemanticCommand::RecordSocketWait {
                socket_wait,
                wait,
                wait_generation,
                endpoint,
                endpoint_generation,
                wait_kind,
                blocker,
                note,
            } => self.record_socket_wait_with_id(
                socket_wait,
                wait,
                wait_generation,
                endpoint,
                endpoint_generation,
                wait_kind,
                blocker,
                &note,
            ),
            SemanticCommand::ResolveSocketWait {
                socket_wait,
                socket_wait_generation,
                ready_sequence,
                byte_len,
                note,
            } => self.resolve_socket_wait(
                socket_wait,
                socket_wait_generation,
                ready_sequence,
                byte_len,
                &note,
            ),
            SemanticCommand::CancelSocketWait {
                socket_wait,
                socket_wait_generation,
                errno,
                reason,
                note,
            } => self.cancel_socket_wait(socket_wait, socket_wait_generation, errno, reason, &note),
            SemanticCommand::RecordNetworkBackpressure {
                backpressure,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                endpoint,
                endpoint_generation,
                direction,
                reason,
                action,
                queue_depth,
                queue_limit,
                dropped_packets,
                dropped_bytes,
                sequence,
                note,
            } => self.record_network_backpressure_with_id(
                backpressure,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                endpoint,
                endpoint_generation,
                direction,
                reason,
                action,
                queue_depth,
                queue_limit,
                dropped_packets,
                dropped_bytes,
                sequence,
                &note,
            ),
            SemanticCommand::CleanupNetworkDriver {
                cleanup,
                io_cleanup,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                backend,
                reason,
                note,
            } => self.cleanup_network_driver_with_id(
                cleanup,
                io_cleanup,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                backend,
                &reason,
                &note,
            ),
            SemanticCommand::RecordNetworkGenerationAudit {
                audit,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                dma_buffer,
                device_capability,
                rejected_packet_generation_probes,
                rejected_dma_generation_probes,
                note,
            } => self.record_network_generation_audit_with_id(
                audit,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                dma_buffer,
                device_capability,
                rejected_packet_generation_probes,
                rejected_dma_generation_probes,
                &note,
            ),
            SemanticCommand::RecordNetworkFaultInjection {
                injection,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                endpoint,
                endpoint_generation,
                direction,
                kind,
                effect,
                injected_packets,
                dropped_packets,
                error_packets,
                error_code,
                sequence,
                note,
            } => self.record_network_fault_injection_with_id(
                injection,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                endpoint,
                endpoint_generation,
                direction,
                kind,
                effect,
                injected_packets,
                dropped_packets,
                error_packets,
                &error_code,
                sequence,
                &note,
            ),
            SemanticCommand::RecordNetworkBenchmark {
                benchmark,
                scenario,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                rx_queue,
                rx_queue_generation,
                tx_completion,
                tx_completion_generation,
                rx_wait_resolution,
                rx_wait_resolution_generation,
                endpoint,
                endpoint_generation,
                backpressure,
                backpressure_generation,
                sample_packets,
                sample_bytes,
                tx_completed_packets,
                rx_resolved_packets,
                dropped_packets,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                note,
            } => self.record_network_benchmark_with_id(
                benchmark,
                &scenario,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                rx_queue,
                rx_queue_generation,
                tx_completion,
                tx_completion_generation,
                rx_wait_resolution,
                rx_wait_resolution_generation,
                endpoint,
                endpoint_generation,
                backpressure,
                backpressure_generation,
                sample_packets,
                sample_bytes,
                tx_completed_packets,
                rx_resolved_packets,
                dropped_packets,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                &note,
            ),
            SemanticCommand::RecordNetworkRecoveryBenchmark {
                benchmark,
                scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                fault_injection,
                fault_injection_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                recovery_nanos,
                budget_nanos,
                note,
            } => self.record_network_recovery_benchmark_with_id(
                benchmark,
                &scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                fault_injection,
                fault_injection_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                recovery_nanos,
                budget_nanos,
                &note,
            ),
            SemanticCommand::RecordBlockDeviceObject {
                block_device,
                name,
                device,
                device_generation,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                note,
            } => self.record_block_device_object_with_id(
                block_device,
                &name,
                device,
                device_generation,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                &note,
            ),
            SemanticCommand::RecordBlockRangeObject {
                block_range,
                block_device,
                block_device_generation,
                start_sector,
                sector_count,
                note,
            } => self.record_block_range_object_with_id(
                block_range,
                block_device,
                block_device_generation,
                start_sector,
                sector_count,
                &note,
            ),
            SemanticCommand::RecordBlockRequestObject {
                block_request,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                operation,
                sequence,
                note,
            } => self.record_block_request_object_with_id(
                block_request,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                operation,
                sequence,
                &note,
            ),
            SemanticCommand::RecordBlockCompletionObject {
                block_completion,
                block_request,
                block_request_generation,
                sequence,
                completed_bytes,
                status,
                note,
            } => self.record_block_completion_object_with_id(
                block_completion,
                block_request,
                block_request_generation,
                sequence,
                completed_bytes,
                status,
                &note,
            ),
            SemanticCommand::RecordBlockWait {
                block_wait,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
                note,
            } => self.record_block_wait_with_id(
                block_wait,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
                &note,
            ),
            SemanticCommand::ResolveBlockWait {
                block_wait,
                block_wait_generation,
                block_completion,
                block_completion_generation,
                note,
            } => self.resolve_block_wait_with_completion(
                block_wait,
                block_wait_generation,
                block_completion,
                block_completion_generation,
                &note,
            ),
            SemanticCommand::CancelBlockWait {
                block_wait,
                block_wait_generation,
                errno,
                reason,
                note,
            } => self.cancel_block_wait(block_wait, block_wait_generation, errno, reason, &note),
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy,
                block_wait,
                block_wait_generation,
                action,
                retry_request,
                retry_request_generation,
                errno,
                retry_attempt,
                max_retries,
                note,
            } => self.apply_block_pending_io_policy_with_id(
                policy,
                block_wait,
                block_wait_generation,
                action,
                retry_request,
                retry_request_generation,
                errno,
                retry_attempt,
                max_retries,
                &note,
            ),
            SemanticCommand::RecordBlockRequestGenerationAudit {
                audit,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                block_request,
                block_request_generation,
                backend,
                dma_buffer,
                rejected_completion_generation_probes,
                rejected_wait_generation_probes,
                rejected_dma_generation_probes,
                rejected_queue_generation_probes,
                note,
            } => self.record_block_request_generation_audit_with_id(
                audit,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                block_request,
                block_request_generation,
                backend,
                dma_buffer,
                rejected_completion_generation_probes,
                rejected_wait_generation_probes,
                rejected_dma_generation_probes,
                rejected_queue_generation_probes,
                &note,
            ),
            SemanticCommand::RecordBlockBenchmark {
                benchmark,
                scenario,
                backend,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                read_path,
                read_path_generation,
                write_path,
                write_path_generation,
                request_queue,
                request_queue_generation,
                block_dma_buffer,
                block_dma_buffer_generation,
                sample_requests,
                sample_bytes,
                read_completed_requests,
                write_completed_requests,
                queue_completed_requests,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                note,
            } => self.record_block_benchmark_with_id(
                benchmark,
                &scenario,
                backend,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                read_path,
                read_path_generation,
                write_path,
                write_path_generation,
                request_queue,
                request_queue_generation,
                block_dma_buffer,
                block_dma_buffer_generation,
                sample_requests,
                sample_bytes,
                read_completed_requests,
                write_completed_requests,
                queue_completed_requests,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                &note,
            ),
            SemanticCommand::RecordBlockRecoveryBenchmark {
                benchmark,
                scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_block_waits,
                cancelled_wait_tokens,
                released_dma_buffers,
                revoked_device_capabilities,
                recovery_nanos,
                budget_nanos,
                note,
            } => self.record_block_recovery_benchmark_with_id(
                benchmark,
                &scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_block_waits,
                cancelled_wait_tokens,
                released_dma_buffers,
                revoked_device_capabilities,
                recovery_nanos,
                budget_nanos,
                &note,
            ),
            SemanticCommand::RecordTargetFeatureSet {
                feature_set,
                name,
                discovery_source,
                target_profile,
                target_arch,
                base_isa,
                simd_abi,
                simd_supported,
                vector_register_count,
                vector_register_bits,
                scalar_fallback,
                unsupported_reason,
                note,
            } => self.record_target_feature_set_with_id(
                feature_set,
                &name,
                &discovery_source,
                &target_profile,
                &target_arch,
                &base_isa,
                &simd_abi,
                simd_supported,
                vector_register_count,
                vector_register_bits,
                scalar_fallback,
                &unsupported_reason,
                &note,
            ),
            SemanticCommand::RecordVectorState {
                vector_state,
                owner_activation,
                owner_store,
                code_object,
                target_feature_set,
                simd_abi,
                vector_register_count,
                vector_register_bits,
                register_bytes,
                state,
                note,
            } => self.record_vector_state_with_id(
                vector_state,
                owner_activation,
                owner_store,
                code_object,
                target_feature_set,
                &simd_abi,
                vector_register_count,
                vector_register_bits,
                register_bytes,
                state,
                &note,
            ),
            SemanticCommand::RecordQueueObject {
                queue,
                name,
                role,
                queue_index,
                depth,
                device,
                device_generation,
                note,
            } => self.record_queue_object_with_id(
                queue,
                &name,
                role,
                queue_index,
                depth,
                device,
                device_generation,
                &note,
            ),
            SemanticCommand::RecordDescriptorObject {
                descriptor,
                queue,
                queue_generation,
                slot,
                access,
                length,
                note,
            } => self.record_descriptor_object_with_id(
                descriptor,
                queue,
                queue_generation,
                slot,
                access,
                length,
                &note,
            ),
            SemanticCommand::RecordDmaBufferObject {
                dma_buffer,
                descriptor,
                descriptor_generation,
                resource,
                resource_generation,
                access,
                length,
                note,
            } => self.record_dma_buffer_object_with_id(
                dma_buffer,
                descriptor,
                descriptor_generation,
                resource,
                resource_generation,
                access,
                length,
                &note,
            ),
            SemanticCommand::RecordMmioRegionObject {
                mmio_region,
                device,
                device_generation,
                resource,
                resource_generation,
                region_index,
                offset,
                length,
                access,
                note,
            } => self.record_mmio_region_object_with_id(
                mmio_region,
                device,
                device_generation,
                resource,
                resource_generation,
                region_index,
                offset,
                length,
                access,
                &note,
            ),
            SemanticCommand::RecordIrqLineObject {
                irq_line,
                device,
                device_generation,
                resource,
                resource_generation,
                irq_number,
                trigger,
                polarity,
                note,
            } => self.record_irq_line_object_with_id(
                irq_line,
                device,
                device_generation,
                resource,
                resource_generation,
                irq_number,
                trigger,
                polarity,
                &note,
            ),
            SemanticCommand::RecordIrqEvent {
                irq_event,
                irq_line,
                irq_line_generation,
                device,
                device_generation,
                driver_store,
                driver_store_generation,
                sequence,
                note,
            } => self.record_irq_event_with_id(
                irq_event,
                irq_line,
                irq_line_generation,
                device,
                device_generation,
                driver_store,
                driver_store_generation,
                sequence,
                &note,
            ),
            SemanticCommand::RecordDeviceCapability {
                device_capability,
                driver_store,
                driver_store_generation,
                target,
                class,
                operation,
                handle,
                note,
            } => self.record_device_capability_with_id(
                device_capability,
                driver_store,
                driver_store_generation,
                target,
                class,
                &operation,
                handle,
                &note,
            ),
            SemanticCommand::BindDriverStore {
                binding,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                device_capability,
                device_capability_generation,
                note,
            } => self.record_driver_store_binding_with_id(
                binding,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                device_capability,
                device_capability_generation,
                &note,
            ),
            SemanticCommand::RecordIoWait {
                io_wait,
                wait,
                wait_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                blocker,
                note,
            } => self.record_io_wait_with_id(
                io_wait,
                wait,
                wait_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                blocker,
                &note,
            ),
            SemanticCommand::ResolveIoWait {
                io_wait,
                io_wait_generation,
                irq_event,
                irq_event_generation,
                note,
            } => self.resolve_io_wait_with_irq_event(
                io_wait,
                io_wait_generation,
                irq_event,
                irq_event_generation,
                &note,
            ),
            SemanticCommand::CancelIoWait {
                io_wait,
                io_wait_generation,
                errno,
                reason,
                note,
            } => self.cancel_io_wait(io_wait, io_wait_generation, errno, reason, &note),
            SemanticCommand::CleanupIoDriver {
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                reason,
                note,
            } => self.cleanup_io_driver_for_device_fault_with_id(
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                &reason,
                &note,
            ),
            SemanticCommand::InjectIoFault {
                fault,
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                target,
                kind,
                note,
            } => self.inject_io_fault_with_id(
                fault,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                target,
                cleanup,
                kind,
                &note,
            ),
            SemanticCommand::ValidateIoRuntime { report, note } => {
                self.record_io_validation_report_with_id(report, &note)
            }
            SemanticCommand::ResumeActivation {
                resume,
                scheduler_decision,
                scheduler_decision_generation,
                activation,
                activation_generation,
                note,
            } => self.resume_activation_with_id(
                resume,
                scheduler_decision,
                scheduler_decision_generation,
                activation,
                activation_generation,
                &note,
            ),
            SemanticCommand::RecordPreemptionLatencySample {
                sample,
                timer_interrupt,
                timer_interrupt_generation,
                preemption,
                preemption_generation,
                scheduler_decision,
                scheduler_decision_generation,
                activation_resume,
                activation_resume_generation,
                measured_nanos,
                budget_nanos,
                note,
            } => self.record_preemption_latency_sample_with_id(
                sample,
                timer_interrupt,
                timer_interrupt_generation,
                preemption,
                preemption_generation,
                scheduler_decision,
                scheduler_decision_generation,
                activation_resume,
                activation_resume_generation,
                measured_nanos,
                budget_nanos,
                &note,
            ),
            SemanticCommand::BlockActivationOnWait {
                activation_wait,
                activation,
                activation_generation,
                wait,
                kind,
                blockers,
                deadline,
                restart_policy,
                note,
            } => self.block_activation_on_wait_with_id(
                activation_wait,
                activation,
                activation_generation,
                wait,
                kind,
                blockers,
                deadline,
                restart_policy,
                &note,
            ),
            SemanticCommand::CancelActivationWait {
                activation_wait,
                activation_wait_generation,
                wait_generation,
                errno,
                reason,
                note,
            } => self.cancel_activation_wait(
                activation_wait,
                activation_wait_generation,
                wait_generation,
                errno,
                reason,
                &note,
            ),
            SemanticCommand::CleanupActivationForStoreFault {
                cleanup,
                store,
                store_generation,
                activation,
                activation_generation,
                wait,
                wait_generation,
                reason,
                note,
            } => self.cleanup_activation_for_store_fault_with_id(
                cleanup,
                store,
                store_generation,
                activation,
                activation_generation,
                wait,
                wait_generation,
                &reason,
                &note,
            ),
            SemanticCommand::GrantCapability {
                subject,
                debug_object_label,
                object_ref,
                operations,
                lifetime,
                owner_store,
                owner_store_generation,
                owner_task,
                source,
                manifest_decl,
            } => {
                let operations = operations.iter().map(String::as_str).collect::<Vec<_>>();
                let cap = self.capabilities.grant_with_authority_ref(
                    &subject,
                    &debug_object_label,
                    object_ref,
                    &operations,
                    &lifetime,
                    owner_store,
                    owner_store_generation,
                    owner_task,
                    &source,
                    manifest_decl,
                );
                let Ok(cap) = cap else {
                    return false;
                };
                self.event_log
                    .push("command", EventKind::CapabilityGranted { cap });
                true
            }
            SemanticCommand::RevokeCapability { cap } => {
                let changed = self.capabilities.revoke(cap);
                if changed {
                    self.event_log
                        .push("command", EventKind::CapabilityRevoked { cap });
                }
                changed
            }
            SemanticCommand::CreateWait {
                wait,
                owner_task,
                owner_store,
                owner_store_generation,
                kind,
                generation,
                blockers,
                deadline,
                restart_policy,
                saved_context,
            } => {
                self.record_wait_created_with_details(
                    wait,
                    owner_task,
                    owner_store,
                    owner_store_generation,
                    kind,
                    generation,
                    blockers,
                    deadline,
                    restart_policy,
                    saved_context,
                );
                true
            }
            SemanticCommand::ResolveWait { wait, reason } => {
                self.record_wait_resolved(wait, &reason);
                true
            }
            SemanticCommand::CancelWait {
                wait,
                errno,
                reason,
            } => {
                self.record_wait_cancelled_with_reason(wait, errno, reason);
                true
            }
            SemanticCommand::RecordTrap {
                store,
                task,
                trap,
                detail,
            } => {
                self.event_log.push(
                    "command",
                    EventKind::FaultClassified {
                        trap,
                        class: trap.fault_class(),
                        store,
                        task,
                        detail,
                    },
                );
                true
            }
            SemanticCommand::BeginCleanup {
                cleanup,
                store,
                generation,
                reason,
            } => {
                self.next_transaction_id = self.next_transaction_id.max(cleanup + 1);
                self.transactions.push(SemanticTransactionRecord {
                    id: cleanup,
                    label: format!("cleanup:{reason}"),
                    store: Some(store),
                    task: None,
                    state: TransactionState::Begun,
                    generation,
                });
                self.event_log.push(
                    "command",
                    EventKind::TransactionBegan {
                        transaction: cleanup,
                        store: Some(store),
                        task: None,
                        label: format!("cleanup:{reason}"),
                    },
                );
                true
            }
            SemanticCommand::ApplyCleanupStep {
                cleanup,
                step,
                target,
                observed_generation,
            } => {
                self.event_log.push(
                    "command",
                    EventKind::CleanupStepApplied {
                        cleanup,
                        step: step.as_str().to_string(),
                        target: target.summary(),
                        observed_generation,
                    },
                );
                true
            }
            SemanticCommand::CommitCleanup { cleanup } => {
                let before = self.event_count();
                self.commit_transaction(cleanup);
                self.event_count() != before
            }
        }
    }
}

fn rejected_command_result(
    command_id: CommandId,
    issuer: String,
    command: &'static str,
    detail: &str,
) -> CommandResult {
    CommandResult {
        command_id,
        issuer,
        command,
        status: CommandStatus::Rejected,
        events: Vec::new(),
        effects: Vec::new(),
        violations: {
            let mut violations = Vec::new();
            violations.push(detail.to_string());
            violations
        },
    }
}

fn event_refs_between(before: usize, after: usize) -> Vec<EventId> {
    ((before + 1)..=after)
        .map(|event| event as EventId)
        .collect()
}

fn command_effects(outcome: &CommandOutcome) -> Vec<CommandEffect> {
    if !outcome.changed {
        return Vec::new();
    }
    let mut effects = Vec::new();
    effects.push(CommandEffect::new(outcome.command, None));
    effects
}
