use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    HartRegistered {
        hart: HartId,
        hardware_id: u32,
        label: String,
        boot: bool,
        generation: Generation,
    },
    HartStateChanged {
        hart: HartId,
        from: HartState,
        to: HartState,
        reason: String,
        generation: Generation,
    },
    HartCurrentActivationBound {
        hart: HartId,
        from: HartState,
        activation: ActivationId,
        activation_generation: Generation,
        generation: Generation,
    },
    HartCurrentActivationCleared {
        hart: HartId,
        activation: ActivationId,
        activation_generation: Generation,
        reason: String,
        generation: Generation,
    },
    TaskCreated {
        task: TaskId,
        frontend: FrontendKind,
    },
    TaskStateChanged {
        task: TaskId,
        from: TaskState,
        to: TaskState,
    },
    RuntimeActivationCreated {
        activation: ActivationId,
        task: TaskId,
        generation: Generation,
    },
    RuntimeActivationStateChanged {
        activation: ActivationId,
        from: RuntimeActivationState,
        to: RuntimeActivationState,
        generation: Generation,
    },
    RunnableQueueCreated {
        queue: RunnableQueueId,
        label: String,
        generation: Generation,
    },
    RunnableQueueOwnerBound {
        queue: RunnableQueueId,
        hart: HartId,
        hart_generation: Generation,
        generation: Generation,
        note: String,
    },
    RunnableQueued {
        queue: RunnableQueueId,
        activation: ActivationId,
        activation_generation: Generation,
    },
    RunnableDequeued {
        queue: RunnableQueueId,
        activation: ActivationId,
        activation_generation: Generation,
    },
    ActivationContextCreated {
        context: ActivationContextId,
        activation: ActivationId,
        activation_generation: Generation,
        generation: Generation,
    },
    SavedContextCaptured {
        saved_context: SavedContextId,
        context: ActivationContextId,
        context_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        reason: SavedContextReason,
        generation: Generation,
    },
    TimerInterruptRecorded {
        interrupt: TimerInterruptId,
        timer_epoch: u64,
        hart: HartId,
        hart_generation: Generation,
        hardware_hart: u32,
        target_activation: Option<ActivationId>,
        target_activation_generation: Option<Generation>,
        generation: Generation,
    },
    IpiEventRecorded {
        ipi: IpiEventId,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        kind: IpiEventKind,
        generation: Generation,
    },
    RemoteActivationPreempted {
        remote_preempt: RemotePreemptId,
        ipi: IpiEventId,
        ipi_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation_before: Generation,
        target_hart_generation_after: Generation,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        queue: RunnableQueueId,
        queue_generation: Generation,
        generation: Generation,
    },
    RemoteHartParked {
        remote_park: RemoteParkId,
        ipi: IpiEventId,
        ipi_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation_before: Generation,
        target_hart_generation_after: Generation,
        reason: String,
        generation: Generation,
    },
    RuntimeActivationPreempted {
        preemption: PreemptionId,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        queue: RunnableQueueId,
        queue_generation: Generation,
        generation: Generation,
    },
    SchedulerDecisionRecorded {
        decision: SchedulerDecisionId,
        queue: RunnableQueueId,
        queue_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        generation: Generation,
    },
    CrossHartSchedulerDecisionRecorded {
        cross_decision: CrossHartSchedulerDecisionId,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        deciding_hart: HartId,
        deciding_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        queue: RunnableQueueId,
        queue_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        generation: Generation,
    },
    ActivationMigrated {
        migration: ActivationMigrationId,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        source_queue: RunnableQueueId,
        source_queue_generation: Generation,
        target_queue: RunnableQueueId,
        target_queue_generation: Generation,
        generation: Generation,
    },
    SmpSafePointRecorded {
        safe_point: SmpSafePointId,
        coordinator_hart: HartId,
        coordinator_hart_generation: Generation,
        participant_count: u32,
        generation: Generation,
    },
    StopTheWorldRendezvousCompleted {
        rendezvous: StopTheWorldRendezvousId,
        epoch: u64,
        safe_point: SmpSafePointId,
        safe_point_generation: Generation,
        coordinator_hart: HartId,
        coordinator_hart_generation: Generation,
        participant_count: u32,
        generation: Generation,
    },
    SmpCodePublishBarrierValidated {
        barrier: SmpCodePublishBarrierId,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        code_publish_epoch_before: u64,
        code_publish_epoch_after: u64,
        participant_count: u32,
        generation: Generation,
    },
    SmpCleanupQuiescenceValidated {
        quiescence: SmpCleanupQuiescenceId,
        cleanup: ActivationCleanupId,
        cleanup_generation: Generation,
        store: StoreId,
        target_store_generation: Generation,
        result_store_generation: Generation,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        participant_count: u32,
        generation: Generation,
    },
    SmpSnapshotBarrierValidated {
        barrier: SmpSnapshotBarrierId,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        event_log_cursor: EventId,
        participant_count: u32,
        generation: Generation,
    },
    SmpStressRunRecorded {
        run: SmpStressRunId,
        scenario: String,
        iterations: u32,
        hart_count: u32,
        safe_point_count: u32,
        rendezvous_count: u32,
        property_failures: u32,
        generation: Generation,
    },
    SmpScalingBenchmarkRecorded {
        benchmark: SmpScalingBenchmarkId,
        stress_run: SmpStressRunId,
        stress_run_generation: Generation,
        hart_count: u32,
        workload_units: u64,
        measured_smp_nanos: u64,
        budget_nanos: u64,
        speedup_milli: u64,
        efficiency_milli: u64,
        generation: Generation,
    },
    DeviceObjectRecorded {
        device: DeviceObjectId,
        resource: ResourceId,
        resource_generation: Generation,
        class: String,
        backend: String,
        generation: Generation,
    },
    QueueObjectRecorded {
        queue: QueueObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        role: QueueObjectRole,
        queue_index: u16,
        depth: u32,
        generation: Generation,
    },
    DescriptorObjectRecorded {
        descriptor: DescriptorObjectId,
        queue: QueueObjectId,
        queue_generation: Generation,
        slot: u16,
        access: DescriptorObjectAccess,
        length: u32,
        generation: Generation,
    },
    DmaBufferObjectRecorded {
        dma_buffer: DmaBufferObjectId,
        descriptor: DescriptorObjectId,
        descriptor_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        access: DmaBufferObjectAccess,
        length: u32,
        generation: Generation,
    },
    MmioRegionObjectRecorded {
        mmio_region: MmioRegionObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        region_index: u16,
        offset: u64,
        length: u64,
        access: MmioRegionObjectAccess,
        generation: Generation,
    },
    IrqLineObjectRecorded {
        irq_line: IrqLineObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        irq_number: u32,
        trigger: IrqLineTrigger,
        polarity: IrqLinePolarity,
        generation: Generation,
    },
    IrqEventRecorded {
        irq_event: IrqEventId,
        irq_line: IrqLineObjectId,
        irq_line_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_store: StoreId,
        driver_store_generation: Generation,
        irq_number: u32,
        sequence: u64,
        generation: Generation,
    },
    DeviceCapabilityRecorded {
        device_capability: DeviceCapabilityId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        target: ContractObjectRef,
        class: CapabilityClass,
        operation: String,
        capability: CapabilityId,
        capability_generation: Generation,
        handle_slot: u32,
        handle_generation: u32,
        generation: Generation,
    },
    DriverStoreBound {
        binding: DriverStoreBindingId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        device_capability: DeviceCapabilityId,
        device_capability_generation: Generation,
        capability: CapabilityId,
        capability_generation: Generation,
        generation: Generation,
    },
    IoWaitCreated {
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
        generation: Generation,
    },
    IoWaitResolved {
        io_wait: IoWaitId,
        wait: WaitId,
        wait_generation: Generation,
        irq_event: IrqEventId,
        irq_event_generation: Generation,
        generation: Generation,
    },
    IoWaitCancelled {
        io_wait: IoWaitId,
        wait: WaitId,
        wait_generation: Generation,
        reason: WaitCancelReason,
        generation: Generation,
    },
    IoCleanupStarted {
        cleanup: IoCleanupId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        generation: Generation,
    },
    IoCleanupCompleted {
        cleanup: IoCleanupId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        cancelled_io_waits: usize,
        revoked_device_capabilities: usize,
        released_dma_buffers: usize,
        released_mmio_regions: usize,
        released_irq_lines: usize,
        generation: Generation,
    },
    IoFaultInjected {
        fault: IoFaultInjectionId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        target: ContractObjectRef,
        cleanup: IoCleanupId,
        cleanup_generation: Generation,
        kind: IoFaultInjectionKind,
        generation: Generation,
    },
    IoValidationReportRecorded {
        report: IoValidationReportId,
        ok: bool,
        violation_count: usize,
        device_count: usize,
        dma_buffer_count: usize,
        irq_event_count: usize,
        cleanup_count: usize,
        fault_injection_count: usize,
        generation: Generation,
    },
    PacketDeviceObjectRecorded {
        packet_device: PacketDeviceObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        frame_format_version: u32,
        max_payload_len: u32,
        generation: Generation,
    },
    BlockDeviceObjectRecorded {
        block_device: BlockDeviceObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        sector_size: u32,
        sector_count: u64,
        read_only: bool,
        max_transfer_sectors: u32,
        generation: Generation,
    },
    BlockRangeObjectRecorded {
        block_range: BlockRangeObjectId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        start_sector: u64,
        sector_count: u64,
        byte_offset: u64,
        byte_len: u64,
        generation: Generation,
    },
    BlockRequestObjectRecorded {
        block_request: BlockRequestObjectId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        operation: BlockRequestOperation,
        sequence: u64,
        byte_len: u64,
        generation: Generation,
    },
    BlockCompletionObjectRecorded {
        block_completion: BlockCompletionObjectId,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        sequence: u64,
        completed_bytes: u64,
        status: BlockCompletionStatus,
        generation: Generation,
    },
    BlockWaitCreated {
        block_wait: BlockWaitId,
        wait: WaitId,
        wait_generation: Generation,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        operation: BlockRequestOperation,
        sequence: u64,
        byte_len: u64,
        generation: Generation,
    },
    BlockWaitResolved {
        block_wait: BlockWaitId,
        wait: WaitId,
        wait_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        generation: Generation,
    },
    BlockWaitCancelled {
        block_wait: BlockWaitId,
        wait: WaitId,
        wait_generation: Generation,
        reason: WaitCancelReason,
        generation: Generation,
    },
    FakeBlockBackendObjectBound {
        fake_block_backend: FakeBlockBackendObjectId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        sector_size: u32,
        sector_count: u64,
        read_only: bool,
        max_transfer_sectors: u32,
        deterministic_seed: u64,
        generation: Generation,
    },
    VirtioBlkBackendSkeletonBound {
        virtio_blk_backend: VirtioBlkBackendObjectId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        queue_size: u16,
        request_queue_index: u16,
        negotiated_features: u64,
        generation: Generation,
    },
    BlockReadPathRecorded {
        read_path: BlockReadPathId,
        backend: ContractObjectRef,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        sequence: u64,
        completed_bytes: u64,
        data_digest: u64,
        generation: Generation,
    },
    BlockWritePathRecorded {
        write_path: BlockWritePathId,
        backend: ContractObjectRef,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        sequence: u64,
        completed_bytes: u64,
        payload_digest: u64,
        generation: Generation,
    },
    BlockRequestQueueRecorded {
        queue: BlockRequestQueueId,
        backend: ContractObjectRef,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        depth: u32,
        request_count: u32,
        pending_count: u32,
        completed_count: u32,
        first_sequence: u64,
        last_sequence: u64,
        generation: Generation,
    },
    BlockDmaBufferBound {
        block_dma_buffer: BlockDmaBufferId,
        backend: ContractObjectRef,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        dma_buffer: DmaBufferObjectId,
        dma_buffer_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        descriptor: DescriptorObjectId,
        descriptor_generation: Generation,
        queue: QueueObjectId,
        queue_generation: Generation,
        operation: BlockRequestOperation,
        access: DmaBufferObjectAccess,
        byte_len: u64,
        buffer_len: u32,
        buffer_digest: u64,
        generation: Generation,
    },
    BlockPageObjectIntegrated {
        block_page_object: BlockPageObjectId,
        block_dma_buffer: BlockDmaBufferId,
        block_dma_buffer_generation: Generation,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        dma_buffer: DmaBufferObjectId,
        dma_buffer_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        aspace: ContractObjectRef,
        vma_region: ContractObjectRef,
        page: ContractObjectRef,
        page_dirty_generation: Generation,
        page_offset: u64,
        byte_len: u64,
        operation: BlockRequestOperation,
        generation: Generation,
    },
    BufferCacheObjectRecorded {
        buffer_cache_object: BufferCacheObjectId,
        block_page_object: BlockPageObjectId,
        block_page_object_generation: Generation,
        block_dma_buffer: BlockDmaBufferId,
        block_dma_buffer_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        aspace: ContractObjectRef,
        vma_region: ContractObjectRef,
        page: ContractObjectRef,
        page_dirty_generation: Generation,
        page_offset: u64,
        block_offset: u64,
        byte_len: u64,
        operation: BlockRequestOperation,
        cache_state: BufferCacheObjectState,
        coherency_epoch: u64,
        generation: Generation,
    },
    FileObjectRecorded {
        file_object: FileObjectId,
        buffer_cache_object: BufferCacheObjectId,
        buffer_cache_object_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        page: ContractObjectRef,
        page_dirty_generation: Generation,
        namespace: String,
        file_key: String,
        path: String,
        file_offset: u64,
        byte_len: u64,
        file_size: u64,
        content_digest: u64,
        cache_state: BufferCacheObjectState,
        state: FileObjectState,
        generation: Generation,
    },
    PacketBufferObjectRecorded {
        packet_buffer: PacketBufferObjectId,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        direction: PacketBufferDirection,
        frame_format_version: u32,
        capacity: u32,
        payload_len: u32,
        sequence: u64,
        state: PacketBufferObjectState,
        generation: Generation,
    },
    PacketQueueObjectRecorded {
        packet_queue: PacketQueueObjectId,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        role: PacketQueueRole,
        queue_index: u16,
        depth: u32,
        generation: Generation,
    },
    PacketDescriptorObjectRecorded {
        packet_descriptor: PacketDescriptorObjectId,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        packet_buffer: PacketBufferObjectId,
        packet_buffer_generation: Generation,
        slot: u16,
        length: u32,
        generation: Generation,
    },
    FakeNetBackendObjectBound {
        fake_net_backend: FakeNetBackendObjectId,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        frame_format_version: u32,
        max_payload_len: u32,
        deterministic_seed: u64,
        generation: Generation,
    },
    VirtioNetBackendSkeletonBound {
        virtio_net_backend: VirtioNetBackendObjectId,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        queue_size: u16,
        rx_queue_index: u16,
        tx_queue_index: u16,
        negotiated_features: u64,
        generation: Generation,
    },
    NetworkRxInterruptRecorded {
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
        generation: Generation,
    },
    NetworkRxWaitResolved {
        resolution: NetworkRxWaitResolutionId,
        io_wait: IoWaitId,
        io_wait_generation: Generation,
        wait: WaitId,
        wait_generation: Generation,
        rx_interrupt: NetworkRxInterruptId,
        rx_interrupt_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        ready_descriptors: u16,
        generation: Generation,
    },
    NetworkTxCapabilityGateRecorded {
        tx_gate: NetworkTxCapabilityGateId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        tx_queue: PacketQueueObjectId,
        tx_queue_generation: Generation,
        packet_descriptor: PacketDescriptorObjectId,
        packet_descriptor_generation: Generation,
        packet_buffer: PacketBufferObjectId,
        packet_buffer_generation: Generation,
        device_capability: DeviceCapabilityId,
        device_capability_generation: Generation,
        capability: CapabilityId,
        capability_generation: Generation,
        handle_slot: u32,
        handle_generation: u32,
        handle_tag: u64,
        byte_len: u32,
        sequence: u64,
        generation: Generation,
    },
    NetworkTxCompleted {
        completion: NetworkTxCompletionId,
        tx_gate: NetworkTxCapabilityGateId,
        tx_gate_generation: Generation,
        backend: ContractObjectRef,
        driver_store: StoreId,
        driver_store_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        tx_queue: PacketQueueObjectId,
        tx_queue_generation: Generation,
        packet_descriptor: PacketDescriptorObjectId,
        packet_descriptor_generation: Generation,
        packet_buffer: PacketBufferObjectId,
        packet_buffer_generation: Generation,
        byte_len: u32,
        sequence: u64,
        completion_sequence: u64,
        generation: Generation,
    },
    NetworkStackAdapterBound {
        adapter: NetworkStackAdapterId,
        implementation: String,
        implementation_version: String,
        profile: String,
        medium: String,
        backend: ContractObjectRef,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        tx_queue: PacketQueueObjectId,
        tx_queue_generation: Generation,
        mac: [u8; 6],
        ipv4_addr: [u8; 4],
        ipv4_prefix_len: u8,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        max_payload_len: u32,
        socket_capacity: u16,
        generation: Generation,
    },
    SocketObjectCreated {
        socket: SocketObjectId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        owner_store: StoreId,
        owner_store_generation: Generation,
        domain: u32,
        socket_type: u32,
        protocol: u32,
        canonical_protocol: u16,
        family: String,
        transport: String,
        generation: Generation,
    },
    EndpointObjectCreated {
        endpoint: EndpointObjectId,
        socket: SocketObjectId,
        socket_generation: Generation,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        owner_store: StoreId,
        owner_store_generation: Generation,
        family: String,
        transport: String,
        local_addr: [u8; 4],
        local_port: u16,
        remote_addr: [u8; 4],
        remote_port: u16,
        generation: Generation,
    },
    SocketOperationRecorded {
        operation_id: SocketOperationId,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        socket: SocketObjectId,
        socket_generation: Generation,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        owner_store: StoreId,
        owner_store_generation: Generation,
        operation: SocketOperationKind,
        local_addr: [u8; 4],
        local_port: u16,
        remote_addr: [u8; 4],
        remote_port: u16,
        backlog: u16,
        byte_len: u32,
        sequence: u64,
        generation: Generation,
    },
    SocketWaitCreated {
        socket_wait: SocketWaitId,
        wait: WaitId,
        wait_generation: Generation,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        socket: SocketObjectId,
        socket_generation: Generation,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        owner_store: StoreId,
        owner_store_generation: Generation,
        wait_kind: SemanticWaitKind,
        blocker: ContractObjectRef,
        generation: Generation,
    },
    SocketWaitResolved {
        socket_wait: SocketWaitId,
        wait: WaitId,
        wait_generation: Generation,
        ready_sequence: u64,
        byte_len: u32,
        generation: Generation,
    },
    SocketWaitCancelled {
        socket_wait: SocketWaitId,
        wait: WaitId,
        wait_generation: Generation,
        reason: WaitCancelReason,
        generation: Generation,
    },
    NetworkBackpressureRecorded {
        backpressure: NetworkBackpressureId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        endpoint: Option<EndpointObjectId>,
        endpoint_generation: Option<Generation>,
        socket: Option<SocketObjectId>,
        socket_generation: Option<Generation>,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        direction: PacketBufferDirection,
        reason: NetworkBackpressureReason,
        action: NetworkBackpressureAction,
        queue_depth: u32,
        queue_limit: u32,
        dropped_packets: u32,
        dropped_bytes: u32,
        sequence: u64,
        generation: Generation,
    },
    NetworkDriverCleanupStarted {
        cleanup: NetworkDriverCleanupId,
        io_cleanup: IoCleanupId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        backend: ContractObjectRef,
        generation: Generation,
    },
    NetworkDriverCleanupCompleted {
        cleanup: NetworkDriverCleanupId,
        io_cleanup: IoCleanupId,
        io_cleanup_generation: Generation,
        cancelled_socket_waits: usize,
        revoked_packet_capabilities: usize,
        generation: Generation,
    },
    NetworkGenerationAuditRecorded {
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
        generation: Generation,
    },
    NetworkFaultInjectionRecorded {
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
        socket: Option<SocketObjectId>,
        socket_generation: Option<Generation>,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        direction: PacketBufferDirection,
        kind: NetworkFaultInjectionKind,
        effect: NetworkFaultInjectionEffect,
        injected_packets: u32,
        dropped_packets: u32,
        error_packets: u32,
        error_code: String,
        sequence: u64,
        generation: Generation,
    },
    NetworkBenchmarkRecorded {
        benchmark: NetworkBenchmarkId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        tx_completion: NetworkTxCompletionId,
        tx_completion_generation: Generation,
        rx_wait_resolution: NetworkRxWaitResolutionId,
        rx_wait_resolution_generation: Generation,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        socket: SocketObjectId,
        socket_generation: Generation,
        owner_store: StoreId,
        owner_store_generation: Generation,
        sample_packets: u32,
        sample_bytes: u64,
        tx_completed_packets: u32,
        rx_resolved_packets: u32,
        dropped_packets: u32,
        measured_nanos: u64,
        budget_nanos: u64,
        throughput_bytes_per_sec: u64,
        p50_latency_nanos: u64,
        p99_latency_nanos: u64,
        generation: Generation,
    },
    NetworkRecoveryBenchmarkRecorded {
        benchmark: NetworkRecoveryBenchmarkId,
        cleanup: NetworkDriverCleanupId,
        cleanup_generation: Generation,
        io_cleanup: IoCleanupId,
        io_cleanup_generation: Generation,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        driver_store: StoreId,
        driver_store_generation: Generation,
        fault_injection: Option<NetworkFaultInjectionId>,
        fault_injection_generation: Option<Generation>,
        recovery_start_event: EventId,
        recovery_complete_event: EventId,
        cancelled_socket_waits: u32,
        revoked_packet_capabilities: u32,
        recovery_nanos: u64,
        budget_nanos: u64,
        generation: Generation,
    },
    RuntimeActivationResumed {
        resume: ActivationResumeId,
        decision: SchedulerDecisionId,
        decision_generation: Generation,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        queue: RunnableQueueId,
        queue_generation: Generation,
        generation: Generation,
    },
    PreemptionLatencySampleRecorded {
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
        generation: Generation,
    },
    RuntimeActivationWaitBlocked {
        activation_wait: ActivationWaitId,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        wait: WaitId,
        wait_generation: Generation,
        generation: Generation,
    },
    RuntimeActivationWaitCancelled {
        activation_wait: ActivationWaitId,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        wait: WaitId,
        wait_generation: Generation,
        reason: WaitCancelReason,
        generation: Generation,
    },
    RuntimeActivationCleanupStarted {
        cleanup: ActivationCleanupId,
        store: StoreId,
        store_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        generation: Generation,
    },
    RuntimeActivationCleanupCompleted {
        cleanup: ActivationCleanupId,
        store: StoreId,
        target_store_generation: Generation,
        result_store_generation: Generation,
        activation: ActivationId,
        activation_generation_before: Generation,
        activation_generation_after: Generation,
        generation: Generation,
    },
    ResourceCreated {
        resource: ResourceId,
        kind: ResourceKind,
        generation: Generation,
    },
    ResourceClosed {
        resource: ResourceId,
        generation: Generation,
    },
    ResourceHandleValidated {
        resource: ResourceId,
        generation: Generation,
    },
    ResourceHandleRejected {
        resource: ResourceId,
        expected: Generation,
        actual: Option<Generation>,
        reason: GenerationCheckError,
    },
    AuthorityBound {
        authority: AuthorityId,
        resource: ResourceId,
        kind: AuthorityKind,
        subject: String,
        object: String,
        generation: Generation,
    },
    AuthorityReleased {
        authority: AuthorityId,
        resource: ResourceId,
        generation: Generation,
        reason: String,
    },
    AuthorityRevoked {
        authority: AuthorityId,
        resource: ResourceId,
        generation: Generation,
        reason: String,
    },
    BoundaryPublished {
        boundary: BoundaryId,
        name: String,
        kind: BoundaryKind,
        status: BoundaryStatus,
        backend: String,
        blocked_by: Option<String>,
        generation: Generation,
    },
    ArtifactVerificationRecorded {
        artifact: ArtifactId,
        package: String,
        artifact_name: String,
        state: ArtifactVerificationState,
        manifest_binding_hash: String,
        blocked_by: Option<String>,
        generation: Generation,
    },
    WaitCreated {
        wait: WaitId,
        task: TaskId,
        kind: SemanticWaitKind,
        generation: Generation,
    },
    WaitPending {
        wait: WaitId,
        generation: Generation,
    },
    WaitResolved {
        wait: WaitId,
        reason: String,
    },
    WaitConsumed {
        wait: WaitId,
    },
    WaitCancelled {
        wait: WaitId,
        errno: i32,
        reason: WaitCancelReason,
    },
    WaitInterrupted {
        wait: WaitId,
        reason: WaitCancelReason,
    },
    WaitRestarted {
        wait: WaitId,
        class: String,
    },
    WaitTokenValidated {
        wait: WaitId,
        generation: Generation,
    },
    WaitTokenRejected {
        wait: WaitId,
        expected: Generation,
        actual: Option<Generation>,
        reason: GenerationCheckError,
    },
    CapabilityGranted {
        cap: CapabilityId,
    },
    CapabilityRevoked {
        cap: CapabilityId,
    },
    CapabilityUsed {
        cap: CapabilityId,
        subject: String,
        object: String,
        operation: String,
        generation: Generation,
    },
    CapabilityDenied {
        subject: String,
        object: String,
        operation: String,
        reason: CapabilityDenyReason,
    },
    CapabilityGenerationMismatch {
        subject: String,
        object: String,
        operation: String,
        expected: Generation,
        actual: Option<Generation>,
    },
    HostcallEntered {
        label: String,
        class: HostcallClass,
        subject: String,
        object: String,
        operation: String,
    },
    SubstrateUnsupported {
        authority: String,
        operation: String,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
    },
    SubstrateCapabilityDenied {
        authority: String,
        operation: String,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
        capability: Option<CapabilityId>,
        capability_generation: Option<Generation>,
    },
    InterfaceUnsupported {
        interface_kind: String,
        interface: String,
        operation: String,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
    },
    FaultDomainRegistered {
        domain: FaultDomainId,
    },
    FaultDomainStateChanged {
        domain: FaultDomainId,
        from: FaultDomainState,
        to: FaultDomainState,
        generation: Generation,
    },
    FaultClassified {
        trap: TrapClass,
        class: FaultClass,
        store: Option<StoreId>,
        task: Option<TaskId>,
        detail: String,
    },
    DriverTrap {
        domain: Option<FaultDomainId>,
        trap: TrapClass,
        detail: String,
    },
    PacketReceived {
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    },
    PacketTransmitted {
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    },
    NetInterfaceStateChanged {
        interface: ResourceId,
        up: bool,
    },
    SocketStateChanged {
        socket: ResourceId,
        state: String,
    },
    DeviceIrqDelivered {
        irq: ResourceId,
        device: ResourceId,
        cause: String,
    },
    DriverCompletion {
        device: ResourceId,
        operation: String,
    },
    DmaSubmitted {
        buffer: ResourceId,
        device: ResourceId,
        len: usize,
    },
    DmaCompleted {
        buffer: ResourceId,
        device: ResourceId,
        len: usize,
    },
    FaultDomainRestarted {
        domain: FaultDomainId,
    },
    StoreRegistered {
        store: StoreId,
        domain: FaultDomainId,
        resource: ResourceId,
        generation: Generation,
    },
    StoreStateChanged {
        store: StoreId,
        from: StoreState,
        to: StoreState,
        generation: Generation,
    },
    StoreExecutorTransition {
        store: StoreId,
        from: String,
        to: String,
        blocked_by: Option<String>,
        hostcall_table: String,
        trap_surface: String,
    },
    StoreActivationRecorded {
        activation: StoreActivationId,
        store: StoreId,
        package: String,
        code_publish_state: CodePublishState,
        memory_layout_state: MemoryLayoutState,
        hostcall_table_state: HostcallLinkState,
        trap_surface_state: TrapSurfaceState,
        entrypoint_state: EntrypointState,
        blocked_by: Option<String>,
        generation: Generation,
    },
    StoreActivationHandleValidated {
        store: StoreId,
        generation: Generation,
    },
    StoreActivationHandleRejected {
        store: StoreId,
        expected: Generation,
        actual: Option<Generation>,
        reason: GenerationCheckError,
    },
    StoreTrap {
        store: StoreId,
        trap: TrapClass,
        detail: String,
    },
    StoreDropped {
        store: StoreId,
        generation: Generation,
        resource: Option<ResourceId>,
    },
    StoreRebound {
        store: StoreId,
        generation: Generation,
        resource: ResourceId,
    },
    WindowLeaseCreated {
        lease: ResourceId,
        generation: Generation,
    },
    WindowLeaseDestroyed {
        lease: ResourceId,
        generation: Generation,
    },
    SnapshotBarrierEnter {
        barrier: u64,
    },
    SnapshotBarrierExit {
        barrier: u64,
    },
    FastPathPlanInstalled {
        plan: u64,
    },
    FastPathPlanInvalidated {
        plan: u64,
    },
    TransactionBegan {
        transaction: TransactionId,
        store: Option<StoreId>,
        task: Option<TaskId>,
        label: String,
    },
    TransactionCommitted {
        transaction: TransactionId,
        generation: Generation,
    },
    TransactionRolledBack {
        transaction: TransactionId,
        reason: String,
        generation: Generation,
    },
    CleanupStepApplied {
        cleanup: TransactionId,
        step: String,
        target: String,
        observed_generation: Generation,
    },
    FailureEffect {
        effect: FailureEffect,
    },
}

impl EventKind {
    pub fn summary(&self) -> String {
        match self {
            Self::HartRegistered {
                hart,
                hardware_id,
                label,
                boot,
                generation,
            } => format!(
                "HartRegistered hart={hart} hardware_id={hardware_id} label={label} boot={boot} generation={generation}"
            ),
            Self::HartStateChanged {
                hart,
                from,
                to,
                reason,
                generation,
            } => format!(
                "HartStateChanged hart={hart} from={} to={} reason={reason} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::HartCurrentActivationBound {
                hart,
                from,
                activation,
                activation_generation,
                generation,
            } => format!(
                "HartCurrentActivationBound hart={hart} from={} activation={activation}@{activation_generation} generation={generation}",
                from.as_str()
            ),
            Self::HartCurrentActivationCleared {
                hart,
                activation,
                activation_generation,
                reason,
                generation,
            } => format!(
                "HartCurrentActivationCleared hart={hart} activation={activation}@{activation_generation} reason={reason} generation={generation}"
            ),
            Self::TaskCreated { task, frontend } => {
                format!("TaskCreated task={task} frontend={}", frontend.as_str())
            }
            Self::TaskStateChanged { task, from, to } => {
                format!(
                    "TaskStateChanged task={task} {}->{}",
                    from.as_str(),
                    to.as_str()
                )
            }
            Self::RuntimeActivationCreated {
                activation,
                task,
                generation,
            } => format!(
                "RuntimeActivationCreated activation={activation} task={task} generation={generation}"
            ),
            Self::RuntimeActivationStateChanged {
                activation,
                from,
                to,
                generation,
            } => format!(
                "RuntimeActivationStateChanged activation={activation} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::RunnableQueueCreated {
                queue,
                label,
                generation,
            } => {
                format!("RunnableQueueCreated queue={queue} label={label} generation={generation}")
            }
            Self::RunnableQueueOwnerBound {
                queue,
                hart,
                hart_generation,
                generation,
                note,
            } => format!(
                "RunnableQueueOwnerBound queue={queue} hart={hart}@{hart_generation} generation={generation} note={note}"
            ),
            Self::RunnableQueued {
                queue,
                activation,
                activation_generation,
            } => format!(
                "RunnableQueued queue={queue} activation={activation}@{activation_generation}"
            ),
            Self::RunnableDequeued {
                queue,
                activation,
                activation_generation,
            } => format!(
                "RunnableDequeued queue={queue} activation={activation}@{activation_generation}"
            ),
            Self::ActivationContextCreated {
                context,
                activation,
                activation_generation,
                generation,
            } => format!(
                "ActivationContextCreated context={context} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::SavedContextCaptured {
                saved_context,
                context,
                context_generation,
                activation,
                activation_generation,
                reason,
                generation,
            } => format!(
                "SavedContextCaptured saved_context={saved_context} context={context}@{context_generation} activation={activation}@{activation_generation} reason={} generation={generation}",
                reason.as_str()
            ),
            Self::TimerInterruptRecorded {
                interrupt,
                timer_epoch,
                hart,
                hart_generation,
                hardware_hart,
                target_activation,
                target_activation_generation,
                generation,
            } => format!(
                "TimerInterruptRecorded interrupt={interrupt} epoch={timer_epoch} hart={hart}@{hart_generation} hardware_id={hardware_hart} target={}@{} generation={generation}",
                target_activation
                    .map(|activation| activation.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                target_activation_generation
                    .map(|generation| generation.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
            Self::IpiEventRecorded {
                ipi,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                kind,
                generation,
            } => format!(
                "IpiEventRecorded ipi={ipi} kind={} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation} generation={generation}",
                kind.as_str()
            ),
            Self::RemoteActivationPreempted {
                remote_preempt,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation_before,
                target_hart_generation_after,
                activation,
                from_generation,
                to_generation,
                queue,
                queue_generation,
                generation,
            } => format!(
                "RemoteActivationPreempted remote_preempt={remote_preempt} ipi={ipi}@{ipi_generation} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation_before}->{target_hart_generation_after} activation={activation}@{from_generation}->{to_generation} queue={queue}@{queue_generation} generation={generation}"
            ),
            Self::RemoteHartParked {
                remote_park,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation_before,
                target_hart_generation_after,
                reason,
                generation,
            } => format!(
                "RemoteHartParked remote_park={remote_park} ipi={ipi}@{ipi_generation} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation_before}->{target_hart_generation_after} reason={reason} generation={generation}"
            ),
            Self::RuntimeActivationPreempted {
                preemption,
                activation,
                from_generation,
                to_generation,
                timer_interrupt,
                timer_interrupt_generation,
                queue,
                queue_generation,
                generation,
            } => format!(
                "RuntimeActivationPreempted preemption={preemption} activation={activation}@{from_generation}->{to_generation} timer={timer_interrupt}@{timer_interrupt_generation} queue={queue}@{queue_generation} generation={generation}",
            ),
            Self::SchedulerDecisionRecorded {
                decision,
                queue,
                queue_generation,
                activation,
                activation_generation,
                generation,
            } => format!(
                "SchedulerDecisionRecorded decision={decision} queue={queue}@{queue_generation} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::CrossHartSchedulerDecisionRecorded {
                cross_decision,
                scheduler_decision,
                scheduler_decision_generation,
                deciding_hart,
                deciding_hart_generation,
                target_hart,
                target_hart_generation,
                queue,
                queue_generation,
                activation,
                activation_generation,
                generation,
            } => format!(
                "CrossHartSchedulerDecisionRecorded cross_decision={cross_decision} decision={scheduler_decision}@{scheduler_decision_generation} deciding_hart={deciding_hart}@{deciding_hart_generation} target_hart={target_hart}@{target_hart_generation} queue={queue}@{queue_generation} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::ActivationMigrated {
                migration,
                activation,
                from_generation,
                to_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                source_queue,
                source_queue_generation,
                target_queue,
                target_queue_generation,
                generation,
            } => format!(
                "ActivationMigrated migration={migration} activation={activation}@{from_generation}->{to_generation} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation} source_queue={source_queue}@{source_queue_generation} target_queue={target_queue}@{target_queue_generation} generation={generation}"
            ),
            Self::SmpSafePointRecorded {
                safe_point,
                coordinator_hart,
                coordinator_hart_generation,
                participant_count,
                generation,
            } => format!(
                "SmpSafePointRecorded safe_point={safe_point} coordinator_hart={coordinator_hart}@{coordinator_hart_generation} participants={participant_count} generation={generation}"
            ),
            Self::StopTheWorldRendezvousCompleted {
                rendezvous,
                epoch,
                safe_point,
                safe_point_generation,
                coordinator_hart,
                coordinator_hart_generation,
                participant_count,
                generation,
            } => format!(
                "StopTheWorldRendezvousCompleted rendezvous={rendezvous} epoch={epoch} safe_point={safe_point}@{safe_point_generation} coordinator_hart={coordinator_hart}@{coordinator_hart_generation} participants={participant_count} generation={generation}"
            ),
            Self::SmpCodePublishBarrierValidated {
                barrier,
                rendezvous,
                rendezvous_generation,
                code_publish_epoch_before,
                code_publish_epoch_after,
                participant_count,
                generation,
            } => format!(
                "SmpCodePublishBarrierValidated barrier={barrier} rendezvous={rendezvous}@{rendezvous_generation} code_publish_epoch={code_publish_epoch_before}->{code_publish_epoch_after} participants={participant_count} generation={generation}"
            ),
            Self::SmpCleanupQuiescenceValidated {
                quiescence,
                cleanup,
                cleanup_generation,
                store,
                target_store_generation,
                result_store_generation,
                rendezvous,
                rendezvous_generation,
                participant_count,
                generation,
            } => format!(
                "SmpCleanupQuiescenceValidated quiescence={quiescence} cleanup={cleanup}@{cleanup_generation} store={store}@{target_store_generation}->{result_store_generation} rendezvous={rendezvous}@{rendezvous_generation} participants={participant_count} generation={generation}"
            ),
            Self::SmpSnapshotBarrierValidated {
                barrier,
                rendezvous,
                rendezvous_generation,
                event_log_cursor,
                participant_count,
                generation,
            } => format!(
                "SmpSnapshotBarrierValidated barrier={barrier} rendezvous={rendezvous}@{rendezvous_generation} cursor={event_log_cursor} participants={participant_count} generation={generation}"
            ),
            Self::SmpStressRunRecorded {
                run,
                scenario,
                iterations,
                hart_count,
                safe_point_count,
                rendezvous_count,
                property_failures,
                generation,
            } => format!(
                "SmpStressRunRecorded run={run} scenario={scenario} iterations={iterations} harts={hart_count} safe_points={safe_point_count} rendezvous={rendezvous_count} property_failures={property_failures} generation={generation}"
            ),
            Self::SmpScalingBenchmarkRecorded {
                benchmark,
                stress_run,
                stress_run_generation,
                hart_count,
                workload_units,
                measured_smp_nanos,
                budget_nanos,
                speedup_milli,
                efficiency_milli,
                generation,
            } => format!(
                "SmpScalingBenchmarkRecorded benchmark={benchmark} stress_run={stress_run}@{stress_run_generation} harts={hart_count} workload_units={workload_units} measured_nanos={measured_smp_nanos} budget_nanos={budget_nanos} speedup_milli={speedup_milli} efficiency_milli={efficiency_milli} generation={generation}"
            ),
            Self::DeviceObjectRecorded {
                device,
                resource,
                resource_generation,
                class,
                backend,
                generation,
            } => format!(
                "DeviceObjectRecorded device={device} resource={resource}@{resource_generation} class={class} backend={backend} generation={generation}"
            ),
            Self::QueueObjectRecorded {
                queue,
                device,
                device_generation,
                role,
                queue_index,
                depth,
                generation,
            } => format!(
                "QueueObjectRecorded queue={queue} device={device}@{device_generation} role={} index={queue_index} depth={depth} generation={generation}",
                role.as_str()
            ),
            Self::DescriptorObjectRecorded {
                descriptor,
                queue,
                queue_generation,
                slot,
                access,
                length,
                generation,
            } => format!(
                "DescriptorObjectRecorded descriptor={descriptor} queue={queue}@{queue_generation} slot={slot} access={} length={length} generation={generation}",
                access.as_str()
            ),
            Self::DmaBufferObjectRecorded {
                dma_buffer,
                descriptor,
                descriptor_generation,
                resource,
                resource_generation,
                access,
                length,
                generation,
            } => format!(
                "DmaBufferObjectRecorded dma_buffer={dma_buffer} descriptor={descriptor}@{descriptor_generation} resource={resource}@{resource_generation} access={} length={length} generation={generation}",
                access.as_str()
            ),
            Self::MmioRegionObjectRecorded {
                mmio_region,
                device,
                device_generation,
                resource,
                resource_generation,
                region_index,
                offset,
                length,
                access,
                generation,
            } => format!(
                "MmioRegionObjectRecorded mmio_region={mmio_region} device={device}@{device_generation} resource={resource}@{resource_generation} index={region_index} offset={offset} length={length} access={} generation={generation}",
                access.as_str()
            ),
            Self::IrqLineObjectRecorded {
                irq_line,
                device,
                device_generation,
                resource,
                resource_generation,
                irq_number,
                trigger,
                polarity,
                generation,
            } => format!(
                "IrqLineObjectRecorded irq_line={irq_line} device={device}@{device_generation} resource={resource}@{resource_generation} irq_number={irq_number} trigger={} polarity={} generation={generation}",
                trigger.as_str(),
                polarity.as_str()
            ),
            Self::IrqEventRecorded {
                irq_event,
                irq_line,
                irq_line_generation,
                device,
                device_generation,
                driver_store,
                driver_store_generation,
                irq_number,
                sequence,
                generation,
            } => format!(
                "IrqEventRecorded irq_event={irq_event} irq_line={irq_line}@{irq_line_generation} device={device}@{device_generation} driver_store={driver_store}@{driver_store_generation} irq_number={irq_number} sequence={sequence} generation={generation}"
            ),
            Self::DeviceCapabilityRecorded {
                device_capability,
                driver_store,
                driver_store_generation,
                target,
                class,
                operation,
                capability,
                capability_generation,
                handle_slot,
                handle_generation,
                generation,
            } => format!(
                "DeviceCapabilityRecorded device_capability={device_capability} driver_store={driver_store}@{driver_store_generation} target={} class={} operation={operation} capability={capability}@{capability_generation} handle_slot={handle_slot} handle_generation={handle_generation} generation={generation}",
                target.summary(),
                class.as_str()
            ),
            Self::DriverStoreBound {
                binding,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                device_capability,
                device_capability_generation,
                capability,
                capability_generation,
                generation,
            } => format!(
                "DriverStoreBound binding={binding} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} device_capability={device_capability}@{device_capability_generation} capability={capability}@{capability_generation} generation={generation}"
            ),
            Self::IoWaitCreated {
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
                generation,
            } => format!(
                "IoWaitCreated io_wait={io_wait} wait={wait}@{wait_generation} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} blocker={} generation={generation}",
                blocker.summary()
            ),
            Self::IoWaitResolved {
                io_wait,
                wait,
                wait_generation,
                irq_event,
                irq_event_generation,
                generation,
            } => format!(
                "IoWaitResolved io_wait={io_wait} wait={wait}@{wait_generation} irq_event={irq_event}@{irq_event_generation} generation={generation}"
            ),
            Self::IoWaitCancelled {
                io_wait,
                wait,
                wait_generation,
                reason,
                generation,
            } => format!(
                "IoWaitCancelled io_wait={io_wait} wait={wait}@{wait_generation} reason={} generation={generation}",
                reason.as_str()
            ),
            Self::IoCleanupStarted {
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                generation,
            } => format!(
                "IoCleanupStarted cleanup={cleanup} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} generation={generation}"
            ),
            Self::IoCleanupCompleted {
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                cancelled_io_waits,
                revoked_device_capabilities,
                released_dma_buffers,
                released_mmio_regions,
                released_irq_lines,
                generation,
            } => format!(
                "IoCleanupCompleted cleanup={cleanup} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} cancelled_io_waits={cancelled_io_waits} revoked_device_capabilities={revoked_device_capabilities} released_dma_buffers={released_dma_buffers} released_mmio_regions={released_mmio_regions} released_irq_lines={released_irq_lines} generation={generation}"
            ),
            Self::IoFaultInjected {
                fault,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                target,
                cleanup,
                cleanup_generation,
                kind,
                generation,
            } => format!(
                "IoFaultInjected fault={fault} kind={} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} target={} cleanup={cleanup}@{cleanup_generation} generation={generation}",
                kind.as_str(),
                target.summary()
            ),
            Self::IoValidationReportRecorded {
                report,
                ok,
                violation_count,
                device_count,
                dma_buffer_count,
                irq_event_count,
                cleanup_count,
                fault_injection_count,
                generation,
            } => format!(
                "IoValidationReportRecorded report={report} ok={ok} violations={violation_count} devices={device_count} dma_buffers={dma_buffer_count} irq_events={irq_event_count} cleanups={cleanup_count} fault_injections={fault_injection_count} generation={generation}"
            ),
            Self::PacketDeviceObjectRecorded {
                packet_device,
                device,
                device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                frame_format_version,
                max_payload_len,
                generation,
            } => format!(
                "PacketDeviceObjectRecorded packet_device={packet_device} device={device}@{device_generation} mtu={mtu} rx_queue_depth={rx_queue_depth} tx_queue_depth={tx_queue_depth} frame_format_version={frame_format_version} max_payload_len={max_payload_len} generation={generation}"
            ),
            Self::BlockDeviceObjectRecorded {
                block_device,
                device,
                device_generation,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                generation,
            } => format!(
                "BlockDeviceObjectRecorded block_device={block_device} device={device}@{device_generation} sector_size={sector_size} sector_count={sector_count} read_only={read_only} max_transfer_sectors={max_transfer_sectors} generation={generation}"
            ),
            Self::BlockRangeObjectRecorded {
                block_range,
                block_device,
                block_device_generation,
                start_sector,
                sector_count,
                byte_offset,
                byte_len,
                generation,
            } => format!(
                "BlockRangeObjectRecorded block_range={block_range} block_device={block_device}@{block_device_generation} start_sector={start_sector} sector_count={sector_count} byte_offset={byte_offset} byte_len={byte_len} generation={generation}"
            ),
            Self::BlockRequestObjectRecorded {
                block_request,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                operation,
                sequence,
                byte_len,
                generation,
            } => format!(
                "BlockRequestObjectRecorded block_request={block_request} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} operation={} sequence={sequence} byte_len={byte_len} generation={generation}",
                operation.as_str()
            ),
            Self::BlockCompletionObjectRecorded {
                block_completion,
                block_request,
                block_request_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                sequence,
                completed_bytes,
                status,
                generation,
            } => format!(
                "BlockCompletionObjectRecorded block_completion={block_completion} block_request={block_request}@{block_request_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} sequence={sequence} completed_bytes={completed_bytes} status={} generation={generation}",
                status.as_str()
            ),
            Self::BlockWaitCreated {
                block_wait,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                operation,
                sequence,
                byte_len,
                generation,
            } => format!(
                "BlockWaitCreated block_wait={block_wait} wait={wait}@{wait_generation} block_request={block_request}@{block_request_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} operation={} sequence={sequence} byte_len={byte_len} generation={generation}",
                operation.as_str()
            ),
            Self::BlockWaitResolved {
                block_wait,
                wait,
                wait_generation,
                block_completion,
                block_completion_generation,
                generation,
            } => format!(
                "BlockWaitResolved block_wait={block_wait} wait={wait}@{wait_generation} block_completion={block_completion}@{block_completion_generation} generation={generation}"
            ),
            Self::BlockWaitCancelled {
                block_wait,
                wait,
                wait_generation,
                reason,
                generation,
            } => format!(
                "BlockWaitCancelled block_wait={block_wait} wait={wait}@{wait_generation} reason={} generation={generation}",
                reason.as_str()
            ),
            Self::FakeBlockBackendObjectBound {
                fake_block_backend,
                block_device,
                block_device_generation,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                deterministic_seed,
                generation,
            } => format!(
                "FakeBlockBackendObjectBound fake_block_backend={fake_block_backend} block_device={block_device}@{block_device_generation} sector_size={sector_size} sector_count={sector_count} read_only={read_only} max_transfer_sectors={max_transfer_sectors} deterministic_seed={deterministic_seed} generation={generation}"
            ),
            Self::VirtioBlkBackendSkeletonBound {
                virtio_blk_backend,
                block_device,
                block_device_generation,
                driver_binding,
                driver_binding_generation,
                device,
                device_generation,
                queue_size,
                request_queue_index,
                negotiated_features,
                generation,
            } => format!(
                "VirtioBlkBackendSkeletonBound virtio_blk_backend={virtio_blk_backend} block_device={block_device}@{block_device_generation} driver_binding={driver_binding}@{driver_binding_generation} device={device}@{device_generation} queue_size={queue_size} request_queue_index={request_queue_index} negotiated_features={negotiated_features} generation={generation}"
            ),
            Self::BlockReadPathRecorded {
                read_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                sequence,
                completed_bytes,
                data_digest,
                generation,
            } => format!(
                "BlockReadPathRecorded read_path={read_path} backend={} block_request={block_request}@{block_request_generation} block_completion={block_completion}@{block_completion_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} sequence={sequence} completed_bytes={completed_bytes} data_digest={data_digest} generation={generation}",
                backend.summary()
            ),
            Self::BlockWritePathRecorded {
                write_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                sequence,
                completed_bytes,
                payload_digest,
                generation,
            } => format!(
                "BlockWritePathRecorded write_path={write_path} backend={} block_request={block_request}@{block_request_generation} block_completion={block_completion}@{block_completion_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} sequence={sequence} completed_bytes={completed_bytes} payload_digest={payload_digest} generation={generation}",
                backend.summary()
            ),
            Self::BlockRequestQueueRecorded {
                queue,
                backend,
                block_device,
                block_device_generation,
                depth,
                request_count,
                pending_count,
                completed_count,
                first_sequence,
                last_sequence,
                generation,
            } => format!(
                "BlockRequestQueueRecorded queue={queue} backend={} block_device={block_device}@{block_device_generation} depth={depth} request_count={request_count} pending_count={pending_count} completed_count={completed_count} first_sequence={first_sequence} last_sequence={last_sequence} generation={generation}",
                backend.summary()
            ),
            Self::BlockDmaBufferBound {
                block_dma_buffer,
                backend,
                block_request,
                block_request_generation,
                dma_buffer,
                dma_buffer_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                descriptor,
                descriptor_generation,
                queue,
                queue_generation,
                operation,
                access,
                byte_len,
                buffer_len,
                buffer_digest,
                generation,
            } => format!(
                "BlockDmaBufferBound block_dma_buffer={block_dma_buffer} backend={} block_request={block_request}@{block_request_generation} dma_buffer={dma_buffer}@{dma_buffer_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} descriptor={descriptor}@{descriptor_generation} queue={queue}@{queue_generation} operation={} access={} byte_len={byte_len} buffer_len={buffer_len} buffer_digest={buffer_digest} generation={generation}",
                backend.summary(),
                operation.as_str(),
                access.as_str()
            ),
            Self::BlockPageObjectIntegrated {
                block_page_object,
                block_dma_buffer,
                block_dma_buffer_generation,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                dma_buffer,
                dma_buffer_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                aspace,
                vma_region,
                page,
                page_dirty_generation,
                page_offset,
                byte_len,
                operation,
                generation,
            } => format!(
                "BlockPageObjectIntegrated block_page_object={block_page_object} block_dma_buffer={block_dma_buffer}@{block_dma_buffer_generation} block_request={block_request}@{block_request_generation} block_completion={block_completion}@{block_completion_generation} dma_buffer={dma_buffer}@{dma_buffer_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} aspace={} vma_region={} page={} page_dirty_generation={page_dirty_generation} page_offset={page_offset} byte_len={byte_len} operation={} generation={generation}",
                aspace.summary(),
                vma_region.summary(),
                page.summary(),
                operation.as_str()
            ),
            Self::BufferCacheObjectRecorded {
                buffer_cache_object,
                block_page_object,
                block_page_object_generation,
                block_dma_buffer,
                block_dma_buffer_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                aspace,
                vma_region,
                page,
                page_dirty_generation,
                page_offset,
                block_offset,
                byte_len,
                operation,
                cache_state,
                coherency_epoch,
                generation,
            } => format!(
                "BufferCacheObjectRecorded buffer_cache_object={buffer_cache_object} block_page_object={block_page_object}@{block_page_object_generation} block_dma_buffer={block_dma_buffer}@{block_dma_buffer_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} aspace={} vma_region={} page={} page_dirty_generation={page_dirty_generation} page_offset={page_offset} block_offset={block_offset} byte_len={byte_len} operation={} cache_state={} coherency_epoch={coherency_epoch} generation={generation}",
                aspace.summary(),
                vma_region.summary(),
                page.summary(),
                operation.as_str(),
                cache_state.as_str()
            ),
            Self::FileObjectRecorded {
                file_object,
                buffer_cache_object,
                buffer_cache_object_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                page,
                page_dirty_generation,
                namespace,
                file_key,
                path,
                file_offset,
                byte_len,
                file_size,
                content_digest,
                cache_state,
                state,
                generation,
            } => format!(
                "FileObjectRecorded file_object={file_object} buffer_cache_object={buffer_cache_object}@{buffer_cache_object_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} page={} page_dirty_generation={page_dirty_generation} namespace={namespace} file_key={file_key} path={path} file_offset={file_offset} byte_len={byte_len} file_size={file_size} content_digest={content_digest} cache_state={} state={} generation={generation}",
                page.summary(),
                cache_state.as_str(),
                state.as_str()
            ),
            Self::PacketBufferObjectRecorded {
                packet_buffer,
                packet_device,
                packet_device_generation,
                direction,
                frame_format_version,
                capacity,
                payload_len,
                sequence,
                state,
                generation,
            } => format!(
                "PacketBufferObjectRecorded packet_buffer={packet_buffer} packet_device={packet_device}@{packet_device_generation} direction={} frame_format_version={frame_format_version} capacity={capacity} payload_len={payload_len} sequence={sequence} state={} generation={generation}",
                direction.as_str(),
                state.as_str()
            ),
            Self::PacketQueueObjectRecorded {
                packet_queue,
                packet_device,
                packet_device_generation,
                role,
                queue_index,
                depth,
                generation,
            } => format!(
                "PacketQueueObjectRecorded packet_queue={packet_queue} packet_device={packet_device}@{packet_device_generation} role={} queue_index={queue_index} depth={depth} generation={generation}",
                role.as_str()
            ),
            Self::PacketDescriptorObjectRecorded {
                packet_descriptor,
                packet_queue,
                packet_queue_generation,
                packet_buffer,
                packet_buffer_generation,
                slot,
                length,
                generation,
            } => format!(
                "PacketDescriptorObjectRecorded packet_descriptor={packet_descriptor} packet_queue={packet_queue}@{packet_queue_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} slot={slot} length={length} generation={generation}"
            ),
            Self::FakeNetBackendObjectBound {
                fake_net_backend,
                packet_device,
                packet_device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                frame_format_version,
                max_payload_len,
                deterministic_seed,
                generation,
            } => format!(
                "FakeNetBackendObjectBound fake_net_backend={fake_net_backend} packet_device={packet_device}@{packet_device_generation} mtu={mtu} rx_queue_depth={rx_queue_depth} tx_queue_depth={tx_queue_depth} frame_format_version={frame_format_version} max_payload_len={max_payload_len} deterministic_seed={deterministic_seed} generation={generation}"
            ),
            Self::VirtioNetBackendSkeletonBound {
                virtio_net_backend,
                packet_device,
                packet_device_generation,
                driver_binding,
                driver_binding_generation,
                device,
                device_generation,
                queue_size,
                rx_queue_index,
                tx_queue_index,
                negotiated_features,
                generation,
            } => format!(
                "VirtioNetBackendSkeletonBound virtio_net_backend={virtio_net_backend} packet_device={packet_device}@{packet_device_generation} driver_binding={driver_binding}@{driver_binding_generation} device={device}@{device_generation} queue_size={queue_size} rx_queue_index={rx_queue_index} tx_queue_index={tx_queue_index} negotiated_features={negotiated_features} generation={generation}"
            ),
            Self::NetworkRxInterruptRecorded {
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
                generation,
            } => format!(
                "NetworkRxInterruptRecorded rx_interrupt={rx_interrupt} virtio_net_backend={virtio_net_backend}@{virtio_net_backend_generation} irq_event={irq_event}@{irq_event_generation} packet_device={packet_device}@{packet_device_generation} rx_queue={rx_queue}@{rx_queue_generation} ready_descriptors={ready_descriptors} sequence={sequence} generation={generation}"
            ),
            Self::NetworkRxWaitResolved {
                resolution,
                io_wait,
                io_wait_generation,
                wait,
                wait_generation,
                rx_interrupt,
                rx_interrupt_generation,
                rx_queue,
                rx_queue_generation,
                ready_descriptors,
                generation,
            } => format!(
                "NetworkRxWaitResolved resolution={resolution} io_wait={io_wait}@{io_wait_generation} wait={wait}@{wait_generation} rx_interrupt={rx_interrupt}@{rx_interrupt_generation} rx_queue={rx_queue}@{rx_queue_generation} ready_descriptors={ready_descriptors} generation={generation}"
            ),
            Self::NetworkTxCapabilityGateRecorded {
                tx_gate,
                driver_store,
                driver_store_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                device_capability,
                device_capability_generation,
                capability,
                capability_generation,
                handle_slot,
                handle_generation,
                handle_tag,
                byte_len,
                sequence,
                generation,
            } => format!(
                "NetworkTxCapabilityGateRecorded tx_gate={tx_gate} driver_store={driver_store}@{driver_store_generation} packet_device={packet_device}@{packet_device_generation} tx_queue={tx_queue}@{tx_queue_generation} packet_descriptor={packet_descriptor}@{packet_descriptor_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} device_capability={device_capability}@{device_capability_generation} capability={capability}@{capability_generation} handle_slot={handle_slot} handle_generation={handle_generation} handle_tag={handle_tag} byte_len={byte_len} sequence={sequence} generation={generation}"
            ),
            Self::NetworkTxCompleted {
                completion,
                tx_gate,
                tx_gate_generation,
                backend,
                driver_store,
                driver_store_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                byte_len,
                sequence,
                completion_sequence,
                generation,
            } => format!(
                "NetworkTxCompleted completion={completion} tx_gate={tx_gate}@{tx_gate_generation} backend={} driver_store={driver_store}@{driver_store_generation} packet_device={packet_device}@{packet_device_generation} tx_queue={tx_queue}@{tx_queue_generation} packet_descriptor={packet_descriptor}@{packet_descriptor_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} byte_len={byte_len} sequence={sequence} completion_sequence={completion_sequence} generation={generation}",
                backend.summary()
            ),
            Self::NetworkStackAdapterBound {
                adapter,
                implementation,
                implementation_version,
                profile,
                medium,
                backend,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                tx_queue,
                tx_queue_generation,
                mac,
                ipv4_addr,
                ipv4_prefix_len,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                max_payload_len,
                socket_capacity,
                generation,
            } => format!(
                "NetworkStackAdapterBound adapter={adapter} implementation={implementation} version={implementation_version} profile={profile} medium={medium} backend={} packet_device={packet_device}@{packet_device_generation} rx_queue={rx_queue}@{rx_queue_generation} tx_queue={tx_queue}@{tx_queue_generation} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ipv4={}.{}.{}.{}/{} mtu={mtu} rx_queue_depth={rx_queue_depth} tx_queue_depth={tx_queue_depth} max_payload_len={max_payload_len} socket_capacity={socket_capacity} generation={generation}",
                backend.summary(),
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5],
                ipv4_addr[0],
                ipv4_addr[1],
                ipv4_addr[2],
                ipv4_addr[3],
                ipv4_prefix_len
            ),
            Self::SocketObjectCreated {
                socket,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                domain,
                socket_type,
                protocol,
                canonical_protocol,
                family,
                transport,
                generation,
            } => format!(
                "SocketObjectCreated socket={socket} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} domain={domain} type={socket_type} protocol={protocol} canonical_protocol={canonical_protocol} family={family} transport={transport} generation={generation}"
            ),
            Self::EndpointObjectCreated {
                endpoint,
                socket,
                socket_generation,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                family,
                transport,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                generation,
            } => format!(
                "EndpointObjectCreated endpoint={endpoint} socket={socket}@{socket_generation} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} family={family} transport={transport} local={}.{}.{}.{}:{local_port} remote={}.{}.{}.{}:{remote_port} generation={generation}",
                local_addr[0],
                local_addr[1],
                local_addr[2],
                local_addr[3],
                remote_addr[0],
                remote_addr[1],
                remote_addr[2],
                remote_addr[3]
            ),
            Self::SocketOperationRecorded {
                operation_id,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                operation,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                backlog,
                byte_len,
                sequence,
                generation,
            } => format!(
                "SocketOperationRecorded operation_id={operation_id} operation={} endpoint={endpoint}@{endpoint_generation} socket={socket}@{socket_generation} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} local={}.{}.{}.{}:{local_port} remote={}.{}.{}.{}:{remote_port} backlog={backlog} byte_len={byte_len} sequence={sequence} generation={generation}",
                operation.as_str(),
                local_addr[0],
                local_addr[1],
                local_addr[2],
                local_addr[3],
                remote_addr[0],
                remote_addr[1],
                remote_addr[2],
                remote_addr[3]
            ),
            Self::SocketWaitCreated {
                socket_wait,
                wait,
                wait_generation,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                wait_kind,
                blocker,
                generation,
            } => format!(
                "SocketWaitCreated socket_wait={socket_wait} wait={wait}@{wait_generation} endpoint={endpoint}@{endpoint_generation} socket={socket}@{socket_generation} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} kind={} blocker={}:{}@{} generation={generation}",
                wait_kind.as_str(),
                blocker.kind.as_str(),
                blocker.id,
                blocker.generation
            ),
            Self::SocketWaitResolved {
                socket_wait,
                wait,
                wait_generation,
                ready_sequence,
                byte_len,
                generation,
            } => format!(
                "SocketWaitResolved socket_wait={socket_wait} wait={wait}@{wait_generation} ready_sequence={ready_sequence} byte_len={byte_len} generation={generation}"
            ),
            Self::SocketWaitCancelled {
                socket_wait,
                wait,
                wait_generation,
                reason,
                generation,
            } => format!(
                "SocketWaitCancelled socket_wait={socket_wait} wait={wait}@{wait_generation} reason={} generation={generation}",
                reason.as_str()
            ),
            Self::NetworkBackpressureRecorded {
                backpressure,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                owner_store,
                owner_store_generation,
                direction,
                reason,
                action,
                queue_depth,
                queue_limit,
                dropped_packets,
                dropped_bytes,
                sequence,
                generation,
            } => {
                let endpoint_summary = endpoint.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", endpoint_generation.unwrap_or(0)),
                );
                let socket_summary = socket.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", socket_generation.unwrap_or(0)),
                );
                let owner_store_summary = owner_store.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", owner_store_generation.unwrap_or(0)),
                );
                format!(
                    "NetworkBackpressureRecorded backpressure={backpressure} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} packet_queue={packet_queue}@{packet_queue_generation} endpoint={endpoint_summary} socket={socket_summary} owner_store={owner_store_summary} direction={} reason={} action={} queue_depth={queue_depth} queue_limit={queue_limit} dropped_packets={dropped_packets} dropped_bytes={dropped_bytes} sequence={sequence} generation={generation}",
                    direction.as_str(),
                    reason.as_str(),
                    action.as_str()
                )
            }
            Self::NetworkDriverCleanupStarted {
                cleanup,
                io_cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                packet_device,
                packet_device_generation,
                adapter,
                adapter_generation,
                backend,
                generation,
            } => format!(
                "NetworkDriverCleanupStarted cleanup={cleanup} io_cleanup={io_cleanup} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} packet_device={packet_device}@{packet_device_generation} adapter={adapter}@{adapter_generation} backend={}:{}@{} generation={generation}",
                backend.kind.as_str(),
                backend.id,
                backend.generation
            ),
            Self::NetworkDriverCleanupCompleted {
                cleanup,
                io_cleanup,
                io_cleanup_generation,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                generation,
            } => format!(
                "NetworkDriverCleanupCompleted cleanup={cleanup} io_cleanup={io_cleanup}@{io_cleanup_generation} cancelled_socket_waits={cancelled_socket_waits} revoked_packet_capabilities={revoked_packet_capabilities} generation={generation}"
            ),
            Self::NetworkGenerationAuditRecorded {
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
                generation,
            } => format!(
                "NetworkGenerationAuditRecorded audit={audit} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} packet_queue={packet_queue}@{packet_queue_generation} packet_descriptor={packet_descriptor}@{packet_descriptor_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} dma_buffer={}:{}@{} device_capability={}:{}@{} rejected_packet_generation_probes={rejected_packet_generation_probes} rejected_dma_generation_probes={rejected_dma_generation_probes} generation={generation}",
                dma_buffer.kind.as_str(),
                dma_buffer.id,
                dma_buffer.generation,
                device_capability.kind.as_str(),
                device_capability.id,
                device_capability.generation
            ),
            Self::NetworkFaultInjectionRecorded {
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
                socket,
                socket_generation,
                owner_store,
                owner_store_generation,
                direction,
                kind,
                effect,
                injected_packets,
                dropped_packets,
                error_packets,
                error_code,
                sequence,
                generation,
            } => {
                let descriptor_summary = packet_descriptor.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", packet_descriptor_generation.unwrap_or(0)),
                );
                let buffer_summary = packet_buffer.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", packet_buffer_generation.unwrap_or(0)),
                );
                let endpoint_summary = endpoint.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", endpoint_generation.unwrap_or(0)),
                );
                let socket_summary = socket.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", socket_generation.unwrap_or(0)),
                );
                let owner_store_summary = owner_store.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", owner_store_generation.unwrap_or(0)),
                );
                format!(
                    "NetworkFaultInjectionRecorded injection={injection} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} packet_queue={packet_queue}@{packet_queue_generation} packet_descriptor={descriptor_summary} packet_buffer={buffer_summary} endpoint={endpoint_summary} socket={socket_summary} owner_store={owner_store_summary} direction={} kind={} effect={} injected_packets={injected_packets} dropped_packets={dropped_packets} error_packets={error_packets} error_code={error_code} sequence={sequence} generation={generation}",
                    direction.as_str(),
                    kind.as_str(),
                    effect.as_str()
                )
            }
            Self::NetworkBenchmarkRecorded {
                benchmark,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                tx_completion,
                tx_completion_generation,
                rx_wait_resolution,
                rx_wait_resolution_generation,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                owner_store,
                owner_store_generation,
                sample_packets,
                sample_bytes,
                tx_completed_packets,
                rx_resolved_packets,
                dropped_packets,
                measured_nanos,
                budget_nanos,
                throughput_bytes_per_sec,
                p50_latency_nanos,
                p99_latency_nanos,
                generation,
            } => format!(
                "NetworkBenchmarkRecorded benchmark={benchmark} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} tx_completion={tx_completion}@{tx_completion_generation} rx_wait_resolution={rx_wait_resolution}@{rx_wait_resolution_generation} endpoint={endpoint}@{endpoint_generation} socket={socket}@{socket_generation} owner_store={owner_store}@{owner_store_generation} sample_packets={sample_packets} sample_bytes={sample_bytes} tx_completed_packets={tx_completed_packets} rx_resolved_packets={rx_resolved_packets} dropped_packets={dropped_packets} measured_nanos={measured_nanos} budget_nanos={budget_nanos} throughput_bytes_per_sec={throughput_bytes_per_sec} p50_latency_nanos={p50_latency_nanos} p99_latency_nanos={p99_latency_nanos} generation={generation}",
            ),
            Self::NetworkRecoveryBenchmarkRecorded {
                benchmark,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                driver_store,
                driver_store_generation,
                fault_injection,
                fault_injection_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                recovery_nanos,
                budget_nanos,
                generation,
            } => {
                let fault_injection_summary = match (*fault_injection, *fault_injection_generation)
                {
                    (Some(injection), Some(injection_generation)) => {
                        format!("{injection}@{injection_generation}")
                    }
                    _ => "none".to_string(),
                };
                format!(
                    "NetworkRecoveryBenchmarkRecorded benchmark={benchmark} cleanup={cleanup}@{cleanup_generation} io_cleanup={io_cleanup}@{io_cleanup_generation} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} driver_store={driver_store}@{driver_store_generation} fault_injection={fault_injection_summary} recovery_start_event={recovery_start_event} recovery_complete_event={recovery_complete_event} cancelled_socket_waits={cancelled_socket_waits} revoked_packet_capabilities={revoked_packet_capabilities} recovery_nanos={recovery_nanos} budget_nanos={budget_nanos} generation={generation}"
                )
            }
            Self::RuntimeActivationResumed {
                resume,
                decision,
                decision_generation,
                activation,
                from_generation,
                to_generation,
                queue,
                queue_generation,
                generation,
            } => format!(
                "RuntimeActivationResumed resume={resume} decision={decision}@{decision_generation} activation={activation}@{from_generation}->{to_generation} queue={queue}@{queue_generation} generation={generation}"
            ),
            Self::PreemptionLatencySampleRecorded {
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
                generation,
            } => format!(
                "PreemptionLatencySampleRecorded sample={sample} timer={timer_interrupt}@{timer_interrupt_generation} preemption={preemption}@{preemption_generation} decision={scheduler_decision}@{scheduler_decision_generation} resume={activation_resume}@{activation_resume_generation} measured_nanos={measured_nanos} budget_nanos={budget_nanos} generation={generation}"
            ),
            Self::RuntimeActivationWaitBlocked {
                activation_wait,
                activation,
                from_generation,
                to_generation,
                wait,
                wait_generation,
                generation,
            } => format!(
                "RuntimeActivationWaitBlocked activation_wait={activation_wait} activation={activation}@{from_generation}->{to_generation} wait={wait}@{wait_generation} generation={generation}"
            ),
            Self::RuntimeActivationWaitCancelled {
                activation_wait,
                activation,
                from_generation,
                to_generation,
                wait,
                wait_generation,
                reason,
                generation,
            } => format!(
                "RuntimeActivationWaitCancelled activation_wait={activation_wait} activation={activation}@{from_generation}->{to_generation} wait={wait}@{wait_generation} reason={} generation={generation}",
                reason.as_str()
            ),
            Self::RuntimeActivationCleanupStarted {
                cleanup,
                store,
                store_generation,
                activation,
                activation_generation,
                generation,
            } => format!(
                "RuntimeActivationCleanupStarted cleanup={cleanup} store={store}@{store_generation} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::RuntimeActivationCleanupCompleted {
                cleanup,
                store,
                target_store_generation,
                result_store_generation,
                activation,
                activation_generation_before,
                activation_generation_after,
                generation,
            } => format!(
                "RuntimeActivationCleanupCompleted cleanup={cleanup} store={store}@{target_store_generation}->{result_store_generation} activation={activation}@{activation_generation_before}->{activation_generation_after} generation={generation}"
            ),
            Self::ResourceCreated {
                resource,
                kind,
                generation,
            } => format!(
                "ResourceCreated resource={resource} kind={} generation={generation}",
                kind.as_str()
            ),
            Self::ResourceClosed {
                resource,
                generation,
            } => format!("ResourceClosed resource={resource} generation={generation}"),
            Self::ResourceHandleValidated {
                resource,
                generation,
            } => format!("ResourceHandleValidated resource={resource} generation={generation}"),
            Self::ResourceHandleRejected {
                resource,
                expected,
                actual,
                reason,
            } => match actual {
                Some(actual) => format!(
                    "ResourceHandleRejected resource={resource} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "ResourceHandleRejected resource={resource} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::AuthorityBound {
                authority,
                resource,
                kind,
                subject,
                object,
                generation,
            } => format!(
                "AuthorityBound authority={authority} resource={resource} kind={} subject={subject} object={object} generation={generation}",
                kind.as_str()
            ),
            Self::AuthorityReleased {
                authority,
                resource,
                generation,
                reason,
            } => format!(
                "AuthorityReleased authority={authority} resource={resource} generation={generation} reason={reason}"
            ),
            Self::AuthorityRevoked {
                authority,
                resource,
                generation,
                reason,
            } => format!(
                "AuthorityRevoked authority={authority} resource={resource} generation={generation} reason={reason}"
            ),
            Self::BoundaryPublished {
                boundary,
                name,
                kind,
                status,
                backend,
                blocked_by,
                generation,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "BoundaryPublished boundary={boundary} name={name} kind={} status={} backend={backend} blocked={blocked_by} generation={generation}",
                    kind.as_str(),
                    status.as_str()
                )
            }
            Self::ArtifactVerificationRecorded {
                artifact,
                package,
                artifact_name,
                state,
                manifest_binding_hash,
                blocked_by,
                generation,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "ArtifactVerificationRecorded artifact={artifact} package={package} name={artifact_name} state={} binding={manifest_binding_hash} blocked={blocked_by} generation={generation}",
                    state.as_str()
                )
            }
            Self::WaitCreated {
                wait,
                task,
                kind,
                generation,
            } => format!(
                "WaitCreated wait={wait} task={task} kind={} generation={generation}",
                kind.as_str()
            ),
            Self::WaitPending { wait, generation } => {
                format!("WaitPending wait={wait} generation={generation}")
            }
            Self::WaitResolved { wait, reason } => {
                format!("WaitResolved wait={wait} reason={reason}")
            }
            Self::WaitConsumed { wait } => {
                format!("WaitConsumed wait={wait}")
            }
            Self::WaitCancelled {
                wait,
                errno,
                reason,
            } => {
                format!(
                    "WaitCancelled wait={wait} errno={errno} reason={}",
                    reason.as_str()
                )
            }
            Self::WaitInterrupted { wait, reason } => {
                format!("WaitInterrupted wait={wait} reason={}", reason.as_str())
            }
            Self::WaitRestarted { wait, class } => {
                format!("WaitRestarted wait={wait} class={class}")
            }
            Self::WaitTokenValidated { wait, generation } => {
                format!("WaitTokenValidated wait={wait} generation={generation}")
            }
            Self::WaitTokenRejected {
                wait,
                expected,
                actual,
                reason,
            } => match actual {
                Some(actual) => format!(
                    "WaitTokenRejected wait={wait} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "WaitTokenRejected wait={wait} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::CapabilityGranted { cap } => format!("CapabilityGranted cap={cap}"),
            Self::CapabilityRevoked { cap } => format!("CapabilityRevoked cap={cap}"),
            Self::CapabilityUsed {
                cap,
                subject,
                object,
                operation,
                generation,
            } => format!(
                "CapabilityUsed cap={cap} subject={subject} object={object} op={operation} generation={generation}"
            ),
            Self::CapabilityDenied {
                subject,
                object,
                operation,
                reason,
            } => format!(
                "CapabilityDenied subject={subject} object={object} op={operation} reason={}",
                reason.as_str()
            ),
            Self::CapabilityGenerationMismatch {
                subject,
                object,
                operation,
                expected,
                actual,
            } => match actual {
                Some(actual) => format!(
                    "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual={actual}"
                ),
                None => format!(
                    "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual=missing"
                ),
            },
            Self::HostcallEntered {
                label,
                class,
                subject,
                object,
                operation,
            } => format!(
                "HostcallEntered label={label} class={} subject={subject} object={object} op={operation}",
                class.as_str()
            ),
            Self::SubstrateUnsupported {
                authority,
                operation,
                requester,
                artifact,
                store,
            } => {
                let requester = requester.as_deref().unwrap_or("none");
                let artifact = artifact
                    .map(|artifact| artifact.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "SubstrateUnsupported authority={authority} op={operation} requester={requester} artifact={artifact} store={store}"
                )
            }
            Self::SubstrateCapabilityDenied {
                authority,
                operation,
                requester,
                artifact,
                store,
                capability,
                capability_generation,
            } => {
                let requester = requester.as_deref().unwrap_or("none");
                let artifact = artifact
                    .map(|artifact| artifact.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let capability = capability
                    .map(|capability| capability.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let generation = capability_generation
                    .map(|generation| generation.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "SubstrateCapabilityDenied authority={authority} op={operation} requester={requester} artifact={artifact} store={store} capability={capability} generation={generation}"
                )
            }
            Self::InterfaceUnsupported {
                interface_kind,
                interface,
                operation,
                requester,
                artifact,
                store,
            } => {
                let requester = requester.as_deref().unwrap_or("none");
                let artifact = artifact
                    .map(|artifact| artifact.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "InterfaceUnsupported kind={interface_kind} interface={interface} op={operation} requester={requester} artifact={artifact} store={store}"
                )
            }
            Self::FaultDomainRegistered { domain } => {
                format!("FaultDomainRegistered domain={domain}")
            }
            Self::FaultDomainStateChanged {
                domain,
                from,
                to,
                generation,
            } => format!(
                "FaultDomainStateChanged domain={domain} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::FaultClassified {
                trap,
                class,
                store,
                task,
                detail,
            } => {
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let task = task
                    .map(|task| task.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "FaultClassified trap={} class={} store={store} task={task} detail={detail}",
                    trap.as_str(),
                    class.as_str()
                )
            }
            Self::DriverTrap {
                domain,
                trap,
                detail,
            } => match domain {
                Some(domain) => format!(
                    "DriverTrap domain={domain} trap={} detail={detail}",
                    trap.as_str()
                ),
                None => format!("DriverTrap trap={} detail={detail}", trap.as_str()),
            },
            Self::PacketReceived {
                interface,
                socket,
                ready_key,
                len,
            } => {
                let socket = socket
                    .map(|socket| socket.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "PacketReceived interface={interface} socket={socket} ready_key=0x{ready_key:x} len={len}"
                )
            }
            Self::PacketTransmitted {
                interface,
                socket,
                ready_key,
                len,
            } => {
                let socket = socket
                    .map(|socket| socket.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "PacketTransmitted interface={interface} socket={socket} ready_key=0x{ready_key:x} len={len}"
                )
            }
            Self::NetInterfaceStateChanged { interface, up } => {
                let state = if *up { "up" } else { "down" };
                format!("NetInterfaceStateChanged interface={interface} state={state}")
            }
            Self::SocketStateChanged { socket, state } => {
                format!("SocketStateChanged socket={socket} state={state}")
            }
            Self::DeviceIrqDelivered { irq, device, cause } => {
                format!("DeviceIrqDelivered irq={irq} device={device} cause={cause}")
            }
            Self::DriverCompletion { device, operation } => {
                format!("DriverCompletion device={device} operation={operation}")
            }
            Self::DmaSubmitted {
                buffer,
                device,
                len,
            } => format!("DmaSubmitted buffer={buffer} device={device} len={len}"),
            Self::DmaCompleted {
                buffer,
                device,
                len,
            } => format!("DmaCompleted buffer={buffer} device={device} len={len}"),
            Self::FaultDomainRestarted { domain } => {
                format!("FaultDomainRestarted domain={domain}")
            }
            Self::StoreRegistered {
                store,
                domain,
                resource,
                generation,
            } => format!(
                "StoreRegistered store={store} domain={domain} resource={resource} generation={generation}"
            ),
            Self::StoreStateChanged {
                store,
                from,
                to,
                generation,
            } => format!(
                "StoreStateChanged store={store} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::StoreExecutorTransition {
                store,
                from,
                to,
                blocked_by,
                hostcall_table,
                trap_surface,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "StoreExecutorTransition store={store} {from}->{to} blocked={blocked_by} hostcalls={hostcall_table} traps={trap_surface}"
                )
            }
            Self::StoreActivationRecorded {
                activation,
                store,
                package,
                code_publish_state,
                memory_layout_state,
                hostcall_table_state,
                trap_surface_state,
                entrypoint_state,
                blocked_by,
                generation,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "StoreActivationRecorded activation={activation} store={store} package={package} code={} memory={} hostcalls={} traps={} entry={} blocked={blocked_by} generation={generation}",
                    code_publish_state.as_str(),
                    memory_layout_state.as_str(),
                    hostcall_table_state.as_str(),
                    trap_surface_state.as_str(),
                    entrypoint_state.as_str()
                )
            }
            Self::StoreActivationHandleValidated { store, generation } => {
                format!("StoreActivationHandleValidated store={store} generation={generation}")
            }
            Self::StoreActivationHandleRejected {
                store,
                expected,
                actual,
                reason,
            } => match actual {
                Some(actual) => format!(
                    "StoreActivationHandleRejected store={store} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "StoreActivationHandleRejected store={store} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::StoreTrap {
                store,
                trap,
                detail,
            } => {
                format!(
                    "StoreTrap store={store} trap={} detail={detail}",
                    trap.as_str()
                )
            }
            Self::StoreDropped {
                store,
                generation,
                resource,
            } => match resource {
                Some(resource) => format!(
                    "StoreDropped store={store} generation={generation} resource={resource}"
                ),
                None => format!("StoreDropped store={store} generation={generation}"),
            },
            Self::StoreRebound {
                store,
                generation,
                resource,
            } => format!("StoreRebound store={store} generation={generation} resource={resource}"),
            Self::WindowLeaseCreated { lease, generation } => {
                format!("WindowLeaseCreated lease={lease} generation={generation}")
            }
            Self::WindowLeaseDestroyed { lease, generation } => {
                format!("WindowLeaseDestroyed lease={lease} generation={generation}")
            }
            Self::SnapshotBarrierEnter { barrier } => {
                format!("SnapshotBarrierEnter barrier={barrier}")
            }
            Self::SnapshotBarrierExit { barrier } => {
                format!("SnapshotBarrierExit barrier={barrier}")
            }
            Self::FastPathPlanInstalled { plan } => {
                format!("FastPathPlanInstalled plan={plan}")
            }
            Self::FastPathPlanInvalidated { plan } => {
                format!("FastPathPlanInvalidated plan={plan}")
            }
            Self::TransactionBegan {
                transaction,
                store,
                task,
                label,
            } => {
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let task = task
                    .map(|task| task.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "TransactionBegan transaction={transaction} store={store} task={task} label={label}"
                )
            }
            Self::TransactionCommitted {
                transaction,
                generation,
            } => {
                format!("TransactionCommitted transaction={transaction} generation={generation}")
            }
            Self::TransactionRolledBack {
                transaction,
                reason,
                generation,
            } => {
                format!(
                    "TransactionRolledBack transaction={transaction} reason={reason} generation={generation}"
                )
            }
            Self::CleanupStepApplied {
                cleanup,
                step,
                target,
                observed_generation,
            } => {
                format!(
                    "CleanupStepApplied cleanup={cleanup} step={step} target={target} observed_generation={observed_generation}"
                )
            }
            Self::FailureEffect { effect } => {
                format!("FailureEffect {}", effect.summary())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub id: EventId,
    pub epoch: u64,
    pub source: String,
    pub causal_parent: Option<EventId>,
    pub kind: EventKind,
}

impl EventRecord {
    pub fn summary(&self) -> String {
        format!(
            "#{} epoch={} source={} {}",
            self.id,
            self.epoch,
            self.source,
            self.kind.summary()
        )
    }
}

#[derive(Clone, Debug)]
pub struct EventLog {
    next_id: EventId,
    epoch: u64,
    runtime_mode: RuntimeMode,
    pub(crate) events: Vec<EventRecord>,
}

impl EventLog {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            epoch: 0,
            runtime_mode: RuntimeMode::Research,
            events: Vec::new(),
        }
    }

    pub const fn with_runtime_mode(runtime_mode: RuntimeMode) -> Self {
        Self {
            next_id: 1,
            epoch: 0,
            runtime_mode,
            events: Vec::new(),
        }
    }

    pub const fn runtime_mode(&self) -> RuntimeMode {
        self.runtime_mode
    }

    pub fn push(&mut self, source: &str, kind: EventKind) -> EventId {
        let id = self.next_id;
        self.next_id += 1;
        self.epoch += 1;
        self.events.push(EventRecord {
            id,
            epoch: self.epoch,
            source: source.to_string(),
            causal_parent: None,
            kind,
        });
        id
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn cursor(&self) -> EventId {
        self.next_id.saturating_sub(1)
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn tail(&self, count: usize) -> &[EventRecord] {
        let start = self.events.len().saturating_sub(count);
        &self.events[start..]
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}
