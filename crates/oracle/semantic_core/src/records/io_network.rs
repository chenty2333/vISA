use alloc::{string::String, vec::Vec};

use super::super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceObjectRecord {
    pub id: DeviceObjectId,
    pub name: String,
    pub class: String,
    pub resource: ResourceId,
    pub resource_generation: Generation,
    pub backend: String,
    pub bus: String,
    pub vendor: String,
    pub model: String,
    pub generation: Generation,
    pub state: DeviceObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DeviceObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DeviceObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueObjectRecord {
    pub id: QueueObjectId,
    pub name: String,
    pub role: QueueObjectRole,
    pub queue_index: u16,
    pub depth: u32,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub generation: Generation,
    pub state: QueueObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl QueueObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::QueueObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorObjectRecord {
    pub id: DescriptorObjectId,
    pub queue: QueueObjectId,
    pub queue_generation: Generation,
    pub slot: u16,
    pub access: DescriptorObjectAccess,
    pub length: u32,
    pub generation: Generation,
    pub state: DescriptorObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DescriptorObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DescriptorObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmaBufferObjectRecord {
    pub id: DmaBufferObjectId,
    pub descriptor: DescriptorObjectId,
    pub descriptor_generation: Generation,
    pub resource: ResourceId,
    pub resource_generation: Generation,
    pub access: DmaBufferObjectAccess,
    pub length: u32,
    pub generation: Generation,
    pub state: DmaBufferObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DmaBufferObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DmaBufferObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmioRegionObjectRecord {
    pub id: MmioRegionObjectId,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub resource: ResourceId,
    pub resource_generation: Generation,
    pub region_index: u16,
    pub offset: u64,
    pub length: u64,
    pub access: MmioRegionObjectAccess,
    pub generation: Generation,
    pub state: MmioRegionObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl MmioRegionObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::MmioRegionObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrqLineObjectRecord {
    pub id: IrqLineObjectId,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub resource: ResourceId,
    pub resource_generation: Generation,
    pub irq_number: u32,
    pub trigger: IrqLineTrigger,
    pub polarity: IrqLinePolarity,
    pub generation: Generation,
    pub state: IrqLineObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IrqLineObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrqEventRecord {
    pub id: IrqEventId,
    pub irq_line: IrqLineObjectId,
    pub irq_line_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub irq_number: u32,
    pub sequence: u64,
    pub generation: Generation,
    pub state: IrqEventState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IrqEventRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IrqEvent, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCapabilityRecord {
    pub id: DeviceCapabilityId,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub target: ContractObjectRef,
    pub class: CapabilityClass,
    pub operation: String,
    pub capability: CapabilityId,
    pub capability_generation: Generation,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub generation: Generation,
    pub state: DeviceCapabilityState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DeviceCapabilityRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DeviceCapability, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverStoreBindingRecord {
    pub id: DriverStoreBindingId,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub device_capability: DeviceCapabilityId,
    pub device_capability_generation: Generation,
    pub capability: CapabilityId,
    pub capability_generation: Generation,
    pub generation: Generation,
    pub state: DriverStoreBindingState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DriverStoreBindingRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DriverStoreBinding, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoWaitRecord {
    pub id: IoWaitId,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub blocker: ContractObjectRef,
    pub generation: Generation,
    pub state: IoWaitState,
    pub created_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub completion_irq_event: Option<IrqEventId>,
    pub completion_irq_event_generation: Option<Generation>,
    pub cancel_reason: Option<WaitCancelReason>,
    pub note: String,
}

impl IoWaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IoWait, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoCleanupStepRecord {
    pub kind: IoCleanupStepKind,
    pub target: ContractObjectRef,
    pub observed_generation: Generation,
    pub status: IoCleanupStepStatus,
    pub event: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoCleanupRecord {
    pub id: IoCleanupId,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub generation: Generation,
    pub state: IoCleanupState,
    pub reason: String,
    pub started_at_event: EventId,
    pub completed_at_event: EventId,
    pub cancelled_io_waits: Vec<ContractObjectRef>,
    pub revoked_device_capabilities: Vec<ContractObjectRef>,
    pub revoked_capabilities: Vec<ContractObjectRef>,
    pub released_dma_buffers: Vec<ContractObjectRef>,
    pub released_mmio_regions: Vec<ContractObjectRef>,
    pub released_irq_lines: Vec<ContractObjectRef>,
    pub steps: Vec<IoCleanupStepRecord>,
    pub note: String,
}

impl IoCleanupRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IoCleanup, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoFaultInjectionRecord {
    pub id: IoFaultInjectionId,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub target: ContractObjectRef,
    pub cleanup: IoCleanupId,
    pub cleanup_generation: Generation,
    pub generation: Generation,
    pub kind: IoFaultInjectionKind,
    pub state: IoFaultInjectionState,
    pub injected_at_event: EventId,
    pub note: String,
}

impl IoFaultInjectionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IoFaultInjection, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoValidationViolationRecord {
    pub code: IoValidationViolationCode,
    pub subject: ContractObjectRef,
    pub relation: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoValidationReportRecord {
    pub id: IoValidationReportId,
    pub generation: Generation,
    pub state: IoValidationReportState,
    pub validated_at_event: EventId,
    pub event_log_cursor: EventId,
    pub observed_device_count: usize,
    pub observed_queue_count: usize,
    pub observed_descriptor_count: usize,
    pub observed_dma_buffer_count: usize,
    pub observed_mmio_region_count: usize,
    pub observed_irq_line_count: usize,
    pub observed_irq_event_count: usize,
    pub observed_device_capability_count: usize,
    pub observed_driver_binding_count: usize,
    pub observed_io_wait_count: usize,
    pub observed_io_cleanup_count: usize,
    pub observed_io_fault_injection_count: usize,
    pub violations: Vec<IoValidationViolationRecord>,
    pub note: String,
}

impl IoValidationReportRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IoValidationReport, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketDeviceObjectRecord {
    pub id: PacketDeviceObjectId,
    pub name: String,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub generation: Generation,
    pub state: PacketDeviceObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl PacketDeviceObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::PacketDeviceObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketBufferObjectRecord {
    pub id: PacketBufferObjectId,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub direction: PacketBufferDirection,
    pub frame_format_version: u32,
    pub capacity: u32,
    pub payload_len: u32,
    pub sequence: u64,
    pub generation: Generation,
    pub state: PacketBufferObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl PacketBufferObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::PacketBufferObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketQueueObjectRecord {
    pub id: PacketQueueObjectId,
    pub name: String,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub role: PacketQueueRole,
    pub queue_index: u16,
    pub depth: u32,
    pub generation: Generation,
    pub state: PacketQueueObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl PacketQueueObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::PacketQueueObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketDescriptorObjectRecord {
    pub id: PacketDescriptorObjectId,
    pub packet_queue: PacketQueueObjectId,
    pub packet_queue_generation: Generation,
    pub packet_buffer: PacketBufferObjectId,
    pub packet_buffer_generation: Generation,
    pub slot: u16,
    pub length: u32,
    pub generation: Generation,
    pub state: PacketDescriptorObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl PacketDescriptorObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::PacketDescriptorObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeNetBackendObjectRecord {
    pub id: FakeNetBackendObjectId,
    pub name: String,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub provider: String,
    pub profile: String,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub deterministic_seed: u64,
    pub generation: Generation,
    pub state: FakeNetBackendObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FakeNetBackendObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FakeNetBackendObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioNetBackendObjectRecord {
    pub id: VirtioNetBackendObjectId,
    pub name: String,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub provider: String,
    pub profile: String,
    pub model: String,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub device_features: u64,
    pub driver_features: u64,
    pub negotiated_features: u64,
    pub rx_queue_index: u16,
    pub tx_queue_index: u16,
    pub queue_size: u16,
    pub irq_vector: u16,
    pub generation: Generation,
    pub state: VirtioNetBackendObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl VirtioNetBackendObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRxInterruptRecord {
    pub id: NetworkRxInterruptId,
    pub virtio_net_backend: VirtioNetBackendObjectId,
    pub virtio_net_backend_generation: Generation,
    pub irq_event: IrqEventId,
    pub irq_event_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub rx_queue: PacketQueueObjectId,
    pub rx_queue_generation: Generation,
    pub ready_descriptors: u16,
    pub sequence: u64,
    pub generation: Generation,
    pub state: NetworkRxInterruptState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkRxInterruptRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::NetworkRxInterrupt, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRxWaitResolutionRecord {
    pub id: NetworkRxWaitResolutionId,
    pub io_wait: IoWaitId,
    pub io_wait_generation: Generation,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub rx_interrupt: NetworkRxInterruptId,
    pub rx_interrupt_generation: Generation,
    pub irq_event: IrqEventId,
    pub irq_event_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub rx_queue: PacketQueueObjectId,
    pub rx_queue_generation: Generation,
    pub ready_descriptors: u16,
    pub sequence: u64,
    pub generation: Generation,
    pub state: NetworkRxWaitResolutionState,
    pub resolved_at_event: EventId,
    pub note: String,
}

impl NetworkRxWaitResolutionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkRxWaitResolution,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkTxCapabilityGateRecord {
    pub id: NetworkTxCapabilityGateId,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub tx_queue: PacketQueueObjectId,
    pub tx_queue_generation: Generation,
    pub packet_descriptor: PacketDescriptorObjectId,
    pub packet_descriptor_generation: Generation,
    pub packet_buffer: PacketBufferObjectId,
    pub packet_buffer_generation: Generation,
    pub device_capability: DeviceCapabilityId,
    pub device_capability_generation: Generation,
    pub capability: CapabilityId,
    pub capability_generation: Generation,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub operation: String,
    pub byte_len: u32,
    pub sequence: u64,
    pub generation: Generation,
    pub state: NetworkTxCapabilityGateState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkTxCapabilityGateRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkTxCapabilityGate,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkTxCompletionRecord {
    pub id: NetworkTxCompletionId,
    pub tx_gate: NetworkTxCapabilityGateId,
    pub tx_gate_generation: Generation,
    pub backend: ContractObjectRef,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub tx_queue: PacketQueueObjectId,
    pub tx_queue_generation: Generation,
    pub packet_descriptor: PacketDescriptorObjectId,
    pub packet_descriptor_generation: Generation,
    pub packet_buffer: PacketBufferObjectId,
    pub packet_buffer_generation: Generation,
    pub byte_len: u32,
    pub sequence: u64,
    pub completion_sequence: u64,
    pub generation: Generation,
    pub state: NetworkTxCompletionState,
    pub completed_at_event: EventId,
    pub note: String,
}

impl NetworkTxCompletionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::NetworkTxCompletion, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkStackAdapterRecord {
    pub id: NetworkStackAdapterId,
    pub implementation: String,
    pub implementation_version: String,
    pub profile: String,
    pub medium: String,
    pub backend: ContractObjectRef,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub rx_queue: PacketQueueObjectId,
    pub rx_queue_generation: Generation,
    pub tx_queue: PacketQueueObjectId,
    pub tx_queue_generation: Generation,
    pub mac: [u8; 6],
    pub ipv4_addr: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub max_payload_len: u32,
    pub socket_capacity: u16,
    pub generation: Generation,
    pub state: NetworkStackAdapterState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkStackAdapterRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::NetworkStackAdapter, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketObjectRecord {
    pub id: SocketObjectId,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub domain: u32,
    pub socket_type: u32,
    pub protocol: u32,
    pub canonical_protocol: u16,
    pub family: String,
    pub transport: String,
    pub generation: Generation,
    pub state: SocketObjectState,
    pub created_at_event: EventId,
    pub note: String,
}

impl SocketObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SocketObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointObjectRecord {
    pub id: EndpointObjectId,
    pub socket: SocketObjectId,
    pub socket_generation: Generation,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub family: String,
    pub transport: String,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub generation: Generation,
    pub state: EndpointObjectState,
    pub created_at_event: EventId,
    pub note: String,
}

impl EndpointObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::EndpointObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketOperationRecord {
    pub id: SocketOperationId,
    pub endpoint: EndpointObjectId,
    pub endpoint_generation: Generation,
    pub socket: SocketObjectId,
    pub socket_generation: Generation,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub operation: SocketOperationKind,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub backlog: u16,
    pub byte_len: u32,
    pub sequence: u64,
    pub generation: Generation,
    pub state: SocketOperationState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl SocketOperationRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SocketOperation, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketWaitRecord {
    pub id: SocketWaitId,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub endpoint: EndpointObjectId,
    pub endpoint_generation: Generation,
    pub socket: SocketObjectId,
    pub socket_generation: Generation,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub wait_kind: SemanticWaitKind,
    pub blocker: ContractObjectRef,
    pub generation: Generation,
    pub state: SocketWaitState,
    pub created_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub cancel_reason: Option<WaitCancelReason>,
    pub ready_sequence: Option<u64>,
    pub byte_len: Option<u32>,
    pub note: String,
}

impl SocketWaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SocketWait, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkBackpressureRecord {
    pub id: NetworkBackpressureId,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub packet_queue: PacketQueueObjectId,
    pub packet_queue_generation: Generation,
    pub endpoint: Option<EndpointObjectId>,
    pub endpoint_generation: Option<Generation>,
    pub socket: Option<SocketObjectId>,
    pub socket_generation: Option<Generation>,
    pub owner_store: Option<StoreId>,
    pub owner_store_generation: Option<Generation>,
    pub direction: PacketBufferDirection,
    pub reason: NetworkBackpressureReason,
    pub action: NetworkBackpressureAction,
    pub queue_depth: u32,
    pub queue_limit: u32,
    pub dropped_packets: u32,
    pub dropped_bytes: u32,
    pub sequence: u64,
    pub generation: Generation,
    pub state: NetworkBackpressureState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkBackpressureRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::NetworkBackpressure, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkBenchmarkRecord {
    pub id: NetworkBenchmarkId,
    pub scenario: String,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub tx_queue: PacketQueueObjectId,
    pub tx_queue_generation: Generation,
    pub rx_queue: PacketQueueObjectId,
    pub rx_queue_generation: Generation,
    pub tx_completion: NetworkTxCompletionId,
    pub tx_completion_generation: Generation,
    pub rx_wait_resolution: NetworkRxWaitResolutionId,
    pub rx_wait_resolution_generation: Generation,
    pub endpoint: EndpointObjectId,
    pub endpoint_generation: Generation,
    pub socket: SocketObjectId,
    pub socket_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub backpressure: Option<NetworkBackpressureId>,
    pub backpressure_generation: Option<Generation>,
    pub sample_packets: u32,
    pub sample_bytes: u64,
    pub tx_completed_packets: u32,
    pub rx_resolved_packets: u32,
    pub dropped_packets: u32,
    pub measured_nanos: u64,
    pub budget_nanos: u64,
    pub throughput_bytes_per_sec: u64,
    pub p50_latency_nanos: u64,
    pub p99_latency_nanos: u64,
    pub generation: Generation,
    pub state: NetworkBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::NetworkBenchmark, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRecoveryBenchmarkRecord {
    pub id: NetworkRecoveryBenchmarkId,
    pub scenario: String,
    pub cleanup: NetworkDriverCleanupId,
    pub cleanup_generation: Generation,
    pub io_cleanup: IoCleanupId,
    pub io_cleanup_generation: Generation,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub backend: ContractObjectRef,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub fault_injection: Option<NetworkFaultInjectionId>,
    pub fault_injection_generation: Option<Generation>,
    pub recovery_start_event: EventId,
    pub recovery_complete_event: EventId,
    pub cancelled_socket_waits: u32,
    pub revoked_packet_capabilities: u32,
    pub recovery_nanos: u64,
    pub budget_nanos: u64,
    pub generation: Generation,
    pub state: NetworkRecoveryBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkRecoveryBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkRecoveryBenchmark,
            self.id,
            self.generation,
        )
    }
}
