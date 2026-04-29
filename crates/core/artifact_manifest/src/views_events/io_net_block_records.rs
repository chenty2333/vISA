use serde::{Deserialize, Serialize};

use crate::target_runtime::ContractObjectRefManifest;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DeviceObjectManifest {
    pub id: u64,
    pub name: String,
    pub class: String,
    pub resource: u64,
    pub resource_generation: u64,
    pub backend: String,
    pub bus: String,
    pub vendor: String,
    pub model: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QueueObjectManifest {
    pub id: u64,
    pub name: String,
    pub role: String,
    pub queue_index: u16,
    pub depth: u32,
    pub device: u64,
    pub device_generation: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DescriptorObjectManifest {
    pub id: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub slot: u16,
    pub access: String,
    pub length: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DmaBufferObjectManifest {
    pub id: u64,
    pub descriptor: u64,
    pub descriptor_generation: u64,
    pub resource: u64,
    pub resource_generation: u64,
    pub access: String,
    pub length: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MmioRegionObjectManifest {
    pub id: u64,
    pub device: u64,
    pub device_generation: u64,
    pub resource: u64,
    pub resource_generation: u64,
    pub region_index: u16,
    pub offset: u64,
    pub length: u64,
    pub access: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IrqLineObjectManifest {
    pub id: u64,
    pub device: u64,
    pub device_generation: u64,
    pub resource: u64,
    pub resource_generation: u64,
    pub irq_number: u32,
    pub trigger: String,
    pub polarity: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IrqEventManifest {
    pub id: u64,
    pub irq_line: u64,
    pub irq_line_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub irq_number: u32,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DeviceCapabilityManifest {
    pub id: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub target: ContractObjectRefManifest,
    pub class: String,
    pub operation: String,
    pub capability: u64,
    pub capability_generation: u64,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DriverStoreBindingManifest {
    pub id: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub device_capability: u64,
    pub device_capability_generation: u64,
    pub capability: u64,
    pub capability_generation: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoWaitManifest {
    pub id: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub blocker: ContractObjectRefManifest,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    #[serde(default)]
    pub completion_irq_event: Option<u64>,
    #[serde(default)]
    pub completion_irq_event_generation: Option<u64>,
    #[serde(default)]
    pub cancel_reason: Option<String>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoCleanupManifest {
    pub id: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub generation: u64,
    pub state: String,
    pub reason: String,
    pub started_at_event: u64,
    pub completed_at_event: u64,
    #[serde(default)]
    pub cancelled_io_waits: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub revoked_device_capabilities: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub revoked_capabilities: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub released_dma_buffers: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub released_mmio_regions: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub released_irq_lines: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub steps: Vec<IoCleanupStepManifest>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoCleanupStepManifest {
    pub kind: String,
    pub target: ContractObjectRefManifest,
    pub observed_generation: u64,
    pub status: String,
    #[serde(default)]
    pub event: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoFaultInjectionManifest {
    pub id: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub target: ContractObjectRefManifest,
    pub cleanup: u64,
    pub cleanup_generation: u64,
    pub generation: u64,
    pub kind: String,
    pub state: String,
    pub injected_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoValidationViolationManifest {
    pub code: String,
    pub subject: ContractObjectRefManifest,
    pub relation: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoValidationReportManifest {
    pub id: u64,
    pub generation: u64,
    pub state: String,
    pub validated_at_event: u64,
    pub event_log_cursor: u64,
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
    pub violation_count: usize,
    pub violations: Vec<IoValidationViolationManifest>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PacketDeviceObjectManifest {
    pub id: u64,
    pub name: String,
    pub device: u64,
    pub device_generation: u64,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PacketBufferObjectManifest {
    pub id: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub direction: String,
    pub frame_format_version: u32,
    pub capacity: u32,
    pub payload_len: u32,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PacketQueueObjectManifest {
    pub id: u64,
    pub name: String,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub role: String,
    pub queue_index: u16,
    pub depth: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PacketDescriptorObjectManifest {
    pub id: u64,
    pub packet_queue: u64,
    pub packet_queue_generation: u64,
    pub packet_buffer: u64,
    pub packet_buffer_generation: u64,
    pub slot: u16,
    pub length: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FakeNetBackendObjectManifest {
    pub id: u64,
    pub name: String,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub provider: String,
    pub profile: String,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub deterministic_seed: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VirtioNetBackendObjectManifest {
    pub id: u64,
    pub name: String,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub device: u64,
    pub device_generation: u64,
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
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkRxInterruptManifest {
    pub id: u64,
    pub virtio_net_backend: u64,
    pub virtio_net_backend_generation: u64,
    pub irq_event: u64,
    pub irq_event_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub rx_queue: u64,
    pub rx_queue_generation: u64,
    pub ready_descriptors: u16,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkRxWaitResolutionManifest {
    pub id: u64,
    pub io_wait: u64,
    pub io_wait_generation: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub rx_interrupt: u64,
    pub rx_interrupt_generation: u64,
    pub irq_event: u64,
    pub irq_event_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub rx_queue: u64,
    pub rx_queue_generation: u64,
    pub ready_descriptors: u16,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub resolved_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkTxCapabilityGateManifest {
    pub id: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub tx_queue: u64,
    pub tx_queue_generation: u64,
    pub packet_descriptor: u64,
    pub packet_descriptor_generation: u64,
    pub packet_buffer: u64,
    pub packet_buffer_generation: u64,
    pub device_capability: u64,
    pub device_capability_generation: u64,
    pub capability: u64,
    pub capability_generation: u64,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub operation: String,
    pub byte_len: u32,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkTxCompletionManifest {
    pub id: u64,
    pub tx_gate: u64,
    pub tx_gate_generation: u64,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub tx_queue: u64,
    pub tx_queue_generation: u64,
    pub packet_descriptor: u64,
    pub packet_descriptor_generation: u64,
    pub packet_buffer: u64,
    pub packet_buffer_generation: u64,
    pub byte_len: u32,
    pub sequence: u64,
    pub completion_sequence: u64,
    pub generation: u64,
    pub state: String,
    pub completed_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkStackAdapterManifest {
    pub id: u64,
    pub implementation: String,
    pub implementation_version: String,
    pub profile: String,
    pub medium: String,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub rx_queue: u64,
    pub rx_queue_generation: u64,
    pub tx_queue: u64,
    pub tx_queue_generation: u64,
    pub mac: [u8; 6],
    pub ipv4_addr: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub max_payload_len: u32,
    pub socket_capacity: u16,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SocketObjectManifest {
    pub id: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub domain: u32,
    pub socket_type: u32,
    pub protocol: u32,
    pub canonical_protocol: u16,
    pub family: String,
    pub transport: String,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EndpointObjectManifest {
    pub id: u64,
    pub socket: u64,
    pub socket_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub family: String,
    pub transport: String,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SocketOperationManifest {
    pub id: u64,
    pub endpoint: u64,
    pub endpoint_generation: u64,
    pub socket: u64,
    pub socket_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub operation: String,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub backlog: u16,
    pub byte_len: u32,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SocketWaitManifest {
    pub id: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub endpoint: u64,
    pub endpoint_generation: u64,
    pub socket: u64,
    pub socket_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub wait_kind: String,
    pub blocker: ContractObjectRefManifest,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    pub completed_at_event: Option<u64>,
    pub cancel_reason: Option<String>,
    pub ready_sequence: Option<u64>,
    pub byte_len: Option<u32>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkBackpressureManifest {
    pub id: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub packet_queue: u64,
    pub packet_queue_generation: u64,
    pub endpoint: Option<u64>,
    pub endpoint_generation: Option<u64>,
    pub socket: Option<u64>,
    pub socket_generation: Option<u64>,
    pub owner_store: Option<u64>,
    pub owner_store_generation: Option<u64>,
    pub direction: String,
    pub reason: String,
    pub action: String,
    pub queue_depth: u32,
    pub queue_limit: u32,
    pub dropped_packets: u32,
    pub dropped_bytes: u32,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkDriverCleanupManifest {
    pub id: u64,
    pub io_cleanup: u64,
    pub io_cleanup_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub backend: ContractObjectRefManifest,
    #[serde(default)]
    pub cancelled_socket_waits: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub cancelled_wait_tokens: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub revoked_packet_capabilities: Vec<ContractObjectRefManifest>,
    pub generation: u64,
    pub state: String,
    pub started_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkGenerationAuditManifest {
    pub id: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub packet_queue: u64,
    pub packet_queue_generation: u64,
    pub packet_descriptor: u64,
    pub packet_descriptor_generation: u64,
    pub packet_buffer: u64,
    pub packet_buffer_generation: u64,
    pub dma_buffer: ContractObjectRefManifest,
    pub device_capability: ContractObjectRefManifest,
    pub rejected_packet_generation_probes: u32,
    pub rejected_dma_generation_probes: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkFaultInjectionManifest {
    pub id: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub packet_queue: u64,
    pub packet_queue_generation: u64,
    pub packet_descriptor: Option<u64>,
    pub packet_descriptor_generation: Option<u64>,
    pub packet_buffer: Option<u64>,
    pub packet_buffer_generation: Option<u64>,
    pub endpoint: Option<u64>,
    pub endpoint_generation: Option<u64>,
    pub socket: Option<u64>,
    pub socket_generation: Option<u64>,
    pub owner_store: Option<u64>,
    pub owner_store_generation: Option<u64>,
    pub direction: String,
    pub kind: String,
    pub effect: String,
    pub injected_packets: u32,
    pub dropped_packets: u32,
    pub error_packets: u32,
    pub error_code: String,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkBenchmarkManifest {
    pub id: u64,
    pub scenario: String,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub tx_queue: u64,
    pub tx_queue_generation: u64,
    pub rx_queue: u64,
    pub rx_queue_generation: u64,
    pub tx_completion: u64,
    pub tx_completion_generation: u64,
    pub rx_wait_resolution: u64,
    pub rx_wait_resolution_generation: u64,
    pub endpoint: u64,
    pub endpoint_generation: u64,
    pub socket: u64,
    pub socket_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub backpressure: Option<u64>,
    pub backpressure_generation: Option<u64>,
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
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkRecoveryBenchmarkManifest {
    pub id: u64,
    pub scenario: String,
    pub cleanup: u64,
    pub cleanup_generation: u64,
    pub io_cleanup: u64,
    pub io_cleanup_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub backend: ContractObjectRefManifest,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    #[serde(default)]
    pub fault_injection: Option<u64>,
    #[serde(default)]
    pub fault_injection_generation: Option<u64>,
    pub recovery_start_event: u64,
    pub recovery_complete_event: u64,
    pub cancelled_socket_waits: u32,
    pub revoked_packet_capabilities: u32,
    pub recovery_nanos: u64,
    pub budget_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockDeviceObjectManifest {
    pub id: u64,
    pub name: String,
    pub device: u64,
    pub device_generation: u64,
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRangeObjectManifest {
    pub id: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub start_sector: u64,
    pub sector_count: u64,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRequestObjectManifest {
    pub id: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub operation: String,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockCompletionObjectManifest {
    pub id: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub status: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockWaitManifest {
    pub id: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub operation: String,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    #[serde(default)]
    pub completion: Option<u64>,
    #[serde(default)]
    pub completion_generation: Option<u64>,
    #[serde(default)]
    pub cancel_reason: Option<String>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FakeBlockBackendObjectManifest {
    pub id: u64,
    pub name: String,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub provider: String,
    pub profile: String,
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub deterministic_seed: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VirtioBlkBackendObjectManifest {
    pub id: u64,
    pub name: String,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub provider: String,
    pub profile: String,
    pub model: String,
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub device_features: u64,
    pub driver_features: u64,
    pub negotiated_features: u64,
    pub request_queue_index: u16,
    pub queue_size: u16,
    pub irq_vector: u16,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockReadPathManifest {
    pub id: u64,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub block_completion: u64,
    pub block_completion_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub data_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockWritePathManifest {
    pub id: u64,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub block_completion: u64,
    pub block_completion_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub payload_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRequestQueueEntryManifest {
    pub request: u64,
    pub request_generation: u64,
    #[serde(default)]
    pub completion: Option<u64>,
    #[serde(default)]
    pub completion_generation: Option<u64>,
    pub sequence: u64,
    pub operation: String,
    pub byte_len: u64,
    pub state: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRequestQueueManifest {
    pub id: u64,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub depth: u32,
    #[serde(default)]
    pub entries: Vec<BlockRequestQueueEntryManifest>,
    pub pending_count: u32,
    pub completed_count: u32,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockDmaBufferManifest {
    pub id: u64,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub dma_buffer: u64,
    pub dma_buffer_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub descriptor: u64,
    pub descriptor_generation: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub operation: String,
    pub access: String,
    pub byte_len: u64,
    pub buffer_len: u32,
    pub buffer_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockPageObjectManifest {
    pub id: u64,
    pub block_dma_buffer: u64,
    pub block_dma_buffer_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub block_completion: u64,
    pub block_completion_generation: u64,
    pub dma_buffer: u64,
    pub dma_buffer_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub aspace: ContractObjectRefManifest,
    pub vma_region: ContractObjectRefManifest,
    pub page: ContractObjectRefManifest,
    pub page_dirty_generation: u64,
    pub page_backing: String,
    pub cow_state: String,
    pub page_state: String,
    pub page_offset: u64,
    pub byte_len: u64,
    pub operation: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BufferCacheObjectManifest {
    pub id: u64,
    pub block_page_object: u64,
    pub block_page_object_generation: u64,
    pub block_dma_buffer: u64,
    pub block_dma_buffer_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub aspace: ContractObjectRefManifest,
    pub vma_region: ContractObjectRefManifest,
    pub page: ContractObjectRefManifest,
    pub page_dirty_generation: u64,
    pub page_offset: u64,
    pub block_offset: u64,
    pub byte_len: u64,
    pub operation: String,
    pub cache_state: String,
    pub coherency_epoch: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FileObjectManifest {
    pub id: u64,
    pub buffer_cache_object: u64,
    pub buffer_cache_object_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub page: ContractObjectRefManifest,
    pub page_dirty_generation: u64,
    pub namespace: String,
    pub file_key: String,
    pub path: String,
    pub file_offset: u64,
    pub byte_len: u64,
    pub file_size: u64,
    pub content_digest: u64,
    pub cache_state: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DirectoryObjectManifest {
    pub id: u64,
    pub file_object: u64,
    pub file_object_generation: u64,
    pub namespace: String,
    pub directory_key: String,
    pub directory_path: String,
    pub entry_name: String,
    pub child_file_key: String,
    pub child_path: String,
    pub entry_kind: String,
    pub file_size: u64,
    pub content_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FatAdapterObjectManifest {
    pub id: u64,
    pub directory_object: u64,
    pub directory_object_generation: u64,
    pub file_object: u64,
    pub file_object_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub implementation: String,
    pub version: String,
    pub profile: String,
    pub volume_label: String,
    pub image_bytes: u64,
    pub adapter_path: String,
    pub semantic_path: String,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub write_digest: u64,
    pub read_digest: u64,
    pub file_content_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Ext4AdapterObjectManifest {
    pub id: u64,
    pub directory_object: u64,
    pub directory_object_generation: u64,
    pub file_object: u64,
    pub file_object_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub implementation: String,
    pub version: String,
    pub profile: String,
    pub volume_label: String,
    pub image_bytes: u64,
    pub adapter_path: String,
    pub semantic_path: String,
    pub bytes_read: u64,
    pub read_digest: u64,
    pub file_content_digest: u64,
    pub directory_entries: u64,
    pub read_only_enforced: bool,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FileHandleCapabilityManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub file_object: u64,
    pub file_object_generation: u64,
    pub directory_object: u64,
    pub directory_object_generation: u64,
    pub capability: u64,
    pub capability_generation: u64,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub operation: String,
    pub file_offset: u64,
    pub byte_len: u64,
    pub content_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FsWaitManifest {
    pub id: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub file_object: u64,
    pub file_object_generation: u64,
    pub directory_object: u64,
    pub directory_object_generation: u64,
    pub file_handle_capability: u64,
    pub file_handle_capability_generation: u64,
    pub operation: String,
    pub blocker: ContractObjectRefManifest,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    #[serde(default)]
    pub cancel_reason: Option<String>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockDriverCleanupManifest {
    pub id: u64,
    pub io_cleanup: u64,
    pub io_cleanup_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub backend: ContractObjectRefManifest,
    #[serde(default)]
    pub cancelled_block_waits: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub cancelled_wait_tokens: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub revoked_device_capabilities: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub released_dma_buffers: Vec<ContractObjectRefManifest>,
    pub generation: u64,
    pub state: String,
    pub started_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockPendingIoPolicyManifest {
    pub id: u64,
    pub block_wait: u64,
    pub block_wait_generation: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    #[serde(default)]
    pub retry_request: Option<u64>,
    #[serde(default)]
    pub retry_request_generation: Option<u64>,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub operation: String,
    pub sequence: u64,
    pub byte_len: u64,
    pub action: String,
    pub errno: i32,
    pub retry_attempt: u32,
    pub max_retries: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRequestGenerationAuditManifest {
    pub id: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub backend: ContractObjectRefManifest,
    pub dma_buffer: ContractObjectRefManifest,
    pub rejected_completion_generation_probes: u32,
    pub rejected_wait_generation_probes: u32,
    pub rejected_dma_generation_probes: u32,
    pub rejected_queue_generation_probes: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockBenchmarkManifest {
    pub id: u64,
    pub scenario: String,
    pub backend: ContractObjectRefManifest,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub read_path: u64,
    pub read_path_generation: u64,
    pub write_path: u64,
    pub write_path_generation: u64,
    pub request_queue: u64,
    pub request_queue_generation: u64,
    pub block_dma_buffer: u64,
    pub block_dma_buffer_generation: u64,
    pub sample_requests: u32,
    pub sample_bytes: u64,
    pub read_completed_requests: u32,
    pub write_completed_requests: u32,
    pub queue_completed_requests: u32,
    pub measured_nanos: u64,
    pub budget_nanos: u64,
    pub iops: u64,
    pub throughput_bytes_per_sec: u64,
    pub p50_latency_nanos: u64,
    pub p99_latency_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRecoveryBenchmarkManifest {
    pub id: u64,
    pub scenario: String,
    pub cleanup: u64,
    pub cleanup_generation: u64,
    pub io_cleanup: u64,
    pub io_cleanup_generation: u64,
    pub backend: ContractObjectRefManifest,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub recovery_start_event: u64,
    pub recovery_complete_event: u64,
    pub cancelled_block_waits: u32,
    pub cancelled_wait_tokens: u32,
    pub released_dma_buffers: u32,
    pub revoked_device_capabilities: u32,
    pub recovery_nanos: u64,
    pub budget_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}
