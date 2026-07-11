use alloc::{string::String, vec::Vec};

use super::super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDeviceObjectRecord {
    pub id: BlockDeviceObjectId,
    pub name: String,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub generation: Generation,
    pub state: BlockDeviceObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockDeviceObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockDeviceObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRangeObjectRecord {
    pub id: BlockRangeObjectId,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub start_sector: u64,
    pub sector_count: u64,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub generation: Generation,
    pub state: BlockRangeObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockRangeObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockRangeObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestObjectRecord {
    pub id: BlockRequestObjectId,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub operation: BlockRequestOperation,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: Generation,
    pub state: BlockRequestObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockRequestObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockRequestObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockCompletionObjectRecord {
    pub id: BlockCompletionObjectId,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub status: BlockCompletionStatus,
    pub generation: Generation,
    pub state: BlockCompletionObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockCompletionObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockCompletionObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockWaitRecord {
    pub id: BlockWaitId,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub operation: BlockRequestOperation,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: Generation,
    pub state: BlockWaitState,
    pub created_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub completion: Option<BlockCompletionObjectId>,
    pub completion_generation: Option<Generation>,
    pub cancel_reason: Option<WaitCancelReason>,
    pub note: String,
}

impl BlockWaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockWait, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeBlockBackendObjectRecord {
    pub id: FakeBlockBackendObjectId,
    pub name: String,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub provider: String,
    pub profile: String,
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub deterministic_seed: u64,
    pub generation: Generation,
    pub state: FakeBlockBackendObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FakeBlockBackendObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioBlkBackendObjectRecord {
    pub id: VirtioBlkBackendObjectId,
    pub name: String,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
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
    pub generation: Generation,
    pub state: VirtioBlkBackendObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl VirtioBlkBackendObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockReadPathRecord {
    pub id: BlockReadPathId,
    pub backend: ContractObjectRef,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub block_completion: BlockCompletionObjectId,
    pub block_completion_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub data_digest: u64,
    pub generation: Generation,
    pub state: BlockReadPathState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockReadPathRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockReadPath, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockWritePathRecord {
    pub id: BlockWritePathId,
    pub backend: ContractObjectRef,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub block_completion: BlockCompletionObjectId,
    pub block_completion_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub payload_digest: u64,
    pub generation: Generation,
    pub state: BlockWritePathState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockWritePathRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockWritePath, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestQueueEntryRef {
    pub request: BlockRequestObjectId,
    pub request_generation: Generation,
    pub completion: Option<BlockCompletionObjectId>,
    pub completion_generation: Option<Generation>,
}

impl BlockRequestQueueEntryRef {
    pub const fn pending(request: BlockRequestObjectId, request_generation: Generation) -> Self {
        Self { request, request_generation, completion: None, completion_generation: None }
    }

    pub const fn completed(
        request: BlockRequestObjectId,
        request_generation: Generation,
        completion: BlockCompletionObjectId,
        completion_generation: Generation,
    ) -> Self {
        Self {
            request,
            request_generation,
            completion: Some(completion),
            completion_generation: Some(completion_generation),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestQueueEntryRecord {
    pub request: BlockRequestObjectId,
    pub request_generation: Generation,
    pub completion: Option<BlockCompletionObjectId>,
    pub completion_generation: Option<Generation>,
    pub sequence: u64,
    pub operation: BlockRequestOperation,
    pub byte_len: u64,
    pub state: BlockRequestQueueEntryState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestQueueRecord {
    pub id: BlockRequestQueueId,
    pub backend: ContractObjectRef,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub depth: u32,
    pub entries: Vec<BlockRequestQueueEntryRecord>,
    pub pending_count: u32,
    pub completed_count: u32,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub generation: Generation,
    pub state: BlockRequestQueueState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockRequestQueueRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockRequestQueue, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDmaBufferRecord {
    pub id: BlockDmaBufferId,
    pub backend: ContractObjectRef,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub dma_buffer: DmaBufferObjectId,
    pub dma_buffer_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub descriptor: DescriptorObjectId,
    pub descriptor_generation: Generation,
    pub queue: QueueObjectId,
    pub queue_generation: Generation,
    pub operation: BlockRequestOperation,
    pub access: DmaBufferObjectAccess,
    pub byte_len: u64,
    pub buffer_len: u32,
    pub buffer_digest: u64,
    pub generation: Generation,
    pub state: BlockDmaBufferState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockDmaBufferRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockDmaBuffer, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPageObjectRecord {
    pub id: BlockPageObjectId,
    pub block_dma_buffer: BlockDmaBufferId,
    pub block_dma_buffer_generation: Generation,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub block_completion: BlockCompletionObjectId,
    pub block_completion_generation: Generation,
    pub dma_buffer: DmaBufferObjectId,
    pub dma_buffer_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub aspace: ContractObjectRef,
    pub vma_region: ContractObjectRef,
    pub page: ContractObjectRef,
    pub page_dirty_generation: Generation,
    pub page_backing: PageBacking,
    pub cow_state: CowState,
    pub page_state: PageObjectState,
    pub page_offset: u64,
    pub byte_len: u64,
    pub operation: BlockRequestOperation,
    pub generation: Generation,
    pub state: BlockPageObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockPageObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockPageObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BufferCacheObjectRecord {
    pub id: BufferCacheObjectId,
    pub block_page_object: BlockPageObjectId,
    pub block_page_object_generation: Generation,
    pub block_dma_buffer: BlockDmaBufferId,
    pub block_dma_buffer_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub aspace: ContractObjectRef,
    pub vma_region: ContractObjectRef,
    pub page: ContractObjectRef,
    pub page_dirty_generation: Generation,
    pub page_offset: u64,
    pub block_offset: u64,
    pub byte_len: u64,
    pub operation: BlockRequestOperation,
    pub cache_state: BufferCacheObjectState,
    pub coherency_epoch: u64,
    pub generation: Generation,
    pub state: BufferCacheObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BufferCacheObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BufferCacheObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileObjectRecord {
    pub id: FileObjectId,
    pub buffer_cache_object: BufferCacheObjectId,
    pub buffer_cache_object_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub page: ContractObjectRef,
    pub page_dirty_generation: Generation,
    pub namespace: String,
    pub file_key: String,
    pub path: String,
    pub file_offset: u64,
    pub byte_len: u64,
    pub file_size: u64,
    pub content_digest: u64,
    pub cache_state: BufferCacheObjectState,
    pub generation: Generation,
    pub state: FileObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FileObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FileObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryObjectRecord {
    pub id: DirectoryObjectId,
    pub file_object: FileObjectId,
    pub file_object_generation: Generation,
    pub namespace: String,
    pub directory_key: String,
    pub directory_path: String,
    pub entry_name: String,
    pub child_file_key: String,
    pub child_path: String,
    pub entry_kind: DirectoryEntryKind,
    pub file_size: u64,
    pub content_digest: u64,
    pub generation: Generation,
    pub state: DirectoryObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DirectoryObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DirectoryObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FatAdapterObjectRecord {
    pub id: FatAdapterObjectId,
    pub directory_object: DirectoryObjectId,
    pub directory_object_generation: Generation,
    pub file_object: FileObjectId,
    pub file_object_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
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
    pub generation: Generation,
    pub state: FatAdapterObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FatAdapterObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FatAdapterObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ext4AdapterObjectRecord {
    pub id: Ext4AdapterObjectId,
    pub directory_object: DirectoryObjectId,
    pub directory_object_generation: Generation,
    pub file_object: FileObjectId,
    pub file_object_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
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
    pub generation: Generation,
    pub state: Ext4AdapterObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl Ext4AdapterObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Ext4AdapterObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHandleCapabilityRecord {
    pub id: FileHandleCapabilityId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub file_object: FileObjectId,
    pub file_object_generation: Generation,
    pub directory_object: DirectoryObjectId,
    pub directory_object_generation: Generation,
    pub capability: CapabilityId,
    pub capability_generation: Generation,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub operation: String,
    pub file_offset: u64,
    pub byte_len: u64,
    pub content_digest: u64,
    pub generation: Generation,
    pub state: FileHandleCapabilityState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FileHandleCapabilityRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FileHandleCapability, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsWaitRecord {
    pub id: FsWaitId,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub file_object: FileObjectId,
    pub file_object_generation: Generation,
    pub directory_object: DirectoryObjectId,
    pub directory_object_generation: Generation,
    pub file_handle_capability: FileHandleCapabilityId,
    pub file_handle_capability_generation: Generation,
    pub operation: String,
    pub blocker: ContractObjectRef,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: Generation,
    pub state: FsWaitState,
    pub created_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub cancel_reason: Option<WaitCancelReason>,
    pub note: String,
}

impl FsWaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FsWait, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDriverCleanupRecord {
    pub id: BlockDriverCleanupId,
    pub io_cleanup: IoCleanupId,
    pub io_cleanup_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub backend: ContractObjectRef,
    pub cancelled_block_waits: Vec<ContractObjectRef>,
    pub cancelled_wait_tokens: Vec<ContractObjectRef>,
    pub revoked_device_capabilities: Vec<ContractObjectRef>,
    pub released_dma_buffers: Vec<ContractObjectRef>,
    pub generation: Generation,
    pub state: BlockDriverCleanupState,
    pub started_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub reason: String,
    pub note: String,
}

impl BlockDriverCleanupRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockDriverCleanup, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPendingIoPolicyRecord {
    pub id: BlockPendingIoPolicyId,
    pub block_wait: BlockWaitId,
    pub block_wait_generation: Generation,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub retry_request: Option<BlockRequestObjectId>,
    pub retry_request_generation: Option<Generation>,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub operation: BlockRequestOperation,
    pub sequence: u64,
    pub byte_len: u64,
    pub action: BlockPendingIoAction,
    pub errno: i32,
    pub retry_attempt: u32,
    pub max_retries: u32,
    pub generation: Generation,
    pub state: BlockPendingIoPolicyState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockPendingIoPolicyRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockPendingIoPolicy, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestGenerationAuditRecord {
    pub id: BlockRequestGenerationAuditId,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub backend: ContractObjectRef,
    pub dma_buffer: ContractObjectRef,
    pub rejected_completion_generation_probes: u32,
    pub rejected_wait_generation_probes: u32,
    pub rejected_dma_generation_probes: u32,
    pub rejected_queue_generation_probes: u32,
    pub generation: Generation,
    pub state: BlockRequestGenerationAuditState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockRequestGenerationAuditRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockRequestGenerationAudit,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBenchmarkRecord {
    pub id: BlockBenchmarkId,
    pub scenario: String,
    pub backend: ContractObjectRef,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub read_path: BlockReadPathId,
    pub read_path_generation: Generation,
    pub write_path: BlockWritePathId,
    pub write_path_generation: Generation,
    pub request_queue: BlockRequestQueueId,
    pub request_queue_generation: Generation,
    pub block_dma_buffer: BlockDmaBufferId,
    pub block_dma_buffer_generation: Generation,
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
    pub generation: Generation,
    pub state: BlockBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockBenchmark, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecoveryBenchmarkRecord {
    pub id: BlockRecoveryBenchmarkId,
    pub scenario: String,
    pub cleanup: BlockDriverCleanupId,
    pub cleanup_generation: Generation,
    pub io_cleanup: IoCleanupId,
    pub io_cleanup_generation: Generation,
    pub backend: ContractObjectRef,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub recovery_start_event: EventId,
    pub recovery_complete_event: EventId,
    pub cancelled_block_waits: u32,
    pub cancelled_wait_tokens: u32,
    pub released_dma_buffers: u32,
    pub revoked_device_capabilities: u32,
    pub recovery_nanos: u64,
    pub budget_nanos: u64,
    pub generation: Generation,
    pub state: BlockRecoveryBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockRecoveryBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockRecoveryBenchmark, self.id, self.generation)
    }
}
