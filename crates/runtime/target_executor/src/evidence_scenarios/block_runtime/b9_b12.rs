use super::*;

pub(crate) fn record_block_runtime_b9_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 1);
    let entries = vec![
        BlockRequestQueueEntryRef::completed(20_009, 1, 20_013, 1),
        BlockRequestQueueEntryRef::completed(20_046, 1, 20_047, 1),
    ];
    let queue = semantic.apply_envelope(CommandEnvelope::new(
        248,
        "target-executor-b9",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_053,
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            depth: 8,
            entries: entries.clone(),
            note: "b9-record-block-request-queue-through-fake-backend".to_owned(),
        },
    ));
    if queue.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b9 queue command {} ({}) failed: status={} violations={:?}",
            queue.command_id,
            queue.command,
            queue.status.as_str(),
            queue.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        249,
        "target-executor-b9",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_054,
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            depth: 8,
            entries: entries.clone(),
            note: "b9-reject-request-already-queued".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("already belongs to an active queue"))
    {
        return Err(format!(
            "block runtime b9 duplicate request queue command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    let stale_backend = semantic.apply_envelope(CommandEnvelope::new(
        250,
        "target-executor-b9",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_055,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 2),
            block_device: 20_002,
            block_device_generation: 1,
            depth: 8,
            entries: vec![BlockRequestQueueEntryRef::completed(20_009, 1, 20_013, 1)],
            note: "b9-reject-stale-backend-generation".to_owned(),
        },
    ));
    if stale_backend.status != CommandStatus::Rejected
        || !stale_backend
            .violations
            .iter()
            .any(|violation| violation.contains("backend generation"))
    {
        return Err(format!(
            "block runtime b9 stale backend queue command {} ({}) was not rejected: status={} violations={:?}",
            stale_backend.command_id,
            stale_backend.command,
            stale_backend.status.as_str(),
            stale_backend.violations
        )
        .into());
    }

    let over_depth = semantic.apply_envelope(CommandEnvelope::new(
        251,
        "target-executor-b9",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_056,
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            depth: 1,
            entries: entries.clone(),
            note: "b9-reject-depth-exceeded".to_owned(),
        },
    ));
    if over_depth.status != CommandStatus::Rejected
        || !over_depth.violations.iter().any(|violation| violation.contains("depth exceeded"))
    {
        return Err(format!(
            "block runtime b9 over-depth queue command {} ({}) was not rejected: status={} violations={:?}",
            over_depth.command_id,
            over_depth.command,
            over_depth.status.as_str(),
            over_depth.violations
        )
        .into());
    }

    let stale_request = semantic.apply_envelope(CommandEnvelope::new(
        252,
        "target-executor-b9",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_057,
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            depth: 8,
            entries: vec![BlockRequestQueueEntryRef::completed(20_046, 2, 20_047, 1)],
            note: "b9-reject-stale-request-generation".to_owned(),
        },
    ));
    if stale_request.status != CommandStatus::Rejected
        || !stale_request
            .violations
            .iter()
            .any(|violation| violation.contains("request generation"))
    {
        return Err(format!(
            "block runtime b9 stale request queue command {} ({}) was not rejected: status={} violations={:?}",
            stale_request.command_id,
            stale_request.command,
            stale_request.status.as_str(),
            stale_request.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b10_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let config = FakeBlockBackendConfig::blk0();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 1);
    let dma_resource =
        semantic.register_resource(ResourceKind::DmaBuffer, None, "dma:fake-block0-buf0");
    let dma_resource_generation = semantic
        .resource_handle(dma_resource)
        .map(|handle| handle.generation)
        .ok_or("b10 dma resource handle is missing")?;

    let queue = semantic.apply_envelope(CommandEnvelope::new(
        253,
        "target-executor-b10",
        SemanticCommand::RecordQueueObject {
            queue: 20_058,
            name: "fake-block0-submit".to_owned(),
            role: QueueObjectRole::Submission,
            queue_index: 1,
            depth: 16,
            device: 20_001,
            device_generation: 1,
            note: "b10-record-block-submission-queue".to_owned(),
        },
    ));
    if queue.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b10 queue command {} ({}) failed: status={} violations={:?}",
            queue.command_id,
            queue.command,
            queue.status.as_str(),
            queue.violations
        )
        .into());
    }

    let descriptor = semantic.apply_envelope(CommandEnvelope::new(
        254,
        "target-executor-b10",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 20_059,
            queue: 20_058,
            queue_generation: 1,
            slot: 0,
            access: DescriptorObjectAccess::ReadWrite,
            length: 4096,
            note: "b10-record-block-dma-descriptor".to_owned(),
        },
    ));
    if descriptor.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b10 descriptor command {} ({}) failed: status={} violations={:?}",
            descriptor.command_id,
            descriptor.command,
            descriptor.status.as_str(),
            descriptor.violations
        )
        .into());
    }

    let dma_buffer = semantic.apply_envelope(CommandEnvelope::new(
        255,
        "target-executor-b10",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 20_060,
            descriptor: 20_059,
            descriptor_generation: 1,
            resource: dma_resource,
            resource_generation: dma_resource_generation,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 4096,
            note: "b10-record-dma-buffer-object".to_owned(),
        },
    ));
    if dma_buffer.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b10 dma buffer command {} ({}) failed: status={} violations={:?}",
            dma_buffer.command_id,
            dma_buffer.command,
            dma_buffer.status.as_str(),
            dma_buffer.violations
        )
        .into());
    }

    let buffer_digest = SemanticGraph::expected_block_dma_buffer_digest_v1(
        config.deterministic_seed,
        20_002,
        1,
        20_005,
        1,
        20_046,
        1,
        20_060,
        1,
        20_059,
        1,
        20_058,
        1,
        BlockRequestOperation::Write,
        DmaBufferObjectAccess::ReadWrite,
        5,
        4096,
        4096,
    );
    let binding = semantic.apply_envelope(CommandEnvelope::new(
        256,
        "target-executor-b10",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 20_061,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            dma_buffer: 20_060,
            dma_buffer_generation: 1,
            buffer_digest,
            note: "b10-bind-block-request-to-dma-buffer".to_owned(),
        },
    ));
    if binding.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b10 binding command {} ({}) failed: status={} violations={:?}",
            binding.command_id,
            binding.command,
            binding.status.as_str(),
            binding.violations
        )
        .into());
    }

    let stale_dma = semantic.apply_envelope(CommandEnvelope::new(
        257,
        "target-executor-b10",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 20_062,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            dma_buffer: 20_060,
            dma_buffer_generation: 2,
            buffer_digest,
            note: "b10-reject-stale-dma-generation".to_owned(),
        },
    ));
    if stale_dma.status != CommandStatus::Rejected
        || !stale_dma.violations.iter().any(|violation| violation.contains("dma generation"))
    {
        return Err(format!(
            "block runtime b10 stale dma command {} ({}) was not rejected: status={} violations={:?}",
            stale_dma.command_id,
            stale_dma.command,
            stale_dma.status.as_str(),
            stale_dma.violations
        )
        .into());
    }

    let bad_digest = semantic.apply_envelope(CommandEnvelope::new(
        258,
        "target-executor-b10",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 20_063,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            dma_buffer: 20_060,
            dma_buffer_generation: 1,
            buffer_digest: buffer_digest ^ 1,
            note: "b10-reject-dma-buffer-digest-mismatch".to_owned(),
        },
    ));
    if bad_digest.status != CommandStatus::Rejected
        || !bad_digest.violations.iter().any(|violation| violation.contains("digest mismatch"))
    {
        return Err(format!(
            "block runtime b10 bad digest command {} ({}) was not rejected: status={} violations={:?}",
            bad_digest.command_id,
            bad_digest.command,
            bad_digest.status.as_str(),
            bad_digest.violations
        )
        .into());
    }

    let stale_request = semantic.apply_envelope(CommandEnvelope::new(
        259,
        "target-executor-b10",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 20_064,
            backend,
            block_request: 20_046,
            block_request_generation: 2,
            dma_buffer: 20_060,
            dma_buffer_generation: 1,
            buffer_digest,
            note: "b10-reject-stale-request-generation".to_owned(),
        },
    ));
    if stale_request.status != CommandStatus::Rejected
        || !stale_request
            .violations
            .iter()
            .any(|violation| violation.contains("request generation"))
    {
        return Err(format!(
            "block runtime b10 stale request command {} ({}) was not rejected: status={} violations={:?}",
            stale_request.command_id,
            stale_request.command,
            stale_request.status.as_str(),
            stale_request.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b11_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let aspace = ContractObjectRef::new(ContractObjectKind::GuestAddressSpace, 30_001, 1);
    let vma_region = ContractObjectRef::new(ContractObjectKind::VmaRegion, 30_002, 1);
    let page = ContractObjectRef::new(ContractObjectKind::PageObject, 30_003, 1);

    let integrated = semantic.apply_envelope(CommandEnvelope::new(
        260,
        "target-executor-b11",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 20_065,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            aspace,
            vma_region,
            page,
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 0,
            byte_len: 4096,
            note: "b11-integrate-block-dma-buffer-with-page-object".to_owned(),
        },
    ));
    if integrated.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b11 page object command {} ({}) failed: status={} violations={:?}",
            integrated.command_id,
            integrated.command,
            integrated.status.as_str(),
            integrated.violations
        )
        .into());
    }

    let stale_dma = semantic.apply_envelope(CommandEnvelope::new(
        261,
        "target-executor-b11",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 20_066,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 2,
            block_completion: 20_047,
            block_completion_generation: 1,
            aspace,
            vma_region,
            page: ContractObjectRef::new(ContractObjectKind::PageObject, 30_004, 1),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 0,
            byte_len: 4096,
            note: "b11-reject-stale-block-dma-generation".to_owned(),
        },
    ));
    if stale_dma.status != CommandStatus::Rejected
        || !stale_dma.violations.iter().any(|violation| violation.contains("dma buffer generation"))
    {
        return Err(format!(
            "block runtime b11 stale dma command {} ({}) was not rejected: status={} violations={:?}",
            stale_dma.command_id,
            stale_dma.command,
            stale_dma.status.as_str(),
            stale_dma.violations
        )
        .into());
    }

    let dead_page = semantic.apply_envelope(CommandEnvelope::new(
        262,
        "target-executor-b11",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 20_067,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            aspace,
            vma_region,
            page: ContractObjectRef::new(ContractObjectKind::PageObject, 30_005, 1),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Dead,
            page_offset: 0,
            byte_len: 4096,
            note: "b11-reject-dead-page-object".to_owned(),
        },
    ));
    if dead_page.status != CommandStatus::Rejected
        || !dead_page.violations.iter().any(|violation| violation.contains("page must be live"))
    {
        return Err(format!(
            "block runtime b11 dead page command {} ({}) was not rejected: status={} violations={:?}",
            dead_page.command_id,
            dead_page.command,
            dead_page.status.as_str(),
            dead_page.violations
        )
        .into());
    }

    let over_page = semantic.apply_envelope(CommandEnvelope::new(
        263,
        "target-executor-b11",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 20_068,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            aspace,
            vma_region,
            page: ContractObjectRef::new(ContractObjectKind::PageObject, 30_006, 1),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 1,
            byte_len: 4096,
            note: "b11-reject-page-byte-range-overflow".to_owned(),
        },
    ));
    if over_page.status != CommandStatus::Rejected
        || !over_page
            .violations
            .iter()
            .any(|violation| violation.contains("byte range exceeds page"))
    {
        return Err(format!(
            "block runtime b11 over-page command {} ({}) was not rejected: status={} violations={:?}",
            over_page.command_id,
            over_page.command,
            over_page.status.as_str(),
            over_page.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b12_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let page = ContractObjectRef::new(ContractObjectKind::PageObject, 30_003, 1);

    let cached = semantic.apply_envelope(CommandEnvelope::new(
        264,
        "target-executor-b12",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 20_069,
            block_page_object: 20_065,
            block_page_object_generation: 1,
            page,
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 1,
            note: "b12-cache-block-page-object-as-dirty-buffer".to_owned(),
        },
    ));
    if cached.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b12 buffer cache command {} ({}) failed: status={} violations={:?}",
            cached.command_id,
            cached.command,
            cached.status.as_str(),
            cached.violations
        )
        .into());
    }

    let stale_page = semantic.apply_envelope(CommandEnvelope::new(
        265,
        "target-executor-b12",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 20_070,
            block_page_object: 20_065,
            block_page_object_generation: 2,
            page: ContractObjectRef::new(ContractObjectKind::PageObject, 30_004, 1),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 2,
            note: "b12-reject-stale-block-page-generation".to_owned(),
        },
    ));
    if stale_page.status != CommandStatus::Rejected
        || !stale_page
            .violations
            .iter()
            .any(|violation| violation.contains("page integration generation"))
    {
        return Err(format!(
            "block runtime b12 stale page command {} ({}) was not rejected: status={} violations={:?}",
            stale_page.command_id,
            stale_page.command,
            stale_page.status.as_str(),
            stale_page.violations
        )
        .into());
    }

    let wrong_page = semantic.apply_envelope(CommandEnvelope::new(
        266,
        "target-executor-b12",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 20_071,
            block_page_object: 20_065,
            block_page_object_generation: 1,
            page: ContractObjectRef::new(ContractObjectKind::PageObject, 30_005, 1),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 3,
            note: "b12-reject-page-ref-mismatch".to_owned(),
        },
    ));
    if wrong_page.status != CommandStatus::Rejected
        || !wrong_page
            .violations
            .iter()
            .any(|violation| violation.contains("page ref does not match"))
    {
        return Err(format!(
            "block runtime b12 wrong page command {} ({}) was not rejected: status={} violations={:?}",
            wrong_page.command_id,
            wrong_page.command,
            wrong_page.status.as_str(),
            wrong_page.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        267,
        "target-executor-b12",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 20_072,
            block_page_object: 20_065,
            block_page_object_generation: 1,
            page,
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::WritebackPending,
            coherency_epoch: 4,
            note: "b12-reject-duplicate-cache-key".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("block range already cached"))
    {
        return Err(format!(
            "block runtime b12 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}
