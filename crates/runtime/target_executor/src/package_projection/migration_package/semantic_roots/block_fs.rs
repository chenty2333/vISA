use super::*;

pub(super) fn push_block_fs_roots(
    roots: &mut SemanticRootSetManifest,
    semantic: &SemanticGraph,
    _capabilities: &[MigrationCapabilityManifest],
    _target_v1: &TargetExecutorV1Report,
) {
    roots.block_device_object_roots = semantic            .block_device_objects()
            .iter()
            .map(|block_device| {
                format!(
                    "block-device-object id={} name={} device={}@{} sector_size={} sector_count={} read_only={} max_transfer_sectors={} state={} generation={}",
                    block_device.id,
                    block_device.name,
                    block_device.device,
                    block_device.device_generation,
                    block_device.sector_size,
                    block_device.sector_count,
                    block_device.read_only,
                    block_device.max_transfer_sectors,
                    block_device.state.as_str(),
                    block_device.generation
                )
            })
            .collect();
    roots.block_range_object_roots = semantic            .block_range_objects()
            .iter()
            .map(|block_range| {
                format!(
                    "block-range-object id={} block_device={}@{} start_sector={} sector_count={} byte_offset={} byte_len={} state={} generation={}",
                    block_range.id,
                    block_range.block_device,
                    block_range.block_device_generation,
                    block_range.start_sector,
                    block_range.sector_count,
                    block_range.byte_offset,
                    block_range.byte_len,
                    block_range.state.as_str(),
                    block_range.generation
                )
            })
            .collect();
    roots.block_request_object_roots = semantic            .block_request_objects()
            .iter()
            .map(|request| {
                format!(
                    "block-request-object id={} block_device={}@{} block_range={}@{} operation={} sequence={} byte_len={} state={} generation={}",
                    request.id,
                    request.block_device,
                    request.block_device_generation,
                    request.block_range,
                    request.block_range_generation,
                    request.operation.as_str(),
                    request.sequence,
                    request.byte_len,
                    request.state.as_str(),
                    request.generation
                )
            })
            .collect();
    roots.block_completion_object_roots = semantic            .block_completion_objects()
            .iter()
            .map(|completion| {
                format!(
                    "block-completion-object id={} block_request={}@{} block_device={}@{} block_range={}@{} sequence={} completed_bytes={} status={} state={} generation={}",
                    completion.id,
                    completion.block_request,
                    completion.block_request_generation,
                    completion.block_device,
                    completion.block_device_generation,
                    completion.block_range,
                    completion.block_range_generation,
                    completion.sequence,
                    completion.completed_bytes,
                    completion.status.as_str(),
                    completion.state.as_str(),
                    completion.generation
                )
            })
            .collect();
    roots.block_wait_roots = semantic            .block_waits()
            .iter()
            .map(|wait| {
                format!(
                    "block-wait id={} wait={}@{} block_request={}@{} block_device={}@{} block_range={}@{} operation={} sequence={} byte_len={} state={} generation={}",
                    wait.id,
                    wait.wait,
                    wait.wait_generation,
                    wait.block_request,
                    wait.block_request_generation,
                    wait.block_device,
                    wait.block_device_generation,
                    wait.block_range,
                    wait.block_range_generation,
                    wait.operation.as_str(),
                    wait.sequence,
                    wait.byte_len,
                    wait.state.as_str(),
                    wait.generation
                )
            })
            .collect();
    roots.fake_block_backend_object_roots = semantic            .fake_block_backends()
            .iter()
            .map(|backend| {
                format!(
                    "fake-block-backend-object id={} name={} block_device={}@{} provider={} profile={} sector_size={} sector_count={} read_only={} max_transfer_sectors={} deterministic_seed={} state={} generation={}",
                    backend.id,
                    backend.name,
                    backend.block_device,
                    backend.block_device_generation,
                    backend.provider,
                    backend.profile,
                    backend.sector_size,
                    backend.sector_count,
                    backend.read_only,
                    backend.max_transfer_sectors,
                    backend.deterministic_seed,
                    backend.state.as_str(),
                    backend.generation
                )
            })
            .collect();
    roots.virtio_blk_backend_object_roots = semantic            .virtio_blk_backends()
            .iter()
            .map(|backend| {
                format!(
                    "virtio-blk-backend-object id={} name={} block_device={}@{} driver_binding={}@{} device={}@{} provider={} profile={} model={} sector_size={} sector_count={} read_only={} max_transfer_sectors={} device_features={} driver_features={} negotiated_features={} request_queue_index={} queue_size={} irq_vector={} state={} generation={}",
                    backend.id,
                    backend.name,
                    backend.block_device,
                    backend.block_device_generation,
                    backend.driver_binding,
                    backend.driver_binding_generation,
                    backend.device,
                    backend.device_generation,
                    backend.provider,
                    backend.profile,
                    backend.model,
                    backend.sector_size,
                    backend.sector_count,
                    backend.read_only,
                    backend.max_transfer_sectors,
                    backend.device_features,
                    backend.driver_features,
                    backend.negotiated_features,
                    backend.request_queue_index,
                    backend.queue_size,
                    backend.irq_vector,
                    backend.state.as_str(),
                    backend.generation
                )
            })
            .collect();
    roots.block_read_path_roots = semantic            .block_read_paths()
            .iter()
            .map(|read_path| {
                format!(
                    "block-read-path id={} backend={} block_request={}@{} block_completion={}@{} block_device={}@{} block_range={}@{} sequence={} completed_bytes={} data_digest={} state={} generation={}",
                    read_path.id,
                    read_path.backend.summary(),
                    read_path.block_request,
                    read_path.block_request_generation,
                    read_path.block_completion,
                    read_path.block_completion_generation,
                    read_path.block_device,
                    read_path.block_device_generation,
                    read_path.block_range,
                    read_path.block_range_generation,
                    read_path.sequence,
                    read_path.completed_bytes,
                    read_path.data_digest,
                    read_path.state.as_str(),
                    read_path.generation
                )
            })
            .collect();
    roots.block_write_path_roots = semantic            .block_write_paths()
            .iter()
            .map(|write_path| {
                format!(
                    "block-write-path id={} backend={} block_request={}@{} block_completion={}@{} block_device={}@{} block_range={}@{} sequence={} completed_bytes={} payload_digest={} state={} generation={}",
                    write_path.id,
                    write_path.backend.summary(),
                    write_path.block_request,
                    write_path.block_request_generation,
                    write_path.block_completion,
                    write_path.block_completion_generation,
                    write_path.block_device,
                    write_path.block_device_generation,
                    write_path.block_range,
                    write_path.block_range_generation,
                    write_path.sequence,
                    write_path.completed_bytes,
                    write_path.payload_digest,
                    write_path.state.as_str(),
                    write_path.generation
                )
            })
            .collect();
    roots.block_request_queue_roots = semantic            .block_request_queues()
            .iter()
            .map(|queue| {
                format!(
                    "block-request-queue id={} backend={} block_device={}@{} depth={} entries={} pending={} completed={} first_sequence={} last_sequence={} state={} generation={}",
                    queue.id,
                    queue.backend.summary(),
                    queue.block_device,
                    queue.block_device_generation,
                    queue.depth,
                    queue.entries.len(),
                    queue.pending_count,
                    queue.completed_count,
                    queue.first_sequence,
                    queue.last_sequence,
                    queue.state.as_str(),
                    queue.generation
                )
            })
            .collect();
    roots.block_dma_buffer_roots = semantic            .block_dma_buffers()
            .iter()
            .map(|buffer| {
                format!(
                    "block-dma-buffer id={} backend={} block_request={}@{} dma_buffer={}@{} block_device={}@{} block_range={}@{} descriptor={}@{} queue={}@{} operation={} access={} byte_len={} buffer_len={} buffer_digest={} state={} generation={}",
                    buffer.id,
                    buffer.backend.summary(),
                    buffer.block_request,
                    buffer.block_request_generation,
                    buffer.dma_buffer,
                    buffer.dma_buffer_generation,
                    buffer.block_device,
                    buffer.block_device_generation,
                    buffer.block_range,
                    buffer.block_range_generation,
                    buffer.descriptor,
                    buffer.descriptor_generation,
                    buffer.queue,
                    buffer.queue_generation,
                    buffer.operation.as_str(),
                    buffer.access.as_str(),
                    buffer.byte_len,
                    buffer.buffer_len,
                    buffer.buffer_digest,
                    buffer.state.as_str(),
                    buffer.generation
                )
            })
            .collect();
    roots.block_page_object_roots = semantic            .block_page_objects()
            .iter()
            .map(|page| {
                format!(
                    "block-page-object id={} block_dma_buffer={}@{} block_request={}@{} block_completion={}@{} dma_buffer={}@{} block_device={}@{} block_range={}@{} aspace={} vma_region={} page={} page_dirty_generation={} page_backing={} cow_state={} page_state={} page_offset={} byte_len={} operation={} state={} generation={}",
                    page.id,
                    page.block_dma_buffer,
                    page.block_dma_buffer_generation,
                    page.block_request,
                    page.block_request_generation,
                    page.block_completion,
                    page.block_completion_generation,
                    page.dma_buffer,
                    page.dma_buffer_generation,
                    page.block_device,
                    page.block_device_generation,
                    page.block_range,
                    page.block_range_generation,
                    page.aspace.summary(),
                    page.vma_region.summary(),
                    page.page.summary(),
                    page.page_dirty_generation,
                    page.page_backing.as_str(),
                    page.cow_state.as_str(),
                    page.page_state.as_str(),
                    page.page_offset,
                    page.byte_len,
                    page.operation.as_str(),
                    page.state.as_str(),
                    page.generation
                )
            })
            .collect();
    roots.buffer_cache_object_roots = semantic            .buffer_cache_objects()
            .iter()
            .map(|cache| {
                format!(
                    "buffer-cache-object id={} block_page_object={}@{} block_dma_buffer={}@{} block_device={}@{} block_range={}@{} aspace={} vma_region={} page={} page_dirty_generation={} page_offset={} block_offset={} byte_len={} operation={} cache_state={} coherency_epoch={} state={} generation={}",
                    cache.id,
                    cache.block_page_object,
                    cache.block_page_object_generation,
                    cache.block_dma_buffer,
                    cache.block_dma_buffer_generation,
                    cache.block_device,
                    cache.block_device_generation,
                    cache.block_range,
                    cache.block_range_generation,
                    cache.aspace.summary(),
                    cache.vma_region.summary(),
                    cache.page.summary(),
                    cache.page_dirty_generation,
                    cache.page_offset,
                    cache.block_offset,
                    cache.byte_len,
                    cache.operation.as_str(),
                    cache.cache_state.as_str(),
                    cache.coherency_epoch,
                    cache.state.as_str(),
                    cache.generation
                )
            })
            .collect();
    roots.file_object_roots = semantic            .file_objects()
            .iter()
            .map(|file| {
                format!(
                    "file-object id={} buffer_cache_object={}@{} block_device={}@{} block_range={}@{} page={} page_dirty_generation={} namespace={} file_key={} path={} file_offset={} byte_len={} file_size={} content_digest={} cache_state={} state={} generation={}",
                    file.id,
                    file.buffer_cache_object,
                    file.buffer_cache_object_generation,
                    file.block_device,
                    file.block_device_generation,
                    file.block_range,
                    file.block_range_generation,
                    file.page.summary(),
                    file.page_dirty_generation,
                    file.namespace,
                    file.file_key,
                    file.path,
                    file.file_offset,
                    file.byte_len,
                    file.file_size,
                    file.content_digest,
                    file.cache_state.as_str(),
                    file.state.as_str(),
                    file.generation
                )
            })
            .collect();
    roots.directory_object_roots = semantic            .directory_objects()
            .iter()
            .map(|directory| {
                format!(
                    "directory-object id={} file_object={}@{} namespace={} directory_key={} directory_path={} entry_name={} child_file_key={} child_path={} entry_kind={} file_size={} content_digest={} state={} generation={}",
                    directory.id,
                    directory.file_object,
                    directory.file_object_generation,
                    directory.namespace,
                    directory.directory_key,
                    directory.directory_path,
                    directory.entry_name,
                    directory.child_file_key,
                    directory.child_path,
                    directory.entry_kind.as_str(),
                    directory.file_size,
                    directory.content_digest,
                    directory.state.as_str(),
                    directory.generation
                )
            })
            .collect();
    roots.fat_adapter_object_roots = semantic            .fat_adapter_objects()
            .iter()
            .map(|adapter| {
                format!(
                    "fat-adapter-object id={} directory_object={}@{} file_object={}@{} block_device={}@{} implementation={} version={} profile={} volume_label={} image_bytes={} adapter_path={} semantic_path={} bytes_written={} bytes_read={} write_digest={} read_digest={} file_content_digest={} state={} generation={}",
                    adapter.id,
                    adapter.directory_object,
                    adapter.directory_object_generation,
                    adapter.file_object,
                    adapter.file_object_generation,
                    adapter.block_device,
                    adapter.block_device_generation,
                    adapter.implementation,
                    adapter.version,
                    adapter.profile,
                    adapter.volume_label,
                    adapter.image_bytes,
                    adapter.adapter_path,
                    adapter.semantic_path,
                    adapter.bytes_written,
                    adapter.bytes_read,
                    adapter.write_digest,
                    adapter.read_digest,
                    adapter.file_content_digest,
                    adapter.state.as_str(),
                    adapter.generation
                )
            })
            .collect();
    roots.ext4_adapter_object_roots = semantic            .ext4_adapter_objects()
            .iter()
            .map(|adapter| {
                format!(
                    "ext4-adapter-object id={} directory_object={}@{} file_object={}@{} block_device={}@{} implementation={} version={} profile={} volume_label={} image_bytes={} adapter_path={} semantic_path={} bytes_read={} read_digest={} file_content_digest={} directory_entries={} read_only_enforced={} state={} generation={}",
                    adapter.id,
                    adapter.directory_object,
                    adapter.directory_object_generation,
                    adapter.file_object,
                    adapter.file_object_generation,
                    adapter.block_device,
                    adapter.block_device_generation,
                    adapter.implementation,
                    adapter.version,
                    adapter.profile,
                    adapter.volume_label,
                    adapter.image_bytes,
                    adapter.adapter_path,
                    adapter.semantic_path,
                    adapter.bytes_read,
                    adapter.read_digest,
                    adapter.file_content_digest,
                    adapter.directory_entries,
                    adapter.read_only_enforced,
                    adapter.state.as_str(),
                    adapter.generation
                )
            })
            .collect();
    roots.file_handle_capability_roots = semantic            .file_handle_capabilities()
            .iter()
            .map(|capability| {
                format!(
                    "file-handle-capability id={} owner_store={}@{} file_object={}@{} directory_object={}@{} capability={}@{} handle_slot={} handle_generation={} handle_tag={} operation={} file_offset={} byte_len={} content_digest={} state={} generation={}",
                    capability.id,
                    capability.owner_store,
                    capability.owner_store_generation,
                    capability.file_object,
                    capability.file_object_generation,
                    capability.directory_object,
                    capability.directory_object_generation,
                    capability.capability,
                    capability.capability_generation,
                    capability.handle_slot,
                    capability.handle_generation,
                    capability.handle_tag,
                    capability.operation,
                    capability.file_offset,
                    capability.byte_len,
                    capability.content_digest,
                    capability.state.as_str(),
                    capability.generation
                )
            })
            .collect();
    roots.fs_wait_roots = semantic            .fs_waits()
            .iter()
            .map(|wait| {
                format!(
                    "fs-wait id={} wait={}@{} owner_store={}@{} file_object={}@{} directory_object={}@{} file_handle_capability={}@{} operation={} blocker={} sequence={} byte_len={} state={} generation={}",
                    wait.id,
                    wait.wait,
                    wait.wait_generation,
                    wait.owner_store,
                    wait.owner_store_generation,
                    wait.file_object,
                    wait.file_object_generation,
                    wait.directory_object,
                    wait.directory_object_generation,
                    wait.file_handle_capability,
                    wait.file_handle_capability_generation,
                    wait.operation,
                    wait.blocker.summary(),
                    wait.sequence,
                    wait.byte_len,
                    wait.state.as_str(),
                    wait.generation
                )
            })
            .collect();
    roots.block_driver_cleanup_roots = semantic            .block_driver_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "block-driver-cleanup id={} io_cleanup={}@{} driver_store={}@{} device={}@{} binding={}@{} block_device={}@{} backend={}:{}@{} state={} generation={} cancelled_block_waits={} released_dma_buffers={} revoked_device_capabilities={}",
                    cleanup.id,
                    cleanup.io_cleanup,
                    cleanup.io_cleanup_generation,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                    cleanup.device,
                    cleanup.device_generation,
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                    cleanup.block_device,
                    cleanup.block_device_generation,
                    cleanup.backend.kind.as_str(),
                    cleanup.backend.id,
                    cleanup.backend.generation,
                    cleanup.state.as_str(),
                    cleanup.generation,
                    cleanup.cancelled_block_waits.len(),
                    cleanup.released_dma_buffers.len(),
                    cleanup.revoked_device_capabilities.len()
                )
            })
            .collect();
    roots.block_pending_io_policy_roots = semantic            .block_pending_io_policies()
            .iter()
            .map(|policy| {
                format!(
                    "block-pending-io-policy id={} block_wait={}@{} wait={}@{} block_request={}@{} retry_request={} block_device={}@{} block_range={}@{} action={} errno={} retry_attempt={} max_retries={} state={} generation={}",
                    policy.id,
                    policy.block_wait,
                    policy.block_wait_generation,
                    policy.wait,
                    policy.wait_generation,
                    policy.block_request,
                    policy.block_request_generation,
                    policy
                        .retry_request
                        .zip(policy.retry_request_generation)
                        .map(|(id, generation)| format!("{id}@{generation}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    policy.block_device,
                    policy.block_device_generation,
                    policy.block_range,
                    policy.block_range_generation,
                    policy.action.as_str(),
                    policy.errno,
                    policy.retry_attempt,
                    policy.max_retries,
                    policy.state.as_str(),
                    policy.generation
                )
            })
            .collect();
    roots.block_request_generation_audit_roots = semantic            .block_request_generation_audits()
            .iter()
            .map(|audit| {
                format!(
                    "block-request-generation-audit id={} block_device={}@{} block_range={}@{} block_request={}@{} backend={}:{}@{} dma_buffer={}:{}@{} rejected_completion_generation_probes={} rejected_wait_generation_probes={} rejected_dma_generation_probes={} rejected_queue_generation_probes={} state={} generation={}",
                    audit.id,
                    audit.block_device,
                    audit.block_device_generation,
                    audit.block_range,
                    audit.block_range_generation,
                    audit.block_request,
                    audit.block_request_generation,
                    audit.backend.kind.as_str(),
                    audit.backend.id,
                    audit.backend.generation,
                    audit.dma_buffer.kind.as_str(),
                    audit.dma_buffer.id,
                    audit.dma_buffer.generation,
                    audit.rejected_completion_generation_probes,
                    audit.rejected_wait_generation_probes,
                    audit.rejected_dma_generation_probes,
                    audit.rejected_queue_generation_probes,
                    audit.state.as_str(),
                    audit.generation
                )
            })
            .collect();
    roots.block_benchmark_roots = semantic            .block_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "block-benchmark id={} scenario={} backend={}:{}@{} block_device={}@{} block_range={}@{} read_path={}@{} write_path={}@{} request_queue={}@{} block_dma_buffer={}@{} sample_requests={} sample_bytes={} iops={} throughput_bytes_per_sec={} p50_latency_nanos={} p99_latency_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.backend.kind.as_str(),
                    benchmark.backend.id,
                    benchmark.backend.generation,
                    benchmark.block_device,
                    benchmark.block_device_generation,
                    benchmark.block_range,
                    benchmark.block_range_generation,
                    benchmark.read_path,
                    benchmark.read_path_generation,
                    benchmark.write_path,
                    benchmark.write_path_generation,
                    benchmark.request_queue,
                    benchmark.request_queue_generation,
                    benchmark.block_dma_buffer,
                    benchmark.block_dma_buffer_generation,
                    benchmark.sample_requests,
                    benchmark.sample_bytes,
                    benchmark.iops,
                    benchmark.throughput_bytes_per_sec,
                    benchmark.p50_latency_nanos,
                    benchmark.p99_latency_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect();
    roots.block_recovery_benchmark_roots = semantic            .block_recovery_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "block-recovery-benchmark id={} scenario={} cleanup={}@{} io_cleanup={}@{} backend={}:{}@{} block_device={}@{} driver_store={}@{} device={}@{} driver_binding={}@{} recovery_start_event={} recovery_complete_event={} cancelled_block_waits={} cancelled_wait_tokens={} released_dma_buffers={} revoked_device_capabilities={} recovery_nanos={} budget_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.cleanup,
                    benchmark.cleanup_generation,
                    benchmark.io_cleanup,
                    benchmark.io_cleanup_generation,
                    benchmark.backend.kind.as_str(),
                    benchmark.backend.id,
                    benchmark.backend.generation,
                    benchmark.block_device,
                    benchmark.block_device_generation,
                    benchmark.driver_store,
                    benchmark.driver_store_generation,
                    benchmark.device,
                    benchmark.device_generation,
                    benchmark.driver_binding,
                    benchmark.driver_binding_generation,
                    benchmark.recovery_start_event,
                    benchmark.recovery_complete_event,
                    benchmark.cancelled_block_waits,
                    benchmark.cancelled_wait_tokens,
                    benchmark.released_dma_buffers,
                    benchmark.revoked_device_capabilities,
                    benchmark.recovery_nanos,
                    benchmark.budget_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect();
}
