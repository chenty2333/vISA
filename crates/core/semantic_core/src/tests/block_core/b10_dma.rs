use super::*;

pub(in crate::tests) fn setup_b10_block_dma_buffer_graph(
    access: DmaBufferObjectAccess,
) -> SemanticGraph {
    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_block_completion_object_with_id(
        1830,
        1828,
        1,
        2,
        4096,
        BlockCompletionStatus::Success,
        "b10 write completion",
    ));
    assert!(graph.record_queue_object_with_id(
        1831,
        "fake-block9-submit",
        QueueObjectRole::Submission,
        0,
        8,
        1823,
        1,
        "b10 block submission queue",
    ));
    assert!(graph.record_descriptor_object_with_id(
        1832,
        1831,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        4096,
        "b10 block dma descriptor",
    ));
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:block9-buf0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_dma_buffer_object_with_id(
        1833,
        1832,
        1,
        dma_resource,
        dma_resource_generation,
        access,
        4096,
        "b10 block dma buffer",
    ));
    graph
}

pub(in crate::tests) fn b10_expected_digest(access: DmaBufferObjectAccess) -> u64 {
    SemanticGraph::expected_block_dma_buffer_digest_v1(
        0x766d_6f73_626c_6b39,
        1824,
        1,
        1825,
        1,
        1828,
        1,
        1833,
        1,
        1832,
        1,
        1831,
        1,
        BlockRequestOperation::Write,
        access,
        2,
        4096,
        4096,
    )
}

pub(in crate::tests) fn setup_b21_stale_block_request_generation_graph() -> SemanticGraph {
    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_queue_object_with_id(
        1831,
        "fake-block9-submit",
        QueueObjectRole::Submission,
        0,
        8,
        1823,
        1,
        "b21 block submission queue",
    ));
    assert!(graph.record_descriptor_object_with_id(
        1832,
        1831,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        4096,
        "b21 block dma descriptor",
    ));
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:block9-b21");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_dma_buffer_object_with_id(
        1833,
        1832,
        1,
        dma_resource,
        dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        4096,
        "b21 block dma buffer",
    ));
    graph
}

#[test]
pub(super) fn block_runtime_b10_dma_backed_block_buffer_binds_request_to_dma_generation() {
    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    let digest = b10_expected_digest(DmaBufferObjectAccess::ReadWrite);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b10-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1834,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_request: 1828,
            block_request_generation: 1,
            dma_buffer: 1833,
            dma_buffer_generation: 1,
            buffer_digest: digest,
            note: "b10 bind write request to dma buffer".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_dma_buffer_count(), 1);
    let buffer = &graph.block_dma_buffers()[0];
    assert_eq!(
        buffer.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockDmaBuffer, 1834, 1)
    );
    assert_eq!(buffer.block_request, 1828);
    assert_eq!(buffer.dma_buffer, 1833);
    assert_eq!(buffer.descriptor, 1832);
    assert_eq!(buffer.queue, 1831);
    assert_eq!(buffer.operation, BlockRequestOperation::Write);
    assert_eq!(buffer.access, DmaBufferObjectAccess::ReadWrite);
    assert_eq!(buffer.byte_len, 4096);
    assert_eq!(buffer.buffer_len, 4096);
    assert_eq!(buffer.buffer_digest, digest);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "BlockDmaBufferBound block_dma_buffer=1834 backend=fake-block-backend-object:1829@1 block_request=1828@1 dma_buffer=1833@1 block_device=1824@1 block_range=1825@1 descriptor=1832@1 queue=1831@1 operation=write access=read-write byte_len=4096 buffer_len=4096 buffer_digest={digest} generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b10_rejects_duplicate_stale_digest_and_access_mismatch() {
    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    let digest = b10_expected_digest(DmaBufferObjectAccess::ReadWrite);
    assert!(graph.record_block_dma_buffer_with_id(
        1834,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1828,
        1,
        1833,
        1,
        digest,
        "b10 existing buffer",
    ));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b10-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1835,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_request: 1828,
            block_request_generation: 1,
            dma_buffer: 1833,
            dma_buffer_generation: 1,
            buffer_digest: digest,
            note: "b10 duplicate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["block dma buffer request already has a bound dma buffer".to_string()]
    );

    let stale_dma = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b10-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1836,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_request: 1828,
            block_request_generation: 1,
            dma_buffer: 1833,
            dma_buffer_generation: 2,
            buffer_digest: digest,
            note: "b10 stale dma".to_string(),
        },
    ));
    assert_eq!(stale_dma.status, CommandStatus::Rejected);
    assert_eq!(
        stale_dma.violations,
        vec!["block dma buffer dma generation is missing or inactive".to_string()]
    );

    let bad_digest = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b10-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1837,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_request: 1828,
            block_request_generation: 1,
            dma_buffer: 1833,
            dma_buffer_generation: 1,
            buffer_digest: digest ^ 1,
            note: "b10 bad digest".to_string(),
        },
    ));
    assert_eq!(bad_digest.status, CommandStatus::Rejected);
    assert_eq!(bad_digest.violations, vec!["block dma buffer digest mismatch".to_string()]);

    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::WriteOnly);
    let wrong_access_digest = b10_expected_digest(DmaBufferObjectAccess::WriteOnly);
    let access_mismatch = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b10-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1834,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_request: 1828,
            block_request_generation: 1,
            dma_buffer: 1833,
            dma_buffer_generation: 1,
            buffer_digest: wrong_access_digest,
            note: "b10 access mismatch".to_string(),
        },
    ));
    assert_eq!(access_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        access_mismatch.violations,
        vec!["block dma buffer access does not match request operation".to_string()]
    );
}

#[test]
pub(super) fn block_runtime_b10_invariants_reject_dma_generation_and_digest_leaks() {
    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    let digest = b10_expected_digest(DmaBufferObjectAccess::ReadWrite);
    assert!(graph.record_block_dma_buffer_with_id(
        1834,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1828,
        1,
        1833,
        1,
        digest,
        "b10 invariant buffer",
    ));
    graph.corrupt_block_dma_buffer_dma_generation_for_test(1834, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockDmaBufferMissingDmaBuffer {
            block_dma_buffer: 1834,
            dma_buffer: 1833,
        })
    );

    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    assert!(graph.record_block_dma_buffer_with_id(
        1834,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1828,
        1,
        1833,
        1,
        digest,
        "b10 invariant buffer",
    ));
    graph.corrupt_block_dma_buffer_digest_for_test(1834, digest ^ 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockDmaBufferInvalid { block_dma_buffer: 1834 })
    );
}
