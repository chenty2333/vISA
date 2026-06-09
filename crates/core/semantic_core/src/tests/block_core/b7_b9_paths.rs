use super::*;

pub(in crate::tests) fn setup_b7_block_read_graph() -> (SemanticGraph, u64) {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk7");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1796,
        "fake-block7",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b7 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1797,
        "blk7",
        1796,
        1,
        512,
        4096,
        false,
        128,
        "b7 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1798, 1797, 1, 64, 8, "b7 range"));
    assert!(graph.record_block_request_object_with_id(
        1799,
        1797,
        1,
        1798,
        1,
        BlockRequestOperation::Read,
        1,
        "b7 read request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1800,
        1799,
        1,
        1,
        4096,
        BlockCompletionStatus::Success,
        "b7 read completion",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1801,
        "fake-block7",
        1797,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b31,
        "b7 backend",
    ));
    let digest = SemanticGraph::expected_block_read_digest_v1(
        0x766d_6f73_626c_6b31,
        1797,
        1,
        1798,
        1,
        64,
        8,
        1,
        4096,
    );
    (graph, digest)
}

#[test]
pub(super) fn block_runtime_b7_read_path_records_backend_request_completion_and_digest() {
    let (mut graph, digest) = setup_b7_block_read_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b7-test",
        SemanticCommand::RecordBlockReadPath {
            read_path: 1802,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
            block_request: 1799,
            block_request_generation: 1,
            block_completion: 1800,
            block_completion_generation: 1,
            data_digest: digest,
            note: "b7 record read path".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_read_path_count(), 1);
    let read_path = &graph.block_read_paths()[0];
    assert_eq!(
        read_path.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockReadPath, 1802, 1)
    );
    assert_eq!(
        read_path.backend,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1)
    );
    assert_eq!(read_path.block_request, 1799);
    assert_eq!(read_path.block_completion, 1800);
    assert_eq!(read_path.completed_bytes, 4096);
    assert_eq!(read_path.data_digest, digest);
    assert_eq!(read_path.state, BlockReadPathState::Completed);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "BlockReadPathRecorded read_path=1802 backend=fake-block-backend-object:1801@1 block_request=1799@1 block_completion=1800@1 block_device=1797@1 block_range=1798@1 sequence=1 completed_bytes=4096 data_digest={digest} generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b7_rejects_duplicate_stale_write_and_bad_digest_paths() {
    let (mut graph, digest) = setup_b7_block_read_graph();
    assert!(graph.record_block_read_path_with_id(
        1802,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
        1799,
        1,
        1800,
        1,
        digest,
        "b7 existing read path",
    ));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b7-test",
        SemanticCommand::RecordBlockReadPath {
            read_path: 1803,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
            block_request: 1799,
            block_request_generation: 1,
            block_completion: 1800,
            block_completion_generation: 1,
            data_digest: digest,
            note: "b7 duplicate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["block read path already exists for request generation".to_string()]
    );

    let stale_backend = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b7-test",
        SemanticCommand::RecordBlockReadPath {
            read_path: 1804,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 2),
            block_request: 1799,
            block_request_generation: 1,
            block_completion: 1800,
            block_completion_generation: 1,
            data_digest: digest,
            note: "b7 stale backend".to_string(),
        },
    ));
    assert_eq!(stale_backend.status, CommandStatus::Rejected);
    assert_eq!(
        stale_backend.violations,
        vec!["block read path backend generation is missing or inactive".to_string()]
    );

    let bad_digest = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b7-test",
        SemanticCommand::RecordBlockReadPath {
            read_path: 1805,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
            block_request: 1799,
            block_request_generation: 1,
            block_completion: 1800,
            block_completion_generation: 1,
            data_digest: digest.wrapping_add(1),
            note: "b7 bad digest".to_string(),
        },
    ));
    assert_eq!(bad_digest.status, CommandStatus::Rejected);
    assert_eq!(bad_digest.violations, vec!["block read path data digest mismatch".to_string()]);

    assert!(graph.record_block_request_object_with_id(
        1806,
        1797,
        1,
        1798,
        1,
        BlockRequestOperation::Write,
        2,
        "b7 write request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1807,
        1806,
        1,
        2,
        4096,
        BlockCompletionStatus::Success,
        "b7 write completion",
    ));
    let write_request = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b7-test",
        SemanticCommand::RecordBlockReadPath {
            read_path: 1808,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
            block_request: 1806,
            block_request_generation: 1,
            block_completion: 1807,
            block_completion_generation: 1,
            data_digest: digest,
            note: "b7 write as read".to_string(),
        },
    ));
    assert_eq!(write_request.status, CommandStatus::Rejected);
    assert_eq!(
        write_request.violations,
        vec!["block read path request operation is not read".to_string()]
    );
}

#[test]
pub(super) fn block_runtime_b7_invariants_reject_backend_generation_and_digest_leaks() {
    let (mut graph, digest) = setup_b7_block_read_graph();
    assert!(graph.record_block_read_path_with_id(
        1802,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
        1799,
        1,
        1800,
        1,
        digest,
        "b7 invariant read path",
    ));
    graph.corrupt_block_read_path_backend_generation_for_test(1802, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockReadPathMissingBackend {
            read_path: 1802,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 2),
        })
    );

    let (mut graph, digest) = setup_b7_block_read_graph();
    assert!(graph.record_block_read_path_with_id(
        1802,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
        1799,
        1,
        1800,
        1,
        digest,
        "b7 invariant read path",
    ));
    graph.corrupt_block_read_path_data_digest_for_test(1802, digest.wrapping_add(1));
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockReadPathInvalid { read_path: 1802 })
    );
}

pub(in crate::tests) fn setup_b8_block_write_graph() -> (SemanticGraph, u64) {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk8");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1810,
        "fake-block8",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b8 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1811,
        "blk8",
        1810,
        1,
        512,
        4096,
        false,
        128,
        "b8 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1812, 1811, 1, 96, 8, "b8 range"));
    assert!(graph.record_block_request_object_with_id(
        1813,
        1811,
        1,
        1812,
        1,
        BlockRequestOperation::Write,
        2,
        "b8 write request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1814,
        1813,
        1,
        2,
        4096,
        BlockCompletionStatus::Success,
        "b8 write completion",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1815,
        "fake-block8",
        1811,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b38,
        "b8 backend",
    ));
    let digest = SemanticGraph::expected_block_write_payload_digest_v1(
        0x766d_6f73_626c_6b38,
        1811,
        1,
        1812,
        1,
        96,
        8,
        2,
        4096,
    );
    (graph, digest)
}

#[test]
pub(super) fn block_runtime_b8_write_path_records_backend_request_completion_and_payload_digest() {
    let (mut graph, digest) = setup_b8_block_write_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b8-test",
        SemanticCommand::RecordBlockWritePath {
            write_path: 1816,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
            block_request: 1813,
            block_request_generation: 1,
            block_completion: 1814,
            block_completion_generation: 1,
            payload_digest: digest,
            note: "b8 record write path".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_write_path_count(), 1);
    let write_path = &graph.block_write_paths()[0];
    assert_eq!(
        write_path.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockWritePath, 1816, 1)
    );
    assert_eq!(
        write_path.backend,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1)
    );
    assert_eq!(write_path.block_request, 1813);
    assert_eq!(write_path.block_completion, 1814);
    assert_eq!(write_path.completed_bytes, 4096);
    assert_eq!(write_path.payload_digest, digest);
    assert_eq!(write_path.state, BlockWritePathState::Completed);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "BlockWritePathRecorded write_path=1816 backend=fake-block-backend-object:1815@1 block_request=1813@1 block_completion=1814@1 block_device=1811@1 block_range=1812@1 sequence=2 completed_bytes=4096 payload_digest={digest} generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b8_rejects_duplicate_stale_read_and_bad_digest_paths() {
    let (mut graph, digest) = setup_b8_block_write_graph();
    assert!(graph.record_block_write_path_with_id(
        1816,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
        1813,
        1,
        1814,
        1,
        digest,
        "b8 existing write path",
    ));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b8-test",
        SemanticCommand::RecordBlockWritePath {
            write_path: 1817,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
            block_request: 1813,
            block_request_generation: 1,
            block_completion: 1814,
            block_completion_generation: 1,
            payload_digest: digest,
            note: "b8 duplicate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["block write path already exists for request generation".to_string()]
    );

    let stale_backend = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b8-test",
        SemanticCommand::RecordBlockWritePath {
            write_path: 1818,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 2),
            block_request: 1813,
            block_request_generation: 1,
            block_completion: 1814,
            block_completion_generation: 1,
            payload_digest: digest,
            note: "b8 stale backend".to_string(),
        },
    ));
    assert_eq!(stale_backend.status, CommandStatus::Rejected);
    assert_eq!(
        stale_backend.violations,
        vec!["block write path backend generation is missing or inactive".to_string()]
    );

    let bad_digest = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b8-test",
        SemanticCommand::RecordBlockWritePath {
            write_path: 1819,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
            block_request: 1813,
            block_request_generation: 1,
            block_completion: 1814,
            block_completion_generation: 1,
            payload_digest: digest.wrapping_add(1),
            note: "b8 bad digest".to_string(),
        },
    ));
    assert_eq!(bad_digest.status, CommandStatus::Rejected);
    assert_eq!(bad_digest.violations, vec!["block write path payload digest mismatch".to_string()]);

    assert!(graph.record_block_request_object_with_id(
        1820,
        1811,
        1,
        1812,
        1,
        BlockRequestOperation::Read,
        3,
        "b8 read request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1821,
        1820,
        1,
        3,
        4096,
        BlockCompletionStatus::Success,
        "b8 read completion",
    ));
    let read_request = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b8-test",
        SemanticCommand::RecordBlockWritePath {
            write_path: 1822,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
            block_request: 1820,
            block_request_generation: 1,
            block_completion: 1821,
            block_completion_generation: 1,
            payload_digest: digest,
            note: "b8 read as write".to_string(),
        },
    ));
    assert_eq!(read_request.status, CommandStatus::Rejected);
    assert_eq!(
        read_request.violations,
        vec!["block write path request operation is not write".to_string()]
    );
}

#[test]
pub(super) fn block_runtime_b8_invariants_reject_backend_generation_and_payload_digest_leaks() {
    let (mut graph, digest) = setup_b8_block_write_graph();
    assert!(graph.record_block_write_path_with_id(
        1816,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
        1813,
        1,
        1814,
        1,
        digest,
        "b8 invariant write path",
    ));
    graph.corrupt_block_write_path_backend_generation_for_test(1816, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockWritePathMissingBackend {
            write_path: 1816,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 2),
        })
    );

    let (mut graph, digest) = setup_b8_block_write_graph();
    assert!(graph.record_block_write_path_with_id(
        1816,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
        1813,
        1,
        1814,
        1,
        digest,
        "b8 invariant write path",
    ));
    graph.corrupt_block_write_path_payload_digest_for_test(1816, digest.wrapping_add(1));
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockWritePathInvalid { write_path: 1816 })
    );
}

pub(in crate::tests) fn setup_b9_block_request_queue_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk9");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1823,
        "fake-block9",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b9 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1824,
        "blk9",
        1823,
        1,
        512,
        4096,
        false,
        128,
        "b9 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1825, 1824, 1, 128, 8, "b9 range"));
    assert!(graph.record_block_request_object_with_id(
        1826,
        1824,
        1,
        1825,
        1,
        BlockRequestOperation::Read,
        1,
        "b9 completed read request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1827,
        1826,
        1,
        1,
        4096,
        BlockCompletionStatus::Success,
        "b9 read completion",
    ));
    assert!(graph.record_block_request_object_with_id(
        1828,
        1824,
        1,
        1825,
        1,
        BlockRequestOperation::Write,
        2,
        "b9 pending write request",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1829,
        "fake-block9",
        1824,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b39,
        "b9 backend",
    ));
    graph
}

#[test]
pub(super) fn block_runtime_b9_request_queue_records_backend_device_request_order() {
    let mut graph = setup_b9_block_request_queue_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b9-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1830,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_device: 1824,
            block_device_generation: 1,
            depth: 4,
            entries: vec![
                BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
                BlockRequestQueueEntryRef::pending(1828, 1),
            ],
            note: "b9 record request queue".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_request_queue_count(), 1);
    let queue = &graph.block_request_queues()[0];
    assert_eq!(
        queue.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockRequestQueue, 1830, 1)
    );
    assert_eq!(
        queue.backend,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1)
    );
    assert_eq!(queue.block_device, 1824);
    assert_eq!(queue.depth, 4);
    assert_eq!(queue.entries.len(), 2);
    assert_eq!(queue.pending_count, 1);
    assert_eq!(queue.completed_count, 1);
    assert_eq!(queue.first_sequence, 1);
    assert_eq!(queue.last_sequence, 2);
    assert_eq!(queue.entries[0].state, BlockRequestQueueEntryState::Completed);
    assert_eq!(queue.entries[1].state, BlockRequestQueueEntryState::Pending);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockRequestQueueRecorded queue=1830 backend=fake-block-backend-object:1829@1 block_device=1824@1 depth=4 request_count=2 pending_count=1 completed_count=1 first_sequence=1 last_sequence=2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b9_rejects_duplicate_stale_overdepth_and_bad_completion_queues() {
    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_block_request_queue_with_id(
        1830,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::pending(1828, 1),
        ],
        "b9 existing queue",
    ));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b9-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1831,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_device: 1824,
            block_device_generation: 1,
            depth: 4,
            entries: vec![BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1)],
            note: "b9 duplicate request".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["block request queue request already belongs to an active queue".to_string()]
    );

    let stale_backend = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b9-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1832,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 2),
            block_device: 1824,
            block_device_generation: 1,
            depth: 4,
            entries: vec![BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1)],
            note: "b9 stale backend".to_string(),
        },
    ));
    assert_eq!(stale_backend.status, CommandStatus::Rejected);
    assert_eq!(
        stale_backend.violations,
        vec!["block request queue backend generation is missing or inactive".to_string()]
    );

    let over_depth = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b9-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1833,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_device: 1824,
            block_device_generation: 1,
            depth: 1,
            entries: vec![
                BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
                BlockRequestQueueEntryRef::pending(1828, 1),
            ],
            note: "b9 over depth".to_string(),
        },
    ));
    assert_eq!(over_depth.status, CommandStatus::Rejected);
    assert_eq!(over_depth.violations, vec!["block request queue depth exceeded".to_string()]);

    assert!(graph.record_block_request_object_with_id(
        1834,
        1824,
        1,
        1825,
        1,
        BlockRequestOperation::Read,
        3,
        "b9 second completed request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1835,
        1834,
        1,
        3,
        4096,
        BlockCompletionStatus::Success,
        "b9 second completion",
    ));
    let bad_completion = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b9-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1836,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_device: 1824,
            block_device_generation: 1,
            depth: 4,
            entries: vec![BlockRequestQueueEntryRef::completed(1834, 1, 1827, 1)],
            note: "b9 bad completion".to_string(),
        },
    ));
    assert_eq!(bad_completion.status, CommandStatus::Rejected);
    assert_eq!(
        bad_completion.violations,
        vec!["block request queue completion does not match request".to_string()]
    );
}

#[test]
pub(super) fn block_runtime_b9_invariants_reject_backend_generation_and_count_leaks() {
    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_block_request_queue_with_id(
        1830,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::pending(1828, 1),
        ],
        "b9 invariant queue",
    ));
    graph.corrupt_block_request_queue_backend_generation_for_test(1830, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRequestQueueMissingBackend {
            queue: 1830,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 2),
        })
    );

    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_block_request_queue_with_id(
        1830,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::pending(1828, 1),
        ],
        "b9 invariant queue",
    ));
    graph.corrupt_block_request_queue_block_device_generation_for_test(1830, 2);
    assert_eq!(
        graph.check_block_request_queue_invariants(),
        Err(SemanticInvariantError::BlockRequestQueueMissingBlockDevice {
            queue: 1830,
            block_device: 1824,
        })
    );

    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_block_request_queue_with_id(
        1830,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::pending(1828, 1),
        ],
        "b9 invariant queue",
    ));
    graph.corrupt_block_request_queue_pending_count_for_test(1830, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRequestQueueInvalid { queue: 1830 })
    );
}
