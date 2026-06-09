use super::*;

#[test]
pub(super) fn block_runtime_b0_block_device_object_records_contract_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1701,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b0 backing device",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b0-test",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 1702,
            name: "blk0".to_string(),
            device: 1701,
            device_generation: 1,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0 block device object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_device_object_count(), 1);
    let block_device = &graph.block_device_objects()[0];
    assert_eq!(
        block_device.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockDeviceObject, 1702, 1)
    );
    assert_eq!(block_device.device, 1701);
    assert_eq!(block_device.device_generation, 1);
    assert_eq!(block_device.sector_size, 512);
    assert_eq!(block_device.sector_count, 4096);
    assert_eq!(block_device.max_transfer_sectors, 128);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockDeviceObjectRecorded block_device=1702 device=1701@1 sector_size=512 sector_count=4096 read_only=false max_transfer_sectors=128 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b0_rejects_stale_or_non_block_device() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:not-block");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1703,
        "not-block0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "visa",
        "fake-io-v1",
        "b0 wrong backing device",
    ));

    let wrong_class = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b0-test",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 1704,
            name: "blk0".to_string(),
            device: 1703,
            device_generation: 1,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0 wrong class".to_string(),
        },
    ));
    assert_eq!(wrong_class.status, CommandStatus::Rejected);

    let block_resource =
        graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk1");
    let block_resource_generation = graph.resource_handle(block_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1705,
        "fake-block1",
        "block-device",
        block_resource,
        block_resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b0 stale backing device",
    ));
    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b0-test",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 1706,
            name: "blk1".to_string(),
            device: 1705,
            device_generation: 2,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0 stale generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let bad_contract = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b0-test",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 1709,
            name: "blk1".to_string(),
            device: 1705,
            device_generation: 1,
            sector_size: 0,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0 bad sector size".to_string(),
        },
    ));
    assert_eq!(bad_contract.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn block_runtime_b0_invariants_reject_block_device_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1707,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b0 invariant backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1708,
        "blk0",
        1707,
        1,
        512,
        4096,
        false,
        128,
        "b0 invariant block device",
    ));
    graph.corrupt_block_device_object_device_generation_for_test(1708, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockDeviceObjectMissingDevice {
            block_device: 1708,
            device: 1707,
        })
    );
}

#[test]
pub(super) fn block_runtime_b1_block_range_records_sector_and_byte_bounds() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1710,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b1 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1711,
        "blk0",
        1710,
        1,
        512,
        4096,
        false,
        128,
        "b1 block device",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b1-test",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 1712,
            block_device: 1711,
            block_device_generation: 1,
            start_sector: 64,
            sector_count: 8,
            note: "b1 range".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_range_object_count(), 1);
    let block_range = &graph.block_range_objects()[0];
    assert_eq!(
        block_range.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockRangeObject, 1712, 1)
    );
    assert_eq!(block_range.block_device, 1711);
    assert_eq!(block_range.block_device_generation, 1);
    assert_eq!(block_range.start_sector, 64);
    assert_eq!(block_range.sector_count, 8);
    assert_eq!(block_range.byte_offset, 32768);
    assert_eq!(block_range.byte_len, 4096);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockRangeObjectRecorded block_range=1712 block_device=1711@1 start_sector=64 sector_count=8 byte_offset=32768 byte_len=4096 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b1_rejects_stale_out_of_bounds_and_over_transfer_ranges() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1713,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b1 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1714,
        "blk0",
        1713,
        1,
        512,
        4096,
        false,
        128,
        "b1 block device",
    ));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b1-test",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 1715,
            block_device: 1714,
            block_device_generation: 2,
            start_sector: 64,
            sector_count: 8,
            note: "b1 stale device generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let out_of_bounds = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b1-test",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 1716,
            block_device: 1714,
            block_device_generation: 1,
            start_sector: 4090,
            sector_count: 16,
            note: "b1 out of bounds".to_string(),
        },
    ));
    assert_eq!(out_of_bounds.status, CommandStatus::Rejected);

    let over_transfer = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b1-test",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 1717,
            block_device: 1714,
            block_device_generation: 1,
            start_sector: 128,
            sector_count: 129,
            note: "b1 over transfer".to_string(),
        },
    ));
    assert_eq!(over_transfer.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn block_runtime_b1_invariants_reject_block_range_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1718,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b1 invariant backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1719,
        "blk0",
        1718,
        1,
        512,
        4096,
        false,
        128,
        "b1 invariant block device",
    ));
    assert!(graph.record_block_range_object_with_id(1720, 1719, 1, 64, 8, "b1 invariant range",));
    graph.corrupt_block_range_object_device_generation_for_test(1720, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRangeObjectMissingDevice {
            block_range: 1720,
            block_device: 1719,
        })
    );
}

#[test]
pub(super) fn block_runtime_b2_block_request_records_range_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1721,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b2 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1722,
        "blk0",
        1721,
        1,
        512,
        4096,
        false,
        128,
        "b2 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1723, 1722, 1, 64, 8, "b2 range",));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b2-test",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 1724,
            block_device: 1722,
            block_device_generation: 1,
            block_range: 1723,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 1,
            note: "b2 request".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_request_object_count(), 1);
    let request = &graph.block_request_objects()[0];
    assert_eq!(
        request.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1724, 1)
    );
    assert_eq!(request.block_device, 1722);
    assert_eq!(request.block_device_generation, 1);
    assert_eq!(request.block_range, 1723);
    assert_eq!(request.block_range_generation, 1);
    assert_eq!(request.operation, BlockRequestOperation::Read);
    assert_eq!(request.sequence, 1);
    assert_eq!(request.byte_len, 4096);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockRequestObjectRecorded block_request=1724 block_device=1722@1 block_range=1723@1 operation=read sequence=1 byte_len=4096 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b2_rejects_stale_duplicate_and_read_only_write() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1725,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b2 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1726,
        "blk0",
        1725,
        1,
        512,
        4096,
        true,
        128,
        "b2 read-only block device",
    ));
    assert!(graph.record_block_range_object_with_id(1727, 1726, 1, 64, 8, "b2 range",));
    assert!(graph.record_block_request_object_with_id(
        1728,
        1726,
        1,
        1727,
        1,
        BlockRequestOperation::Read,
        1,
        "b2 existing read",
    ));

    let stale_range = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b2-test",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 1729,
            block_device: 1726,
            block_device_generation: 1,
            block_range: 1727,
            block_range_generation: 2,
            operation: BlockRequestOperation::Read,
            sequence: 2,
            note: "b2 stale range".to_string(),
        },
    ));
    assert_eq!(stale_range.status, CommandStatus::Rejected);

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b2-test",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 1730,
            block_device: 1726,
            block_device_generation: 1,
            block_range: 1727,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 1,
            note: "b2 duplicate sequence".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);

    let write_read_only = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b2-test",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 1731,
            block_device: 1726,
            block_device_generation: 1,
            block_range: 1727,
            block_range_generation: 1,
            operation: BlockRequestOperation::Write,
            sequence: 3,
            note: "b2 write read-only".to_string(),
        },
    ));
    assert_eq!(write_read_only.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn block_runtime_b2_invariants_reject_block_request_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1732,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b2 invariant backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1733,
        "blk0",
        1732,
        1,
        512,
        4096,
        false,
        128,
        "b2 invariant block device",
    ));
    assert!(graph.record_block_range_object_with_id(1734, 1733, 1, 64, 8, "b2 invariant range",));
    assert!(graph.record_block_request_object_with_id(
        1735,
        1733,
        1,
        1734,
        1,
        BlockRequestOperation::Read,
        1,
        "b2 invariant request",
    ));
    graph.corrupt_block_request_range_generation_for_test(1735, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRequestObjectMissingRange {
            block_request: 1735,
            block_range: 1734,
        })
    );
}

#[test]
pub(super) fn block_runtime_b3_block_completion_records_request_outcome() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1736,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b3 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1737,
        "blk0",
        1736,
        1,
        512,
        4096,
        false,
        128,
        "b3 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1738, 1737, 1, 64, 8, "b3 range",));
    assert!(graph.record_block_request_object_with_id(
        1739,
        1737,
        1,
        1738,
        1,
        BlockRequestOperation::Read,
        1,
        "b3 request",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b3-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1740,
            block_request: 1739,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3 completion".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_completion_object_count(), 1);
    let completion = &graph.block_completion_objects()[0];
    assert_eq!(
        completion.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockCompletionObject, 1740, 1)
    );
    assert_eq!(completion.block_request, 1739);
    assert_eq!(completion.block_request_generation, 1);
    assert_eq!(completion.block_device, 1737);
    assert_eq!(completion.block_range, 1738);
    assert_eq!(completion.sequence, 1);
    assert_eq!(completion.completed_bytes, 4096);
    assert_eq!(completion.status, BlockCompletionStatus::Success);
    assert_eq!(graph.block_request_objects()[0].state, BlockRequestObjectState::Completed);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockCompletionObjectRecorded block_completion=1740 block_request=1739@1 block_device=1737@1 block_range=1738@1 sequence=1 completed_bytes=4096 status=success generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b3_rejects_stale_duplicate_and_bad_byte_count() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1741,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b3 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1742,
        "blk0",
        1741,
        1,
        512,
        4096,
        false,
        128,
        "b3 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1743, 1742, 1, 64, 8, "b3 range",));
    assert!(graph.record_block_request_object_with_id(
        1744,
        1742,
        1,
        1743,
        1,
        BlockRequestOperation::Read,
        1,
        "b3 existing request",
    ));

    let stale_request = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b3-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1745,
            block_request: 1744,
            block_request_generation: 2,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3 stale request".to_string(),
        },
    ));
    assert_eq!(stale_request.status, CommandStatus::Rejected);

    let completion = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b3-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1746,
            block_request: 1744,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3 completion".to_string(),
        },
    ));
    assert_eq!(completion.status, CommandStatus::Applied);

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b3-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1747,
            block_request: 1744,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3 duplicate completion".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);

    assert!(graph.record_block_request_object_with_id(
        1748,
        1742,
        1,
        1743,
        1,
        BlockRequestOperation::Read,
        2,
        "b3 second request",
    ));
    let partial_success = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b3-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1749,
            block_request: 1748,
            block_request_generation: 1,
            sequence: 2,
            completed_bytes: 2048,
            status: BlockCompletionStatus::Success,
            note: "b3 partial success".to_string(),
        },
    ));
    assert_eq!(partial_success.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn block_runtime_b3_invariants_reject_completion_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1750,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b3 invariant backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1751,
        "blk0",
        1750,
        1,
        512,
        4096,
        false,
        128,
        "b3 invariant block device",
    ));
    assert!(graph.record_block_range_object_with_id(1752, 1751, 1, 64, 8, "b3 invariant range",));
    assert!(graph.record_block_request_object_with_id(
        1753,
        1751,
        1,
        1752,
        1,
        BlockRequestOperation::Read,
        1,
        "b3 invariant request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1754,
        1753,
        1,
        1,
        4096,
        BlockCompletionStatus::Success,
        "b3 invariant completion",
    ));
    graph.corrupt_block_completion_request_generation_for_test(1754, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRequestObjectInvalid { block_request: 1753 })
    );
}

#[test]
pub(super) fn block_runtime_b4_block_wait_bridges_wait_token_to_completion() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1755,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b4 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1756,
        "blk0",
        1755,
        1,
        512,
        4096,
        false,
        128,
        "b4 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1757, 1756, 1, 64, 8, "b4 range",));
    assert!(graph.record_block_request_object_with_id(
        1758,
        1756,
        1,
        1757,
        1,
        BlockRequestOperation::Read,
        1,
        "b4 request",
    ));
    let driver_store = graph.register_store(
        "driver.fake-block0",
        "driver.fake-block0.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1758, 1);
    let create_wait = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b4-test",
        SemanticCommand::CreateWait {
            wait: 1759,
            owner_task: None,
            owner_store: Some(driver_store),
            owner_store_generation: Some(driver_store_generation),
            kind: SemanticWaitKind::DriverCompletion,
            generation: 1,
            blockers: vec![blocker],
            deadline: None,
            restart_policy: RestartPolicy::InternalOnly,
            saved_context: Some("b4-block-wait".to_string()),
        },
    ));
    assert_eq!(create_wait.status, CommandStatus::Applied);

    let record_wait = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b4-test",
        SemanticCommand::RecordBlockWait {
            block_wait: 1760,
            wait: 1759,
            wait_generation: 1,
            block_request: 1758,
            block_request_generation: 1,
            note: "b4 block wait".to_string(),
        },
    ));
    assert_eq!(record_wait.status, CommandStatus::Applied);
    assert_eq!(graph.block_wait_count(), 1);
    assert_eq!(
        graph.block_waits()[0].object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockWait, 1760, 1)
    );
    assert_eq!(graph.block_waits()[0].wait, 1759);
    assert_eq!(graph.block_waits()[0].block_request, 1758);
    assert_eq!(graph.block_waits()[0].state, BlockWaitState::Pending);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockWaitCreated block_wait=1760 wait=1759@1 block_request=1758@1 block_device=1756@1 block_range=1757@1 operation=read sequence=1 byte_len=4096 generation=1"
    );

    let completion = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b4-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1761,
            block_request: 1758,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b4 completion".to_string(),
        },
    ));
    assert_eq!(completion.status, CommandStatus::Applied);
    let resolve_wait = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b4-test",
        SemanticCommand::ResolveBlockWait {
            block_wait: 1760,
            block_wait_generation: 1,
            block_completion: 1761,
            block_completion_generation: 1,
            note: "b4 resolve block wait".to_string(),
        },
    ));
    assert_eq!(resolve_wait.status, CommandStatus::Applied);
    assert_eq!(graph.block_waits()[0].state, BlockWaitState::Resolved);
    assert_eq!(graph.block_waits()[0].completion, Some(1761));
    assert_eq!(graph.wait_records()[0].state, WaitState::Resolved);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockWaitResolved block_wait=1760 wait=1759@1 block_completion=1761@1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b4_rejects_stale_duplicate_and_bad_completion_waits() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1762,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b4 reject backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1763,
        "blk0",
        1762,
        1,
        512,
        4096,
        false,
        128,
        "b4 reject block device",
    ));
    assert!(graph.record_block_range_object_with_id(1764, 1763, 1, 64, 8, "b4 reject range",));
    assert!(graph.record_block_request_object_with_id(
        1765,
        1763,
        1,
        1764,
        1,
        BlockRequestOperation::Read,
        1,
        "b4 reject request",
    ));
    let driver_store = graph.register_store(
        "driver.fake-block1",
        "driver.fake-block1.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1765, 1);
    assert!(matches!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "b4-test",
                SemanticCommand::CreateWait {
                    wait: 1766,
                    owner_task: None,
                    owner_store: Some(driver_store),
                    owner_store_generation: Some(driver_store_generation),
                    kind: SemanticWaitKind::DriverCompletion,
                    generation: 1,
                    blockers: vec![blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::InternalOnly,
                    saved_context: None,
                },
            ))
            .status,
        CommandStatus::Applied
    ));
    assert!(graph.record_block_wait_with_id(1767, 1766, 1, 1765, 1, "b4 existing wait"));

    let stale_request = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b4-test",
        SemanticCommand::RecordBlockWait {
            block_wait: 1768,
            wait: 1766,
            wait_generation: 1,
            block_request: 1765,
            block_request_generation: 2,
            note: "b4 stale request".to_string(),
        },
    ));
    assert_eq!(stale_request.status, CommandStatus::Rejected);

    let duplicate_wait = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b4-test",
        SemanticCommand::RecordBlockWait {
            block_wait: 1769,
            wait: 1766,
            wait_generation: 1,
            block_request: 1765,
            block_request_generation: 1,
            note: "b4 duplicate wait".to_string(),
        },
    ));
    assert_eq!(duplicate_wait.status, CommandStatus::Rejected);

    assert!(graph.record_block_request_object_with_id(
        1770,
        1763,
        1,
        1764,
        1,
        BlockRequestOperation::Read,
        2,
        "b4 other request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1771,
        1770,
        1,
        2,
        4096,
        BlockCompletionStatus::Success,
        "b4 other completion",
    ));
    let wrong_completion = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b4-test",
        SemanticCommand::ResolveBlockWait {
            block_wait: 1767,
            block_wait_generation: 1,
            block_completion: 1771,
            block_completion_generation: 1,
            note: "b4 wrong completion".to_string(),
        },
    ));
    assert_eq!(wrong_completion.status, CommandStatus::Rejected);

    graph.record_wait_resolved(1766, "b4-direct-wait-resolution");
    let stale_wait_state = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b4-test",
        SemanticCommand::CancelBlockWait {
            block_wait: 1767,
            block_wait_generation: 1,
            errno: 5,
            reason: WaitCancelReason::DeviceFault,
            note: "b4 stale wait state".to_string(),
        },
    ));
    assert_eq!(stale_wait_state.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn block_runtime_b4_cancelled_wait_records_reason_and_invariant_generation() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1772,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b4 cancel backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1773,
        "blk0",
        1772,
        1,
        512,
        4096,
        false,
        128,
        "b4 cancel block device",
    ));
    assert!(graph.record_block_range_object_with_id(1774, 1773, 1, 64, 8, "b4 cancel range",));
    assert!(graph.record_block_request_object_with_id(
        1775,
        1773,
        1,
        1774,
        1,
        BlockRequestOperation::Read,
        1,
        "b4 cancel request",
    ));
    let driver_store = graph.register_store(
        "driver.fake-block2",
        "driver.fake-block2.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    graph.record_wait_created_with_details(
        1776,
        None,
        Some(driver_store),
        Some(driver_store_generation),
        SemanticWaitKind::DriverCompletion,
        1,
        vec![ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1775, 1)],
        None,
        RestartPolicy::InternalOnly,
        None,
    );
    assert!(graph.record_block_wait_with_id(1777, 1776, 1, 1775, 1, "b4 cancel wait"));
    let cancel = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b4-test",
        SemanticCommand::CancelBlockWait {
            block_wait: 1777,
            block_wait_generation: 1,
            errno: 5,
            reason: WaitCancelReason::DeviceFault,
            note: "b4 cancel block wait".to_string(),
        },
    ));
    assert_eq!(cancel.status, CommandStatus::Applied);
    assert_eq!(graph.block_waits()[0].state, BlockWaitState::Cancelled);
    assert_eq!(graph.block_waits()[0].cancel_reason, Some(WaitCancelReason::DeviceFault));
    assert_eq!(graph.wait_records()[0].state, WaitState::Cancelled);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockWaitCancelled block_wait=1777 wait=1776@1 reason=device-fault generation=1"
    );
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_block_wait_request_generation_for_test(1777, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockWaitMissingRequest {
            block_wait: 1777,
            block_request: 1775,
        })
    );
}

#[test]
pub(super) fn block_runtime_b5_fake_block_backend_binds_exact_block_device_contract() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1778,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b5 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1779,
        "blk0",
        1778,
        1,
        512,
        4096,
        false,
        128,
        "b5 block device",
    ));

    let command = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b5-test",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 1780,
            name: "fake-block0".to_string(),
            block_device: 1779,
            block_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-block-v1".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            deterministic_seed: 0x766d_6f73_626c_6b31,
            note: "b5 bind fake block backend".to_string(),
        },
    ));
    assert_eq!(command.status, CommandStatus::Applied);
    assert_eq!(graph.fake_block_backend_object_count(), 1);
    let backend = &graph.fake_block_backends()[0];
    assert_eq!(
        backend.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1780, 1)
    );
    assert_eq!(backend.block_device, 1779);
    assert_eq!(backend.block_device_generation, 1);
    assert_eq!(backend.state, FakeBlockBackendObjectState::Bound);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FakeBlockBackendObjectBound fake_block_backend=1780 block_device=1779@1 sector_size=512 sector_count=4096 read_only=false max_transfer_sectors=128 deterministic_seed=8533599410300152625 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b5_rejects_stale_duplicate_and_mismatched_backends() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk1");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1781,
        "fake-block1",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b5 reject backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1782,
        "blk1",
        1781,
        1,
        512,
        4096,
        false,
        128,
        "b5 reject block device",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1783,
        "fake-block1",
        1782,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b31,
        "b5 existing backend",
    ));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b5-test",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 1784,
            name: "fake-block1-duplicate".to_string(),
            block_device: 1782,
            block_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-block-v1".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            deterministic_seed: 0x766d_6f73_626c_6b31,
            note: "b5 duplicate backend".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);

    let stale = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b5-test",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 1785,
            name: "fake-block1-stale".to_string(),
            block_device: 1782,
            block_device_generation: 2,
            provider: "service_core".to_string(),
            profile: "fake-block-v1".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            deterministic_seed: 0x766d_6f73_626c_6b31,
            note: "b5 stale backend".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let mismatch = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b5-test",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 1786,
            name: "fake-block1-mismatch".to_string(),
            block_device: 1782,
            block_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-block-v1".to_string(),
            sector_size: 512,
            sector_count: 8192,
            read_only: false,
            max_transfer_sectors: 128,
            deterministic_seed: 0x766d_6f73_626c_6b31,
            note: "b5 mismatched backend".to_string(),
        },
    ));
    assert_eq!(mismatch.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn block_runtime_b5_invariants_reject_fake_backend_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk2");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1787,
        "fake-block2",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b5 invariant backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1788,
        "blk2",
        1787,
        1,
        512,
        4096,
        false,
        128,
        "b5 invariant block device",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1789,
        "fake-block2",
        1788,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b31,
        "b5 invariant backend",
    ));
    graph.corrupt_fake_block_backend_block_device_generation_for_test(1789, 2);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FakeBlockBackendObjectMissingBlockDevice {
            fake_block_backend: 1789,
            block_device: 1788,
        }),
    ));
}
