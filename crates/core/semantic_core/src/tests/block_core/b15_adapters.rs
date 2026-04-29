use super::*;

pub(in crate::tests) fn setup_b15_fat_adapter_graph() -> SemanticGraph {
    let mut graph = setup_b14_directory_object_graph();
    assert!(graph.record_directory_object_with_id(
        1850,
        1845,
        1,
        "rootfs",
        "demo-dir",
        "/demo",
        "file.txt",
        "demo-file",
        "/demo/file.txt",
        DirectoryEntryKind::File,
        4096,
        0xB13,
        DirectoryObjectState::Cached,
        "b15 source directory object",
    ));
    graph
}

#[test]
pub(super) fn block_runtime_b15_fat_adapter_records_read_write_contract() {
    let mut graph = setup_b15_fat_adapter_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b15-test",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 1855,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "fatfs".to_string(),
            version: "0.3.6".to_string(),
            profile: "fatfs-read-write-demo-v1".to_string(),
            volume_label: "VMOSFAT".to_string(),
            image_bytes: 1_048_576,
            adapter_path: "DEMO.TXT".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x5151,
            read_digest: 0x5151,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "b15 record fat adapter object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.fat_adapter_object_count(), 1);
    let adapter = &graph.fat_adapter_objects()[0];
    assert_eq!(
        adapter.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FatAdapterObject, 1855, 1)
    );
    assert_eq!(adapter.directory_object, 1850);
    assert_eq!(adapter.file_object, 1845);
    assert_eq!(adapter.block_device, 1824);
    assert_eq!(adapter.implementation, "fatfs");
    assert_eq!(adapter.profile, "fatfs-read-write-demo-v1");
    assert_eq!(adapter.adapter_path, "DEMO.TXT");
    assert_eq!(adapter.semantic_path, "/demo/file.txt");
    assert_eq!(adapter.bytes_written, 35);
    assert_eq!(adapter.bytes_read, 35);
    assert_eq!(adapter.write_digest, 0x5151);
    assert_eq!(adapter.read_digest, 0x5151);
    assert_eq!(adapter.file_content_digest, 0xB13);
    assert_eq!(adapter.state, FatAdapterObjectState::Verified);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FatAdapterObjectRecorded fat_adapter_object=1855 directory_object=1850@1 file_object=1845@1 block_device=1824@1 implementation=fatfs version=0.3.6 profile=fatfs-read-write-demo-v1 volume_label=VMOSFAT image_bytes=1048576 adapter_path=DEMO.TXT semantic_path=/demo/file.txt bytes_written=35 bytes_read=35 write_digest=20817 read_digest=20817 file_content_digest=2835 state=verified generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b15_rejects_stale_mismatch_duplicate_and_invalid_adapter() {
    let mut graph = setup_b15_fat_adapter_graph();

    let stale_directory = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b15-test",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 1856,
            directory_object: 1850,
            directory_object_generation: 2,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "fatfs".to_string(),
            version: "0.3.6".to_string(),
            profile: "fatfs-read-write-demo-v1".to_string(),
            volume_label: "VMOSFAT".to_string(),
            image_bytes: 1_048_576,
            adapter_path: "DEMO.TXT".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x5151,
            read_digest: 0x5151,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "stale directory generation".to_string(),
        },
    ));
    assert_eq!(stale_directory.status, CommandStatus::Rejected);
    assert_eq!(
        stale_directory.violations,
        vec!["fat adapter directory generation is missing".to_string()]
    );

    let digest_mismatch = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b15-test",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 1857,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "fatfs".to_string(),
            version: "0.3.6".to_string(),
            profile: "fatfs-read-write-demo-v1".to_string(),
            volume_label: "VMOSFAT".to_string(),
            image_bytes: 1_048_576,
            adapter_path: "BROKEN.TXT".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x5151,
            read_digest: 0x5152,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "digest mismatch".to_string(),
        },
    ));
    assert_eq!(digest_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        digest_mismatch.violations,
        vec!["fat adapter read/write roundtrip mismatch".to_string()]
    );

    let invalid_state = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b15-test",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 1858,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "fatfs".to_string(),
            version: "0.3.6".to_string(),
            profile: "fatfs-read-write-demo-v1".to_string(),
            volume_label: "VMOSFAT".to_string(),
            image_bytes: 1_048_576,
            adapter_path: "INVALID.TXT".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x5151,
            read_digest: 0x5151,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Rejected,
            note: "invalid adapter state".to_string(),
        },
    ));
    assert_eq!(invalid_state.status, CommandStatus::Rejected);
    assert_eq!(invalid_state.violations, vec!["fat adapter object must be verified".to_string()]);

    assert!(graph.record_fat_adapter_object_with_id(
        1855,
        1850,
        1,
        1845,
        1,
        1824,
        1,
        "fatfs",
        "0.3.6",
        "fatfs-read-write-demo-v1",
        "VMOSFAT",
        1_048_576,
        "DEMO.TXT",
        "/demo/file.txt",
        35,
        35,
        0x5151,
        0x5151,
        0xB13,
        FatAdapterObjectState::Verified,
        "b15 existing fat adapter binding",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b15-test",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 1859,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "fatfs".to_string(),
            version: "0.3.6".to_string(),
            profile: "fatfs-read-write-demo-v1".to_string(),
            volume_label: "VMOSFAT".to_string(),
            image_bytes: 1_048_576,
            adapter_path: "DEMO.TXT".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x5151,
            read_digest: 0x5151,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "duplicate fat adapter binding".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(duplicate.violations, vec!["fat adapter binding already verified".to_string()]);
}

#[test]
pub(super) fn block_runtime_b15_invariants_reject_fat_adapter_generation_leak() {
    let mut graph = setup_b15_fat_adapter_graph();
    assert!(graph.record_fat_adapter_object_with_id(
        1855,
        1850,
        1,
        1845,
        1,
        1824,
        1,
        "fatfs",
        "0.3.6",
        "fatfs-read-write-demo-v1",
        "VMOSFAT",
        1_048_576,
        "DEMO.TXT",
        "/demo/file.txt",
        35,
        35,
        0x5151,
        0x5151,
        0xB13,
        FatAdapterObjectState::Verified,
        "b15 invariant fat adapter object",
    ));
    graph.corrupt_fat_adapter_file_generation_for_test(1855, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FatAdapterObjectMissingFileObject {
            fat_adapter_object: 1855,
            file_object: 1845,
        })
    );
}

pub(in crate::tests) fn setup_b16_ext4_adapter_graph() -> SemanticGraph {
    setup_b15_fat_adapter_graph()
}

#[test]
pub(super) fn block_runtime_b16_ext4_adapter_records_read_only_contract() {
    let mut graph = setup_b16_ext4_adapter_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b16-test",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 1860,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "ext4-view".to_string(),
            version: "0.9.3".to_string(),
            profile: "ext4-read-only-demo-v1".to_string(),
            volume_label: "VMOSEXT4".to_string(),
            image_bytes: 32_768,
            adapter_path: "/demo.txt".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_read: 34,
            read_digest: 0x6161,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: true,
            state: Ext4AdapterObjectState::Verified,
            note: "b16 record ext4 adapter object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.ext4_adapter_object_count(), 1);
    let adapter = &graph.ext4_adapter_objects()[0];
    assert_eq!(
        adapter.object_ref(),
        ContractObjectRef::new(ContractObjectKind::Ext4AdapterObject, 1860, 1)
    );
    assert_eq!(adapter.directory_object, 1850);
    assert_eq!(adapter.file_object, 1845);
    assert_eq!(adapter.block_device, 1824);
    assert_eq!(adapter.implementation, "ext4-view");
    assert_eq!(adapter.profile, "ext4-read-only-demo-v1");
    assert_eq!(adapter.adapter_path, "/demo.txt");
    assert_eq!(adapter.semantic_path, "/demo/file.txt");
    assert_eq!(adapter.bytes_read, 34);
    assert_eq!(adapter.read_digest, 0x6161);
    assert_eq!(adapter.file_content_digest, 0xB13);
    assert_eq!(adapter.directory_entries, 1);
    assert!(adapter.read_only_enforced);
    assert_eq!(adapter.state, Ext4AdapterObjectState::Verified);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "Ext4AdapterObjectRecorded ext4_adapter_object=1860 directory_object=1850@1 file_object=1845@1 block_device=1824@1 implementation=ext4-view version=0.9.3 profile=ext4-read-only-demo-v1 volume_label=VMOSEXT4 image_bytes=32768 adapter_path=/demo.txt semantic_path=/demo/file.txt bytes_read=34 read_digest=24929 file_content_digest=2835 directory_entries=1 read_only_enforced=true state=verified generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b16_rejects_stale_not_read_only_duplicate_and_invalid_adapter() {
    let mut graph = setup_b16_ext4_adapter_graph();

    let stale_directory = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b16-test",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 1861,
            directory_object: 1850,
            directory_object_generation: 2,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "ext4-view".to_string(),
            version: "0.9.3".to_string(),
            profile: "ext4-read-only-demo-v1".to_string(),
            volume_label: "VMOSEXT4".to_string(),
            image_bytes: 32_768,
            adapter_path: "/demo.txt".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_read: 34,
            read_digest: 0x6161,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: true,
            state: Ext4AdapterObjectState::Verified,
            note: "stale directory generation".to_string(),
        },
    ));
    assert_eq!(stale_directory.status, CommandStatus::Rejected);
    assert_eq!(
        stale_directory.violations,
        vec!["ext4 adapter directory generation is missing".to_string()]
    );

    let not_read_only = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b16-test",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 1862,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "ext4-view".to_string(),
            version: "0.9.3".to_string(),
            profile: "ext4-read-only-demo-v1".to_string(),
            volume_label: "VMOSEXT4".to_string(),
            image_bytes: 32_768,
            adapter_path: "/demo-ro-false.txt".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_read: 34,
            read_digest: 0x6161,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: false,
            state: Ext4AdapterObjectState::Verified,
            note: "not read-only".to_string(),
        },
    ));
    assert_eq!(not_read_only.status, CommandStatus::Rejected);
    assert_eq!(
        not_read_only.violations,
        vec!["ext4 adapter object must be verified read-only evidence".to_string()]
    );

    let invalid_state = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b16-test",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 1863,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "ext4-view".to_string(),
            version: "0.9.3".to_string(),
            profile: "ext4-read-only-demo-v1".to_string(),
            volume_label: "VMOSEXT4".to_string(),
            image_bytes: 32_768,
            adapter_path: "/invalid.txt".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_read: 34,
            read_digest: 0x6161,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: true,
            state: Ext4AdapterObjectState::Rejected,
            note: "invalid adapter state".to_string(),
        },
    ));
    assert_eq!(invalid_state.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_state.violations,
        vec!["ext4 adapter object must be verified read-only evidence".to_string()]
    );

    assert!(graph.record_ext4_adapter_object_with_id(
        1860,
        1850,
        1,
        1845,
        1,
        1824,
        1,
        "ext4-view",
        "0.9.3",
        "ext4-read-only-demo-v1",
        "VMOSEXT4",
        32_768,
        "/demo.txt",
        "/demo/file.txt",
        34,
        0x6161,
        0xB13,
        1,
        true,
        Ext4AdapterObjectState::Verified,
        "b16 existing ext4 adapter binding",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b16-test",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 1864,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "ext4-view".to_string(),
            version: "0.9.3".to_string(),
            profile: "ext4-read-only-demo-v1".to_string(),
            volume_label: "VMOSEXT4".to_string(),
            image_bytes: 32_768,
            adapter_path: "/demo.txt".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_read: 34,
            read_digest: 0x6161,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: true,
            state: Ext4AdapterObjectState::Verified,
            note: "duplicate ext4 adapter binding".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(duplicate.violations, vec!["ext4 adapter binding already verified".to_string()]);
}

#[test]
pub(super) fn block_runtime_b16_invariants_reject_ext4_adapter_generation_leak() {
    let mut graph = setup_b16_ext4_adapter_graph();
    assert!(graph.record_ext4_adapter_object_with_id(
        1860,
        1850,
        1,
        1845,
        1,
        1824,
        1,
        "ext4-view",
        "0.9.3",
        "ext4-read-only-demo-v1",
        "VMOSEXT4",
        32_768,
        "/demo.txt",
        "/demo/file.txt",
        34,
        0x6161,
        0xB13,
        1,
        true,
        Ext4AdapterObjectState::Verified,
        "b16 invariant ext4 adapter object",
    ));
    graph.corrupt_ext4_adapter_file_generation_for_test(1860, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::Ext4AdapterObjectMissingFileObject {
            ext4_adapter_object: 1860,
            file_object: 1845,
        })
    );
}
