use super::*;

pub(in crate::tests) fn setup_b13_file_object_graph() -> SemanticGraph {
    let mut graph = setup_b12_buffer_cache_graph();
    assert!(graph.record_buffer_cache_object_with_id(
        1840,
        1835,
        1,
        b11_page(1903),
        1,
        0,
        4096,
        BufferCacheObjectState::Dirty,
        1,
        "b13 source buffer cache entry",
    ));
    graph
}

#[test]
pub(super) fn block_runtime_b13_file_object_records_cache_backed_file_contract() {
    let mut graph = setup_b13_file_object_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b13-test",
        SemanticCommand::RecordFileObject {
            file_object: 1845,
            buffer_cache_object: 1840,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_string(),
            file_key: "demo-file".to_string(),
            path: "/demo/file.txt".to_string(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "b13 record dirty file object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.file_object_count(), 1);
    let file = &graph.file_objects()[0];
    assert_eq!(file.object_ref(), ContractObjectRef::new(ContractObjectKind::FileObject, 1845, 1));
    assert_eq!(file.buffer_cache_object, 1840);
    assert_eq!(file.block_device, 1824);
    assert_eq!(file.block_range, 1825);
    assert_eq!(file.page, b11_page(1903));
    assert_eq!(file.namespace, "rootfs");
    assert_eq!(file.file_key, "demo-file");
    assert_eq!(file.path, "/demo/file.txt");
    assert_eq!(file.file_offset, 0);
    assert_eq!(file.byte_len, 4096);
    assert_eq!(file.file_size, 4096);
    assert_eq!(file.content_digest, 0xB13);
    assert_eq!(file.cache_state, BufferCacheObjectState::Dirty);
    assert_eq!(file.state, FileObjectState::Dirty);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FileObjectRecorded file_object=1845 buffer_cache_object=1840@1 block_device=1824@1 block_range=1825@1 page=page-object:1903@1 page_dirty_generation=1 namespace=rootfs file_key=demo-file path=/demo/file.txt file_offset=0 byte_len=4096 file_size=4096 content_digest=2835 cache_state=dirty state=dirty generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b13_rejects_stale_oversized_duplicate_and_invalid_file() {
    let mut graph = setup_b13_file_object_graph();

    let stale_cache = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b13-test",
        SemanticCommand::RecordFileObject {
            file_object: 1846,
            buffer_cache_object: 1840,
            buffer_cache_object_generation: 2,
            namespace: "rootfs".to_string(),
            file_key: "demo-file".to_string(),
            path: "/demo/file.txt".to_string(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "stale cache generation".to_string(),
        },
    ));
    assert_eq!(stale_cache.status, CommandStatus::Rejected);
    assert_eq!(
        stale_cache.violations,
        vec!["file object buffer cache generation is missing".to_string()]
    );

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b13-test",
        SemanticCommand::RecordFileObject {
            file_object: 1847,
            buffer_cache_object: 1840,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_string(),
            file_key: "demo-file".to_string(),
            path: "/demo/file.txt".to_string(),
            file_offset: 0,
            byte_len: 4097,
            file_size: 4097,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "oversized file object".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);
    assert_eq!(
        oversized.violations,
        vec!["file object byte range exceeds file or cache".to_string()]
    );

    let invalid_state = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b13-test",
        SemanticCommand::RecordFileObject {
            file_object: 1848,
            buffer_cache_object: 1840,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_string(),
            file_key: "demo-file".to_string(),
            path: "/demo/file.txt".to_string(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Invalidated,
            note: "invalidated file object".to_string(),
        },
    ));
    assert_eq!(invalid_state.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_state.violations,
        vec!["file object cannot be recorded as invalidated".to_string()]
    );

    assert!(graph.record_file_object_with_id(
        1845,
        1840,
        1,
        "rootfs",
        "demo-file",
        "/demo/file.txt",
        0,
        4096,
        4096,
        0xB13,
        FileObjectState::Dirty,
        "b13 existing file object",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b13-test",
        SemanticCommand::RecordFileObject {
            file_object: 1849,
            buffer_cache_object: 1840,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_string(),
            file_key: "demo-file".to_string(),
            path: "/demo/file.txt".to_string(),
            file_offset: 1024,
            byte_len: 1024,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "overlapping file range".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(duplicate.violations, vec!["file object range already materialized".to_string()]);
}

#[test]
pub(super) fn block_runtime_b13_invariants_reject_file_page_generation_leak() {
    let mut graph = setup_b13_file_object_graph();
    assert!(graph.record_file_object_with_id(
        1845,
        1840,
        1,
        "rootfs",
        "demo-file",
        "/demo/file.txt",
        0,
        4096,
        4096,
        0xB13,
        FileObjectState::Dirty,
        "b13 invariant file object",
    ));
    graph.corrupt_file_object_page_generation_for_test(1845, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FileObjectInvalid { file_object: 1845 })
    );
}

pub(in crate::tests) fn setup_b14_directory_object_graph() -> SemanticGraph {
    let mut graph = setup_b13_file_object_graph();
    assert!(graph.record_file_object_with_id(
        1845,
        1840,
        1,
        "rootfs",
        "demo-file",
        "/demo/file.txt",
        0,
        4096,
        4096,
        0xB13,
        FileObjectState::Dirty,
        "b14 source file object",
    ));
    graph
}

#[test]
pub(super) fn block_runtime_b14_directory_object_records_file_entry_contract() {
    let mut graph = setup_b14_directory_object_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b14-test",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 1850,
            file_object: 1845,
            file_object_generation: 1,
            namespace: "rootfs".to_string(),
            directory_key: "demo-dir".to_string(),
            directory_path: "/demo".to_string(),
            entry_name: "file.txt".to_string(),
            child_file_key: "demo-file".to_string(),
            child_path: "/demo/file.txt".to_string(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "b14 record directory entry".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.directory_object_count(), 1);
    let directory = &graph.directory_objects()[0];
    assert_eq!(
        directory.object_ref(),
        ContractObjectRef::new(ContractObjectKind::DirectoryObject, 1850, 1)
    );
    assert_eq!(directory.file_object, 1845);
    assert_eq!(directory.file_object_generation, 1);
    assert_eq!(directory.namespace, "rootfs");
    assert_eq!(directory.directory_key, "demo-dir");
    assert_eq!(directory.directory_path, "/demo");
    assert_eq!(directory.entry_name, "file.txt");
    assert_eq!(directory.child_file_key, "demo-file");
    assert_eq!(directory.child_path, "/demo/file.txt");
    assert_eq!(directory.entry_kind, DirectoryEntryKind::File);
    assert_eq!(directory.file_size, 4096);
    assert_eq!(directory.content_digest, 0xB13);
    assert_eq!(directory.state, DirectoryObjectState::Cached);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "DirectoryObjectRecorded directory_object=1850 file_object=1845@1 namespace=rootfs directory_key=demo-dir directory_path=/demo entry_name=file.txt child_file_key=demo-file child_path=/demo/file.txt entry_kind=file file_size=4096 content_digest=2835 state=cached generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b14_rejects_stale_mismatch_duplicate_and_invalid_directory() {
    let mut graph = setup_b14_directory_object_graph();

    let stale_file = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b14-test",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 1851,
            file_object: 1845,
            file_object_generation: 2,
            namespace: "rootfs".to_string(),
            directory_key: "demo-dir".to_string(),
            directory_path: "/demo".to_string(),
            entry_name: "stale.txt".to_string(),
            child_file_key: "demo-file".to_string(),
            child_path: "/demo/file.txt".to_string(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "stale file generation".to_string(),
        },
    ));
    assert_eq!(stale_file.status, CommandStatus::Rejected);
    assert_eq!(
        stale_file.violations,
        vec!["directory object file generation is missing".to_string()]
    );

    let mismatch = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b14-test",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 1852,
            file_object: 1845,
            file_object_generation: 1,
            namespace: "rootfs".to_string(),
            directory_key: "demo-dir".to_string(),
            directory_path: "/demo".to_string(),
            entry_name: "wrong.txt".to_string(),
            child_file_key: "demo-file".to_string(),
            child_path: "/demo/wrong.txt".to_string(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "wrong child path".to_string(),
        },
    ));
    assert_eq!(mismatch.status, CommandStatus::Rejected);
    assert_eq!(mismatch.violations, vec!["directory object file identity mismatch".to_string()]);

    let invalid_state = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b14-test",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 1853,
            file_object: 1845,
            file_object_generation: 1,
            namespace: "rootfs".to_string(),
            directory_key: "demo-dir".to_string(),
            directory_path: "/demo".to_string(),
            entry_name: "invalid.txt".to_string(),
            child_file_key: "demo-file".to_string(),
            child_path: "/demo/file.txt".to_string(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Invalidated,
            note: "invalidated directory object".to_string(),
        },
    ));
    assert_eq!(invalid_state.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_state.violations,
        vec!["directory object cannot be recorded as invalidated".to_string()]
    );

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
        "b14 existing directory entry",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b14-test",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 1854,
            file_object: 1845,
            file_object_generation: 1,
            namespace: "rootfs".to_string(),
            directory_key: "demo-dir".to_string(),
            directory_path: "/demo".to_string(),
            entry_name: "file.txt".to_string(),
            child_file_key: "demo-file".to_string(),
            child_path: "/demo/file.txt".to_string(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "duplicate directory entry".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["directory object entry already materialized".to_string()]
    );
}

#[test]
pub(super) fn block_runtime_b14_invariants_reject_directory_file_generation_leak() {
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
        "b14 invariant directory object",
    ));
    graph.corrupt_directory_object_file_generation_for_test(1850, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DirectoryObjectMissingFileObject {
            directory_object: 1850,
            file_object: 1845,
        })
    );
}
