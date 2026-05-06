use super::super::super::*;

pub(crate) fn file_object_view_v1(file: &FileObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "file-object",
        "id": file.id,
        "generation": file.generation,
        "state": file.state,
        "owner": {
            "namespace": file.namespace,
            "file_key": file.file_key,
            "path": file.path,
        },
        "references": {
            "buffer_cache_object": object_ref_json(
                "buffer-cache-object",
                file.buffer_cache_object,
                file.buffer_cache_object_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                file.block_device,
                file.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                file.block_range,
                file.block_range_generation,
            ),
            "page": object_ref_manifest_json(&file.page),
            "event": {
                "id": file.recorded_at_event,
            },
        },
        "file": {
            "file_offset": file.file_offset,
            "byte_len": file.byte_len,
            "file_size": file.file_size,
            "content_digest": file.content_digest,
            "cache_state": file.cache_state,
            "page_dirty_generation": file.page_dirty_generation,
        },
        "note": file.note,
        "last_transition": {
            "recorded_at_event": file.recorded_at_event,
            "buffer_cache_object_generation": file.buffer_cache_object_generation,
            "page_generation": file.page.generation,
            "page_dirty_generation": file.page_dirty_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn directory_object_view_v1(directory: &DirectoryObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "directory-object",
        "id": directory.id,
        "generation": directory.generation,
        "state": directory.state,
        "owner": {
            "namespace": directory.namespace,
            "directory_key": directory.directory_key,
            "directory_path": directory.directory_path,
            "entry_name": directory.entry_name,
        },
        "references": {
            "file_object": object_ref_json(
                "file-object",
                directory.file_object,
                directory.file_object_generation,
            ),
            "event": {
                "id": directory.recorded_at_event,
            },
        },
        "directory": {
            "entry_kind": directory.entry_kind,
            "child_file_key": directory.child_file_key,
            "child_path": directory.child_path,
            "file_size": directory.file_size,
            "content_digest": directory.content_digest,
        },
        "note": directory.note,
        "last_transition": {
            "recorded_at_event": directory.recorded_at_event,
            "file_object_generation": directory.file_object_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn fat_adapter_object_view_v1(adapter: &FatAdapterObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "fat-adapter-object",
        "id": adapter.id,
        "generation": adapter.generation,
        "state": adapter.state,
        "owner": {
            "implementation": adapter.implementation,
            "version": adapter.version,
            "profile": adapter.profile,
            "volume_label": adapter.volume_label,
            "adapter_path": adapter.adapter_path,
            "semantic_path": adapter.semantic_path,
        },
        "references": {
            "directory_object": object_ref_json(
                "directory-object",
                adapter.directory_object,
                adapter.directory_object_generation,
            ),
            "file_object": object_ref_json(
                "file-object",
                adapter.file_object,
                adapter.file_object_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                adapter.block_device,
                adapter.block_device_generation,
            ),
            "event": {
                "id": adapter.recorded_at_event,
            },
        },
        "fat": {
            "image_bytes": adapter.image_bytes,
            "bytes_written": adapter.bytes_written,
            "bytes_read": adapter.bytes_read,
            "write_digest": adapter.write_digest,
            "read_digest": adapter.read_digest,
            "file_content_digest": adapter.file_content_digest,
        },
        "note": adapter.note,
        "last_transition": {
            "recorded_at_event": adapter.recorded_at_event,
            "directory_object_generation": adapter.directory_object_generation,
            "file_object_generation": adapter.file_object_generation,
            "block_device_generation": adapter.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn ext4_adapter_object_view_v1(
    adapter: &Ext4AdapterObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "ext4-adapter-object",
        "id": adapter.id,
        "generation": adapter.generation,
        "state": adapter.state,
        "owner": {
            "implementation": adapter.implementation,
            "version": adapter.version,
            "profile": adapter.profile,
            "volume_label": adapter.volume_label,
            "adapter_path": adapter.adapter_path,
            "semantic_path": adapter.semantic_path,
        },
        "references": {
            "directory_object": object_ref_json(
                "directory-object",
                adapter.directory_object,
                adapter.directory_object_generation,
            ),
            "file_object": object_ref_json(
                "file-object",
                adapter.file_object,
                adapter.file_object_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                adapter.block_device,
                adapter.block_device_generation,
            ),
            "event": {
                "id": adapter.recorded_at_event,
            },
        },
        "ext4": {
            "image_bytes": adapter.image_bytes,
            "bytes_read": adapter.bytes_read,
            "read_digest": adapter.read_digest,
            "file_content_digest": adapter.file_content_digest,
            "directory_entries": adapter.directory_entries,
            "read_only_enforced": adapter.read_only_enforced,
        },
        "note": adapter.note,
        "last_transition": {
            "recorded_at_event": adapter.recorded_at_event,
            "directory_object_generation": adapter.directory_object_generation,
            "file_object_generation": adapter.file_object_generation,
            "block_device_generation": adapter.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn file_handle_capability_view_v1(
    capability: &FileHandleCapabilityManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "file-handle-capability",
        "id": capability.id,
        "generation": capability.generation,
        "state": capability.state,
        "owner": {
            "store": object_ref_json(
                "store",
                capability.owner_store,
                capability.owner_store_generation,
            ),
            "operation": capability.operation,
        },
        "references": {
            "file_object": object_ref_json(
                "file-object",
                capability.file_object,
                capability.file_object_generation,
            ),
            "directory_object": object_ref_json(
                "directory-object",
                capability.directory_object,
                capability.directory_object_generation,
            ),
            "capability": object_ref_json(
                "capability",
                capability.capability,
                capability.capability_generation,
            ),
            "event": {
                "id": capability.recorded_at_event,
            },
        },
        "handle": {
            "slot": capability.handle_slot,
            "generation": capability.handle_generation,
            "tag": capability.handle_tag,
        },
        "file_access": {
            "operation": capability.operation,
            "file_offset": capability.file_offset,
            "byte_len": capability.byte_len,
            "content_digest": capability.content_digest,
        },
        "note": capability.note,
        "last_transition": {
            "recorded_at_event": capability.recorded_at_event,
            "owner_store_generation": capability.owner_store_generation,
            "file_object_generation": capability.file_object_generation,
            "directory_object_generation": capability.directory_object_generation,
            "capability_generation": capability.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn fs_wait_view_v1(wait: &FsWaitManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "fs-wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "store": object_ref_json(
                "store",
                wait.owner_store,
                wait.owner_store_generation,
            ),
            "operation": wait.operation,
        },
        "references": {
            "wait": object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "owner_store": object_ref_json(
                "store",
                wait.owner_store,
                wait.owner_store_generation,
            ),
            "file_object": object_ref_json(
                "file-object",
                wait.file_object,
                wait.file_object_generation,
            ),
            "directory_object": object_ref_json(
                "directory-object",
                wait.directory_object,
                wait.directory_object_generation,
            ),
            "file_handle_capability": object_ref_json(
                "file-handle-capability",
                wait.file_handle_capability,
                wait.file_handle_capability_generation,
            ),
            "blocker": object_ref_manifest_json(&wait.blocker),
            "created_event": {
                "id": wait.created_at_event,
            },
            "completed_event": wait.completed_at_event.map(|id| serde_json::json!({ "id": id })),
        },
        "wait": {
            "operation": wait.operation,
            "sequence": wait.sequence,
            "byte_len": wait.byte_len,
            "cancel_reason": wait.cancel_reason,
        },
        "note": wait.note,
        "last_transition": {
            "created_at_event": wait.created_at_event,
            "completed_at_event": wait.completed_at_event,
            "wait_generation": wait.wait_generation,
            "file_handle_capability_generation": wait.file_handle_capability_generation,
        },
        "last_error": wait.cancel_reason.as_ref().map(|reason| serde_json::json!({
            "cancel_reason": reason,
        })).unwrap_or(serde_json::Value::Null),
    })
}
