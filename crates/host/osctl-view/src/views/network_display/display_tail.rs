use super::super::super::*;

pub(crate) fn framebuffer_write_view_v1(write: &FramebufferWriteManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-write",
        "id": write.id,
        "generation": write.generation,
        "state": write.state,
        "owner": {
            "store": object_ref_json(
                "store",
                write.owner_store,
                write.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_mapping": object_ref_json(
                "framebuffer-mapping",
                write.framebuffer_mapping,
                write.framebuffer_mapping_generation,
            ),
            "framebuffer_window_lease": object_ref_json(
                "framebuffer-window-lease",
                write.framebuffer_window_lease,
                write.framebuffer_window_lease_generation,
            ),
            "display_capability": object_ref_json(
                "display-capability",
                write.display_capability,
                write.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                write.display,
                write.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                write.framebuffer,
                write.framebuffer_generation,
            ),
            "event": {
                "id": write.recorded_at_event,
            },
        },
        "map_handle": {
            "slot": write.map_handle_slot,
            "generation": write.map_handle_generation,
            "tag": write.map_handle_tag,
        },
        "write": {
            "x": write.x,
            "y": write.y,
            "width": write.width,
            "height": write.height,
            "byte_offset": write.byte_offset,
            "byte_len": write.byte_len,
            "pixel_format": write.pixel_format,
            "payload_digest": write.payload_digest,
        },
        "authority": {
            "requires_framebuffer_mapping": true,
            "requires_framebuffer_window_lease": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "flush_allowed": false,
        },
        "note": write.note,
        "last_transition": {
            "recorded_at_event": write.recorded_at_event,
            "owner_store_generation": write.owner_store_generation,
            "framebuffer_mapping_generation": write.framebuffer_mapping_generation,
            "framebuffer_window_lease_generation": write.framebuffer_window_lease_generation,
            "display_capability_generation": write.display_capability_generation,
            "display_generation": write.display_generation,
            "framebuffer_generation": write.framebuffer_generation,
            "map_handle_generation": write.map_handle_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn framebuffer_flush_region_view_v1(
    flush: &FramebufferFlushRegionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-flush-region",
        "id": flush.id,
        "generation": flush.generation,
        "state": flush.state,
        "owner": {
            "store": object_ref_json(
                "store",
                flush.owner_store,
                flush.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                flush.framebuffer_write,
                flush.framebuffer_write_generation,
            ),
            "display_capability": object_ref_json(
                "display-capability",
                flush.display_capability,
                flush.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                flush.display,
                flush.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                flush.framebuffer,
                flush.framebuffer_generation,
            ),
            "event": {
                "id": flush.recorded_at_event,
            },
        },
        "flush": {
            "x": flush.x,
            "y": flush.y,
            "width": flush.width,
            "height": flush.height,
            "byte_offset": flush.byte_offset,
            "byte_len": flush.byte_len,
            "pixel_format": flush.pixel_format,
            "payload_digest": flush.payload_digest,
        },
        "authority": {
            "requires_display_capability_flush": true,
            "requires_framebuffer_write": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "real_present_executed": false,
        },
        "note": flush.note,
        "last_transition": {
            "recorded_at_event": flush.recorded_at_event,
            "owner_store_generation": flush.owner_store_generation,
            "framebuffer_write_generation": flush.framebuffer_write_generation,
            "display_capability_generation": flush.display_capability_generation,
            "display_generation": flush.display_generation,
            "framebuffer_generation": flush.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn framebuffer_dirty_region_view_v1(
    dirty: &FramebufferDirtyRegionManifest,
) -> serde_json::Value {
    let flush_ref =
        match (dirty.framebuffer_flush_region, dirty.framebuffer_flush_region_generation) {
            (Some(id), Some(generation)) => {
                object_ref_json("framebuffer-flush-region", id, generation)
            }
            _ => serde_json::Value::Null,
        };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-dirty-region",
        "id": dirty.id,
        "generation": dirty.generation,
        "state": dirty.state,
        "owner": {
            "store": object_ref_json(
                "store",
                dirty.owner_store,
                dirty.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                dirty.framebuffer_write,
                dirty.framebuffer_write_generation,
            ),
            "framebuffer_flush_region": flush_ref,
            "display_capability": object_ref_json(
                "display-capability",
                dirty.display_capability,
                dirty.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                dirty.display,
                dirty.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                dirty.framebuffer,
                dirty.framebuffer_generation,
            ),
            "dirty_event": {
                "id": dirty.dirty_at_event,
            },
            "cleaned_event": dirty.cleaned_at_event
                .map(|id| serde_json::json!({"id": id}))
                .unwrap_or(serde_json::Value::Null),
            "recorded_event": {
                "id": dirty.recorded_at_event,
            },
        },
        "region": {
            "x": dirty.x,
            "y": dirty.y,
            "width": dirty.width,
            "height": dirty.height,
            "byte_offset": dirty.byte_offset,
            "byte_len": dirty.byte_len,
            "pixel_format": dirty.pixel_format,
            "payload_digest": dirty.payload_digest,
        },
        "authority": {
            "requires_framebuffer_write": true,
            "clean_state_requires_flush_region": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "real_present_executed": false,
        },
        "note": dirty.note,
        "last_transition": {
            "dirty_at_event": dirty.dirty_at_event,
            "cleaned_at_event": dirty.cleaned_at_event,
            "recorded_at_event": dirty.recorded_at_event,
            "owner_store_generation": dirty.owner_store_generation,
            "framebuffer_write_generation": dirty.framebuffer_write_generation,
            "framebuffer_flush_region_generation": dirty.framebuffer_flush_region_generation,
            "display_capability_generation": dirty.display_capability_generation,
            "display_generation": dirty.display_generation,
            "framebuffer_generation": dirty.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_event_log_view_v1(log: &DisplayEventLogManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-event-log",
        "id": log.id,
        "generation": log.generation,
        "state": log.state,
        "owner": {
            "store": object_ref_json(
                "store",
                log.owner_store,
                log.owner_store_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                log.display_capability,
                log.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                log.display,
                log.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                log.framebuffer,
                log.framebuffer_generation,
            ),
            "framebuffer_dirty_region": object_ref_json(
                "framebuffer-dirty-region",
                log.framebuffer_dirty_region,
                log.framebuffer_dirty_region_generation,
            ),
            "event": {
                "id": log.recorded_at_event,
            },
        },
        "window": {
            "first_event": log.first_event,
            "last_event": log.last_event,
            "event_count": log.event_count,
            "flush_count": log.flush_count,
            "dirty_region_count": log.dirty_region_count,
        },
        "authority": {
            "read_only_control_plane": true,
            "raw_event_storage_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "real_present_executed": false,
        },
        "note": log.note,
        "last_transition": {
            "recorded_at_event": log.recorded_at_event,
            "owner_store_generation": log.owner_store_generation,
            "display_capability_generation": log.display_capability_generation,
            "display_generation": log.display_generation,
            "framebuffer_generation": log.framebuffer_generation,
            "framebuffer_dirty_region_generation": log.framebuffer_dirty_region_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_cleanup_view_v1(cleanup: &DisplayCleanupManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "store": object_ref_json(
                "store",
                cleanup.owner_store,
                cleanup.owner_store_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                cleanup.display_capability,
                cleanup.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                cleanup.display,
                cleanup.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                cleanup.framebuffer,
                cleanup.framebuffer_generation,
            ),
        },
        "cleanup": {
            "reason": cleanup.reason,
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
            "unmapped_framebuffer_mappings": cleanup.unmapped_framebuffer_mappings,
            "released_framebuffer_window_leases": cleanup.released_framebuffer_window_leases,
            "revoked_display_capabilities": cleanup.revoked_display_capabilities,
            "revoked_capabilities": cleanup.revoked_capabilities,
            "steps": cleanup.steps,
        },
        "authority": {
            "releases_handle_mode_mappings": true,
            "releases_framebuffer_leases": true,
            "revokes_display_capability": true,
            "real_present_executed": false,
        },
        "note": cleanup.note,
        "last_transition": {
            "completed_at_event": cleanup.completed_at_event,
            "owner_store_generation": cleanup.owner_store_generation,
            "display_capability_generation": cleanup.display_capability_generation,
            "display_generation": cleanup.display_generation,
            "framebuffer_generation": cleanup.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_snapshot_barrier_view_v1(
    barrier: &DisplaySnapshotBarrierManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-snapshot-barrier",
        "id": barrier.id,
        "generation": barrier.generation,
        "state": barrier.state,
        "owner": {
            "store": object_ref_json(
                "store",
                barrier.owner_store,
                barrier.owner_store_generation,
            ),
        },
        "references": {
            "display": object_ref_json(
                "display-object",
                barrier.display,
                barrier.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                barrier.framebuffer,
                barrier.framebuffer_generation,
            ),
            "display_cleanup": optional_object_ref_json(
                "display-cleanup",
                barrier.display_cleanup,
                barrier.display_cleanup_generation,
            ),
        },
        "snapshot": {
            "reason": barrier.reason,
            "snapshot_validation_ok": barrier.snapshot_validation_ok,
            "active_framebuffer_window_lease_count": barrier.active_framebuffer_window_lease_count,
            "active_framebuffer_mapping_count": barrier.active_framebuffer_mapping_count,
            "dirty_framebuffer_region_count": barrier.dirty_framebuffer_region_count,
            "validated_at_event": barrier.validated_at_event,
        },
        "authority": {
            "requires_no_active_framebuffer_lease": true,
            "requires_no_active_framebuffer_mapping": true,
            "requires_no_dirty_framebuffer_region": true,
            "real_snapshot_cow_executed": false,
            "real_present_executed": false,
        },
        "note": barrier.note,
        "last_transition": {
            "validated_at_event": barrier.validated_at_event,
            "owner_store_generation": barrier.owner_store_generation,
            "display_generation": barrier.display_generation,
            "framebuffer_generation": barrier.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_panic_last_frame_view_v1(
    frame: &DisplayPanicLastFrameManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-panic-last-frame",
        "id": frame.id,
        "generation": frame.generation,
        "state": frame.state,
        "owner": {
            "store": object_ref_json(
                "store",
                frame.owner_store,
                frame.owner_store_generation,
            ),
        },
        "references": {
            "display": object_ref_json(
                "display-object",
                frame.display,
                frame.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                frame.framebuffer,
                frame.framebuffer_generation,
            ),
            "display_snapshot_barrier": object_ref_json(
                "display-snapshot-barrier",
                frame.display_snapshot_barrier,
                frame.display_snapshot_barrier_generation,
            ),
            "display_event_log": object_ref_json(
                "display-event-log",
                frame.display_event_log,
                frame.display_event_log_generation,
            ),
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                frame.framebuffer_write,
                frame.framebuffer_write_generation,
            ),
            "framebuffer_flush_region": object_ref_json(
                "framebuffer-flush-region",
                frame.framebuffer_flush_region,
                frame.framebuffer_flush_region_generation,
            ),
        },
        "frame": {
            "x": frame.x,
            "y": frame.y,
            "width": frame.width,
            "height": frame.height,
            "byte_offset": frame.byte_offset,
            "byte_len": frame.byte_len,
            "pixel_format": frame.pixel_format,
            "payload_digest": frame.payload_digest,
            "summary_digest": frame.summary_digest,
        },
        "panic": {
            "epoch": frame.panic_epoch,
            "cpu": frame.panic_cpu,
            "reason_code": frame.panic_reason_code,
            "record_kind": frame.panic_record_kind,
            "summary_record_bytes": frame.summary_record_bytes,
            "raw_framebuffer_bytes_exported": frame.raw_framebuffer_bytes_exported,
            "recorded_at_event": frame.recorded_at_event,
        },
        "authority": {
            "panic_path_allocates": false,
            "raw_framebuffer_bytes_exported": frame.raw_framebuffer_bytes_exported,
            "real_panic_ring_write_executed": false,
        },
        "note": frame.note,
        "last_transition": {
            "recorded_at_event": frame.recorded_at_event,
            "owner_store_generation": frame.owner_store_generation,
            "display_generation": frame.display_generation,
            "framebuffer_generation": frame.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}
