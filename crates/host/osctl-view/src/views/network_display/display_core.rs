use super::super::super::*;

pub(crate) fn framebuffer_object_view_v1(
    framebuffer: &FramebufferObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-object",
        "id": framebuffer.id,
        "generation": framebuffer.generation,
        "state": framebuffer.state,
        "owner": {
            "resource": object_ref_json("resource", framebuffer.resource, framebuffer.resource_generation),
        },
        "references": {
            "resource": object_ref_json("resource", framebuffer.resource, framebuffer.resource_generation),
            "event": {
                "id": framebuffer.recorded_at_event,
            },
        },
        "identity": {
            "name": framebuffer.name,
        },
        "geometry": {
            "width": framebuffer.width,
            "height": framebuffer.height,
            "stride_bytes": framebuffer.stride_bytes,
            "pixel_format": framebuffer.pixel_format,
            "byte_len": framebuffer.byte_len,
        },
        "authority": {
            "write_requires": "display-capability-and-framebuffer-window-lease",
            "raw_mapping_is_semantic_truth": false,
        },
        "note": framebuffer.note,
        "last_transition": {
            "recorded_at_event": framebuffer.recorded_at_event,
            "state": framebuffer.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_object_view_v1(display: &DisplayObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-object",
        "id": display.id,
        "generation": display.generation,
        "state": display.state,
        "owner": {
            "framebuffer": object_ref_json(
                "framebuffer-object",
                display.framebuffer,
                display.framebuffer_generation,
            ),
        },
        "references": {
            "framebuffer": object_ref_json(
                "framebuffer-object",
                display.framebuffer,
                display.framebuffer_generation,
            ),
            "event": {
                "id": display.recorded_at_event,
            },
        },
        "identity": {
            "name": display.name,
        },
        "mode": {
            "name": display.mode_name,
            "width": display.width,
            "height": display.height,
            "refresh_millihz": display.refresh_millihz,
        },
        "authority": {
            "write_requires": "display-capability-and-framebuffer-window-lease",
            "flush_requires": "display-capability",
            "raw_mapping_is_semantic_truth": false,
        },
        "note": display.note,
        "last_transition": {
            "recorded_at_event": display.recorded_at_event,
            "state": display.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_capability_view_v1(
    capability: &DisplayCapabilityManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-capability",
        "id": capability.id,
        "generation": capability.generation,
        "state": capability.state,
        "owner": {
            "store": object_ref_json(
                "store",
                capability.owner_store,
                capability.owner_store_generation,
            ),
        },
        "references": {
            "display": object_ref_json(
                "display-object",
                capability.display,
                capability.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                capability.framebuffer,
                capability.framebuffer_generation,
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
        "authority": {
            "class": "display",
            "operations": capability.operations,
            "handle": {
                "slot": capability.handle_slot,
                "generation": capability.handle_generation,
                "tag": capability.handle_tag,
            },
            "write_requires_framebuffer_window_lease": true,
            "raw_mapping_is_semantic_truth": false,
        },
        "note": capability.note,
        "last_transition": {
            "recorded_at_event": capability.recorded_at_event,
            "owner_store_generation": capability.owner_store_generation,
            "display_generation": capability.display_generation,
            "framebuffer_generation": capability.framebuffer_generation,
            "capability_generation": capability.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn framebuffer_window_lease_view_v1(
    lease: &FramebufferWindowLeaseManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-window-lease",
        "id": lease.id,
        "generation": lease.generation,
        "state": lease.state,
        "owner": {
            "store": object_ref_json(
                "store",
                lease.owner_store,
                lease.owner_store_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                lease.display_capability,
                lease.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                lease.display,
                lease.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                lease.framebuffer,
                lease.framebuffer_generation,
            ),
            "event": {
                "id": lease.recorded_at_event,
            },
        },
        "window": {
            "x": lease.x,
            "y": lease.y,
            "width": lease.width,
            "height": lease.height,
            "byte_offset": lease.byte_offset,
            "byte_len": lease.byte_len,
            "access": lease.access,
        },
        "authority": {
            "requires_display_capability_operation": "lease",
            "write_requires_this_lease": true,
            "raw_mapping_is_semantic_truth": false,
            "snapshot_barrier_must_release": true,
        },
        "note": lease.note,
        "last_transition": {
            "recorded_at_event": lease.recorded_at_event,
            "owner_store_generation": lease.owner_store_generation,
            "display_capability_generation": lease.display_capability_generation,
            "display_generation": lease.display_generation,
            "framebuffer_generation": lease.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn framebuffer_mapping_view_v1(
    mapping: &FramebufferMappingManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-mapping",
        "id": mapping.id,
        "generation": mapping.generation,
        "state": mapping.state,
        "owner": {
            "store": object_ref_json(
                "store",
                mapping.owner_store,
                mapping.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_window_lease": object_ref_json(
                "framebuffer-window-lease",
                mapping.framebuffer_window_lease,
                mapping.framebuffer_window_lease_generation,
            ),
            "display_capability": object_ref_json(
                "display-capability",
                mapping.display_capability,
                mapping.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                mapping.display,
                mapping.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                mapping.framebuffer,
                mapping.framebuffer_generation,
            ),
            "event": {
                "id": mapping.recorded_at_event,
            },
        },
        "map_handle": {
            "slot": mapping.map_handle_slot,
            "generation": mapping.map_handle_generation,
            "tag": mapping.map_handle_tag,
            "mode": mapping.mode,
        },
        "window": {
            "x": mapping.x,
            "y": mapping.y,
            "width": mapping.width,
            "height": mapping.height,
            "byte_offset": mapping.byte_offset,
            "byte_len": mapping.byte_len,
            "access": mapping.access,
        },
        "authority": {
            "requires_framebuffer_window_lease": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "pixel_write_allowed": false,
            "flush_allowed": false,
            "snapshot_barrier_must_release": true,
        },
        "note": mapping.note,
        "last_transition": {
            "recorded_at_event": mapping.recorded_at_event,
            "owner_store_generation": mapping.owner_store_generation,
            "framebuffer_window_lease_generation": mapping.framebuffer_window_lease_generation,
            "display_capability_generation": mapping.display_capability_generation,
            "display_generation": mapping.display_generation,
            "framebuffer_generation": mapping.framebuffer_generation,
            "map_handle_generation": mapping.map_handle_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}
