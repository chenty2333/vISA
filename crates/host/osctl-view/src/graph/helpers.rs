use super::*;
pub(crate) fn graph_edge(
    from: serde_json::Value,
    to: serde_json::Value,
    relation: &str,
    mode: &str,
    created_at_event: Option<u64>,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "from": from,
        "to": to,
        "relation": relation,
        "mode": mode,
        "created_at_event": created_at_event,
    })
}

pub(crate) fn object_ref_json(kind: &str, id: u64, generation: u64) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "id": id,
        "generation": generation,
    })
}

pub(crate) fn optional_object_ref_json(
    kind: &str,
    id: Option<u64>,
    generation: Option<u64>,
) -> serde_json::Value {
    match (id, generation) {
        (Some(id), Some(generation)) => object_ref_json(kind, id, generation),
        _ => serde_json::Value::Null,
    }
}

pub(crate) fn osctl_kind_from_contract_kind(kind: &str) -> &str {
    match kind {
        "fake-block-backend-object" => "fake-block-backend",
        "fake-net-backend-object" => "fake-net-backend",
        "virtio-blk-backend-object" => "virtio-blk-backend",
        "virtio-net-backend-object" => "virtio-net-backend",
        other => other,
    }
}

pub(crate) fn object_ref_manifest_json(object: &ContractObjectRefManifest) -> serde_json::Value {
    object_ref_json(&object.kind, object.id, object.generation)
}
