pub use visa_component_adapter::ProfileBinding;

wasmtime::component::bindgen!({
    path: "../../../wit/logical-request-continuity",
    world: "logical-request-continuity",
    with: {
        "visa:request-continuity/logical-request.request-binding": ProfileBinding,
    },
    imports: { default: trappable },
});
