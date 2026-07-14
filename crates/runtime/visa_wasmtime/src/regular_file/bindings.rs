pub use visa_component_adapter::ProfileBinding;

wasmtime::component::bindgen!({
    path: "../../../wit/regular-file-continuity",
    world: "regular-file-continuity",
    with: {
        "visa:file-continuity/regular-file.file-binding": ProfileBinding,
    },
    imports: { default: trappable },
});
