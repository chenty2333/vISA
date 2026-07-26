pub use visa_component_adapter::{KvBinding, ProfileBinding, TimerBinding};

/// The regular-file and logical-request imports are both backed by an opaque
/// profile receipt. Wrapping each in its own type keeps them distinguishable
/// inside the single resource table this world shares, so a handle for one
/// profile can never be presented where the other is expected.
#[derive(Clone, Debug)]
pub struct FileBinding(pub ProfileBinding);

#[derive(Clone, Debug)]
pub struct RequestBinding(pub ProfileBinding);

wasmtime::component::bindgen!({
    path: "../../../wit/composite-continuity",
    world: "composite-continuity",
    with: {
        "visa:continuity/key-value.namespace": KvBinding,
        "visa:continuity/timers.timer-binding": TimerBinding,
        "visa:file-continuity/regular-file.file-binding": FileBinding,
        "visa:request-continuity/logical-request.request-binding": RequestBinding,
    },
    imports: { default: trappable },
    additional_derives: [PartialEq, Eq],
});
