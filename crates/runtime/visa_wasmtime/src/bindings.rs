pub use crate::{KvBinding, TimerBinding};

wasmtime::component::bindgen!({
    path: "../../../wit/cooperative-handoff",
    world: "cooperative-handoff",
    with: {
        "visa:continuity/key-value.namespace": KvBinding,
        "visa:continuity/timers.timer-binding": TimerBinding,
    },
    imports: { default: trappable },
});
