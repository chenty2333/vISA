use contract_core::Digest;
use visa_wasmtime::component_digest;

static STAGE1_COMPONENT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/handoff-component.component.wasm"));

pub const fn bytes() -> &'static [u8] {
    STAGE1_COMPONENT
}

pub fn digest() -> Digest {
    component_digest(STAGE1_COMPONENT)
}
