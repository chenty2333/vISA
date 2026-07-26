use contract_core::Digest;
use sha2::{Digest as _, Sha256};

static COMPOSITE_COMPONENT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/composite-component.component.wasm"));

pub const fn composite_bytes() -> &'static [u8] {
    COMPOSITE_COMPONENT
}

pub fn composite_digest() -> Digest {
    Digest::from_bytes(Sha256::digest(COMPOSITE_COMPONENT).into())
}
