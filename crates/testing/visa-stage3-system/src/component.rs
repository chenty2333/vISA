use contract_core::Digest;
use sha2::{Digest as _, Sha256};

static STAGE3A_COMPONENT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/stage3-file-component.component.wasm"));
static STAGE3B_COMPONENT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/stage3-request-component.component.wasm"));

pub const fn stage3a_bytes() -> &'static [u8] {
    STAGE3A_COMPONENT
}

pub const fn stage3b_bytes() -> &'static [u8] {
    STAGE3B_COMPONENT
}

pub fn stage3a_digest() -> Digest {
    digest(STAGE3A_COMPONENT)
}

pub fn stage3b_digest() -> Digest {
    digest(STAGE3B_COMPONENT)
}

fn digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(Sha256::digest(bytes).into())
}
