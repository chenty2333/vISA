use contract_core::Digest;
use sha2::{Digest as _, Sha256};

static ADMISSION_REQUEST_COMPONENT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/admission-request-component.component.wasm"));

pub const fn bytes() -> &'static [u8] {
    ADMISSION_REQUEST_COMPONENT
}

pub fn digest() -> Digest {
    Digest::from_bytes(Sha256::digest(ADMISSION_REQUEST_COMPONENT).into())
}
