pub const SOURCE_SHA256: &str = env!("VISA_BUILD_SOURCE_SHA256");
pub const TOOLCHAIN_SHA256: &str = env!("VISA_BUILD_TOOLCHAIN_SHA256");
pub const TARGET_TRIPLE: &str = env!("VISA_BUILD_TARGET");

pub static SOURCE_MANIFEST_JSON: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/build-source-manifest.json"));
pub static TOOLCHAIN_RAW: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/build-toolchain.txt"));
