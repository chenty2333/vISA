use contract_core::Digest;
use visa_component_adapter::{AdapterError, RuntimeIdentity};

use crate::protocol::RuntimeReport;

pub const VISA_WACOGO_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const WACOGO_VERSION: &str = "v0.0.0-20260617023329-3de16a61796c";
pub const WACOGO_REVISION: &str = "3de16a61796ce02d29795e4a074f37a33e6ebd87";
pub const SOURCE_LOCK_SCHEMA: &str = "visa.wacogo-source-lock.v1";
pub const SOURCE_LOCK_SHA256: &str =
    "f8dfe3c290bc4f6f60843316c8824da9a0bfbb30a1f4fb0bf5845a3fb81b2235";
pub const DERIVATIVE_ID: &str = "partite-ai-wacogo-3de16a61796c-visa-patchset-v1";
pub const UPSTREAM_MODULE: &str = "github.com/partite-ai/wacogo";
pub const UPSTREAM_MODULE_SUM: &str = "h1:WAxQQFk9xW0jy0cu1Ql4JaaUJTUMo0GsK5TNn5Nliiw=";
pub const PATCHSET_ID: &str = "visa-wacogo-downstream-v1";
pub const PATCHSET_SHA256: &str =
    "a377b3d3f0da455f14097638380a8bab566b2aa0d33a4f25d90326e7a2b211e2";
pub const PATCHED_TREE_SHA256: &str =
    "813eb9fad2d93d0c2237edf5d55d18316d1cc313ccf033e079c01fd18f653311";
pub const WAZERO_VERSION: &str = "v1.11.1-0.20260418165552-5cb4bb3ec0c1";
pub const GO_VERSION: &str = "go1.26.5";
pub const TARGET: &str = "linux/amd64";
pub const MAIN_MODULE: &str = "visa.local/wacogo-runtime";
pub const SIDECAR_EXECUTABLE_SIZE: u64 = 6_754_430;
pub const SIDECAR_EXECUTABLE_SHA256: &str =
    "7dd8365e5132fcd32f92ac89d8d1b78b80ec1d285730d8e43b360de6378a0606";
pub const PATCH_SHA256S: [&str; 3] = [
    "c04b82a5ec2a95c45f5f81bdce5b2cbff11e25556865eb19928b48b6f94eed69",
    "3531ff7a61de7c41f4237d7077a4dd0602bedd15e3067db070fd3e659575a37e",
    "4b32fe31643aedab8472c42ae38d635abbfc9133093866b5ff1de9dcc4548d0e",
];
pub const IMPLEMENTATION: &str = "visa_wacogo";
pub const ENGINE: &str = "partite-ai/wacogo+wazero";
pub const ENGINE_VERSION: &str = concat!(
    "wacogo-v0.0.0-20260617023329-3de16a61796c+visa-patchset-v1/",
    "wazero-v1.11.1-0.20260418165552-5cb4bb3ec0c1"
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WacogoProvenance {
    pub source_lock_schema: String,
    pub source_lock_sha256: String,
    pub derivative_id: String,
    pub upstream_module: String,
    pub upstream_module_sum: String,
    pub upstream_is_qualified_without_patches: bool,
    pub patchset_id: String,
    pub patch_sha256s: Vec<String>,
    pub executable_path: String,
    pub executable_digest: Digest,
    pub executable_size: u64,
    pub protocol_version: u32,
    pub execution_carrier: String,
    pub wacogo_version: String,
    pub wacogo_revision: String,
    pub patchset_sha256: String,
    pub patched_tree_sha256: String,
    pub wazero_version: String,
    pub go_version: String,
    pub target: String,
    pub main_module: String,
}

pub(crate) fn static_identity() -> RuntimeIdentity {
    RuntimeIdentity::new(IMPLEMENTATION, VISA_WACOGO_VERSION, ENGINE, ENGINE_VERSION)
}

impl RuntimeReport {
    pub(crate) fn validate(&self) -> Result<(), AdapterError> {
        let expected = Self::expected();
        if self != &expected {
            return Err(AdapterError::UnsupportedRuntimeFeature(format!(
                "live wacogo sidecar identity mismatch: expected {expected:?}, found {self:?}"
            )));
        }
        Ok(())
    }

    pub(crate) fn expected() -> Self {
        Self {
            implementation: IMPLEMENTATION.into(),
            implementation_version: VISA_WACOGO_VERSION.into(),
            engine: ENGINE.into(),
            engine_version: ENGINE_VERSION.into(),
            wacogo_version: WACOGO_VERSION.into(),
            wacogo_revision: WACOGO_REVISION.into(),
            patchset_sha256: PATCHSET_SHA256.into(),
            patched_tree_sha256: PATCHED_TREE_SHA256.into(),
            wazero_version: WAZERO_VERSION.into(),
            go_version: GO_VERSION.into(),
            target: TARGET.into(),
            main_module: MAIN_MODULE.into(),
        }
    }

    pub(crate) fn provenance(
        &self,
        executable_path: String,
        executable_digest: Digest,
        executable_size: u64,
    ) -> WacogoProvenance {
        WacogoProvenance {
            source_lock_schema: SOURCE_LOCK_SCHEMA.into(),
            source_lock_sha256: SOURCE_LOCK_SHA256.into(),
            derivative_id: DERIVATIVE_ID.into(),
            upstream_module: UPSTREAM_MODULE.into(),
            upstream_module_sum: UPSTREAM_MODULE_SUM.into(),
            upstream_is_qualified_without_patches: false,
            patchset_id: PATCHSET_ID.into(),
            patch_sha256s: PATCH_SHA256S.into_iter().map(str::to_owned).collect(),
            executable_path,
            executable_digest,
            executable_size,
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            execution_carrier: crate::carrier::EXECUTION_CARRIER.into(),
            wacogo_version: self.wacogo_version.clone(),
            wacogo_revision: self.wacogo_revision.clone(),
            patchset_sha256: self.patchset_sha256.clone(),
            patched_tree_sha256: self.patched_tree_sha256.clone(),
            wazero_version: self.wazero_version.clone(),
            go_version: self.go_version.clone(),
            target: self.target.clone(),
            main_module: self.main_module.clone(),
        }
    }
}
