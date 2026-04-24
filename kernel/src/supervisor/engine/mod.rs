mod api;
#[cfg(not(target_os = "none"))]
mod wasmi_backend;

#[cfg(target_os = "none")]
pub(crate) use api::SupervisorEngine;
#[cfg(not(target_os = "none"))]
pub(crate) use api::{
    BufferedModule, ModuleInstance, SupervisorEngine, WasmFn, expect_len, expect_ok,
};
