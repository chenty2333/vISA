use alloc::vec::Vec;

use super::super::engine::{ModuleInstance, SupervisorEngine, WasmFn};

const WASM_APP_WASM: &[u8] = include_bytes!(env!("VMOS_WASM_APP_WASM"));

pub(crate) struct WasmApp {
    module: ModuleInstance,
    run: WasmFn<(), u64>,
}

impl WasmApp {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let module =
            ModuleInstance::instantiate(engine, WASM_APP_WASM, "failed to instantiate wasm_app")?;
        let run = module.bind("run", "missing wasm_app run export")?;

        Ok(Self { module, run })
    }

    pub(crate) fn run(&mut self) -> Result<u64, &'static str> {
        self.module.call(&self.run, (), "wasm_app trapped")
    }

    pub(crate) fn read_bytes(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, &'static str> {
        self.module.read_memory(ptr, len, "failed to read wasm_app memory")
    }
}
