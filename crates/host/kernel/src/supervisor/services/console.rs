use super::super::engine::{ModuleInstance, SupervisorEngine, WasmFn};
use crate::serial;

const CONSOLE_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_CONSOLE_SERVICE_WASM"));

pub(crate) struct ConsoleService {
    module: ModuleInstance,
    buffer_ptr: u32,
    buffer_capacity: u32,
    commit_write: WasmFn<(u32, u32), i32>,
}

impl ConsoleService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let mut module = ModuleInstance::instantiate(
            engine,
            CONSOLE_SERVICE_WASM,
            "failed to instantiate console_service",
        )?;
        let buffer_ptr = module.export_u32(
            "buffer_ptr",
            "missing console buffer_ptr export",
            "failed to fetch console buffer ptr",
        )?;
        let buffer_capacity = module.export_u32(
            "buffer_capacity",
            "missing console buffer_capacity export",
            "failed to fetch console buffer capacity",
        )?;
        let commit_write = module.bind("commit_write", "missing console commit_write export")?;

        Ok(Self { module, buffer_ptr, buffer_capacity, commit_write })
    }

    pub(crate) fn write_bytes(
        &mut self,
        bytes: &[u8],
        inject_fault: bool,
    ) -> Result<(), &'static str> {
        if bytes.len() > self.buffer_capacity as usize {
            return Err("console_service buffer was too small");
        }

        self.module.write_memory(
            self.buffer_ptr,
            bytes,
            "failed to write console_service buffer",
        )?;
        let inject = if inject_fault { 1 } else { 0 };
        let rc = self.module.call(
            &self.commit_write,
            (bytes.len() as u32, inject),
            "console_service trapped",
        )?;
        if rc != 0 {
            return Err("console_service rejected the write");
        }

        let echoed = self.module.read_memory(
            self.buffer_ptr,
            bytes.len() as u32,
            "failed to read console_service echo buffer",
        )?;
        serial::write_bytes(&echoed);
        Ok(())
    }
}
