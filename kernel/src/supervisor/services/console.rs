use wasmi::{Engine, Linker, Memory, Store, TypedFunc};

use crate::serial;

use super::super::wasm::{get_memory, load_module, read_memory};

const CONSOLE_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_CONSOLE_SERVICE_WASM"));

pub(crate) struct ConsoleService {
    store: Store<()>,
    memory: Memory,
    buffer_ptr: u32,
    buffer_capacity: u32,
    commit_write: TypedFunc<(u32, u32), i32>,
}

impl ConsoleService {
    pub(crate) fn new(engine: &Engine) -> Result<Self, &'static str> {
        let module = load_module(engine, CONSOLE_SERVICE_WASM)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| "failed to instantiate console_service")?;
        let memory = get_memory(&mut store, &instance)?;
        let buffer_ptr = instance
            .get_typed_func::<(), u32>(&store, "buffer_ptr")
            .map_err(|_| "missing console buffer_ptr export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch console buffer ptr")?;
        let buffer_capacity = instance
            .get_typed_func::<(), u32>(&store, "buffer_capacity")
            .map_err(|_| "missing console buffer_capacity export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch console buffer capacity")?;
        let commit_write = instance
            .get_typed_func::<(u32, u32), i32>(&store, "commit_write")
            .map_err(|_| "missing console commit_write export")?;

        Ok(Self {
            store,
            memory,
            buffer_ptr,
            buffer_capacity,
            commit_write,
        })
    }

    pub(crate) fn write_bytes(
        &mut self,
        bytes: &[u8],
        inject_fault: bool,
    ) -> Result<(), &'static str> {
        if bytes.len() > self.buffer_capacity as usize {
            return Err("console_service buffer was too small");
        }

        self.memory
            .write(&mut self.store, self.buffer_ptr as usize, bytes)
            .map_err(|_| "failed to write console_service buffer")?;
        let inject = if inject_fault { 1 } else { 0 };
        let rc = self
            .commit_write
            .call(&mut self.store, (bytes.len() as u32, inject))
            .map_err(|_| "console_service trapped")?;
        if rc != 0 {
            return Err("console_service rejected the write");
        }

        let echoed = read_memory(
            &self.memory,
            &self.store,
            self.buffer_ptr,
            bytes.len() as u32,
        )?;
        serial::write_bytes(&echoed);
        Ok(())
    }
}
