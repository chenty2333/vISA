use alloc::vec::Vec;

use wasmi::{Engine, Linker, Memory, Store, TypedFunc};

use super::super::wasm::{get_memory, load_module, read_memory};

const WASM_APP_WASM: &[u8] = include_bytes!(env!("VMOS_WASM_APP_WASM"));

pub(crate) struct WasmApp<'engine> {
    store: Store<()>,
    memory: Memory,
    run: TypedFunc<(), u64>,
    _engine: &'engine Engine,
}

impl<'engine> WasmApp<'engine> {
    pub(crate) fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        let module = load_module(engine, WASM_APP_WASM)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| "failed to instantiate wasm_app")?;
        let memory = get_memory(&mut store, &instance)?;
        let run = instance
            .get_typed_func::<(), u64>(&store, "run")
            .map_err(|_| "missing wasm_app run export")?;

        Ok(Self {
            store,
            memory,
            run,
            _engine: engine,
        })
    }

    pub(crate) fn run(&mut self) -> Result<u64, &'static str> {
        self.run
            .call(&mut self.store, ())
            .map_err(|_| "wasm_app trapped")
    }

    pub(crate) fn read_bytes(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, &'static str> {
        read_memory(&self.memory, &self.store, ptr, len)
    }
}
