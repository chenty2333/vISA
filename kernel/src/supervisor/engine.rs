use alloc::vec;
use alloc::vec::Vec;

use wasmi::{
    Engine as BackendEngine, Error, Extern, Instance, Linker, Memory, Module, Store, TypedFunc,
    WasmParams, WasmResults,
};

use super::types::ServiceCallError;

pub(crate) struct SupervisorEngine {
    inner: BackendEngine,
}

impl Default for SupervisorEngine {
    fn default() -> Self {
        Self {
            inner: BackendEngine::default(),
        }
    }
}

pub(crate) struct WasmFn<Params, Results> {
    inner: TypedFunc<Params, Results>,
}

pub(crate) struct ModuleInstance {
    store: Store<()>,
    instance: Instance,
    memory: Memory,
}

impl ModuleInstance {
    pub(crate) fn instantiate(
        engine: &SupervisorEngine,
        bytes: &[u8],
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        let module = load_module(engine, bytes)?;
        let mut store = Store::new(&engine.inner, ());
        let linker = Linker::new(&engine.inner);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|error| {
                crate::kwarn!("{}: {:?}", instantiate_msg, error);
                instantiate_msg
            })?;
        let memory = get_memory(&mut store, &instance)?;
        Ok(Self {
            store,
            instance,
            memory,
        })
    }

    pub(crate) fn bind<Params, Results>(
        &self,
        export: &'static str,
        missing_msg: &'static str,
    ) -> Result<WasmFn<Params, Results>, &'static str>
    where
        Params: WasmParams,
        Results: WasmResults,
    {
        self.instance
            .get_typed_func::<Params, Results>(&self.store, export)
            .map(|inner| WasmFn { inner })
            .map_err(|_| missing_msg)
    }

    pub(crate) fn export_u32(
        &mut self,
        export: &'static str,
        missing_msg: &'static str,
        call_msg: &'static str,
    ) -> Result<u32, &'static str> {
        let getter = self.bind::<(), u32>(export, missing_msg)?;
        self.call(&getter, (), call_msg)
    }

    pub(crate) fn call<Params, Results>(
        &mut self,
        func: &WasmFn<Params, Results>,
        args: Params,
        trap_msg: &'static str,
    ) -> Result<Results, &'static str>
    where
        Params: WasmParams,
        Results: WasmResults,
    {
        func.inner.call(&mut self.store, args).map_err(|_| trap_msg)
    }

    pub(crate) fn write_memory(
        &mut self,
        ptr: u32,
        bytes: &[u8],
        error_msg: &'static str,
    ) -> Result<(), &'static str> {
        self.memory
            .write(&mut self.store, ptr as usize, bytes)
            .map_err(|_| error_msg)
    }

    pub(crate) fn read_memory(
        &self,
        ptr: u32,
        len: u32,
        error_msg: &'static str,
    ) -> Result<Vec<u8>, &'static str> {
        let mut buffer = vec![0_u8; len as usize];
        self.memory
            .read(&self.store, ptr as usize, &mut buffer)
            .map_err(|_| error_msg)?;
        Ok(buffer)
    }
}

pub(crate) struct BufferedModule {
    module: ModuleInstance,
    request_ptr: u32,
    request_capacity: u32,
    response_ptr: u32,
    response_capacity: u32,
}

impl BufferedModule {
    pub(crate) fn instantiate(
        engine: &SupervisorEngine,
        bytes: &[u8],
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        let mut module = ModuleInstance::instantiate(engine, bytes, instantiate_msg)?;
        let request_ptr = module.export_u32(
            "request_ptr",
            "missing service request_ptr export",
            "failed to fetch service request_ptr",
        )?;
        let request_capacity = module.export_u32(
            "request_capacity",
            "missing service request_capacity export",
            "failed to fetch service request_capacity",
        )?;
        let response_ptr = module.export_u32(
            "response_ptr",
            "missing service response_ptr export",
            "failed to fetch service response_ptr",
        )?;
        let response_capacity = module.export_u32(
            "response_capacity",
            "missing service response_capacity export",
            "failed to fetch service response_capacity",
        )?;
        Ok(Self {
            module,
            request_ptr,
            request_capacity,
            response_ptr,
            response_capacity,
        })
    }

    pub(crate) fn bind<Params, Results>(
        &self,
        export: &'static str,
        missing_msg: &'static str,
    ) -> Result<WasmFn<Params, Results>, &'static str>
    where
        Params: WasmParams,
        Results: WasmResults,
    {
        self.module.bind(export, missing_msg)
    }

    pub(crate) fn call<Params, Results>(
        &mut self,
        func: &WasmFn<Params, Results>,
        args: Params,
        trap_msg: &'static str,
    ) -> Result<Results, &'static str>
    where
        Params: WasmParams,
        Results: WasmResults,
    {
        self.module.call(func, args, trap_msg)
    }

    pub(crate) fn write_request(&mut self, bytes: &[u8]) -> Result<u32, &'static str> {
        if bytes.len() > self.request_capacity as usize {
            return Err("service request buffer overflowed");
        }
        self.module.write_memory(
            self.request_ptr,
            bytes,
            "failed to write service request buffer",
        )?;
        Ok(bytes.len() as u32)
    }

    pub(crate) fn read_response(&self, len: u32) -> Result<Vec<u8>, &'static str> {
        if len > self.response_capacity {
            return Err("service response exceeded capacity");
        }
        self.module.read_memory(
            self.response_ptr,
            len,
            "failed to read service response buffer",
        )
    }
}

pub(crate) fn expect_ok(rc: i32) -> Result<(), ServiceCallError> {
    if rc == 0 {
        Ok(())
    } else if rc < 0 {
        Err(ServiceCallError::Errno(-rc))
    } else {
        Err(ServiceCallError::Invalid(
            "service returned an unexpected positive status",
        ))
    }
}

pub(crate) fn expect_len(rc: i32) -> Result<u32, ServiceCallError> {
    if rc < 0 {
        Err(ServiceCallError::Errno(-rc))
    } else {
        Ok(rc as u32)
    }
}

fn load_module(engine: &SupervisorEngine, bytes: &[u8]) -> Result<Module, &'static str> {
    Module::new(&engine.inner, bytes).map_err(map_wasmi_error)
}

fn get_memory(store: &mut Store<()>, instance: &Instance) -> Result<Memory, &'static str> {
    match instance.get_export(store, "memory") {
        Some(Extern::Memory(memory)) => Ok(memory),
        _ => Err("wasm module did not export linear memory"),
    }
}

fn map_wasmi_error(error: Error) -> &'static str {
    let _ = error;
    "wasm engine returned an error"
}
