use alloc::vec;
use alloc::vec::Vec;

use wasmi::{
    Engine, Error, Extern, Instance, Linker, Memory, Module, Store, TypedFunc, WasmParams,
    WasmResults,
};

pub(crate) trait FunctionParams: WasmParams {}
impl<T> FunctionParams for T where T: WasmParams {}

pub(crate) trait FunctionResults: WasmResults {}
impl<T> FunctionResults for T where T: WasmResults {}

pub(crate) type WasmiEngine = Engine;
pub(crate) type WasmiFunction<Params, Results> = TypedFunc<Params, Results>;

pub(crate) struct WasmiModuleInstance {
    store: Store<()>,
    instance: Instance,
    memory: Memory,
}

pub(crate) fn new_engine() -> WasmiEngine {
    Engine::default()
}

pub(crate) fn instantiate(
    engine: &WasmiEngine,
    bytes: &[u8],
    instantiate_msg: &'static str,
) -> Result<WasmiModuleInstance, &'static str> {
    let module = load_module(engine, bytes)?;
    let mut store = Store::new(engine, ());
    let linker = Linker::new(engine);
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|error| {
            crate::kwarn!("{}: {:?}", instantiate_msg, error);
            instantiate_msg
        })?;
    let memory = get_memory(&mut store, &instance)?;
    Ok(WasmiModuleInstance {
        store,
        instance,
        memory,
    })
}

pub(crate) fn bind<Params, Results>(
    module: &WasmiModuleInstance,
    export: &'static str,
    missing_msg: &'static str,
) -> Result<WasmiFunction<Params, Results>, &'static str>
where
    Params: FunctionParams,
    Results: FunctionResults,
{
    module
        .instance
        .get_typed_func::<Params, Results>(&module.store, export)
        .map_err(|_| missing_msg)
}

pub(crate) fn call<Params, Results>(
    module: &mut WasmiModuleInstance,
    func: &WasmiFunction<Params, Results>,
    args: Params,
    trap_msg: &'static str,
) -> Result<Results, &'static str>
where
    Params: FunctionParams,
    Results: FunctionResults,
{
    func.call(&mut module.store, args).map_err(|_| trap_msg)
}

pub(crate) fn write_memory(
    module: &mut WasmiModuleInstance,
    ptr: u32,
    bytes: &[u8],
    error_msg: &'static str,
) -> Result<(), &'static str> {
    module
        .memory
        .write(&mut module.store, ptr as usize, bytes)
        .map_err(|_| error_msg)
}

pub(crate) fn read_memory(
    module: &WasmiModuleInstance,
    ptr: u32,
    len: u32,
    error_msg: &'static str,
) -> Result<Vec<u8>, &'static str> {
    let mut buffer = vec![0_u8; len as usize];
    module
        .memory
        .read(&module.store, ptr as usize, &mut buffer)
        .map_err(|_| error_msg)?;
    Ok(buffer)
}

fn load_module(engine: &WasmiEngine, bytes: &[u8]) -> Result<Module, &'static str> {
    Module::new(engine, bytes).map_err(map_wasmi_error)
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
