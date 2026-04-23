use alloc::vec;
use alloc::vec::Vec;

use wasmi::{Engine, Error, Extern, Instance, Linker, Memory, Module, Store};

use super::types::ServiceCallError;

pub(super) struct BufferedStore {
    pub(super) store: Store<()>,
    pub(super) memory: Memory,
    request_ptr: u32,
    request_capacity: u32,
    response_ptr: u32,
    response_capacity: u32,
}

impl BufferedStore {
    pub(super) fn new(
        engine: &Engine,
        bytes: &[u8],
        module_name: &'static str,
    ) -> Result<(Self, Instance), &'static str> {
        let module = load_module(engine, bytes)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|error| {
                crate::kwarn!("{} instantiate failed: {:?}", module_name, error);
                module_name
            })?;
        let memory = get_memory(&mut store, &instance)?;
        let request_ptr = instance
            .get_typed_func::<(), u32>(&store, "request_ptr")
            .map_err(|_| "missing service request_ptr export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch service request_ptr")?;
        let request_capacity = instance
            .get_typed_func::<(), u32>(&store, "request_capacity")
            .map_err(|_| "missing service request_capacity export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch service request_capacity")?;
        let response_ptr = instance
            .get_typed_func::<(), u32>(&store, "response_ptr")
            .map_err(|_| "missing service response_ptr export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch service response_ptr")?;
        let response_capacity = instance
            .get_typed_func::<(), u32>(&store, "response_capacity")
            .map_err(|_| "missing service response_capacity export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch service response_capacity")?;

        Ok((
            Self {
                store,
                memory,
                request_ptr,
                request_capacity,
                response_ptr,
                response_capacity,
            },
            instance,
        ))
    }

    pub(super) fn write_request(&mut self, bytes: &[u8]) -> Result<u32, &'static str> {
        if bytes.len() > self.request_capacity as usize {
            return Err("service request buffer overflowed");
        }
        self.memory
            .write(&mut self.store, self.request_ptr as usize, bytes)
            .map_err(|_| "failed to write service request buffer")?;
        Ok(bytes.len() as u32)
    }

    pub(super) fn read_response(&mut self, len: u32) -> Result<Vec<u8>, &'static str> {
        if len > self.response_capacity {
            return Err("service response exceeded capacity");
        }
        read_memory(&self.memory, &self.store, self.response_ptr, len)
    }
}

pub(super) fn expect_ok(rc: i32) -> Result<(), ServiceCallError> {
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

pub(super) fn expect_len(rc: i32) -> Result<u32, ServiceCallError> {
    if rc < 0 {
        Err(ServiceCallError::Errno(-rc))
    } else {
        Ok(rc as u32)
    }
}

pub(super) fn load_module(engine: &Engine, bytes: &[u8]) -> Result<Module, &'static str> {
    Module::new(engine, bytes).map_err(map_wasmi_error)
}

pub(super) fn get_memory(
    store: &mut Store<()>,
    instance: &Instance,
) -> Result<Memory, &'static str> {
    match instance.get_export(store, "memory") {
        Some(Extern::Memory(memory)) => Ok(memory),
        _ => Err("wasm module did not export linear memory"),
    }
}

pub(super) fn read_memory(
    memory: &Memory,
    store: &Store<()>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, &'static str> {
    let mut buffer = vec![0_u8; len as usize];
    memory
        .read(store, ptr as usize, &mut buffer)
        .map_err(|_| "failed to read wasm linear memory")?;
    Ok(buffer)
}

fn map_wasmi_error(error: Error) -> &'static str {
    let _ = error;
    "wasmi returned an error"
}
