use alloc::vec::Vec;

use super::wasmi_backend::{self, FunctionParams, FunctionResults};
use crate::supervisor::types::ServiceCallError;

pub(crate) struct SupervisorEngine {
    inner: EngineBackend,
}

enum EngineBackend {
    Wasmi(wasmi_backend::WasmiEngine),
}

pub(crate) struct WasmFn<Params, Results> {
    inner: FunctionBackend<Params, Results>,
}

enum FunctionBackend<Params, Results> {
    Wasmi(wasmi_backend::WasmiFunction<Params, Results>),
}

pub(crate) struct ModuleInstance {
    inner: ModuleBackend,
}

enum ModuleBackend {
    Wasmi(wasmi_backend::WasmiModuleInstance),
}

impl Default for SupervisorEngine {
    fn default() -> Self {
        Self {
            inner: EngineBackend::Wasmi(wasmi_backend::new_engine()),
        }
    }
}

impl ModuleInstance {
    pub(crate) fn instantiate(
        engine: &SupervisorEngine,
        bytes: &[u8],
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        match &engine.inner {
            EngineBackend::Wasmi(engine) => {
                wasmi_backend::instantiate(engine, bytes, instantiate_msg).map(|inner| Self {
                    inner: ModuleBackend::Wasmi(inner),
                })
            }
        }
    }

    pub(crate) fn bind<Params, Results>(
        &self,
        export: &'static str,
        missing_msg: &'static str,
    ) -> Result<WasmFn<Params, Results>, &'static str>
    where
        Params: FunctionParams,
        Results: FunctionResults,
    {
        match &self.inner {
            ModuleBackend::Wasmi(module) => {
                wasmi_backend::bind(module, export, missing_msg).map(|inner| WasmFn {
                    inner: FunctionBackend::Wasmi(inner),
                })
            }
        }
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
        Params: FunctionParams,
        Results: FunctionResults,
    {
        match (&mut self.inner, &func.inner) {
            (ModuleBackend::Wasmi(module), FunctionBackend::Wasmi(func)) => {
                wasmi_backend::call(module, func, args, trap_msg)
            }
        }
    }

    pub(crate) fn write_memory(
        &mut self,
        ptr: u32,
        bytes: &[u8],
        error_msg: &'static str,
    ) -> Result<(), &'static str> {
        match &mut self.inner {
            ModuleBackend::Wasmi(module) => {
                wasmi_backend::write_memory(module, ptr, bytes, error_msg)
            }
        }
    }

    pub(crate) fn read_memory(
        &self,
        ptr: u32,
        len: u32,
        error_msg: &'static str,
    ) -> Result<Vec<u8>, &'static str> {
        match &self.inner {
            ModuleBackend::Wasmi(module) => wasmi_backend::read_memory(module, ptr, len, error_msg),
        }
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
        Params: FunctionParams,
        Results: FunctionResults,
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
        Params: FunctionParams,
        Results: FunctionResults,
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
