use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{
    adapter::RuntimeOnlyExecutor,
    contract::{ArtifactFormat, SupervisorArtifact},
};
use crate::supervisor::types::ServiceCallError;

pub(crate) type SupervisorEngine = RuntimeOnlyExecutor;
pub(crate) type ModuleInstance = ArtifactInstance;
pub(crate) type WasmFn<Params, Results> = ArtifactFn<Params, Results>;
pub(crate) type BufferedModule = BufferedArtifactInstance;

pub(crate) trait FunctionParams {}
impl<T> FunctionParams for T {}

pub(crate) trait FunctionResults {}
impl<T> FunctionResults for T {}

pub(crate) struct ArtifactFn<Params, Results> {
    export: &'static str,
    _marker: PhantomData<fn(Params) -> Results>,
}

impl<Params, Results> ArtifactFn<Params, Results> {
    const fn new(export: &'static str) -> Self {
        Self { export, _marker: PhantomData }
    }

    pub(crate) const fn export(&self) -> &'static str {
        self.export
    }
}

pub(crate) struct ArtifactInstance {
    package: &'static str,
    format: ArtifactFormat,
}

impl ArtifactInstance {
    pub(crate) fn instantiate(
        executor: &RuntimeOnlyExecutor,
        bytes: &[u8],
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        let artifact = SupervisorArtifact::embedded_wasm("embedded-supervisor-module", bytes);
        Self::instantiate_artifact(executor, artifact, instantiate_msg)
    }

    pub(crate) fn instantiate_artifact(
        executor: &RuntimeOnlyExecutor,
        artifact: SupervisorArtifact<'_>,
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        executor.validate_artifact(artifact).map_err(|error| {
            crate::kwarn!(
                "{}: package={} format={} reason={}",
                instantiate_msg,
                artifact.package,
                artifact.format.as_str(),
                error.message()
            );
            instantiate_msg
        })?;
        Ok(Self { package: artifact.package, format: artifact.format })
    }

    pub(crate) fn bind<Params, Results>(
        &self,
        export: &'static str,
        _missing_msg: &'static str,
    ) -> Result<ArtifactFn<Params, Results>, &'static str>
    where
        Params: FunctionParams,
        Results: FunctionResults,
    {
        let _package = self.package;
        Ok(ArtifactFn::new(export))
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
        func: &ArtifactFn<Params, Results>,
        _args: Params,
        trap_msg: &'static str,
    ) -> Result<Results, &'static str>
    where
        Params: FunctionParams,
        Results: FunctionResults,
    {
        crate::kwarn!(
            "runtime-only executor cannot call {}::{} format={} without target loader",
            self.package,
            func.export(),
            self.format.as_str()
        );
        Err(trap_msg)
    }

    pub(crate) fn write_memory(
        &mut self,
        ptr: u32,
        bytes: &[u8],
        error_msg: &'static str,
    ) -> Result<(), &'static str> {
        let _ = (ptr, bytes);
        Err(error_msg)
    }

    pub(crate) fn read_memory(
        &self,
        ptr: u32,
        len: u32,
        error_msg: &'static str,
    ) -> Result<Vec<u8>, &'static str> {
        let _ = (ptr, len);
        Err(error_msg)
    }
}

pub(crate) struct BufferedArtifactInstance {
    module: ArtifactInstance,
    request_ptr: u32,
    request_capacity: u32,
    response_ptr: u32,
    response_capacity: u32,
}

impl BufferedArtifactInstance {
    pub(crate) fn instantiate(
        executor: &RuntimeOnlyExecutor,
        bytes: &[u8],
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        let artifact = SupervisorArtifact::embedded_wasm("embedded-buffered-service", bytes);
        Self::instantiate_artifact(executor, artifact, instantiate_msg)
    }

    pub(crate) fn instantiate_artifact(
        executor: &RuntimeOnlyExecutor,
        artifact: SupervisorArtifact<'_>,
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        let mut module =
            ArtifactInstance::instantiate_artifact(executor, artifact, instantiate_msg)?;
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
        Ok(Self { module, request_ptr, request_capacity, response_ptr, response_capacity })
    }

    pub(crate) fn bind<Params, Results>(
        &self,
        export: &'static str,
        missing_msg: &'static str,
    ) -> Result<ArtifactFn<Params, Results>, &'static str>
    where
        Params: FunctionParams,
        Results: FunctionResults,
    {
        self.module.bind(export, missing_msg)
    }

    pub(crate) fn call<Params, Results>(
        &mut self,
        func: &ArtifactFn<Params, Results>,
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
        self.module.read_memory(self.response_ptr, len, "failed to read service response buffer")
    }
}

pub(crate) fn expect_ok(rc: i32) -> Result<(), ServiceCallError> {
    if rc == 0 {
        Ok(())
    } else if rc < 0 {
        Err(ServiceCallError::Errno(-rc))
    } else {
        Err(ServiceCallError::Invalid("service returned an unexpected positive status"))
    }
}

pub(crate) fn expect_len(rc: i32) -> Result<u32, ServiceCallError> {
    if rc < 0 { Err(ServiceCallError::Errno(-rc)) } else { Ok(rc as u32) }
}
