//! Host-side wasmtime adapter for vISA runtime execution.
//!
//! This crate wraps a Wasmtime engine around `VisaRuntime`, executing Wasm guest
//! modules while routing hostcalls through the contract-aware hostcall dispatch
//! path.  It is a `std` crate and does not modify the `no_std` vms_runtime core.

use std::{
    error::Error,
    fmt,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use semantic_core::target_executor::{ActivationEntry, HostcallSpec};
use target_abi::{SectionKindV1, TargetArtifactError};
use vms_runtime::{
    ActivationHandle, HostcallDispatchReport, LoadedVisaArtifact, VisaArtifactInput,
    VisaExecutionReport, VisaHostcallPayload, VisaHostcallValue, VisaRuntime, VisaRuntimeError,
    VisaSubstrate,
};
use wasmtime::{
    Caller, Engine, ExternType, FuncType, Instance, Linker, Module, Store, Trap, Val, ValType,
};

#[derive(Debug)]
pub enum WasmVisaError {
    Artifact(TargetArtifactError),
    Wasmtime(String),
    Runtime(VisaRuntimeError),
    MissingExport(String),
    HostcallNotBound(u32),
    DuplicateHostcallNumber(u32),
    InvalidHostcallImport(String),
    Trap(String),
}

impl fmt::Display for WasmVisaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Artifact(e) => write!(f, "artifact error: {e:?}"),
            Self::Wasmtime(msg) => write!(f, "wasmtime error: {msg}"),
            Self::Runtime(e) => write!(f, "runtime error: {e:?}"),
            Self::MissingExport(name) => write!(f, "missing export: {name}"),
            Self::HostcallNotBound(n) => write!(f, "hostcall {n} not bound"),
            Self::DuplicateHostcallNumber(n) => write!(f, "duplicate hostcall number: {n}"),
            Self::InvalidHostcallImport(name) => write!(f, "invalid hostcall import: {name}"),
            Self::Trap(msg) => write!(f, "trap: {msg}"),
        }
    }
}

impl Error for WasmVisaError {}

impl From<VisaRuntimeError> for WasmVisaError {
    fn from(e: VisaRuntimeError) -> Self {
        Self::Runtime(e)
    }
}

/// Host state owned by the wasmtime `Store`.
pub struct WasmVisaState {
    pub runtime: VisaRuntime,
    pub substrate: Box<dyn VisaSubstrate>,
    pub loaded: Option<LoadedVisaArtifact>,
    pub activation: Option<ActivationHandle>,
    pub hostcall_reports: Vec<HostcallDispatchReport>,
    /// Hostcall specs from the artifact descriptor, indexed by hostcall number.
    hostcall_specs: Vec<HostcallSpec>,
}

impl WasmVisaState {
    fn clear_execution_state(&mut self) {
        self.loaded = None;
        self.activation = None;
        self.hostcall_specs.clear();
        self.hostcall_reports.clear();
    }

    fn dispatch_hostcall(
        &mut self,
        number: u32,
        payload: VisaHostcallPayload,
    ) -> Result<HostcallDispatchReport, VisaRuntimeError> {
        let activation = self.activation.clone().ok_or(VisaRuntimeError::MissingActivation(0))?;
        let report =
            self.runtime.invoke_hostcall(&activation, number, payload, self.substrate.as_mut())?;
        self.hostcall_reports.push(report.clone());
        Ok(report)
    }
}

/// Wraps a `VisaRuntime` inside a Wasmtime execution engine.
pub struct WasmVisaExecutor {
    engine: Engine,
    linker: Linker<WasmVisaState>,
    store: Store<WasmVisaState>,
    instance: Option<Instance>,
}

impl WasmVisaExecutor {
    pub fn new(runtime: VisaRuntime, substrate: Box<dyn VisaSubstrate>) -> Self {
        let engine = Engine::default();
        let linker = Linker::new(&engine);
        let store = Store::new(
            &engine,
            WasmVisaState {
                runtime,
                substrate,
                loaded: None,
                activation: None,
                hostcall_reports: Vec::new(),
                hostcall_specs: Vec::new(),
            },
        );
        Self { engine, linker, store, instance: None }
    }

    pub fn runtime(&self) -> &VisaRuntime {
        &self.store.data().runtime
    }

    pub fn runtime_mut(&mut self) -> &mut VisaRuntime {
        &mut self.store.data_mut().runtime
    }

    pub fn into_parts(self) -> (VisaRuntime, Box<dyn VisaSubstrate>) {
        let state = self.store.into_data();
        (state.runtime, state.substrate)
    }

    pub fn hostcall_reports(&self) -> &[HostcallDispatchReport] {
        &self.store.data().hostcall_reports
    }

    /// Pass the artifact through VisaRuntime for profile gate + store +
    /// activation. Saves hostcall specs for later binding.
    /// Call `run()` (which compiles, binds, and instantiates) or manually
    /// compile + link_hostcalls + instantiate after calling this.
    pub fn load_and_activate(
        &mut self,
        input: VisaArtifactInput<'_>,
        entry: &str,
    ) -> Result<(), WasmVisaError> {
        // Preserve hostcall specs from the descriptor before load_artifact consumes it
        let hostcall_specs: Vec<HostcallSpec> = input.descriptor.hostcalls.clone();
        self.instance = None;
        self.store.data_mut().clear_execution_state();
        validate_adapter_hostcalls(&hostcall_specs)?;

        let _parsed =
            target_abi::TargetArtifactImage::parse(input.bytes).map_err(WasmVisaError::Artifact)?;

        let loaded = {
            let state = self.store.data_mut();
            let runtime = &mut state.runtime;
            let substrate = state.substrate.as_mut();
            runtime.load_artifact(input, substrate)?
        };

        let activation = {
            let state = self.store.data_mut();
            state.runtime.start_activation(&loaded, ActivationEntry::Symbol(entry.to_string()))?
        };

        let state = self.store.data_mut();
        state.loaded = Some(loaded);
        state.activation = Some(activation);
        state.hostcall_specs = hostcall_specs;
        Ok(())
    }

    /// Call a wasm exported function by name.
    /// Traps are recorded to the runtime executor.
    pub fn call_export(
        &mut self,
        func_name: &str,
        params: &[Val],
    ) -> Result<Vec<Val>, WasmVisaError> {
        let instance = self
            .instance
            .as_ref()
            .ok_or_else(|| WasmVisaError::Wasmtime("no instance loaded".into()))?;
        let func = instance
            .get_func(&mut self.store, func_name)
            .ok_or_else(|| WasmVisaError::MissingExport(func_name.into()))?;
        let result_count = func.ty(&self.store).results().len();
        let mut results = vec![Val::I32(0); result_count];
        func.call(&mut self.store, params, &mut results).map_err(|e| {
            let msg = wasmtime_error_message(&e);
            if e.downcast_ref::<Trap>().is_some() {
                let (activation_id, store_id) = {
                    let state = self.store.data();
                    match (&state.activation, &state.loaded) {
                        (Some(act), Some(loaded)) => (act.activation_id, loaded.store_id),
                        _ => return WasmVisaError::Trap(msg),
                    }
                };
                self.store.data_mut().runtime.record_trap(activation_id, store_id, &msg);
                WasmVisaError::Trap(msg)
            } else {
                WasmVisaError::Wasmtime(msg)
            }
        })?;
        Ok(results)
    }

    /// Run: load artifact, activate, call the wasm entry export.
    pub fn run(
        &mut self,
        input: VisaArtifactInput<'_>,
        entry: &str,
    ) -> Result<VisaExecutionReport, WasmVisaError> {
        self.run_with_entry(input, entry)
    }

    fn run_with_entry(
        &mut self,
        input: VisaArtifactInput<'_>,
        entry: &str,
    ) -> Result<VisaExecutionReport, WasmVisaError> {
        self.instance = None;
        self.store.data_mut().clear_execution_state();
        let artifact_bytes = input.bytes;
        let specs: Vec<HostcallSpec> = input.descriptor.hostcalls.clone();
        validate_adapter_hostcalls(&specs)?;

        let code_payload = {
            target_abi::TargetArtifactImage::parse(artifact_bytes)
                .map_err(WasmVisaError::Artifact)?
                .section_payload(SectionKindV1::CodeObject)
                .map_err(WasmVisaError::Artifact)?
                .ok_or_else(|| WasmVisaError::Wasmtime("missing code section".into()))?
        };

        let module = Module::new(&self.engine, code_payload)
            .map_err(|e| WasmVisaError::Wasmtime(format!("compile: {e}")))?;
        validate_module_hostcall_imports(&module, &specs)?;

        self.load_and_activate(input, entry)?;

        self.linker = Linker::new(&self.engine);
        for spec in &specs {
            let n = spec.number;
            let import_name = format!("hostcall_{n}");
            let ty = FuncType::new(
                &self.engine,
                vec![
                    ValType::I64,
                    ValType::I64,
                    ValType::I64,
                    ValType::I64,
                    ValType::I64,
                    ValType::I64,
                ],
                vec![ValType::I64],
            );
            let obj = spec.object.clone();
            let op = spec.operation.clone();
            self.linker
                .func_new(
                    "vms",
                    &import_name,
                    ty,
                    move |mut caller: Caller<'_, WasmVisaState>,
                          params: &[Val],
                          results: &mut [Val]| {
                        let args = [
                            params.first().map(|v| v.unwrap_i64()).unwrap_or(0),
                            params.get(1).map(|v| v.unwrap_i64()).unwrap_or(0),
                            params.get(2).map(|v| v.unwrap_i64()).unwrap_or(0),
                            params.get(3).map(|v| v.unwrap_i64()).unwrap_or(0),
                            params.get(4).map(|v| v.unwrap_i64()).unwrap_or(0),
                            params.get(5).map(|v| v.unwrap_i64()).unwrap_or(0),
                        ];
                        let payload = hostcall_payload_for_object(&mut caller, &obj, &op, args)
                            .map_err(|error| {
                                wasmtime::Error::msg(format!("hostcall {n} decode failed: {error}"))
                            })?;
                        let report =
                            caller.data_mut().dispatch_hostcall(n, payload).map_err(|error| {
                                wasmtime::Error::msg(format!(
                                    "hostcall {n} dispatch failed: {error:?}"
                                ))
                            })?;
                        let result = {
                            if let VisaHostcallValue::Bytes(bytes) = &report.value
                                && operation_returns_guest_bytes(&obj, &op)
                                && args[4] >= 0
                            {
                                write_guest_bytes(&mut caller, args[4] as usize, bytes)
                                    .map_err(wasmtime::Error::msg)?;
                            }
                            hostcall_result_i64(&report.value)
                        };
                        results[0] = Val::I64(result);
                        Ok(())
                    },
                )
                .map_err(|e| WasmVisaError::Wasmtime(format!("link hostcall {n}: {e}")))?;
        }

        let instance = self
            .linker
            .instantiate(&mut self.store, &module)
            .map_err(|e| WasmVisaError::Wasmtime(format!("instantiate: {e}")))?;
        self.instance = Some(instance);

        // Call the wasm entry point — propagate errors (missing export, trap, etc.)
        self.call_export(entry, &[])?;

        let data = self.store.data();
        Ok(VisaExecutionReport {
            loaded: data
                .loaded
                .clone()
                .ok_or_else(|| WasmVisaError::Wasmtime("no loaded artifact".into()))?,
            activation: data
                .activation
                .clone()
                .ok_or_else(|| WasmVisaError::Wasmtime("no activation".into()))?,
            hostcalls: data.hostcall_reports.clone(),
            events: data.runtime.events().to_vec(),
        })
    }
}

// ── hostcall wire decoding ────────────────────────────────────────────────

fn wasmtime_error_message(error: &wasmtime::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        message.push_str(": ");
        message.push_str(&error.to_string());
        source = error.source();
    }
    message
}

fn validate_adapter_hostcalls(specs: &[HostcallSpec]) -> Result<(), WasmVisaError> {
    let mut numbers = Vec::new();
    for spec in specs {
        if numbers.contains(&spec.number) {
            return Err(WasmVisaError::DuplicateHostcallNumber(spec.number));
        }
        numbers.push(spec.number);
        if !adapter_supports_hostcall(&spec.object, &spec.operation) {
            return Err(WasmVisaError::HostcallNotBound(spec.number));
        }
    }
    Ok(())
}

fn validate_module_hostcall_imports(
    module: &Module,
    specs: &[HostcallSpec],
) -> Result<(), WasmVisaError> {
    for import in module.imports() {
        let module_name = import.module();
        let name = import.name();
        if module_name != "vms" {
            return Err(WasmVisaError::InvalidHostcallImport(format!("{module_name}::{name}")));
        }
        let Some(number) = name.strip_prefix("hostcall_") else {
            return Err(WasmVisaError::InvalidHostcallImport(format!("vms::{name}")));
        };
        let number = number
            .parse::<u32>()
            .map_err(|_| WasmVisaError::InvalidHostcallImport(format!("vms::{name}")))?;
        if !specs.iter().any(|spec| spec.number == number) {
            return Err(WasmVisaError::HostcallNotBound(number));
        }
        let ExternType::Func(func_ty) = import.ty() else {
            return Err(WasmVisaError::InvalidHostcallImport(format!("vms::{name}")));
        };
        if !is_hostcall_import_type(&func_ty) {
            return Err(WasmVisaError::InvalidHostcallImport(format!("vms::{name}")));
        }
    }
    Ok(())
}

fn is_hostcall_import_type(func_ty: &FuncType) -> bool {
    let mut params = func_ty.params();
    for _ in 0..6 {
        if !matches!(params.next(), Some(ValType::I64)) {
            return false;
        }
    }
    if params.next().is_some() {
        return false;
    }

    let mut results = func_ty.results();
    matches!(results.next(), Some(ValType::I64)) && results.next().is_none()
}

fn adapter_supports_hostcall(object: &str, operation: &str) -> bool {
    matches!(
        (object, operation),
        ("wasi.fd", "write")
            | ("test.console", "write")
            | ("visa.console", "write")
            | ("timer.wasi", "read")
            | ("timer", "now")
            | ("visa.timer", "now")
            | ("timer.wasi", "arm")
            | ("visa.timer", "arm")
            | ("guest-memory", "read")
            | ("guest-memory", "copyin")
            | ("visa.memory", "copyin")
            | ("guest-memory", "write")
            | ("guest-memory", "copyout")
            | ("visa.memory", "copyout")
            | ("dmw", "map")
            | ("visa.dmw", "map")
            | ("dmw", "unmap")
            | ("visa.dmw", "unmap")
            | ("mmio", "read32")
            | ("visa.mmio", "read32")
            | ("mmio", "write32")
            | ("visa.mmio", "write32")
            | ("dma", "alloc")
            | ("visa.dma", "alloc")
            | ("dma", "free")
            | ("visa.dma", "free")
            | ("irq", "ack")
            | ("visa.irq", "ack")
            | ("irq", "mask")
            | ("visa.irq", "mask")
            | ("irq", "unmask")
            | ("visa.irq", "unmask")
            | ("snapshot", "enter")
            | ("visa.snapshot", "enter")
            | ("snapshot", "exit")
            | ("visa.snapshot", "exit")
    )
}

fn hostcall_payload_for_object(
    caller: &mut Caller<'_, WasmVisaState>,
    object: &str,
    operation: &str,
    args: [i64; 6],
) -> Result<VisaHostcallPayload, String> {
    let [a, b, c, d, e, _f] = args;
    match (object, operation) {
        ("visa.console", "write") => {
            let bytes = read_guest_bytes(caller, a as usize, b.max(0) as usize)?;
            Ok(VisaHostcallPayload::ConsoleWrite { bytes })
        }
        ("wasi.fd", "write") | ("test.console", "write") => {
            let len = a.max(0) as usize;
            let mut bytes = Vec::with_capacity(len.min(1024));
            for byte in [b, c, d] {
                if byte > 0 {
                    bytes.push(byte as u8);
                }
            }
            Ok(VisaHostcallPayload::ConsoleWrite { bytes })
        }
        ("timer.wasi", "read") | ("timer", "now") | ("visa.timer", "now") => {
            Ok(VisaHostcallPayload::TimerNow)
        }
        ("timer.wasi", "arm") | ("visa.timer", "arm") => Ok(VisaHostcallPayload::TimerArm {
            deadline_ticks: a as u64,
            token: substrate_api::WaitTokenRef::new(b as u64, c as u64),
        }),
        ("guest-memory", "read") | ("guest-memory", "copyin") | ("visa.memory", "copyin") => {
            let memory = substrate_api::UserMemoryHandle::new(a as u64, b as u64);
            let ptr = c as u64;
            let len = d.max(0) as usize;
            Ok(VisaHostcallPayload::GuestMemoryCopyIn { memory, ptr, len })
        }
        ("guest-memory", "write") | ("guest-memory", "copyout") | ("visa.memory", "copyout") => {
            let memory = substrate_api::UserMemoryHandle::new(a as u64, b as u64);
            let ptr = c as u64;
            let bytes = read_guest_bytes(caller, e as usize, d.max(0) as usize)?;
            Ok(VisaHostcallPayload::GuestMemoryCopyOut { memory, ptr, bytes })
        }
        ("dmw", "map") | ("visa.dmw", "map") => {
            let memory = substrate_api::UserMemoryHandle::new(a as u64, b as u64);
            let ptr = c as u64;
            let len = d.max(0) as usize;
            Ok(VisaHostcallPayload::DmwMap {
                memory,
                ptr,
                len,
                perms: window_perms_from_bits(e as u64),
            })
        }
        ("dmw", "unmap") | ("visa.dmw", "unmap") => Ok(VisaHostcallPayload::DmwUnmap {
            lease: substrate_api::WindowLeaseRef::new(a as u64, b as u64),
        }),
        ("mmio", "read32") | ("visa.mmio", "read32") => Ok(VisaHostcallPayload::MmioRead32 {
            region: substrate_api::MmioRegionRef::new(a as u64, b as u64),
            offset: c as u64,
        }),
        ("mmio", "write32") | ("visa.mmio", "write32") => Ok(VisaHostcallPayload::MmioWrite32 {
            region: substrate_api::MmioRegionRef::new(a as u64, b as u64),
            offset: c as u64,
            value: d as u32,
        }),
        ("dma", "alloc") | ("visa.dma", "alloc") => Ok(VisaHostcallPayload::DmaAlloc {
            request: substrate_api::DmaAllocRequest::new(
                a as u64,
                b.max(0) as usize,
                c.max(1) as usize,
            ),
        }),
        ("dma", "free") | ("visa.dma", "free") => Ok(VisaHostcallPayload::DmaFree {
            capability: substrate_api::DmaBufferCapability::new(a as u64, b as u64),
        }),
        ("irq", "ack") | ("visa.irq", "ack") => {
            Ok(VisaHostcallPayload::IrqAck { irq: substrate_api::IrqLine::new(a as u64, b as u64) })
        }
        ("irq", "mask") | ("visa.irq", "mask") => Ok(VisaHostcallPayload::IrqMask {
            irq: substrate_api::IrqLine::new(a as u64, b as u64),
        }),
        ("irq", "unmask") | ("visa.irq", "unmask") => Ok(VisaHostcallPayload::IrqUnmask {
            irq: substrate_api::IrqLine::new(a as u64, b as u64),
        }),
        ("snapshot", "enter") | ("visa.snapshot", "enter") => {
            Ok(VisaHostcallPayload::SnapshotEnter)
        }
        ("snapshot", "exit") | ("visa.snapshot", "exit") => Ok(VisaHostcallPayload::SnapshotExit {
            barrier: substrate_api::SnapshotBarrierRef::new(a as u64, b as u64),
        }),
        _ => Err(format!("unsupported hostcall object={object} operation={operation}")),
    }
}

fn operation_returns_guest_bytes(object: &str, operation: &str) -> bool {
    matches!(
        (object, operation),
        ("guest-memory", "read") | ("guest-memory", "copyin") | ("visa.memory", "copyin")
    )
}

fn read_guest_bytes(
    caller: &mut Caller<'_, WasmVisaState>,
    ptr: usize,
    len: usize,
) -> Result<Vec<u8>, String> {
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or_else(|| "guest memory export is missing".to_string())?;
    let data = memory.data(&mut *caller);
    let end = ptr.checked_add(len).ok_or_else(|| "guest memory read overflow".to_string())?;
    let Some(bytes) = data.get(ptr..end) else {
        return Err("guest memory read is out of bounds".to_string());
    };
    Ok(bytes.to_vec())
}

fn write_guest_bytes(
    caller: &mut Caller<'_, WasmVisaState>,
    ptr: usize,
    bytes: &[u8],
) -> Result<(), String> {
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or_else(|| "guest memory export is missing".to_string())?;
    let data = memory.data_mut(&mut *caller);
    let end =
        ptr.checked_add(bytes.len()).ok_or_else(|| "guest memory write overflow".to_string())?;
    let Some(dst) = data.get_mut(ptr..end) else {
        return Err("guest memory write is out of bounds".to_string());
    };
    dst.copy_from_slice(bytes);
    Ok(())
}

fn window_perms_from_bits(bits: u64) -> substrate_api::WindowPerms {
    substrate_api::WindowPerms {
        read: bits & 0b001 != 0,
        write: bits & 0b010 != 0,
        execute: bits & 0b100 != 0,
    }
}

fn hostcall_result_i64(value: &VisaHostcallValue) -> i64 {
    match value {
        VisaHostcallValue::None => 0,
        VisaHostcallValue::U32(v) => i64::from(*v),
        VisaHostcallValue::U64(v) => *v as i64,
        VisaHostcallValue::Bytes(b) => b.len() as i64,
        VisaHostcallValue::WindowLease(_) => 1,
        VisaHostcallValue::DmaBuffer(_) => 1,
        VisaHostcallValue::SnapshotBarrier(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    use semantic_core::target_executor::HostcallCategory;
    use sha2::{Digest, Sha256};
    use substrate_api::{
        ArtifactAuthority, CodePublisherAuthority, ConsoleAuthority, DmaAuthority, DmwAuthority,
        EventQueueAuthority, GuestBytes, GuestMemoryAuthority, IrqAuthority, MmioAuthority,
        SnapshotAuthority, SubstrateError, SubstrateResult, TimerAuthority, VirtualTime,
    };
    use target_abi::{
        TargetArtifactHeaderV1, TargetSectionHeaderV1, canonical_zero_field_image_hash,
    };
    use visa_profile::SubstrateProfile;
    use vms_runtime::{VisaArtifactDescriptor, VisaHostcallValue, VisaRuntimeConfig};

    use super::*;

    // ── test substrate ────────────────────────────────────────────────────

    #[derive(Default)]
    struct TestSubstrate {
        console: Vec<u8>,
        fail_console: bool,
        timers: usize,
        guest_memory_source: Vec<u8>,
        guest_memory_sink: Vec<u8>,
        dmw_live: bool,
        mmio: u32,
        dma_live: bool,
        irq_ops: Vec<&'static str>,
        snapshot_live: bool,
    }

    impl ConsoleAuthority for TestSubstrate {
        fn console_write(&mut self, bytes: &[u8]) -> SubstrateResult<usize> {
            if self.fail_console {
                return Err(SubstrateError::unsupported("ConsoleAuthority", "console_write"));
            }
            self.console.extend_from_slice(bytes);
            Ok(bytes.len())
        }
    }

    impl TimerAuthority for TestSubstrate {
        fn now(&self) -> SubstrateResult<VirtualTime> {
            Ok(VirtualTime::from_ticks(42))
        }

        fn arm_timer(
            &mut self,
            _deadline: VirtualTime,
            _token: substrate_api::WaitTokenRef,
        ) -> SubstrateResult<()> {
            self.timers += 1;
            Ok(())
        }
    }

    impl EventQueueAuthority for TestSubstrate {}
    impl GuestMemoryAuthority for TestSubstrate {
        fn copyin(
            &self,
            _mem: substrate_api::UserMemoryHandle,
            _ptr: u64,
            len: usize,
        ) -> SubstrateResult<GuestBytes> {
            let source = if self.guest_memory_source.is_empty() {
                b"vISA".as_slice()
            } else {
                self.guest_memory_source.as_slice()
            };
            Ok(source.iter().copied().cycle().take(len).collect())
        }

        fn copyout(
            &mut self,
            _mem: substrate_api::UserMemoryHandle,
            _ptr: u64,
            data: &[u8],
        ) -> SubstrateResult<()> {
            self.guest_memory_sink.clear();
            self.guest_memory_sink.extend_from_slice(data);
            Ok(())
        }
    }

    impl DmwAuthority for TestSubstrate {
        fn map_user_window(
            &mut self,
            _mem: substrate_api::UserMemoryHandle,
            _ptr: u64,
            len: usize,
            perms: substrate_api::WindowPerms,
        ) -> SubstrateResult<substrate_api::WindowLeaseRef> {
            if len == 0 || !perms.read {
                return Err(SubstrateError::InvalidObject { object: "dmw-window" });
            }
            self.dmw_live = true;
            Ok(substrate_api::WindowLeaseRef::new(1, 1))
        }

        fn unmap_user_window(
            &mut self,
            lease: substrate_api::WindowLeaseRef,
        ) -> SubstrateResult<()> {
            if !lease.is_valid() || !self.dmw_live {
                return Err(SubstrateError::InvalidObject { object: "window-lease" });
            }
            self.dmw_live = false;
            Ok(())
        }
    }
    impl ArtifactAuthority for TestSubstrate {
        fn load_artifact_image(
            &mut self,
            _artifact: substrate_api::ArtifactImageRef,
        ) -> SubstrateResult<()> {
            Ok(())
        }
    }
    impl CodePublisherAuthority for TestSubstrate {
        fn publish_code(
            &mut self,
            _artifact: substrate_api::ArtifactImageRef,
            code: substrate_api::CodeObjectRef,
        ) -> SubstrateResult<substrate_api::PublishedCodeRef> {
            Ok(substrate_api::PublishedCodeRef::new(code.id, code.generation))
        }
    }
    impl MmioAuthority for TestSubstrate {
        fn mmio_read32(
            &self,
            _region: substrate_api::MmioRegionRef,
            _offset: u64,
        ) -> SubstrateResult<u32> {
            Ok(self.mmio)
        }

        fn mmio_write32(
            &mut self,
            _region: substrate_api::MmioRegionRef,
            _offset: u64,
            value: u32,
        ) -> SubstrateResult<()> {
            self.mmio = value;
            Ok(())
        }
    }

    impl DmaAuthority for TestSubstrate {
        fn dma_alloc(
            &mut self,
            req: substrate_api::DmaAllocRequest,
        ) -> SubstrateResult<substrate_api::DmaBufferCapability> {
            if req.bytes == 0 || req.alignment == 0 {
                return Err(SubstrateError::InvalidObject { object: "dma-request" });
            }
            self.dma_live = true;
            Ok(substrate_api::DmaBufferCapability::new(1, 1))
        }

        fn dma_free(
            &mut self,
            capability: substrate_api::DmaBufferCapability,
        ) -> SubstrateResult<()> {
            if !capability.is_valid() || !self.dma_live {
                return Err(SubstrateError::InvalidObject { object: "dma-buffer" });
            }
            self.dma_live = false;
            Ok(())
        }
    }

    impl IrqAuthority for TestSubstrate {
        fn irq_ack(&mut self, irq: substrate_api::IrqLine) -> SubstrateResult<()> {
            if !irq.is_valid() {
                return Err(SubstrateError::InvalidObject { object: "irq-line" });
            }
            self.irq_ops.push("ack");
            Ok(())
        }

        fn irq_mask(&mut self, irq: substrate_api::IrqLine) -> SubstrateResult<()> {
            if !irq.is_valid() {
                return Err(SubstrateError::InvalidObject { object: "irq-line" });
            }
            self.irq_ops.push("mask");
            Ok(())
        }

        fn irq_unmask(&mut self, irq: substrate_api::IrqLine) -> SubstrateResult<()> {
            if !irq.is_valid() {
                return Err(SubstrateError::InvalidObject { object: "irq-line" });
            }
            self.irq_ops.push("unmask");
            Ok(())
        }
    }

    impl SnapshotAuthority for TestSubstrate {
        fn enter_snapshot_barrier(&mut self) -> SubstrateResult<substrate_api::SnapshotBarrierRef> {
            self.snapshot_live = true;
            Ok(substrate_api::SnapshotBarrierRef::new(1, 1))
        }

        fn exit_snapshot_barrier(
            &mut self,
            barrier: substrate_api::SnapshotBarrierRef,
        ) -> SubstrateResult<()> {
            if !barrier.is_valid() || !self.snapshot_live {
                return Err(SubstrateError::InvalidObject { object: "snapshot-barrier" });
            }
            self.snapshot_live = false;
            Ok(())
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────

    const REQUIRED_SECTIONS: [SectionKindV1; 7] = [
        SectionKindV1::Manifest,
        SectionKindV1::CodeObject,
        SectionKindV1::HostcallImportTable,
        SectionKindV1::TrapMap,
        SectionKindV1::PcRangeTable,
        SectionKindV1::ProfileRequirements,
        SectionKindV1::Signature,
    ];

    fn fake_artifact(kinds: &[SectionKindV1], code_payload: &[u8]) -> Vec<u8> {
        let header_len = std::mem::size_of::<TargetArtifactHeaderV1>();
        let section_len = std::mem::size_of::<TargetSectionHeaderV1>();
        let payload_len = code_payload.len().max(16);
        let section_table_len = kinds.len() * section_len;
        let payload_base = header_len + section_table_len;
        let image_len = payload_base + kinds.len() * payload_len;
        let mut image = vec![0; image_len];

        let header = TargetArtifactHeaderV1::fake_riscv64(kinds.len() as u32, image_len as u64);
        header.write_to(&mut image).expect("header");

        for (index, kind) in kinds.iter().copied().enumerate() {
            let offset = payload_base + index * payload_len;
            if kind == SectionKindV1::CodeObject {
                let end = (offset + code_payload.len()).min(image_len);
                image[offset..end].copy_from_slice(code_payload);
            } else {
                image[offset..offset + payload_len].fill(kind as u32 as u8);
            }
            let mut section =
                TargetSectionHeaderV1::new(kind, offset as u64, payload_len as u64, 1);
            section.hash = Sha256::digest(&image[offset..offset + payload_len]).into();
            let section_off = header_len + index * section_len;
            section.write_to(&mut image[section_off..section_off + section_len]).expect("section");
        }

        let mut header = TargetArtifactHeaderV1::parse(&image).expect("parse header");
        let (manifest_start, manifest_end) = section_payload_range(&image, SectionKindV1::Manifest);
        header.manifest_hash = Sha256::digest(&image[manifest_start..manifest_end]).into();
        header.write_to(&mut image).expect("manifest hash");
        refresh_image_hash(&mut image);
        image
    }

    fn section_payload_range(image: &[u8], kind: SectionKindV1) -> (usize, usize) {
        let header = TargetArtifactHeaderV1::parse(image).expect("header");
        let section_len = std::mem::size_of::<TargetSectionHeaderV1>();
        for index in 0..header.section_count as usize {
            let section_off = std::mem::size_of::<TargetArtifactHeaderV1>() + index * section_len;
            let section =
                TargetSectionHeaderV1::parse(&image[section_off..section_off + section_len])
                    .expect("section");
            if section.kind == kind {
                let start = section.offset as usize;
                return (start, start + section.len as usize);
            }
        }
        panic!("missing section")
    }

    fn refresh_image_hash(image: &mut [u8]) {
        let mut header = TargetArtifactHeaderV1::parse(image).expect("header");
        header.image_hash = [0; 32];
        header.write_to(image).expect("zero image hash");
        let hash = canonical_zero_field_image_hash(image).expect("canonical hash");
        let mut header = TargetArtifactHeaderV1::parse(image).expect("header");
        header.image_hash = hash;
        header.write_to(image).expect("image hash");
    }

    fn wasm_module_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"(module
  (import "vms" "hostcall_1" (func $hc1 (param i64 i64 i64 i64 i64 i64) (result i64)))
  (func (export "entry") (result i64)
    i64.const 5
    i64.const 104
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $hc1
  )
)"#,
        )
        .expect("parse wat")
    }

    fn visa_native_console_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
  (import "vms" "hostcall_1" (func $console_write (param i64 i64 i64 i64 i64 i64) (result i64)))
  (memory (export "memory") 1)
  (data (i32.const 16) "native-vISA")
  (func (export "visa_start") (result i64)
    i64.const 16
    i64.const 11
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $console_write
  )
)"#,
        )
        .expect("parse wat")
    }

    fn visa_native_console_without_memory_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
  (import "vms" "hostcall_1" (func $console_write (param i64 i64 i64 i64 i64 i64) (result i64)))
  (func (export "visa_start") (result i64)
    i64.const 16
    i64.const 11
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $console_write
  )
)"#,
        )
        .expect("parse wat")
    }

    fn visa_native_console_oob_memory_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
  (import "vms" "hostcall_1" (func $console_write (param i64 i64 i64 i64 i64 i64) (result i64)))
  (memory (export "memory") 1)
  (func (export "visa_start") (result i64)
    i64.const 70000
    i64.const 16
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $console_write
  )
)"#,
        )
        .expect("parse wat")
    }

    fn visa_native_full_hostcall_abi_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
  (import "vms" "hostcall_1" (func $console_write (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_2" (func $timer_now (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_3" (func $timer_arm (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_4" (func $memory_copyin (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_5" (func $memory_copyout (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_6" (func $dmw_map (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_7" (func $dmw_unmap (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_8" (func $mmio_read32 (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_9" (func $mmio_write32 (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_10" (func $dma_alloc (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_11" (func $dma_free (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_12" (func $irq_ack (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_13" (func $irq_mask (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_14" (func $irq_unmask (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_15" (func $snapshot_enter (param i64 i64 i64 i64 i64 i64) (result i64)))
  (import "vms" "hostcall_16" (func $snapshot_exit (param i64 i64 i64 i64 i64 i64) (result i64)))
  (memory (export "memory") 1)
  (data (i32.const 16) "native-vISA")
  (func (export "visa_start") (result i64)
    i64.const 16
    i64.const 11
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $console_write
    drop

    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $timer_now
    drop

    i64.const 100
    i64.const 2
    i64.const 1
    i64.const 0
    i64.const 0
    i64.const 0
    call $timer_arm
    drop

    i64.const 1
    i64.const 1
    i64.const 4096
    i64.const 4
    i64.const 64
    i64.const 0
    call $memory_copyin
    drop

    i64.const 1
    i64.const 1
    i64.const 8192
    i64.const 4
    i64.const 64
    i64.const 0
    call $memory_copyout
    drop

    i64.const 1
    i64.const 1
    i64.const 4096
    i64.const 4096
    i64.const 3
    i64.const 0
    call $dmw_map
    drop

    i64.const 1
    i64.const 1
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $dmw_unmap
    drop

    i64.const 1
    i64.const 1
    i64.const 0
    i64.const 123
    i64.const 0
    i64.const 0
    call $mmio_write32
    drop

    i64.const 1
    i64.const 1
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $mmio_read32
    drop

    i64.const 7
    i64.const 4096
    i64.const 4096
    i64.const 0
    i64.const 0
    i64.const 0
    call $dma_alloc
    drop

    i64.const 1
    i64.const 1
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $dma_free
    drop

    i64.const 3
    i64.const 1
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $irq_ack
    drop

    i64.const 3
    i64.const 1
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $irq_mask
    drop

    i64.const 3
    i64.const 1
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $irq_unmask
    drop

    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $snapshot_enter
    drop

    i64.const 1
    i64.const 1
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $snapshot_exit
    drop

    i64.const 7
  )
  (func (export "probe_copyin_byte") (result i64)
    i32.const 64
    i32.load8_u
    i64.extend_i32_u
  )
)"#,
        )
        .expect("parse wat")
    }

    fn console_descriptor(id: u64) -> VisaArtifactDescriptor {
        VisaArtifactDescriptor::new(id, "test", "test-artifact", SubstrateProfile::GuestFrontend)
            .with_role("frontend-personality")
            .with_hostcall(HostcallSpec::new(
                1,
                "test.write",
                HostcallCategory::Service,
                "test.console",
                "write",
                false,
            ))
    }

    // ── tests ─────────────────────────────────────────────────────────────

    #[test]
    fn executor_creates_and_exposes_runtime() {
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let executor = WasmVisaExecutor::new(runtime, Box::new(substrate));
        let _rt = executor.runtime();
    }

    #[test]
    fn executor_into_parts_returns_runtime_and_substrate() {
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let executor = WasmVisaExecutor::new(runtime, Box::new(substrate));
        let (rt, mut sub) = executor.into_parts();
        assert!(!rt.semantic().tasks().is_empty());
        assert!(sub.console_write(b"test").is_ok());
    }

    #[test]
    fn runtime_loads_artifact_and_starts_activation() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = TestSubstrate::default();
        let artifact = fake_artifact(&REQUIRED_SECTIONS, &wasm_module_bytes());
        let descriptor = console_descriptor(9);

        let loaded = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect("runtime load_artifact");
        assert!(loaded.store_id > 0);
    }

    #[test]
    fn run_executes_wasm_entry_and_dispatches_hostcall() {
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(runtime, Box::new(substrate));

        let artifact = fake_artifact(&REQUIRED_SECTIONS, &wasm_module_bytes());
        let descriptor = console_descriptor(9);

        let report =
            executor.run(VisaArtifactInput { bytes: &artifact, descriptor }, "entry").expect("run");

        assert!(report.loaded.store_id > 0);
        // Hostcall should have been dispatched
        assert!(!report.hostcalls.is_empty(), "must have at least one hostcall dispatch");
    }

    #[test]
    fn run_executes_native_visa_memory_backed_console_hostcall() {
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(runtime, Box::new(substrate));

        let artifact = fake_artifact(&REQUIRED_SECTIONS, &visa_native_console_wasm());
        let personality = vms_runtime::personality::native::VisaNativePersonality::new(
            "native-visa",
            SubstrateProfile::MinimalBareMetal,
        );

        let report = executor
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(19) },
                "visa_start",
            )
            .expect("run native vISA artifact");

        assert_eq!(report.loaded.artifact_id, 19);
        assert_eq!(report.hostcalls.len(), 1);
        assert_eq!(report.hostcalls[0].object, "visa.console");
        assert_eq!(report.hostcalls[0].value, VisaHostcallValue::U64(11));
        assert!(
            executor
                .runtime()
                .snapshot()
                .artifacts
                .iter()
                .any(|artifact| artifact.role == "visa-native-workload")
        );
    }

    #[test]
    fn run_rejects_substrate_dispatch_error_without_success_report() {
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let substrate = TestSubstrate { fail_console: true, ..TestSubstrate::default() };
        let mut executor = WasmVisaExecutor::new(runtime, Box::new(substrate));

        let artifact = fake_artifact(&REQUIRED_SECTIONS, &visa_native_console_wasm());
        let personality = vms_runtime::personality::native::VisaNativePersonality::new(
            "native-visa-console-fails",
            SubstrateProfile::MinimalBareMetal,
        );

        let err = executor
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(41) },
                "visa_start",
            )
            .expect_err("substrate dispatch failure must stop execution");

        assert!(
            matches!(err, WasmVisaError::Wasmtime(ref message) if message.contains("hostcall 1 dispatch failed")),
            "expected hostcall dispatch failure, got: {err}"
        );
        assert!(
            executor.hostcall_reports().is_empty(),
            "failed dispatch must not expose a successful hostcall report"
        );
        assert!(
            executor.runtime().snapshot().hostcalls.is_empty(),
            "failed dispatch must not commit portable-success hostcall evidence"
        );
    }

    #[test]
    fn run_executes_native_visa_full_substrate_hostcall_abi() {
        let runtime = VisaRuntime::new(VisaRuntimeConfig::for_profile(
            SubstrateProfile::SnapshotReplayCapable,
        ));
        let substrate =
            TestSubstrate { guest_memory_source: b"vISA".to_vec(), ..TestSubstrate::default() };
        let mut executor = WasmVisaExecutor::new(runtime, Box::new(substrate));

        let artifact = fake_artifact(&REQUIRED_SECTIONS, &visa_native_full_hostcall_abi_wasm());
        let personality = vms_runtime::personality::native::VisaNativePersonality::new(
            "native-visa-full",
            SubstrateProfile::SnapshotReplayCapable,
        );

        let report = executor
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(29) },
                "visa_start",
            )
            .expect("run native vISA full ABI artifact");

        assert_eq!(report.loaded.artifact_id, 29);
        assert_eq!(report.hostcalls.len(), 16);
        assert_eq!(report.hostcalls[0].object, "visa.console");
        assert_eq!(report.hostcalls[0].value, VisaHostcallValue::U64(11));
        assert_eq!(report.hostcalls[1].value, VisaHostcallValue::U64(42));
        assert_eq!(report.hostcalls[3].value, VisaHostcallValue::Bytes(b"vISA".to_vec()));
        assert!(matches!(
            report.hostcalls[5].value,
            VisaHostcallValue::WindowLease(substrate_api::WindowLeaseRef { id: 1, generation: 1 })
        ));
        assert_eq!(report.hostcalls[8].value, VisaHostcallValue::U32(123));
        assert!(matches!(
            report.hostcalls[9].value,
            VisaHostcallValue::DmaBuffer(substrate_api::DmaBufferCapability {
                id: 1,
                generation: 1
            })
        ));
        assert!(matches!(
            report.hostcalls[14].value,
            VisaHostcallValue::SnapshotBarrier(substrate_api::SnapshotBarrierRef {
                id: 1,
                generation: 1
            })
        ));

        let probe = executor.call_export("probe_copyin_byte", &[]).expect("probe");
        assert!(
            matches!(probe.as_slice(), [Val::I64(value)] if *value == i64::from(b'v')),
            "probe must observe copyin bytes in guest memory: {probe:?}"
        );
        assert!(report.evidence_summary().can_claim_portable_artifact_execution);
        assert_eq!(executor.runtime().executor().hostcall_trace().len(), 16);
    }

    #[test]
    fn run_rejects_visa_console_without_guest_memory_decode() {
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(runtime, Box::new(substrate));
        let artifact =
            fake_artifact(&REQUIRED_SECTIONS, &visa_native_console_without_memory_wasm());
        let personality = vms_runtime::personality::native::VisaNativePersonality::new(
            "native-visa-no-memory",
            SubstrateProfile::MinimalBareMetal,
        );

        let err = executor
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(39) },
                "visa_start",
            )
            .expect_err("missing guest memory must fail payload decode");

        assert!(
            matches!(err, WasmVisaError::Wasmtime(ref message) if message.contains("guest memory export is missing")),
            "expected guest memory decode error, got: {err}"
        );
        assert!(executor.hostcall_reports().is_empty());
    }

    #[test]
    fn run_rejects_visa_console_oob_guest_memory_decode() {
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(runtime, Box::new(substrate));
        let artifact = fake_artifact(&REQUIRED_SECTIONS, &visa_native_console_oob_memory_wasm());
        let personality = vms_runtime::personality::native::VisaNativePersonality::new(
            "native-visa-oob-memory",
            SubstrateProfile::MinimalBareMetal,
        );

        let err = executor
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(40) },
                "visa_start",
            )
            .expect_err("out-of-bounds guest memory must fail payload decode");

        assert!(
            matches!(err, WasmVisaError::Wasmtime(ref message) if message.contains("guest memory read is out of bounds")),
            "expected guest memory bounds error, got: {err}"
        );
        assert!(executor.hostcall_reports().is_empty());
    }

    #[test]
    fn repeated_runs_report_only_current_hostcalls() {
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(runtime, Box::new(substrate));
        let artifact = fake_artifact(&REQUIRED_SECTIONS, &wasm_module_bytes());

        let first = executor
            .run(VisaArtifactInput { bytes: &artifact, descriptor: console_descriptor(9) }, "entry")
            .expect("first run");
        assert_eq!(first.hostcalls.len(), 1);
        assert_eq!(executor.hostcall_reports().len(), 1);

        let second = executor
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: console_descriptor(10) },
                "entry",
            )
            .expect("second run");
        assert_eq!(second.hostcalls.len(), 1);
        assert_eq!(
            executor.hostcall_reports().len(),
            1,
            "adapter-local hostcall reports must be scoped to the latest run"
        );
    }

    #[test]
    fn failed_pre_activation_run_clears_previous_adapter_state() {
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(runtime, Box::new(substrate));
        let good_artifact = fake_artifact(&REQUIRED_SECTIONS, &wasm_module_bytes());
        executor
            .run(
                VisaArtifactInput { bytes: &good_artifact, descriptor: console_descriptor(9) },
                "entry",
            )
            .expect("good run");
        assert_eq!(executor.hostcall_reports().len(), 1);
        let store_count_before_failure = executor.runtime().semantic().store_count();

        let bad_artifact = fake_artifact(&REQUIRED_SECTIONS, &foreign_import_wasm());
        let bad_desc = VisaArtifactDescriptor::new(
            10,
            "test",
            "bad-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_role("frontend-personality");
        let err = executor
            .run(VisaArtifactInput { bytes: &bad_artifact, descriptor: bad_desc }, "entry")
            .expect_err("bad import must fail before activation");
        assert!(
            matches!(err, WasmVisaError::InvalidHostcallImport(_)),
            "expected InvalidHostcallImport, got: {err}"
        );
        assert!(
            executor.hostcall_reports().is_empty(),
            "failed pre-activation run must not expose stale hostcall reports"
        );
        assert_eq!(executor.runtime().semantic().store_count(), store_count_before_failure);
        assert_no_loaded_instance(&mut executor);
    }

    #[test]
    fn failed_manual_load_clears_previous_instance() {
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(runtime, Box::new(substrate));
        let good_artifact = fake_artifact(&REQUIRED_SECTIONS, &wasm_module_bytes());
        executor
            .run(
                VisaArtifactInput { bytes: &good_artifact, descriptor: console_descriptor(9) },
                "entry",
            )
            .expect("good run");

        let err = executor
            .load_and_activate(
                VisaArtifactInput {
                    bytes: b"not a target artifact",
                    descriptor: console_descriptor(10),
                },
                "entry",
            )
            .expect_err("invalid artifact must fail load");
        assert!(matches!(err, WasmVisaError::Artifact(_)), "expected artifact error, got: {err}");
        assert_no_loaded_instance(&mut executor);
    }

    fn assert_no_loaded_instance(executor: &mut WasmVisaExecutor) {
        let err =
            executor.call_export("entry", &[]).expect_err("stale instance must not be callable");
        assert!(
            matches!(err, WasmVisaError::Wasmtime(ref message) if message.contains("no instance loaded")),
            "expected no instance loaded, got: {err}"
        );
    }

    fn no_import_wasm() -> Vec<u8> {
        wat::parse_str(r#"(module (func (export "start") (result i64) i64.const 1))"#)
            .expect("parse wat")
    }

    fn unknown_hostcall_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
  (import "vms" "hostcall_1" (func $hc1 (param i64 i64 i64 i64 i64 i64) (result i64)))
  (func (export "entry") (result i64)
    i64.const 1
    i64.const 2
    i64.const 3
    i64.const 4
    i64.const 0
    i64.const 0
    call $hc1
  )
)"#,
        )
        .expect("parse wat")
    }

    fn foreign_import_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
  (import "env" "foo" (func $foo))
  (func (export "entry")
    call $foo
  )
)"#,
        )
        .expect("parse wat")
    }

    fn wrong_hostcall_signature_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
  (import "vms" "hostcall_1" (func $hc1 (param i32) (result i32)))
  (func (export "entry") (result i32)
    i32.const 1
    call $hc1
  )
)"#,
        )
        .expect("parse wat")
    }

    #[test]
    fn run_returns_missing_export_for_wrong_entry_name() {
        let rt = VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(rt, Box::new(substrate));
        let artifact = fake_artifact(&REQUIRED_SECTIONS, &no_import_wasm());
        let desc = VisaArtifactDescriptor::new(
            9,
            "test",
            "test-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_role("frontend-personality");
        let err = executor
            .run(VisaArtifactInput { bytes: &artifact, descriptor: desc }, "nonexistent")
            .expect_err("run with missing entry must fail");
        assert!(
            matches!(err, WasmVisaError::MissingExport(_)),
            "expected MissingExport, got: {err}"
        );
    }

    #[test]
    fn run_rejects_unknown_declared_hostcall_before_dispatch() {
        let rt = VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(rt, Box::new(substrate));
        let store_count_before = executor.runtime().semantic().store_count();
        let artifact = fake_artifact(&REQUIRED_SECTIONS, &unknown_hostcall_wasm());
        let desc = VisaArtifactDescriptor::new(
            9,
            "test",
            "test-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_role("frontend-personality")
        .with_hostcall(HostcallSpec::new(
            1,
            "test.unknown",
            HostcallCategory::Service,
            "test.unknown",
            "doit",
            false,
        ));

        let err = executor
            .run(VisaArtifactInput { bytes: &artifact, descriptor: desc }, "entry")
            .expect_err("unknown hostcall must not be bound");
        assert!(
            matches!(err, WasmVisaError::HostcallNotBound(1)),
            "expected HostcallNotBound, got: {err}"
        );
        assert!(
            executor.hostcall_reports().is_empty(),
            "unsupported binding rejection must not emit a successful hostcall report"
        );
        assert_eq!(
            executor.runtime().semantic().store_count(),
            store_count_before,
            "unsupported hostcall descriptors must fail before load/activation mutates runtime state"
        );
    }

    #[test]
    fn run_rejects_undeclared_wasm_hostcall_before_activation() {
        let rt = VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(rt, Box::new(substrate));
        let store_count_before = executor.runtime().semantic().store_count();
        let artifact = fake_artifact(&REQUIRED_SECTIONS, &unknown_hostcall_wasm());
        let desc = VisaArtifactDescriptor::new(
            9,
            "test",
            "test-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_role("frontend-personality");

        let err = executor
            .run(VisaArtifactInput { bytes: &artifact, descriptor: desc }, "entry")
            .expect_err("wasm imports must be declared by descriptor hostcall table");
        assert!(
            matches!(err, WasmVisaError::HostcallNotBound(1)),
            "expected HostcallNotBound, got: {err}"
        );
        assert!(executor.hostcall_reports().is_empty());
        assert_eq!(executor.runtime().semantic().store_count(), store_count_before);
    }

    #[test]
    fn run_rejects_duplicate_hostcall_numbers_before_activation() {
        let rt = VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(rt, Box::new(substrate));
        let store_count_before = executor.runtime().semantic().store_count();
        let artifact = fake_artifact(&REQUIRED_SECTIONS, &wasm_module_bytes());
        let desc = console_descriptor(9).with_hostcall(HostcallSpec::new(
            1,
            "timer.now",
            HostcallCategory::Service,
            "timer",
            "now",
            false,
        ));

        let err = executor
            .run(VisaArtifactInput { bytes: &artifact, descriptor: desc }, "entry")
            .expect_err("duplicate hostcall numbers must fail descriptor validation");
        assert!(
            matches!(err, WasmVisaError::DuplicateHostcallNumber(1)),
            "expected DuplicateHostcallNumber, got: {err}"
        );
        assert!(executor.hostcall_reports().is_empty());
        assert_eq!(executor.runtime().semantic().store_count(), store_count_before);
    }

    #[test]
    fn run_rejects_foreign_imports_before_activation() {
        let rt = VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(rt, Box::new(substrate));
        let store_count_before = executor.runtime().semantic().store_count();
        let artifact = fake_artifact(&REQUIRED_SECTIONS, &foreign_import_wasm());
        let desc = VisaArtifactDescriptor::new(
            9,
            "test",
            "test-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_role("frontend-personality");

        let err = executor
            .run(VisaArtifactInput { bytes: &artifact, descriptor: desc }, "entry")
            .expect_err("foreign imports must be rejected before runtime activation");
        assert!(
            matches!(err, WasmVisaError::InvalidHostcallImport(_)),
            "expected InvalidHostcallImport, got: {err}"
        );
        assert!(executor.hostcall_reports().is_empty());
        assert_eq!(executor.runtime().semantic().store_count(), store_count_before);
    }

    #[test]
    fn run_rejects_bad_hostcall_signature_before_activation() {
        let rt = VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(rt, Box::new(substrate));
        let store_count_before = executor.runtime().semantic().store_count();
        let artifact = fake_artifact(&REQUIRED_SECTIONS, &wrong_hostcall_signature_wasm());

        let err = executor
            .run(VisaArtifactInput { bytes: &artifact, descriptor: console_descriptor(9) }, "entry")
            .expect_err("hostcall ABI mismatches must be rejected before runtime activation");
        assert!(
            matches!(err, WasmVisaError::InvalidHostcallImport(_)),
            "expected InvalidHostcallImport, got: {err}"
        );
        assert!(executor.hostcall_reports().is_empty());
        assert_eq!(executor.runtime().semantic().store_count(), store_count_before);
    }

    fn trapping_wasm() -> Vec<u8> {
        wat::parse_str(r#"(module (func (export "entry") unreachable))"#).expect("parse wat")
    }

    #[test]
    fn run_returns_error_for_wasm_trap() {
        let rt = VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let substrate = TestSubstrate::default();
        let mut executor = WasmVisaExecutor::new(rt, Box::new(substrate));
        let artifact = fake_artifact(&REQUIRED_SECTIONS, &trapping_wasm());
        let desc = VisaArtifactDescriptor::new(
            9,
            "test",
            "test-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_role("frontend-personality");
        let err = executor
            .run(VisaArtifactInput { bytes: &artifact, descriptor: desc }, "entry")
            .expect_err("run with trapping wasm must fail");
        assert!(matches!(err, WasmVisaError::Trap(_)), "expected Trap, got: {err}");
    }
}
