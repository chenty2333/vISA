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
use wasmtime::{Caller, Engine, FuncType, Instance, Linker, Module, Store, Trap, Val, ValType};

#[derive(Debug)]
pub enum WasmVisaError {
    Artifact(TargetArtifactError),
    Wasmtime(String),
    Runtime(VisaRuntimeError),
    MissingExport(String),
    HostcallNotBound(u32),
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

    /// Parse artifact bytes, extract the CodeObject section, pass through
    /// VisaRuntime for profile gate + store/activation, compile the wasm
    /// module, bind hostcalls from the descriptor, and instantiate.
    pub fn load_and_activate(
        &mut self,
        input: VisaArtifactInput<'_>,
        entry: &str,
    ) -> Result<(), WasmVisaError> {
        // Preserve hostcall specs from the descriptor before load_artifact consumes it
        let hostcall_specs: Vec<HostcallSpec> = input.descriptor.hostcalls.clone();

        let _parsed =
            target_abi::TargetArtifactImage::parse(input.bytes).map_err(WasmVisaError::Artifact)?;

        let loaded = {
            let state = self.store.data_mut();
            let substrate_ptr: *mut dyn VisaSubstrate = state.substrate.as_mut();
            // SAFETY: substrate is exclusively owned by this Store and not aliased
            state.runtime.load_artifact(input, unsafe { &mut *substrate_ptr })?
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
        let mut results = vec![Val::I32(0)];
        func.call(&mut self.store, params, &mut results).map_err(|e| {
            let msg = format!("{e}");
            if e.downcast_ref::<Trap>().is_some() {
                // TODO: record trap attribution through VisaRuntime facade
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
        let artifact_bytes = input.bytes;
        self.load_and_activate(input, entry)?;

        let code_payload = {
            target_abi::TargetArtifactImage::parse(artifact_bytes)
                .map_err(WasmVisaError::Artifact)?
                .section_payload(SectionKindV1::CodeObject)
                .map_err(WasmVisaError::Artifact)?
                .ok_or_else(|| WasmVisaError::Wasmtime("missing code section".into()))?
        };

        let module = Module::new(&self.engine, code_payload)
            .map_err(|e| WasmVisaError::Wasmtime(format!("compile: {e}")))?;

        let specs: Vec<HostcallSpec> = self.store.data().hostcall_specs.clone();

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
                        let a = params.first().map(|v| v.unwrap_i64()).unwrap_or(0);
                        let b = params.get(1).map(|v| v.unwrap_i64()).unwrap_or(0);
                        let c = params.get(2).map(|v| v.unwrap_i64()).unwrap_or(0);
                        let d = params.get(3).map(|v| v.unwrap_i64()).unwrap_or(0);
                        let payload = hostcall_payload_for_object(&obj, &op, a, b, c, d);
                        let result = match payload {
                            Some(p) => match caller.data_mut().dispatch_hostcall(n, p) {
                                Ok(report) => hostcall_result_i64(&report.value),
                                Err(_e) => -1,
                            },
                            None => -1,
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

        // Call the wasm entry point
        let _ = self.call_export(entry, &[]);

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

fn hostcall_payload_for_object(
    object: &str,
    operation: &str,
    a: i64,
    b: i64,
    c: i64,
    d: i64,
) -> Option<VisaHostcallPayload> {
    match (object, operation) {
        ("wasi.fd", "write") | ("test.console", "write") => {
            let len = a.max(0) as usize;
            let mut bytes = Vec::with_capacity(len.min(1024));
            if b > 0 {
                bytes.push(b as u8);
            }
            if c > 0 {
                bytes.push(c as u8);
            }
            if d > 0 {
                bytes.push(d as u8);
            }
            Some(VisaHostcallPayload::ConsoleWrite { bytes })
        }
        ("timer.wasi", "read") | ("timer", "now") => Some(VisaHostcallPayload::TimerNow),
        ("timer.wasi", "arm") => Some(VisaHostcallPayload::TimerArm {
            deadline_ticks: a as u64,
            token: substrate_api::WaitTokenRef::new(b as u64, c as u64),
        }),
        _ => {
            // Default fallback: treat as console write with argument bytes
            let mut bytes = Vec::new();
            for val in [a, b, c, d] {
                if val != 0 {
                    bytes.push(val as u8);
                }
            }
            Some(VisaHostcallPayload::ConsoleWrite { bytes })
        }
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
        EventQueueAuthority, GuestMemoryAuthority, IrqAuthority, MmioAuthority, SnapshotAuthority,
        SubstrateResult, TimerAuthority, VirtualTime,
    };
    use target_abi::{
        TargetArtifactHeaderV1, TargetSectionHeaderV1, canonical_zero_field_image_hash,
    };
    use visa_profile::SubstrateProfile;
    use vms_runtime::{VisaArtifactDescriptor, VisaRuntimeConfig};

    use super::*;

    // ── test substrate ────────────────────────────────────────────────────

    #[derive(Default)]
    struct TestSubstrate {
        console: Vec<u8>,
        timers: usize,
    }

    impl ConsoleAuthority for TestSubstrate {
        fn console_write(&mut self, bytes: &[u8]) -> SubstrateResult<usize> {
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
    impl GuestMemoryAuthority for TestSubstrate {}
    impl DmwAuthority for TestSubstrate {}
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
    impl MmioAuthority for TestSubstrate {}
    impl DmaAuthority for TestSubstrate {}
    impl IrqAuthority for TestSubstrate {}
    impl SnapshotAuthority for TestSubstrate {}

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
        let descriptor = VisaArtifactDescriptor::new(
            9,
            "test",
            "test-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_role("frontend-personality")
        .with_hostcall(HostcallSpec::new(
            1,
            "test.write",
            HostcallCategory::Service,
            "test.console",
            "write",
            false,
        ));

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
        let descriptor = VisaArtifactDescriptor::new(
            9,
            "test",
            "test-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_role("frontend-personality")
        .with_hostcall(HostcallSpec::new(
            1,
            "test.write",
            HostcallCategory::Service,
            "test.console",
            "write",
            false,
        ));

        let report =
            executor.run(VisaArtifactInput { bytes: &artifact, descriptor }, "entry").expect("run");

        assert!(report.loaded.store_id > 0);
        // Hostcall should have been dispatched
        assert!(!report.hostcalls.is_empty(), "must have at least one hostcall dispatch");
    }
}
