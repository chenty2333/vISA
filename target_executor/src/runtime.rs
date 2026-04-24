use std::error::Error;
use std::fs;
use std::path::PathBuf;

use artifact_manifest::{ArtifactBundleManifest, ModuleArtifactManifest};
use contract_core::validate_manifest_entry;
use service_core::net_contract::{
    NETWORK_CONTRACT_ABI_VERSION, VIRTIO_NET0_MTU, VIRTIO_NET0_RX_QUEUE_DEPTH,
    VIRTIO_NET0_TX_QUEUE_DEPTH,
};
use sha2::{Digest, Sha256};
use supervisor_catalog::WasmModuleSpec;
use wasmtime::{Config, Engine, Instance, Module, Precompiled, Store};

pub struct RuntimeOnlyExecutor {
    engine: Engine,
    workspace_root: PathBuf,
}

impl RuntimeOnlyExecutor {
    pub fn host_validation(workspace_root: PathBuf) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            engine: Engine::new(&Config::new())?,
            workspace_root,
        })
    }

    pub fn load_store(
        &self,
        manifest: &ArtifactBundleManifest,
        spec: &WasmModuleSpec,
    ) -> Result<LoadedRuntimeStore, Box<dyn Error>> {
        let entry = find_entry(manifest, spec)?;
        validate_manifest_entry(spec, entry)?;
        let module_path = self.workspace_root.join(&entry.cwasm_path);
        let module_bytes = fs::read(&module_path)?;
        if sha256_hex(&module_bytes) != entry.cwasm_sha256 {
            return Err(format!("{} cwasm hash mismatch", spec.package).into());
        }

        match Engine::detect_precompiled(&module_bytes) {
            Some(Precompiled::Module) => {}
            Some(Precompiled::Component) => {
                return Err(format!("{} is a component artifact", spec.package).into());
            }
            None => return Err(format!("{} is not a precompiled artifact", spec.package).into()),
        }

        let module = unsafe { Module::deserialize(&self.engine, &module_bytes)? };
        validate_exports(spec, &module)?;
        let mut store = Store::new(&self.engine, ());
        let instance = Instance::new(&mut store, &module, &[])?;
        smoke_instance(spec, &instance, &mut store)?;
        Ok(LoadedRuntimeStore {
            package: spec.package,
            role: spec.role.as_str(),
            fault_policy: spec.fault_policy.as_str(),
        })
    }
}

pub struct LoadedRuntimeStore {
    pub package: &'static str,
    pub role: &'static str,
    pub fault_policy: &'static str,
}

fn find_entry<'a>(
    manifest: &'a ArtifactBundleManifest,
    spec: &WasmModuleSpec,
) -> Result<&'a ModuleArtifactManifest, Box<dyn Error>> {
    manifest
        .modules
        .iter()
        .find(|entry| entry.package == spec.package)
        .ok_or_else(|| format!("manifest is missing {}", spec.package).into())
}

fn validate_exports(spec: &WasmModuleSpec, module: &Module) -> Result<(), Box<dyn Error>> {
    let export_names = module
        .exports()
        .map(|export| export.name().to_owned())
        .collect::<Vec<_>>();
    for expected in spec.expected_exports {
        if !export_names.iter().any(|name| name == expected) {
            return Err(format!("{} missing export `{expected}`", spec.package).into());
        }
    }
    Ok(())
}

fn smoke_instance(
    spec: &WasmModuleSpec,
    instance: &Instance,
    store: &mut Store<()>,
) -> Result<(), Box<dyn Error>> {
    check_u32_export(instance, store, "request_capacity")?;
    check_u32_export(instance, store, "response_capacity")?;
    check_u32_export(instance, store, "buffer_capacity")?;
    check_u32_export(instance, store, "arg_buffer_capacity")?;
    check_u32_export(instance, store, "result_buffer_capacity")?;
    check_u32_export(instance, store, "request_ptr")?;
    check_u32_export(instance, store, "response_ptr")?;
    check_u32_export(instance, store, "buffer_ptr")?;
    check_u32_export(instance, store, "arg_buffer_ptr")?;
    check_u32_export(instance, store, "result_buffer_ptr")?;

    if spec.package == "console_service" {
        if let Ok(func) = instance.get_typed_func::<(u32, u32), i32>(&mut *store, "commit_write") {
            let rc = func.call(&mut *store, (0, 0))?;
            if rc != 0 {
                return Err("console_service commit_write(0, 0) failed".into());
            }
        }
    }
    if spec.package == "wasm_app" {
        if let Ok(func) = instance.get_typed_func::<(), u64>(&mut *store, "run") {
            let _ = func.call(&mut *store, ())?;
        }
    }
    if matches!(
        spec.package,
        "driver_virtio_net" | "net_core" | "linux_socket_service"
    ) {
        check_u32_export_eq(
            instance,
            store,
            "network_contract_version",
            NETWORK_CONTRACT_ABI_VERSION,
        )?;
    }
    if matches!(spec.package, "driver_virtio_net" | "net_core") {
        check_u32_export_eq(instance, store, "packet_mtu", VIRTIO_NET0_MTU)?;
        check_u32_export_eq(
            instance,
            store,
            "packet_rx_queue_depth",
            VIRTIO_NET0_RX_QUEUE_DEPTH,
        )?;
        check_u32_export_eq(
            instance,
            store,
            "packet_tx_queue_depth",
            VIRTIO_NET0_TX_QUEUE_DEPTH,
        )?;
    }
    Ok(())
}

fn check_u32_export(
    instance: &Instance,
    store: &mut Store<()>,
    export: &str,
) -> Result<(), Box<dyn Error>> {
    if let Ok(func) = instance.get_typed_func::<(), u32>(&mut *store, export) {
        let value = func.call(&mut *store, ())?;
        if value == 0 {
            return Err(format!("export `{export}` returned zero").into());
        }
    }
    Ok(())
}

fn check_u32_export_eq(
    instance: &Instance,
    store: &mut Store<()>,
    export: &str,
    expected: u32,
) -> Result<(), Box<dyn Error>> {
    let func = instance.get_typed_func::<(), u32>(&mut *store, export)?;
    let value = func.call(&mut *store, ())?;
    if value != expected {
        return Err(format!("export `{export}` returned {value}, expected {expected}").into());
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
