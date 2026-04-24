use std::error::Error;
use std::fs;
use std::path::PathBuf;

use contract_core::ValidatedArtifactEntry;
use service_core::net_contract::{
    NETWORK_CONTRACT_ABI_VERSION, VIRTIO_NET0_MTU, VIRTIO_NET0_RX_QUEUE_DEPTH,
    VIRTIO_NET0_TX_QUEUE_DEPTH,
};
use sha2::{Digest, Sha256};
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
        entry: &ValidatedArtifactEntry,
    ) -> Result<LoadedRuntimeStore, Box<dyn Error>> {
        let module_path = self.workspace_root.join(&entry.cwasm_path);
        let module_bytes = fs::read(&module_path)?;
        if sha256_hex(&module_bytes) != entry.cwasm_sha256 {
            return Err(format!("{} cwasm hash mismatch", entry.package).into());
        }

        match Engine::detect_precompiled(&module_bytes) {
            Some(Precompiled::Module) => {}
            Some(Precompiled::Component) => {
                return Err(format!("{} is a component artifact", entry.package).into());
            }
            None => return Err(format!("{} is not a precompiled artifact", entry.package).into()),
        }

        let module = unsafe { Module::deserialize(&self.engine, &module_bytes)? };
        validate_exports(entry, &module)?;
        let mut store = Store::new(&self.engine, ());
        let instance = Instance::new(&mut store, &module, &[])?;
        smoke_instance(entry, &instance, &mut store)?;
        Ok(LoadedRuntimeStore {
            package: entry.package.clone(),
            role: entry.role.clone(),
            fault_policy: entry.fault_policy.clone(),
            abi_fingerprint: entry.abi_fingerprint.clone(),
            manifest_binding_hash: entry.manifest_binding_hash.clone(),
        })
    }
}

pub struct LoadedRuntimeStore {
    pub package: String,
    pub role: String,
    pub fault_policy: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
}

fn validate_exports(entry: &ValidatedArtifactEntry, module: &Module) -> Result<(), Box<dyn Error>> {
    let export_names = module
        .exports()
        .map(|export| export.name().to_owned())
        .collect::<Vec<_>>();
    for expected in &entry.expected_exports {
        if !export_names.iter().any(|name| name == expected) {
            return Err(format!("{} missing export `{expected}`", entry.package).into());
        }
    }
    Ok(())
}

fn smoke_instance(
    entry: &ValidatedArtifactEntry,
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

    if entry.package == "console_service" {
        if let Ok(func) = instance.get_typed_func::<(u32, u32), i32>(&mut *store, "commit_write") {
            let rc = func.call(&mut *store, (0, 0))?;
            if rc != 0 {
                return Err("console_service commit_write(0, 0) failed".into());
            }
        }
    }
    if entry.package == "wasm_app" {
        if let Ok(func) = instance.get_typed_func::<(), u64>(&mut *store, "run") {
            let _ = func.call(&mut *store, ())?;
        }
    }
    if matches!(
        entry.package.as_str(),
        "driver_virtio_net" | "net_core" | "linux_socket_service"
    ) {
        check_u32_export_eq(
            instance,
            store,
            "network_contract_version",
            NETWORK_CONTRACT_ABI_VERSION,
        )?;
    }
    if matches!(entry.package.as_str(), "driver_virtio_net" | "net_core") {
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
