use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use artifact_manifest::{ArtifactBundleManifest, ModuleArtifactManifest};
use semantic_core::SemanticGraph;
use sha2::{Digest, Sha256};
use supervisor_catalog::{CapabilitySpec, SUPERVISOR_WASM_MODULES, WasmModuleSpec};
use wasmtime::{Config, Engine, Instance, Module, Precompiled, Store};

const DEFAULT_ARTIFACT_ROOT: &str = "target/aotc/wasmtime/host-validation/debug";

fn main() {
    if let Err(err) = run() {
        eprintln!("target_executor error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let workspace_root = workspace_root()?;
    let artifact_root = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join(DEFAULT_ARTIFACT_ROOT));
    let manifest = read_manifest(&artifact_root)?;
    let engine = runtime_engine()?;
    let mut semantic = SemanticGraph::new();
    let mut stores = Vec::with_capacity(SUPERVISOR_WASM_MODULES.len());

    validate_bundle_manifest(&manifest)?;

    for spec in SUPERVISOR_WASM_MODULES {
        let entry = find_entry(&manifest, spec)?;
        validate_entry(spec, entry)?;
        let module_path = workspace_root.join(&entry.cwasm_path);
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

        let module = unsafe { Module::deserialize(&engine, &module_bytes)? };
        validate_exports(spec, &module)?;
        let mut store = Store::new(&engine, ());
        let instance = Instance::new(&mut store, &module, &[])?;
        smoke_instance(spec, &instance, &mut store)?;
        register_store_semantics(&mut semantic, spec);
        stores.push(LoadedStore {
            package: spec.package,
            role: spec.role.as_str(),
            fault_policy: spec.fault_policy.as_str(),
        });
    }

    println!(
        "target executor loaded {} runtime-only stores with {} capability grants across {} fault domains",
        stores.len(),
        semantic.capability_count(),
        semantic.fault_domain_count()
    );
    println!(
        "semantic event log contains {} events",
        semantic.event_count()
    );
    for store in stores {
        println!(
            "store {} role={} fault_policy={}",
            store.package, store.role, store.fault_policy
        );
    }

    Ok(())
}

fn register_store_semantics(semantic: &mut SemanticGraph, spec: &WasmModuleSpec) {
    semantic.register_fault_domain(spec.package, spec.role.as_str());
    for capability in spec.capabilities {
        semantic.grant_capability(
            spec.package,
            capability.name,
            capability.rights,
            capability.lifetime,
        );
    }
}

fn validate_bundle_manifest(manifest: &ArtifactBundleManifest) -> Result<(), Box<dyn Error>> {
    if manifest.schema_version != 1 {
        return Err("unsupported manifest schema version".into());
    }
    if manifest.compiler.artifact_format != "cwasm" {
        return Err("target executor only accepts cwasm artifacts".into());
    }
    if manifest.compiler.execution_mode != "precompiled-core-module" {
        return Err("target executor only accepts precompiled core modules".into());
    }
    if manifest.target.machine_abi_version != "vmos-machine-abi-v0" {
        return Err("machine ABI version mismatch".into());
    }
    if manifest.target.supervisor_abi_version != "vmos-supervisor-abi-v0" {
        return Err("supervisor ABI version mismatch".into());
    }
    Ok(())
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

fn validate_entry(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> Result<(), Box<dyn Error>> {
    if entry.artifact_name != spec.artifact_name {
        return Err(format!("{} artifact name mismatch", spec.package).into());
    }
    if entry.role != spec.role.as_str() {
        return Err(format!("{} role mismatch", spec.package).into());
    }
    if entry.fault_policy != spec.fault_policy.as_str() {
        return Err(format!("{} fault policy mismatch", spec.package).into());
    }
    if entry.signature.scheme != "prototype-self-signed-sha256" {
        return Err(format!("{} signature scheme mismatch", spec.package).into());
    }
    if entry.signature.artifact_hash != entry.cwasm_sha256 {
        return Err(format!("{} signature artifact hash mismatch", spec.package).into());
    }
    let expected_binding = manifest_binding_hash(spec, &entry.wasm_sha256, &entry.cwasm_sha256);
    if entry.signature.manifest_binding_hash != expected_binding {
        return Err(format!("{} manifest binding hash mismatch", spec.package).into());
    }
    validate_capabilities(spec, entry)?;
    Ok(())
}

fn validate_capabilities(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> Result<(), Box<dyn Error>> {
    if entry.capabilities.len() != spec.capabilities.len() {
        return Err(format!("{} capability count mismatch", spec.package).into());
    }
    for capability in spec.capabilities {
        let Some(entry_capability) = entry
            .capabilities
            .iter()
            .find(|candidate| candidate.name == capability.name)
        else {
            return Err(format!("{} missing capability {}", spec.package, capability.name).into());
        };
        if entry_capability.lifetime != capability.lifetime {
            return Err(format!("{} capability lifetime mismatch", spec.package).into());
        }
        if entry_capability.rights != rights_vec(capability) {
            return Err(format!("{} capability rights mismatch", spec.package).into());
        }
    }
    Ok(())
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

fn runtime_engine() -> Result<Engine, Box<dyn Error>> {
    Ok(Engine::new(&Config::new())?)
}

fn read_manifest(artifact_root: &Path) -> Result<ArtifactBundleManifest, Box<dyn Error>> {
    let bytes = fs::read(artifact_root.join("manifest.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest dir")?);
    Ok(manifest_dir
        .parent()
        .ok_or("target_executor must live in workspace root")?
        .to_path_buf())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn manifest_binding_hash(spec: &WasmModuleSpec, wasm_sha256: &str, cwasm_sha256: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(spec.package.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.artifact_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.role.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.fault_policy.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(wasm_sha256.as_bytes());
    hasher.update(b"\0");
    hasher.update(cwasm_sha256.as_bytes());
    for export in spec.expected_exports {
        hasher.update(b"\0");
        hasher.update(export.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn rights_vec(capability: &CapabilitySpec) -> Vec<String> {
    capability
        .rights
        .iter()
        .map(|right| (*right).to_owned())
        .collect()
}

struct LoadedStore {
    package: &'static str,
    role: &'static str,
    fault_policy: &'static str,
}
