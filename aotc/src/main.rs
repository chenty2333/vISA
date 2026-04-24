use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use artifact_manifest::{
    ArtifactBundleManifest, CapabilityManifest, CompilerManifest, ExternManifest, ImportManifest,
    ModuleArtifactManifest, ResourceLimitsManifest, SignatureManifest, TargetManifest,
};
use contract_core::{
    expected_supervisor_contract, manifest_binding_hash, module_abi_fingerprint,
    validate_artifact_manifest, validate_manifest_entry,
};
use service_core::net_contract::{
    NETWORK_CONTRACT_ABI_VERSION, NETWORK_CONTRACT_VERSION, VIRTIO_NET0_MTU,
    VIRTIO_NET0_RX_QUEUE_DEPTH, VIRTIO_NET0_TX_QUEUE_DEPTH,
};
use sha2::{Digest, Sha256};
use supervisor_catalog::{
    ARTIFACT_SIGNATURE_PROFILE, DMW_LAYOUT, LINUX_ABI_PROFILE, MACHINE_ABI_VERSION,
    SUPERVISOR_ABI_VERSION, SUPERVISOR_WASM_MODULES, WASM_FEATURE_PROFILE, WasmModuleSpec,
    module_dependencies,
};
use wasmtime::{Config, Engine, ExternType, Instance, Module, Precompiled, Store, Strategy};

const WASM_TARGET: &str = "wasm32-unknown-unknown";
const HOST_ARTIFACT_PROFILE: &str = "host-validation";
const WASMTIME_CRATE_VERSION: &str = "43.0.1";

fn main() {
    if let Err(err) = run() {
        eprintln!("aotc error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse(env::args().skip(1));
    let workspace_root = workspace_root()?;
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let wasm_build_root = workspace_root.join("target/aotc/wasm-build");
    let artifact_root = workspace_root.join(format!(
        "target/aotc/wasmtime/{HOST_ARTIFACT_PROFILE}/{}",
        cli.profile.dir_name()
    ));

    match cli.command {
        CommandKind::Compile => {
            build_wasm_modules(&cargo, &workspace_root, &wasm_build_root, cli.profile)?;
            compile_artifacts(
                &workspace_root,
                &wasm_build_root,
                &artifact_root,
                cli.profile,
            )?;
        }
        CommandKind::Verify => {
            verify_artifacts(&artifact_root)?;
        }
        CommandKind::All => {
            build_wasm_modules(&cargo, &workspace_root, &wasm_build_root, cli.profile)?;
            compile_artifacts(
                &workspace_root,
                &wasm_build_root,
                &artifact_root,
                cli.profile,
            )?;
            verify_artifacts(&artifact_root)?;
        }
    }

    Ok(())
}

fn build_wasm_modules(
    cargo: &str,
    workspace_root: &Path,
    target_dir: &Path,
    profile: Profile,
) -> Result<(), Box<dyn Error>> {
    for module in SUPERVISOR_WASM_MODULES {
        let mut cmd = Command::new(cargo);
        cmd.current_dir(workspace_root)
            .env("CARGO_TARGET_DIR", target_dir)
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env("RUSTFLAGS", wasm_rustflags())
            .args(["build", "-p", module.package, "--target", WASM_TARGET]);
        if profile.is_release() {
            cmd.arg("--release");
        }
        let status = cmd.status()?;
        if !status.success() {
            return Err(format!("building {} for {WASM_TARGET} failed", module.package).into());
        }
        strip_custom_sections(&wasm_artifact_path(target_dir, profile, module.package))?;
    }
    Ok(())
}

fn wasm_rustflags() -> &'static str {
    "-C target-feature=-bulk-memory,-multivalue,-reference-types,-sign-ext,-nontrapping-fptoint"
}

fn strip_custom_sections(path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    fs::write(path, strip_wasm_custom_sections(&bytes)?)?;
    Ok(())
}

fn strip_wasm_custom_sections(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if bytes.len() < 8 || &bytes[..4] != b"\0asm" {
        return Err("invalid wasm header".into());
    }
    let mut out = bytes[..8].to_vec();
    let mut offset = 8usize;
    while offset < bytes.len() {
        let section_id = bytes[offset];
        offset += 1;
        let (section_len, leb_len) = read_leb_u32(&bytes[offset..])?;
        offset += leb_len;
        let end = offset
            .checked_add(section_len as usize)
            .ok_or("wasm section length overflowed")?;
        if end > bytes.len() {
            return Err("wasm section exceeded file length".into());
        }
        if section_id != 0 {
            out.push(section_id);
            write_leb_u32(section_len, &mut out);
            out.extend_from_slice(&bytes[offset..end]);
        }
        offset = end;
    }
    Ok(out)
}

fn read_leb_u32(bytes: &[u8]) -> Result<(u32, usize), Box<dyn Error>> {
    let mut value = 0u32;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate().take(5) {
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        shift += 7;
    }
    Err("invalid wasm leb128".into())
}

fn write_leb_u32(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn compile_artifacts(
    workspace_root: &Path,
    wasm_build_root: &Path,
    artifact_root: &Path,
    profile: Profile,
) -> Result<(), Box<dyn Error>> {
    if artifact_root.exists() {
        fs::remove_dir_all(artifact_root)?;
    }
    fs::create_dir_all(artifact_root)?;

    let engine = compile_engine()?;
    let mut modules = Vec::with_capacity(SUPERVISOR_WASM_MODULES.len());

    for module in SUPERVISOR_WASM_MODULES {
        let wasm_path = wasm_artifact_path(wasm_build_root, profile, module.package);
        let cwasm_path = artifact_root.join(format!("{}.cwasm", module.package));
        let wasm_bytes = fs::read(&wasm_path)?;
        let compiled = engine.precompile_module(&wasm_bytes)?;
        fs::write(&cwasm_path, &compiled)?;
        let wasm_sha256 = sha256_hex(&wasm_bytes);
        let cwasm_sha256 = sha256_hex(&compiled);

        let compiled_module = Module::new(&engine, &wasm_bytes)?;
        let exports = compiled_module
            .exports()
            .map(|export| ExternManifest {
                name: export.name().to_owned(),
                kind: extern_kind(export.ty()).to_owned(),
            })
            .collect();
        let imports = compiled_module
            .imports()
            .map(|import| ImportManifest {
                module: import.module().to_owned(),
                name: import.name().to_owned(),
                kind: extern_kind(import.ty()).to_owned(),
            })
            .collect();
        let abi_fingerprint = module_abi_fingerprint(module);
        let manifest_binding_hash =
            manifest_binding_hash(module, &wasm_sha256, &cwasm_sha256, &abi_fingerprint);

        modules.push(ModuleArtifactManifest {
            package: module.package.to_owned(),
            artifact_name: module.artifact_name.to_owned(),
            role: module.role.as_str().to_owned(),
            fault_policy: module.fault_policy.as_str().to_owned(),
            wasm_path: relative_to_workspace(workspace_root, &wasm_path),
            cwasm_path: relative_to_workspace(workspace_root, &cwasm_path),
            wasm_sha256,
            cwasm_sha256: cwasm_sha256.clone(),
            expected_exports: module
                .expected_exports
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            exports,
            imports,
            capabilities: module
                .capabilities
                .iter()
                .map(|capability| CapabilityManifest {
                    name: capability.name.to_owned(),
                    rights: capability
                        .rights
                        .iter()
                        .map(|right| (*right).to_owned())
                        .collect(),
                    lifetime: capability.lifetime.to_owned(),
                })
                .collect(),
            abi_fingerprint,
            service_dependencies: module_dependencies(module)
                .iter()
                .map(|dependency| (*dependency).to_owned())
                .collect(),
            resource_limits: ResourceLimitsManifest {
                max_memory_pages: 16,
                max_table_elements: 0,
                max_hostcalls_per_activation: 64,
            },
            signature: SignatureManifest {
                scheme: "prototype-self-signed-sha256".to_owned(),
                artifact_hash: cwasm_sha256,
                manifest_binding_hash,
                signer: "vmos-aotc-dev".to_owned(),
                public_key_hint: "prototype-dev-key".to_owned(),
                signature: "unsigned-prototype-signature".to_owned(),
            },
        });
    }

    let manifest = ArtifactBundleManifest {
        schema_version: 1,
        artifact_profile: HOST_ARTIFACT_PROFILE.to_owned(),
        contract: expected_supervisor_contract(),
        target: TargetManifest {
            arch: env::consts::ARCH.to_owned(),
            machine_abi_version: MACHINE_ABI_VERSION.to_owned(),
            supervisor_abi_version: SUPERVISOR_ABI_VERSION.to_owned(),
            wasm_feature_profile: WASM_FEATURE_PROFILE.to_owned(),
            memory64: false,
            multi_memory: false,
            dmw_layout: DMW_LAYOUT.to_owned(),
            linux_abi_profile: LINUX_ABI_PROFILE.to_owned(),
            artifact_signature_profile: ARTIFACT_SIGNATURE_PROFILE.to_owned(),
            network_contract_version: NETWORK_CONTRACT_VERSION.to_owned(),
        },
        compiler: CompilerManifest {
            engine: "wasmtime".to_owned(),
            engine_version: WASMTIME_CRATE_VERSION.to_owned(),
            execution_mode: "precompiled-core-module".to_owned(),
            artifact_format: "cwasm".to_owned(),
        },
        modules,
    };
    let manifest_path = artifact_root.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    println!(
        "wrote {}",
        relative_to_workspace(workspace_root, &manifest_path)
    );

    Ok(())
}

fn verify_artifacts(artifact_root: &Path) -> Result<(), Box<dyn Error>> {
    let engine = runtime_engine()?;
    let manifest = read_manifest(artifact_root)?;
    validate_artifact_manifest(&manifest)?;

    for module in SUPERVISOR_WASM_MODULES {
        let Some(entry) = manifest
            .modules
            .iter()
            .find(|entry| entry.package == module.package)
        else {
            return Err(format!("manifest is missing {}", module.package).into());
        };
        validate_manifest_entry(module, entry)?;
        let artifact_path = artifact_root.join(format!("{}.cwasm", module.package));
        let artifact = fs::read(&artifact_path)?;
        if sha256_hex(&artifact) != entry.cwasm_sha256 {
            return Err(format!("{} cwasm hash mismatch", module.package).into());
        }
        match Engine::detect_precompiled_file(&artifact_path)? {
            Some(Precompiled::Module) => {}
            Some(Precompiled::Component) => {
                return Err(format!(
                    "{} was compiled as a component unexpectedly",
                    module.package
                )
                .into());
            }
            None => {
                return Err(
                    format!("{} is not a valid precompiled artifact", module.package).into(),
                );
            }
        }

        let module_binary = unsafe { Module::deserialize_file(&engine, &artifact_path)? };
        verify_exports(module, &module_binary)?;

        let mut store = Store::new(&engine, ());
        let instance = Instance::new(&mut store, &module_binary, &[])?;
        run_smoke_checks(module, &instance, &mut store)?;
    }

    println!(
        "verified {} host-side artifacts",
        SUPERVISOR_WASM_MODULES.len()
    );
    Ok(())
}

fn verify_exports(spec: &WasmModuleSpec, module: &Module) -> Result<(), Box<dyn Error>> {
    let export_names = module
        .exports()
        .map(|export| export.name().to_owned())
        .collect::<Vec<_>>();
    for expected in spec.expected_exports {
        if !export_names.iter().any(|name| name == expected) {
            return Err(format!("{} is missing expected export `{expected}`", spec.package).into());
        }
    }
    Ok(())
}

fn read_manifest(artifact_root: &Path) -> Result<ArtifactBundleManifest, Box<dyn Error>> {
    let bytes = fs::read(artifact_root.join("manifest.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn run_smoke_checks(
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
                return Err(
                    "console_service commit_write(0, 0) failed in host verification".into(),
                );
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
            return Err(format!("export `{export}` returned zero during host verification").into());
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

fn compile_engine() -> Result<Engine, Box<dyn Error>> {
    let mut config = Config::new();
    config.strategy(Strategy::Cranelift);
    Ok(Engine::new(&config)?)
}

fn runtime_engine() -> Result<Engine, Box<dyn Error>> {
    let mut config = Config::new();
    config.strategy(Strategy::Cranelift);
    Ok(Engine::new(&config)?)
}

fn wasm_artifact_path(build_root: &Path, profile: Profile, package: &str) -> PathBuf {
    build_root
        .join(WASM_TARGET)
        .join(profile.dir_name())
        .join(format!("{package}.wasm"))
}

fn relative_to_workspace(workspace_root: &Path, path: &Path) -> String {
    path.strip_prefix(workspace_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn extern_kind(ty: ExternType) -> &'static str {
    match ty {
        ExternType::Func(_) => "func",
        ExternType::Global(_) => "global",
        ExternType::Table(_) => "table",
        ExternType::Memory(_) => "memory",
        ExternType::Tag(_) => "tag",
    }
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest dir")?);
    Ok(manifest_dir
        .parent()
        .ok_or("aotc must live in workspace root")?
        .to_path_buf())
}

#[derive(Clone, Copy)]
enum Profile {
    Debug,
    Release,
}

impl Profile {
    fn dir_name(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }

    fn is_release(self) -> bool {
        matches!(self, Self::Release)
    }
}

enum CommandKind {
    All,
    Compile,
    Verify,
}

struct Cli {
    command: CommandKind,
    profile: Profile,
}

impl Cli {
    fn parse(args: impl IntoIterator<Item = String>) -> Self {
        let mut command = CommandKind::All;
        let mut profile = Profile::Debug;

        for arg in args {
            match arg.as_str() {
                "all" => command = CommandKind::All,
                "compile" => command = CommandKind::Compile,
                "verify" => command = CommandKind::Verify,
                "--release" => profile = Profile::Release,
                _ => {}
            }
        }

        Self { command, profile }
    }
}
