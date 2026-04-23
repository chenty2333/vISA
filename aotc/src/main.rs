use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use artifact_manifest::{
    ArtifactBundleManifest, CapabilityManifest, CompilerManifest, ExternManifest, ImportManifest,
    ModuleArtifactManifest, SignatureManifest, TargetManifest,
};
use sha2::{Digest, Sha256};
use supervisor_catalog::{SUPERVISOR_WASM_MODULES, WasmModuleSpec};
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
            .args(["build", "-p", module.package, "--target", WASM_TARGET]);
        if profile.is_release() {
            cmd.arg("--release");
        }
        let status = cmd.status()?;
        if !status.success() {
            return Err(format!("building {} for {WASM_TARGET} failed", module.package).into());
        }
    }
    Ok(())
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
        let manifest_binding_hash = manifest_binding_hash(module, &wasm_sha256, &cwasm_sha256);

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
            signature: SignatureManifest {
                scheme: "prototype-self-signed-sha256".to_owned(),
                artifact_hash: cwasm_sha256,
                manifest_binding_hash,
                signer: "vmos-aotc-dev".to_owned(),
            },
        });
    }

    let manifest = ArtifactBundleManifest {
        schema_version: 1,
        artifact_profile: HOST_ARTIFACT_PROFILE.to_owned(),
        target: TargetManifest {
            arch: env::consts::ARCH.to_owned(),
            machine_abi_version: "vmos-machine-abi-v0".to_owned(),
            supervisor_abi_version: "vmos-supervisor-abi-v0".to_owned(),
            wasm_feature_profile: "wasm32-core-mvp-single-memory".to_owned(),
            memory64: false,
            multi_memory: false,
            dmw_layout: "logical-activation-leases-v0".to_owned(),
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

    for module in SUPERVISOR_WASM_MODULES {
        let Some(entry) = manifest
            .modules
            .iter()
            .find(|entry| entry.package == module.package)
        else {
            return Err(format!("manifest is missing {}", module.package).into());
        };
        verify_manifest_entry(module, entry)?;
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

fn verify_manifest_entry(
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
    let expected_binding = manifest_binding_hash(spec, &entry.wasm_sha256, &entry.cwasm_sha256);
    if entry.signature.artifact_hash != entry.cwasm_sha256 {
        return Err(format!("{} signature artifact hash mismatch", spec.package).into());
    }
    if entry.signature.manifest_binding_hash != expected_binding {
        return Err(format!("{} manifest binding hash mismatch", spec.package).into());
    }
    Ok(())
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
