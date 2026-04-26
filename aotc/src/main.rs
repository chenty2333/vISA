use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use artifact_manifest::{
    ArtifactBundleManifest, CapabilityManifest, CompilerManifest, ExternManifest, ImportManifest,
    InterfaceRequirementManifest, ModuleArtifactManifest, ResourceLimitsManifest,
    SignatureManifest, SubstrateAuthorityRequirementManifest, TargetManifest,
};
use contract_core::{
    CODE_PAYLOAD_FORMAT_CWASM, RUNTIME_MODE_RESEARCH, TARGET_ARTIFACT_FORMAT_V1,
    ValidatedArtifactEntry, WASMTIME_COMPILATION_STRATEGY, WASMTIME_CRATE_VERSION,
    build_validated_artifact_plan, canonical_wasmtime_config_fingerprint,
    expected_supervisor_contract, manifest_binding_hash, module_abi_fingerprint,
};
use service_core::net_contract::{
    NETWORK_CONTRACT_ABI_VERSION, NETWORK_CONTRACT_VERSION, VIRTIO_NET0_MTU,
    VIRTIO_NET0_RX_QUEUE_DEPTH, VIRTIO_NET0_TX_QUEUE_DEPTH,
};
use sha2::{Digest, Sha256};
use supervisor_catalog::{
    ARTIFACT_SIGNATURE_PROFILE, DMW_LAYOUT, LINUX_ABI_PROFILE, MACHINE_ABI_VERSION,
    RUNTIME_ONLY_EXECUTOR_ABI, SUPERVISOR_ABI_VERSION, SUPERVISOR_ARTIFACT_FORMAT,
    SUPERVISOR_COMPILER_ENGINE, SUPERVISOR_EXECUTION_MODE, SUPERVISOR_WASM_MODULES,
    WASM_FEATURE_PROFILE, module_dependencies, module_interface_spec,
};
use target_abi::artifact::{
    ArtifactKindCodeV1, CodeFormatCodeV1, SectionKindV1, TARGET_ARTIFACT_HEADER_LEN,
    TARGET_SECTION_HEADER_LEN, TargetAbiCodeV1, TargetArchCodeV1, TargetArtifactHeaderV1,
    TargetArtifactImage, TargetSectionHeaderV1, canonical_zero_field_image_hash,
};
use wasmtime::{Config, Engine, ExternType, Instance, Module, Precompiled, Store, Strategy};

const WASM_TARGET: &str = "wasm32-unknown-unknown";
const HOST_ARTIFACT_PROFILE: &str = "host-validation";

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
        let target_artifact_path = artifact_root.join(format!("{}.tart", module.package));
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
            .collect::<Vec<_>>();
        let abi_fingerprint = module_abi_fingerprint(module);
        let manifest_binding_hash =
            manifest_binding_hash(module, &wasm_sha256, &cwasm_sha256, &abi_fingerprint);
        let target_artifact = build_target_artifact_image(TargetArtifactBuildInput {
            module,
            compiled: &compiled,
            wasm_sha256: &wasm_sha256,
            cwasm_sha256: &cwasm_sha256,
            abi_fingerprint: &abi_fingerprint,
            manifest_binding_hash: &manifest_binding_hash,
            imports: &imports,
            profile: HOST_ARTIFACT_PROFILE,
        })?;
        TargetArtifactImage::parse(&target_artifact).map_err(|error| {
            format!(
                "{} target artifact validation failed: {error:?}",
                module.package
            )
        })?;
        fs::write(&target_artifact_path, &target_artifact)?;
        let target_artifact_sha256 = sha256_hex(&target_artifact);

        modules.push(ModuleArtifactManifest {
            package: module.package.to_owned(),
            artifact_name: module.artifact_name.to_owned(),
            role: module.role.as_str().to_owned(),
            fault_policy: module.fault_policy.as_str().to_owned(),
            wasm_path: relative_to_workspace(workspace_root, &wasm_path),
            cwasm_path: relative_to_workspace(workspace_root, &cwasm_path),
            target_artifact_path: relative_to_workspace(workspace_root, &target_artifact_path),
            wasm_sha256,
            cwasm_sha256: cwasm_sha256.clone(),
            target_artifact_sha256: target_artifact_sha256.clone(),
            code_payload_format: CODE_PAYLOAD_FORMAT_CWASM.to_owned(),
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
            interfaces: interface_manifest(module),
            signature: SignatureManifest {
                scheme: "prototype-self-signed-sha256".to_owned(),
                artifact_hash: target_artifact_sha256,
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
        runtime_mode: RUNTIME_MODE_RESEARCH.to_owned(),
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
            engine: SUPERVISOR_COMPILER_ENGINE.to_owned(),
            engine_version: WASMTIME_CRATE_VERSION.to_owned(),
            execution_mode: SUPERVISOR_EXECUTION_MODE.to_owned(),
            artifact_format: SUPERVISOR_ARTIFACT_FORMAT.to_owned(),
            target_artifact_format: TARGET_ARTIFACT_FORMAT_V1.to_owned(),
            runtime_executor_abi: RUNTIME_ONLY_EXECUTOR_ABI.to_owned(),
        },
        modules,
    };
    let manifest_path = artifact_root.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    build_validated_artifact_plan(&manifest)?;
    println!(
        "wrote {}",
        relative_to_workspace(workspace_root, &manifest_path)
    );

    Ok(())
}

fn interface_manifest(module: &supervisor_catalog::WasmModuleSpec) -> InterfaceRequirementManifest {
    let spec = module_interface_spec(module);
    InterfaceRequirementManifest {
        required_wasi_worlds: spec
            .required_wasi_worlds
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        optional_wasi_worlds: spec
            .optional_wasi_worlds
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        custom_wit_worlds: spec
            .custom_wit_worlds
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        wit_package_versions: spec
            .wit_package_versions
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        component_model_version: spec.component_model_version.to_owned(),
        wasi_profile: spec.wasi_profile.to_owned(),
        hostcall_abi_version: spec.hostcall_abi_version.to_owned(),
        capability_abi_version: spec.capability_abi_version.to_owned(),
        semantic_contract_version: spec.semantic_contract_version.to_owned(),
        substrate_profile_required: spec.substrate_profile_required.to_owned(),
        substrate_authorities: SubstrateAuthorityRequirementManifest {
            required: spec
                .substrate_required
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
            optional: spec
                .substrate_optional
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
            forbidden: spec
                .substrate_forbidden
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
        },
    }
}

struct TargetArtifactBuildInput<'a> {
    module: &'a supervisor_catalog::WasmModuleSpec,
    compiled: &'a [u8],
    wasm_sha256: &'a str,
    cwasm_sha256: &'a str,
    abi_fingerprint: &'a str,
    manifest_binding_hash: &'a str,
    imports: &'a [ImportManifest],
    profile: &'a str,
}

struct TargetArtifactSectionPayload {
    kind: SectionKindV1,
    align: usize,
    payload: Vec<u8>,
}

fn build_target_artifact_image(
    input: TargetArtifactBuildInput<'_>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let sections = vec![
        TargetArtifactSectionPayload {
            kind: SectionKindV1::Manifest,
            align: 8,
            payload: serde_json::to_vec_pretty(&serde_json::json!({
                "schema": "vmos-target-artifact-manifest-v1",
                "package": input.module.package,
                "artifact_name": input.module.artifact_name,
                "role": input.module.role.as_str(),
                "fault_policy": input.module.fault_policy.as_str(),
                "wasm_sha256": input.wasm_sha256,
                "code_payload_format": CODE_PAYLOAD_FORMAT_CWASM,
                "code_payload_sha256": input.cwasm_sha256,
                "abi_fingerprint": input.abi_fingerprint,
                "manifest_binding_hash": input.manifest_binding_hash,
            }))?,
        },
        TargetArtifactSectionPayload {
            kind: SectionKindV1::ContractMetadata,
            align: 8,
            payload: serde_json::to_vec_pretty(&serde_json::json!({
                "schema": "vmos-contract-metadata-v1",
                "supervisor_contract": expected_supervisor_contract(),
                "runtime_executor_abi": RUNTIME_ONLY_EXECUTOR_ABI,
                "network_contract_version": NETWORK_CONTRACT_VERSION,
            }))?,
        },
        TargetArtifactSectionPayload {
            kind: SectionKindV1::CodeObject,
            align: 8,
            payload: input.compiled.to_vec(),
        },
        TargetArtifactSectionPayload {
            kind: SectionKindV1::HostcallImportTable,
            align: 8,
            payload: serde_json::to_vec_pretty(&serde_json::json!({
                "schema": "vmos-hostcall-import-table-v1",
                "imports": input.imports,
            }))?,
        },
        TargetArtifactSectionPayload {
            kind: SectionKindV1::TrapMap,
            align: 8,
            payload: serde_json::to_vec_pretty(&serde_json::json!({
                "schema": "vmos-trap-map-v1",
                "entries": [],
                "attribution": "wasmtime-frame-or-unknown-code-trap",
            }))?,
        },
        TargetArtifactSectionPayload {
            kind: SectionKindV1::PcRangeTable,
            align: 8,
            payload: serde_json::to_vec_pretty(&serde_json::json!({
                "schema": "vmos-pc-range-table-v1",
                "entries": [],
                "native_pc": "not-authoritative-for-host-cwasm-validation",
            }))?,
        },
        TargetArtifactSectionPayload {
            kind: SectionKindV1::ProfileRequirements,
            align: 8,
            payload: serde_json::to_vec_pretty(&serde_json::json!({
                "schema": "vmos-target-profile-requirements-v1",
                "artifact_profile": input.profile,
                "host_arch": env::consts::ARCH,
                "target_arch": env::consts::ARCH,
                "compiler_engine": SUPERVISOR_COMPILER_ENGINE,
                "engine_version": WASMTIME_CRATE_VERSION,
                "compilation_strategy": WASMTIME_COMPILATION_STRATEGY,
                "execution_mode": SUPERVISOR_EXECUTION_MODE,
                "target_artifact_format": TARGET_ARTIFACT_FORMAT_V1,
                "code_payload_format": CODE_PAYLOAD_FORMAT_CWASM,
                "wasm_feature_profile": WASM_FEATURE_PROFILE,
                "memory64": false,
                "multi_memory": false,
                "component_model": false,
                "engine_config_fingerprint": canonical_wasmtime_config_fingerprint(
                    env::consts::ARCH,
                    env::consts::ARCH,
                ),
            }))?,
        },
        TargetArtifactSectionPayload {
            kind: SectionKindV1::Signature,
            align: 8,
            payload: serde_json::to_vec_pretty(&serde_json::json!({
                "schema": "vmos-target-signature-v1",
                "scheme": "unsigned-research",
                "signature_enforced": false,
                "signature_verified": false,
            }))?,
        },
    ];

    let section_table_len = sections.len() * TARGET_SECTION_HEADER_LEN;
    let payload_base = align_up_usize(TARGET_ARTIFACT_HEADER_LEN + section_table_len, 8);
    let mut cursor = payload_base;
    let mut layout = Vec::with_capacity(sections.len());
    for section in &sections {
        cursor = align_up_usize(cursor, section.align);
        layout.push(cursor);
        cursor = cursor
            .checked_add(section.payload.len())
            .ok_or("target artifact image length overflowed")?;
    }

    let mut image = vec![0; cursor];
    for (index, section) in sections.iter().enumerate() {
        let offset = layout[index];
        image[offset..offset + section.payload.len()].copy_from_slice(&section.payload);

        let mut header = TargetSectionHeaderV1::new(
            section.kind,
            offset as u64,
            section.payload.len() as u64,
            section.align as u32,
        );
        header.hash = Sha256::digest(&section.payload).into();
        let section_header_start = TARGET_ARTIFACT_HEADER_LEN + index * TARGET_SECTION_HEADER_LEN;
        header
            .write_to(
                &mut image[section_header_start..section_header_start + TARGET_SECTION_HEADER_LEN],
            )
            .map_err(|error| format!("writing target artifact section failed: {error:?}"))?;
    }

    let manifest_hash: [u8; 32] = Sha256::digest(&sections[0].payload).into();
    let mut header = TargetArtifactHeaderV1 {
        magic: target_abi::artifact::TARGET_ARTIFACT_MAGIC,
        header_len: TARGET_ARTIFACT_HEADER_LEN as u32,
        image_len: image.len() as u64,
        schema_major: target_abi::artifact::TARGET_ARTIFACT_SCHEMA_MAJOR,
        schema_minor: 0,
        target_arch: target_arch_code(env::consts::ARCH)?,
        target_abi: TargetAbiCodeV1::Custom as u16,
        endian: 1,
        pointer_width: (usize::BITS) as u8,
        artifact_kind: artifact_kind_code(input.module.role.as_str()),
        code_format: CodeFormatCodeV1::WasmtimeSerialized as u16,
        section_count: sections.len() as u32,
        section_table_off: TARGET_ARTIFACT_HEADER_LEN as u64,
        manifest_hash,
        image_hash: [0; 32],
        flags: 0,
    };
    header
        .write_to(&mut image[..TARGET_ARTIFACT_HEADER_LEN])
        .map_err(|error| format!("writing target artifact header failed: {error:?}"))?;
    header.image_hash = canonical_zero_field_image_hash(&image)
        .map_err(|error| format!("hashing target artifact image failed: {error:?}"))?;
    header
        .write_to(&mut image[..TARGET_ARTIFACT_HEADER_LEN])
        .map_err(|error| format!("writing target artifact hash failed: {error:?}"))?;
    TargetArtifactImage::parse(&image)
        .map_err(|error| format!("validating target artifact image failed: {error:?}"))?;
    Ok(image)
}

fn target_arch_code(arch: &str) -> Result<u16, Box<dyn Error>> {
    match arch {
        "riscv64" => Ok(TargetArchCodeV1::Riscv64 as u16),
        "x86_64" => Ok(TargetArchCodeV1::X86_64 as u16),
        "aarch64" => Ok(TargetArchCodeV1::Aarch64 as u16),
        other => Err(format!("unsupported target artifact host arch `{other}`").into()),
    }
}

fn artifact_kind_code(role: &str) -> u16 {
    match role {
        "driver" => ArtifactKindCodeV1::Driver as u16,
        "frontend_guest" => ArtifactKindCodeV1::App as u16,
        _ => ArtifactKindCodeV1::Service as u16,
    }
}

fn align_up_usize(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn verify_artifacts(artifact_root: &Path) -> Result<(), Box<dyn Error>> {
    let engine = runtime_engine()?;
    let workspace_root = workspace_root()?;
    let manifest = read_manifest(artifact_root)?;
    let plan = build_validated_artifact_plan(&manifest)?;

    for entry in &plan.modules {
        let target_artifact_path = workspace_root.join(&entry.target_artifact_path);
        let target_artifact = fs::read(&target_artifact_path)?;
        if sha256_hex(&target_artifact) != entry.target_artifact_sha256 {
            return Err(format!("{} target artifact hash mismatch", entry.package).into());
        }
        let image = TargetArtifactImage::parse(&target_artifact).map_err(|error| {
            format!(
                "{} target artifact validation failed: {error:?}",
                entry.package
            )
        })?;
        let artifact = image
            .section_payload(SectionKindV1::CodeObject)
            .map_err(|error| {
                format!(
                    "{} code payload extraction failed: {error:?}",
                    entry.package
                )
            })?
            .ok_or_else(|| {
                format!(
                    "{} target artifact missing CodeObject section",
                    entry.package
                )
            })?;
        if sha256_hex(artifact) != entry.cwasm_sha256 {
            return Err(format!("{} CodeObject cwasm payload hash mismatch", entry.package).into());
        }

        let cwasm_path = workspace_root.join(&entry.cwasm_path);
        let cwasm_sidecar = fs::read(&cwasm_path)?;
        if sha256_hex(&cwasm_sidecar) != entry.cwasm_sha256 {
            return Err(format!("{} cwasm sidecar hash mismatch", entry.package).into());
        }
        if cwasm_sidecar != artifact {
            return Err(format!(
                "{} cwasm sidecar differs from CodeObject payload",
                entry.package
            )
            .into());
        }

        match Engine::detect_precompiled(artifact) {
            Some(Precompiled::Module) => {}
            Some(Precompiled::Component) => {
                return Err(
                    format!("{} was compiled as a component unexpectedly", entry.package).into(),
                );
            }
            None => {
                return Err(
                    format!("{} is not a valid precompiled artifact", entry.package).into(),
                );
            }
        }

        let module_binary = unsafe { Module::deserialize(&engine, artifact)? };
        verify_exports(entry, &module_binary)?;

        let mut store = Store::new(&engine, ());
        let instance = Instance::new(&mut store, &module_binary, &[])?;
        run_smoke_checks(entry, &instance, &mut store)?;
    }

    println!("verified {} host-side artifacts", plan.module_count());
    Ok(())
}

fn verify_exports(entry: &ValidatedArtifactEntry, module: &Module) -> Result<(), Box<dyn Error>> {
    let export_names = module
        .exports()
        .map(|export| export.name().to_owned())
        .collect::<Vec<_>>();
    for expected in &entry.expected_exports {
        if !export_names.iter().any(|name| name == expected) {
            return Err(
                format!("{} is missing expected export `{expected}`", entry.package).into(),
            );
        }
    }
    Ok(())
}

fn read_manifest(artifact_root: &Path) -> Result<ArtifactBundleManifest, Box<dyn Error>> {
    let bytes = fs::read(artifact_root.join("manifest.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn run_smoke_checks(
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
                return Err(
                    "console_service commit_write(0, 0) failed in host verification".into(),
                );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwasm_payload_is_wrapped_in_target_artifact_image() {
        let module = &SUPERVISOR_WASM_MODULES[0];
        let compiled = b"fake precompiled cwasm payload";
        let wasm_sha256 = sha256_hex(b"fake wasm");
        let cwasm_sha256 = sha256_hex(compiled);
        let abi_fingerprint = module_abi_fingerprint(module);
        let binding = manifest_binding_hash(module, &wasm_sha256, &cwasm_sha256, &abi_fingerprint);
        let imports = Vec::new();

        let image = build_target_artifact_image(TargetArtifactBuildInput {
            module,
            compiled,
            wasm_sha256: &wasm_sha256,
            cwasm_sha256: &cwasm_sha256,
            abi_fingerprint: &abi_fingerprint,
            manifest_binding_hash: &binding,
            imports: &imports,
            profile: HOST_ARTIFACT_PROFILE,
        })
        .expect("target artifact image");
        let parsed = TargetArtifactImage::parse(&image).expect("parse target artifact");

        assert_eq!(
            parsed.header().code_format,
            CodeFormatCodeV1::WasmtimeSerialized as u16
        );
        assert!(parsed.section(SectionKindV1::Manifest).is_some());
        assert!(parsed.section(SectionKindV1::ContractMetadata).is_some());
        assert_eq!(
            parsed
                .section_payload(SectionKindV1::CodeObject)
                .expect("code payload")
                .expect("code section"),
            compiled
        );
    }
}
