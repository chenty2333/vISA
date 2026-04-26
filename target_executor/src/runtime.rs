use std::error::Error;
use std::fs;
use std::path::PathBuf;

use contract_core::{
    CODE_PAYLOAD_FORMAT_CWASM, TARGET_ARTIFACT_FORMAT_V1, ValidatedArtifactEntry,
    WASMTIME_COMPILATION_STRATEGY, WASMTIME_CRATE_VERSION, canonical_wasmtime_config_fingerprint,
};
use service_core::net_contract::{
    NETWORK_CONTRACT_ABI_VERSION, VIRTIO_NET0_MTU, VIRTIO_NET0_RX_QUEUE_DEPTH,
    VIRTIO_NET0_TX_QUEUE_DEPTH,
};
use sha2::{Digest, Sha256};
use supervisor_catalog::{
    SUPERVISOR_COMPILER_ENGINE, SUPERVISOR_EXECUTION_MODE, WASM_FEATURE_PROFILE,
};
use target_abi::{SectionKindV1, TargetArtifactImage};
use wasmtime::{Config, Engine, Instance, Module, Precompiled, Store};

pub struct RuntimeOnlyExecutor {
    engine: Engine,
    workspace_root: PathBuf,
    artifact_profile: String,
}

impl RuntimeOnlyExecutor {
    pub fn host_validation(
        workspace_root: PathBuf,
        artifact_profile: &str,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            engine: Engine::new(&Config::new())?,
            workspace_root,
            artifact_profile: artifact_profile.to_owned(),
        })
    }

    pub fn load_store(
        &self,
        entry: &ValidatedArtifactEntry,
    ) -> Result<LoadedRuntimeStore, Box<dyn Error>> {
        let target_artifact_path = self.workspace_root.join(&entry.target_artifact_path);
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
        let module_bytes = image
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
        if sha256_hex(module_bytes) != entry.cwasm_sha256 {
            return Err(format!("{} CodeObject cwasm payload hash mismatch", entry.package).into());
        }
        self.validate_profile_requirements(entry, &image)?;

        match Engine::detect_precompiled(module_bytes) {
            Some(Precompiled::Module) => {}
            Some(Precompiled::Component) => {
                return Err(format!("{} is a component artifact", entry.package).into());
            }
            None => return Err(format!("{} is not a precompiled artifact", entry.package).into()),
        }

        let module = unsafe { Module::deserialize(&self.engine, module_bytes)? };
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

    fn validate_profile_requirements(
        &self,
        entry: &ValidatedArtifactEntry,
        image: &TargetArtifactImage<'_>,
    ) -> Result<(), Box<dyn Error>> {
        let payload = image
            .section_payload(SectionKindV1::ProfileRequirements)
            .map_err(|error| {
                format!(
                    "{} profile requirements extraction failed: {error:?}",
                    entry.package
                )
            })?
            .ok_or_else(|| format!("{} missing ProfileRequirements section", entry.package))?;
        validate_profile_requirements_payload(&entry.package, &self.artifact_profile, payload)
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

fn validate_profile_requirements_payload(
    package: &str,
    artifact_profile: &str,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let profile: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|error| format!("{package} invalid ProfileRequirements JSON: {error}"))?;
    let host_arch = std::env::consts::ARCH;
    let target_arch = std::env::consts::ARCH;
    check_profile_string(
        &profile,
        package,
        "schema",
        "vmos-target-profile-requirements-v1",
    )?;
    check_profile_string(&profile, package, "artifact_profile", artifact_profile)?;
    check_profile_string(&profile, package, "host_arch", host_arch)?;
    check_profile_string(&profile, package, "target_arch", target_arch)?;
    check_profile_string(
        &profile,
        package,
        "compiler_engine",
        SUPERVISOR_COMPILER_ENGINE,
    )?;
    check_profile_string(&profile, package, "engine_version", WASMTIME_CRATE_VERSION)?;
    check_profile_string(
        &profile,
        package,
        "compilation_strategy",
        WASMTIME_COMPILATION_STRATEGY,
    )?;
    check_profile_string(
        &profile,
        package,
        "execution_mode",
        SUPERVISOR_EXECUTION_MODE,
    )?;
    check_profile_string(
        &profile,
        package,
        "target_artifact_format",
        TARGET_ARTIFACT_FORMAT_V1,
    )?;
    check_profile_string(
        &profile,
        package,
        "code_payload_format",
        CODE_PAYLOAD_FORMAT_CWASM,
    )?;
    check_profile_string(
        &profile,
        package,
        "wasm_feature_profile",
        WASM_FEATURE_PROFILE,
    )?;
    check_profile_bool(&profile, package, "memory64", false)?;
    check_profile_bool(&profile, package, "multi_memory", false)?;
    check_profile_bool(&profile, package, "component_model", false)?;
    check_profile_string(
        &profile,
        package,
        "engine_config_fingerprint",
        &canonical_wasmtime_config_fingerprint(host_arch, target_arch),
    )?;
    Ok(())
}

fn check_profile_string(
    profile: &serde_json::Value,
    package: &str,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let actual = profile
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{package} ProfileRequirements missing string field `{field}`"))?;
    if actual != expected {
        return Err(format!(
            "{package} ProfileRequirements mismatch for `{field}`: expected `{expected}`, got `{actual}`"
        )
        .into());
    }
    Ok(())
}

fn check_profile_bool(
    profile: &serde_json::Value,
    package: &str,
    field: &str,
    expected: bool,
) -> Result<(), Box<dyn Error>> {
    let actual = profile
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| format!("{package} ProfileRequirements missing bool field `{field}`"))?;
    if actual != expected {
        return Err(format!(
            "{package} ProfileRequirements mismatch for `{field}`: expected `{expected}`, got `{actual}`"
        )
        .into());
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use artifact_manifest::{InterfaceRequirementManifest, ResourceLimitsManifest};
    use target_abi::artifact::{
        ArtifactKindCodeV1, CodeFormatCodeV1, TARGET_ARTIFACT_HEADER_LEN, TARGET_ARTIFACT_MAGIC,
        TARGET_ARTIFACT_SCHEMA_MAJOR, TARGET_SECTION_HEADER_LEN, TargetAbiCodeV1, TargetArchCodeV1,
        TargetArtifactHeaderV1, TargetSectionHeaderV1, canonical_zero_field_image_hash,
    };

    #[test]
    fn profile_requirements_accept_current_host_config() {
        let payload = profile_payload(&canonical_wasmtime_config_fingerprint(
            std::env::consts::ARCH,
            std::env::consts::ARCH,
        ));

        validate_profile_requirements_payload("test_service", "host-validation", &payload)
            .expect("current host profile is compatible");
    }

    #[test]
    fn engine_config_mismatch_rejects_before_deserialize() {
        let root = temp_test_dir("engine-config-mismatch");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp dir");

        let code_payload = b"not a real cwasm module";
        let image = target_artifact_with_profile(code_payload, &profile_payload("bad-fingerprint"));
        let artifact_path = root.join("test_service.tart");
        fs::write(&artifact_path, &image).expect("write test tart");
        let entry = test_entry("test_service.tart", code_payload, &image);
        let executor = RuntimeOnlyExecutor::host_validation(root.clone(), "host-validation")
            .expect("executor");

        let error = match executor.load_store(&entry) {
            Ok(_) => panic!("profile mismatch should reject before deserialize"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("engine_config_fingerprint"));
        assert!(!message.contains("not a precompiled artifact"));

        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    fn temp_test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vmos-target-executor-{name}-{}",
            std::process::id()
        ))
    }

    fn test_entry(path: &str, code_payload: &[u8], image: &[u8]) -> ValidatedArtifactEntry {
        ValidatedArtifactEntry {
            package: "test_service".to_owned(),
            artifact_name: "test_service".to_owned(),
            role: "service".to_owned(),
            fault_policy: "restartable".to_owned(),
            wasm_path: "test_service.wasm".to_owned(),
            cwasm_path: "test_service.cwasm".to_owned(),
            target_artifact_path: path.to_owned(),
            wasm_sha256: sha256_hex(b"wasm"),
            cwasm_sha256: sha256_hex(code_payload),
            target_artifact_sha256: sha256_hex(image),
            code_payload_format: CODE_PAYLOAD_FORMAT_CWASM.to_owned(),
            expected_exports: Vec::new(),
            capabilities: Vec::new(),
            abi_fingerprint: "abi".to_owned(),
            service_dependencies: Vec::new(),
            resource_limits: ResourceLimitsManifest::default(),
            interfaces: InterfaceRequirementManifest::default(),
            signature_scheme: "unsigned-research".to_owned(),
            signer: "test".to_owned(),
            manifest_binding_hash: "binding".to_owned(),
        }
    }

    fn profile_payload(fingerprint: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "vmos-target-profile-requirements-v1",
            "artifact_profile": "host-validation",
            "host_arch": std::env::consts::ARCH,
            "target_arch": std::env::consts::ARCH,
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
            "engine_config_fingerprint": fingerprint,
        }))
        .expect("profile json")
    }

    fn target_artifact_with_profile(code_payload: &[u8], profile_payload: &[u8]) -> Vec<u8> {
        let sections = [
            (
                SectionKindV1::Manifest,
                br#"{"package":"test_service"}"#.as_slice(),
            ),
            (SectionKindV1::CodeObject, code_payload),
            (
                SectionKindV1::HostcallImportTable,
                br#"{"imports":[]}"#.as_slice(),
            ),
            (SectionKindV1::TrapMap, br#"{"entries":[]}"#.as_slice()),
            (SectionKindV1::PcRangeTable, br#"{"entries":[]}"#.as_slice()),
            (SectionKindV1::ProfileRequirements, profile_payload),
            (
                SectionKindV1::Signature,
                br#"{"scheme":"unsigned-research"}"#.as_slice(),
            ),
        ];
        let section_table_len = sections.len() * TARGET_SECTION_HEADER_LEN;
        let payload_base = TARGET_ARTIFACT_HEADER_LEN + section_table_len;
        let image_len = payload_base + sections.iter().map(|(_, bytes)| bytes.len()).sum::<usize>();
        let mut image = vec![0; image_len];
        let mut cursor = payload_base;

        for (index, (kind, payload)) in sections.iter().enumerate() {
            let offset = cursor;
            image[offset..offset + payload.len()].copy_from_slice(payload);
            cursor += payload.len();
            let mut section =
                TargetSectionHeaderV1::new(*kind, offset as u64, payload.len() as u64, 1);
            section.hash = Sha256::digest(payload).into();
            let section_off = TARGET_ARTIFACT_HEADER_LEN + index * TARGET_SECTION_HEADER_LEN;
            section
                .write_to(&mut image[section_off..section_off + TARGET_SECTION_HEADER_LEN])
                .expect("write section");
        }

        let mut header = TargetArtifactHeaderV1 {
            magic: TARGET_ARTIFACT_MAGIC,
            header_len: TARGET_ARTIFACT_HEADER_LEN as u32,
            image_len: image.len() as u64,
            schema_major: TARGET_ARTIFACT_SCHEMA_MAJOR,
            schema_minor: 0,
            target_arch: TargetArchCodeV1::X86_64 as u16,
            target_abi: TargetAbiCodeV1::Custom as u16,
            endian: 1,
            pointer_width: 64,
            artifact_kind: ArtifactKindCodeV1::Service as u16,
            code_format: CodeFormatCodeV1::WasmtimeSerialized as u16,
            section_count: sections.len() as u32,
            section_table_off: TARGET_ARTIFACT_HEADER_LEN as u64,
            manifest_hash: Sha256::digest(sections[0].1).into(),
            image_hash: [0; 32],
            flags: 0,
        };
        header
            .write_to(&mut image[..TARGET_ARTIFACT_HEADER_LEN])
            .expect("write header");
        header.image_hash = canonical_zero_field_image_hash(&image).expect("image hash");
        header
            .write_to(&mut image[..TARGET_ARTIFACT_HEADER_LEN])
            .expect("write header hash");
        TargetArtifactImage::parse(&image).expect("valid target artifact image");
        image
    }
}
