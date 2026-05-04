use super::*;

#[test]
fn substrate_compatibility_accepts_host_validation_capabilities() {
    let manifest = valid_manifest();
    let report = check_artifact_manifest_substrate_compatibility(
        &manifest,
        SubstrateCapabilitySet::host_validation(),
    )
    .expect("compatibility report");

    assert!(report.ok);
    assert_eq!(report.module_count, SUPERVISOR_WASM_MODULES.len());
    assert_eq!(report.reported_profile, "unspecified");
    assert_eq!(report.enforced_profile, "snapshot-replay-capable");
    assert!(report.modules.iter().all(|module| module.ok));
    assert!(report.modules.iter().all(|module| module.enforced_profile == report.enforced_profile));
}

#[test]
fn interface_compatibility_accepts_host_validation_worlds() {
    let manifest = valid_manifest();
    let capabilities = host_validation_interface_capabilities();
    let report = check_artifact_manifest_interface_compatibility(&manifest, &capabilities)
        .expect("interface compatibility report");

    assert!(report.ok);
    assert_eq!(report.module_count, SUPERVISOR_WASM_MODULES.len());
    assert!(report.modules.iter().all(|module| module.ok));
}

#[test]
fn interface_compatibility_reports_missing_custom_wit_world() {
    let manifest = valid_manifest();
    let capabilities = InterfaceHostCapabilitySet::empty();
    let report = check_artifact_manifest_interface_compatibility(&manifest, &capabilities)
        .expect("interface compatibility report");
    let driver = report
        .modules
        .iter()
        .find(|module| module.package == "driver_virtio_net")
        .expect("driver report");

    assert!(!report.ok);
    assert!(!driver.ok);
    assert!(driver.missing_custom_wit_worlds.iter().any(|world| world == "semantic:driverkit"));
    assert!(driver.version_mismatches.is_empty());
}

#[test]
fn interface_compatibility_reports_version_mismatch_separately() {
    let manifest = valid_manifest();
    let mut capabilities = host_validation_interface_capabilities();
    capabilities.hostcall_abi_version = "wire-v0".to_owned();
    let report = check_artifact_manifest_interface_compatibility(&manifest, &capabilities)
        .expect("interface compatibility report");
    let linux = report
        .modules
        .iter()
        .find(|module| module.package == "linux_syscall")
        .expect("linux report");

    assert!(!report.ok);
    assert!(
        linux.version_mismatches.iter().any(|mismatch| mismatch.field == "hostcall_abi_version"
            && mismatch.expected == HOSTCALL_ABI_VERSION
            && mismatch.actual == "wire-v0")
    );
}

#[test]
fn substrate_compatibility_reports_missing_required_authority() {
    let manifest = valid_manifest();
    let report = check_artifact_manifest_substrate_compatibility(
        &manifest,
        SubstrateCapabilitySet::semantic_harness(),
    )
    .expect("compatibility report");
    let driver = report
        .modules
        .iter()
        .find(|module| module.package == "driver_virtio_net")
        .expect("driver report");

    assert!(!report.ok);
    assert!(!driver.ok);
    assert_eq!(driver.reported_profile, "unspecified");
    assert_eq!(driver.enforced_profile, "semantic-harness");
    assert!(driver.missing_required.iter().any(|item| item.authority == "dma"));
    assert!(driver.missing_required.iter().any(|item| item.authority == "mmio"));
    assert!(driver.forbidden_requested.is_empty());
}

#[test]
fn substrate_compatibility_rejects_unknown_required_authority() {
    let manifest = valid_manifest();
    let plan = build_validated_artifact_plan(&manifest).expect("valid plan");
    let mut linux = plan.entry("linux_syscall").expect("linux module").clone();
    linux.interfaces.substrate_authorities.required.push("raw-mmio".to_owned());

    let err =
        check_module_substrate_compatibility(&linux, SubstrateCapabilitySet::host_validation())
            .expect_err("raw requirement token must fail before load");

    assert!(err.to_string().contains("invalid required substrate authority token"));
}

#[test]
fn substrate_compatibility_rejects_forbidden_capability_manifest() {
    let manifest = valid_manifest();
    let plan = build_validated_artifact_plan(&manifest).expect("valid plan");
    let mut linux = plan.entry("linux_syscall").expect("linux module").clone();
    linux.capabilities.push(CapabilityManifest {
        name: "mmio.pci.bar0".to_owned(),
        rights: vec!["read".to_owned()],
        lifetime: "store".to_owned(),
    });

    let report =
        check_module_substrate_compatibility(&linux, SubstrateCapabilitySet::host_validation())
            .expect("compatibility report");

    assert!(!report.ok);
    assert_eq!(report.forbidden_requested, vec!["raw-mmio".to_owned()]);
}

#[test]
fn manifest_validation_rejects_interface_boundary_mismatch() {
    let mut manifest = valid_manifest();
    let linux = manifest
        .modules
        .iter_mut()
        .find(|entry| entry.package == "linux_syscall")
        .expect("linux syscall entry exists");
    linux.interfaces.substrate_profile_required = "device-capable".to_owned();

    let err = validate_artifact_manifest(&manifest).expect_err("bad interface must fail");
    assert!(err.to_string().contains("substrate profile mismatch"));
}

#[test]
fn manifest_validation_rejects_unknown_runtime_mode() {
    let mut manifest = valid_manifest();
    manifest.runtime_mode = "max-debug-production-replay".to_owned();

    assert_eq!(
        validate_artifact_manifest(&manifest).unwrap_err().to_string(),
        "unsupported runtime mode"
    );
}
