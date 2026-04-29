use super::*;

#[test]
fn validated_plan_preserves_manifest_order_and_totals() {
    let manifest = valid_manifest();
    let plan = build_validated_artifact_plan(&manifest).expect("valid plan");

    assert_eq!(plan.module_count(), SUPERVISOR_WASM_MODULES.len());
    assert_eq!(plan.runtime_mode, RUNTIME_MODE_RESEARCH);
    assert_eq!(plan.modules[0].package, SUPERVISOR_WASM_MODULES[0].package);
    assert_eq!(plan.modules[0].hash_status, ARTIFACT_HASH_STATUS_MANIFEST_BOUND);
    assert_eq!(
        plan.modules[0].signature_status,
        ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED
    );
    assert!(!plan.modules[0].signature_verified);
    assert_eq!(
        plan.modules[0].interfaces.semantic_contract_version,
        SEMANTIC_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(plan.modules[0].interfaces.hostcall_abi_version, HOSTCALL_ABI_VERSION);
    assert_eq!(
        plan.capability_count(),
        SUPERVISOR_WASM_MODULES.iter().map(|spec| spec.capabilities.len()).sum()
    );
}

#[test]
fn manifest_validation_rejects_expected_export_tamper() {
    let mut manifest = valid_manifest();
    manifest.modules[0].expected_exports = vec!["evil_export".to_owned()];

    let err = validate_artifact_manifest(&manifest).expect_err("bad exports must fail");
    assert_eq!(err.to_string(), "console_service expected exports mismatch");
}

#[test]
fn manifest_validation_rejects_actual_export_tamper() {
    let mut manifest = valid_manifest();
    manifest.modules[0].exports[0].name = "evil_export".to_owned();

    let err = validate_artifact_manifest(&manifest).expect_err("bad exports must fail");
    assert_eq!(err.to_string(), "console_service unexpected export evil_export");
}

#[test]
fn validated_plan_derives_exports_from_catalog_spec() {
    let manifest = valid_manifest();
    let plan = build_validated_artifact_plan(&manifest).expect("valid plan");
    let expected = SUPERVISOR_WASM_MODULES[0]
        .expected_exports
        .iter()
        .map(|export| (*export).to_owned())
        .collect::<Vec<_>>();

    assert_eq!(plan.modules[0].expected_exports, expected);
}

#[test]
fn manifest_validation_rejects_resource_limit_tamper() {
    let mut manifest = valid_manifest();
    manifest.modules[0].resource_limits.max_memory_pages = u32::MAX;

    let err = validate_artifact_manifest(&manifest).expect_err("bad limits must fail");
    assert_eq!(err.to_string(), "console_service resource limits mismatch");
}

#[test]
fn manifest_validation_rejects_bad_entry_binding() {
    let mut manifest = valid_manifest();
    manifest.modules[0].signature.manifest_binding_hash = "stale-binding".to_owned();

    let err = validate_artifact_manifest(&manifest).expect_err("bad binding must fail");
    assert!(err.to_string().contains("manifest binding hash mismatch"));
}

#[test]
fn migration_against_manifest_rejects_missing_artifact_evidence() {
    let manifest = valid_manifest();
    let package = minimal_migration_package();

    let err = validate_migration_against_manifest(&package, &manifest)
        .expect_err("missing artifact evidence must fail");
    assert_eq!(err.to_string(), "package artifact verification count does not match manifest");
}
