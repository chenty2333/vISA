use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use super::{
    artifacts::{read_contained, single_finding},
    model::{
        STAGE2_WACOGO_ENGINE_VERSION, STAGE2_WACOGO_IMPLEMENTATION_VERSION,
        STAGE2_WASMTIME_ENGINE_VERSION, STAGE2_WASMTIME_IMPLEMENTATION_VERSION,
        Stage2ArtifactReference, Stage2ValidationFinding,
    },
    strict_model::{
        Stage2ComponentModelImplementationLineage, Stage2StrictRuntimeLineage,
        Stage2StrictRuntimeMetadata, Stage2WacogoRuntimeLineageObservation,
    },
};
use crate::{Stage1VersionedIdentity, sha256_hex};

pub const STAGE2_STRICT_LINEAGE_ROOT: &str = "lineage";
pub const STAGE2_STRICT_CARGO_LOCK_URI: &str = "lineage/Cargo.lock";
pub const STAGE2_STRICT_WACOGO_SOURCE_LOCK_URI: &str = "lineage/wacogo-source-lock.json";
pub const STAGE2_STRICT_WACOGO_BUILD_RECEIPT_URI: &str = "lineage/wacogo-build-receipt.json";
pub const STAGE2_STRICT_WACOGO_SIDECAR_URI: &str = "lineage/visa-wacogo-runtime";

pub const STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256: &str =
    "f8dfe3c290bc4f6f60843316c8824da9a0bfbb30a1f4fb0bf5845a3fb81b2235";
pub const STAGE2_STRICT_WACOGO_SIDECAR_SHA256: &str =
    "7dd8365e5132fcd32f92ac89d8d1b78b80ec1d285730d8e43b360de6378a0606";
pub const STAGE2_STRICT_WACOGO_SIDECAR_SIZE: usize = 6_754_430;

const WACOGO_UPSTREAM_VERSION: &str = "v0.0.0-20260617023329-3de16a61796c";
const WACOGO_UPSTREAM_REVISION: &str = "3de16a61796ce02d29795e4a074f37a33e6ebd87";
const WAZERO_VERSION: &str = "v1.11.1-0.20260418165552-5cb4bb3ec0c1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ValidatedStrictLineage {
    pub(super) runtime_lineages: Vec<Stage2StrictRuntimeLineage>,
    pub(super) cargo_lock_identity: StrictCargoLockIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StrictCargoLockIdentity {
    pub(super) byte_length: u64,
    pub(super) sha256: String,
}

pub(super) fn load_and_validate_strict_lineage(
    root: &Path,
) -> Result<ValidatedStrictLineage, Stage2ValidationFinding> {
    let cargo_lock = read_required(root, STAGE2_STRICT_CARGO_LOCK_URI)?;
    validate_cargo_lock(&cargo_lock)?;

    let source_lock = read_required(root, STAGE2_STRICT_WACOGO_SOURCE_LOCK_URI)?;
    if sha256_hex(&source_lock) != STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256 {
        return Err(single_finding(
            "strict-wacogo-source-lock-digest-mismatch",
            "the retained wacogo source lock is not the byte-exact qualified lock",
        ));
    }
    let source: Value = serde_json::from_slice(&source_lock).map_err(|error| {
        single_finding(
            "invalid-strict-wacogo-source-lock",
            format!("cannot parse the retained wacogo source lock: {error}"),
        )
    })?;
    validate_source_lock(&source)?;

    let receipt = read_required(root, STAGE2_STRICT_WACOGO_BUILD_RECEIPT_URI)?;
    let receipt: Value = serde_json::from_slice(&receipt).map_err(|error| {
        single_finding(
            "invalid-strict-wacogo-build-receipt",
            format!("cannot parse the retained wacogo build receipt: {error}"),
        )
    })?;
    let sidecar = read_required(root, STAGE2_STRICT_WACOGO_SIDECAR_URI)?;
    validate_build_receipt(&receipt, &source, &sidecar)?;

    let cargo_reference = artifact(STAGE2_STRICT_CARGO_LOCK_URI, &cargo_lock);
    let source_reference = artifact(STAGE2_STRICT_WACOGO_SOURCE_LOCK_URI, &source_lock);
    let receipt_bytes = read_required(root, STAGE2_STRICT_WACOGO_BUILD_RECEIPT_URI)?;
    let receipt_reference = artifact(STAGE2_STRICT_WACOGO_BUILD_RECEIPT_URI, &receipt_bytes);
    let sidecar_reference = artifact(STAGE2_STRICT_WACOGO_SIDECAR_URI, &sidecar);

    Ok(ValidatedStrictLineage {
        cargo_lock_identity: cargo_lock_identity(&cargo_lock),
        runtime_lineages: vec![
            Stage2StrictRuntimeLineage::Wasmtime {
                expected_metadata: required_wasmtime_metadata(),
                component_model: Stage2ComponentModelImplementationLineage {
                    parser: versioned("wasmtime-environ", STAGE2_WASMTIME_ENGINE_VERSION),
                    canonical_abi: versioned("wasmtime-environ", STAGE2_WASMTIME_ENGINE_VERSION),
                    instantiation: versioned("wasmtime", STAGE2_WASMTIME_ENGINE_VERSION),
                    execution: versioned("wasmtime", STAGE2_WASMTIME_ENGINE_VERSION),
                },
                dependency_lock: cargo_reference,
            },
            Stage2StrictRuntimeLineage::Wacogo {
                expected_metadata: required_wacogo_metadata(),
                component_model: Stage2ComponentModelImplementationLineage {
                    parser: versioned("github.com/partite-ai/wacogo", WACOGO_UPSTREAM_VERSION),
                    canonical_abi: versioned(
                        "github.com/partite-ai/wacogo",
                        WACOGO_UPSTREAM_VERSION,
                    ),
                    instantiation: versioned(
                        "github.com/partite-ai/wacogo",
                        WACOGO_UPSTREAM_VERSION,
                    ),
                    execution: versioned("github.com/tetratelabs/wazero", WAZERO_VERSION),
                },
                source_lock: source_reference,
                build_receipt: receipt_reference,
                sidecar: sidecar_reference,
            },
        ],
    })
}

pub(super) fn validate_stage1_manifest_cargo_lock_binding(
    manifest_bytes: &[u8],
    retained: &StrictCargoLockIdentity,
    label: &str,
) -> Result<(), Stage2ValidationFinding> {
    let manifest: Stage1SourceManifest =
        serde_json::from_slice(manifest_bytes).map_err(|error| {
            single_finding(
                "invalid-stage2-strict-cell-source-manifest",
                format!("cannot parse {label}: {error}"),
            )
        })?;
    if manifest.schema != "visa-stage1-source-manifest-v1" {
        return Err(single_finding(
            "invalid-stage2-strict-cell-source-manifest",
            format!("{label} has an unsupported schema {}", manifest.schema),
        ));
    }
    let cargo_lock =
        manifest.files.iter().filter(|file| file.path == "Cargo.lock").collect::<Vec<_>>();
    if !matches!(cargo_lock.as_slice(), [entry]
        if entry.bytes == retained.byte_length && entry.sha256 == retained.sha256)
    {
        return Err(single_finding(
            "stage2-strict-cell-cargo-lock-binding-mismatch",
            format!(
                "{label} must contain exactly one Cargo.lock entry matching retained length {} and SHA-256 {}",
                retained.byte_length, retained.sha256
            ),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stage1SourceManifest {
    schema: String,
    files: Vec<Stage1SourceManifestFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stage1SourceManifestFile {
    path: String,
    bytes: u64,
    sha256: String,
}

fn cargo_lock_identity(bytes: &[u8]) -> StrictCargoLockIdentity {
    StrictCargoLockIdentity { byte_length: bytes.len() as u64, sha256: sha256_hex(bytes) }
}

pub(super) fn required_wasmtime_metadata() -> Stage2StrictRuntimeMetadata {
    Stage2StrictRuntimeMetadata {
        implementation: "visa_wasmtime".to_owned(),
        implementation_version: STAGE2_WASMTIME_IMPLEMENTATION_VERSION.to_owned(),
        engine: "wasmtime".to_owned(),
        engine_version: STAGE2_WASMTIME_ENGINE_VERSION.to_owned(),
        translation_provenance: None,
        implementation_lineage: None,
    }
}

pub(super) fn required_wacogo_metadata() -> Stage2StrictRuntimeMetadata {
    Stage2StrictRuntimeMetadata {
        implementation: "visa_wacogo".to_owned(),
        implementation_version: STAGE2_WACOGO_IMPLEMENTATION_VERSION.to_owned(),
        engine: "partite-ai/wacogo+wazero".to_owned(),
        engine_version: STAGE2_WACOGO_ENGINE_VERSION.to_owned(),
        translation_provenance: None,
        implementation_lineage: Some(required_wacogo_observation()),
    }
}

fn required_wacogo_observation() -> Stage2WacogoRuntimeLineageObservation {
    Stage2WacogoRuntimeLineageObservation {
        source_lock_schema: "visa.wacogo-source-lock.v1".to_owned(),
        source_lock_sha256: STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256.to_owned(),
        derivative_id: "partite-ai-wacogo-3de16a61796c-visa-patchset-v1".to_owned(),
        upstream_module: "github.com/partite-ai/wacogo".to_owned(),
        upstream_version: WACOGO_UPSTREAM_VERSION.to_owned(),
        upstream_revision: WACOGO_UPSTREAM_REVISION.to_owned(),
        upstream_module_sum: "h1:WAxQQFk9xW0jy0cu1Ql4JaaUJTUMo0GsK5TNn5Nliiw=".to_owned(),
        upstream_is_qualified_without_patches: false,
        patchset_id: "visa-wacogo-downstream-v1".to_owned(),
        patchset_sha256: "a377b3d3f0da455f14097638380a8bab566b2aa0d33a4f25d90326e7a2b211e2"
            .to_owned(),
        patch_sha256s: vec![
            "c04b82a5ec2a95c45f5f81bdce5b2cbff11e25556865eb19928b48b6f94eed69".to_owned(),
            "3531ff7a61de7c41f4237d7077a4dd0602bedd15e3067db070fd3e659575a37e".to_owned(),
            "4b32fe31643aedab8472c42ae38d635abbfc9133093866b5ff1de9dcc4548d0e".to_owned(),
        ],
        patched_tree_sha256: "813eb9fad2d93d0c2237edf5d55d18316d1cc313ccf033e079c01fd18f653311"
            .to_owned(),
        sidecar_executable_sha256: STAGE2_STRICT_WACOGO_SIDECAR_SHA256.to_owned(),
        sidecar_executable_size: STAGE2_STRICT_WACOGO_SIDECAR_SIZE as u64,
        sidecar_protocol_version: 1,
        execution_carrier: "owned-component-stdin-frame-v1".to_owned(),
        wacogo_version: WACOGO_UPSTREAM_VERSION.to_owned(),
        wacogo_revision: WACOGO_UPSTREAM_REVISION.to_owned(),
        wazero_version: WAZERO_VERSION.to_owned(),
        go_version: "go1.26.5".to_owned(),
        target: "linux/amd64".to_owned(),
        main_module: "visa.local/wacogo-runtime".to_owned(),
    }
}

fn validate_cargo_lock(bytes: &[u8]) -> Result<(), Stage2ValidationFinding> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        single_finding(
            "invalid-strict-cargo-lock",
            format!("retained Cargo.lock is not UTF-8: {error}"),
        )
    })?;
    for (name, version) in [
        ("visa_wasmtime", STAGE2_WASMTIME_IMPLEMENTATION_VERSION),
        ("wasmtime", STAGE2_WASMTIME_ENGINE_VERSION),
        ("wasmtime-environ", STAGE2_WASMTIME_ENGINE_VERSION),
    ] {
        if !cargo_lock_contains_package(text, name, version) {
            return Err(single_finding(
                "strict-wasmtime-dependency-lock-mismatch",
                format!("Cargo.lock does not retain {name} {version}"),
            ));
        }
    }
    Ok(())
}

fn cargo_lock_contains_package(text: &str, name: &str, version: &str) -> bool {
    text.split("[[package]]").skip(1).any(|package| {
        let mut observed_name = None;
        let mut observed_version = None;
        for line in package.lines() {
            let Some((field, value)) = line.split_once(" = ") else { continue };
            let value = value.trim().trim_matches('"');
            match field.trim() {
                "name" => observed_name = Some(value),
                "version" => observed_version = Some(value),
                _ => {}
            }
        }
        observed_name == Some(name) && observed_version == Some(version)
    })
}

fn validate_source_lock(source: &Value) -> Result<(), Stage2ValidationFinding> {
    let expected = required_wacogo_observation();
    let checks = [
        (pointer_str(source, "/schema"), expected.source_lock_schema.as_str()),
        (pointer_str(source, "/derivative/id"), expected.derivative_id.as_str()),
        (pointer_str(source, "/upstream/module"), expected.upstream_module.as_str()),
        (pointer_str(source, "/upstream/version"), expected.upstream_version.as_str()),
        (pointer_str(source, "/upstream/revision"), expected.upstream_revision.as_str()),
        (pointer_str(source, "/upstream/module_sum"), expected.upstream_module_sum.as_str()),
        (pointer_str(source, "/patchset/id"), expected.patchset_id.as_str()),
        (
            pointer_str(source, "/patchset/ordered_concatenation_sha256"),
            expected.patchset_sha256.as_str(),
        ),
        (
            pointer_str(source, "/patchset/post_patch_tree/sha256"),
            expected.patched_tree_sha256.as_str(),
        ),
        (pointer_str(source, "/build_toolchain/go/version"), expected.go_version.as_str()),
        (
            pointer_str(source, "/production_artifacts/sidecar/module_path"),
            expected.main_module.as_str(),
        ),
        (
            pointer_str(source, "/production_artifacts/sidecar/carrier_version"),
            expected.execution_carrier.as_str(),
        ),
        (
            pointer_str(source, "/production_artifacts/sidecar/binary/sha256"),
            expected.sidecar_executable_sha256.as_str(),
        ),
    ];
    if checks.iter().any(|(observed, expected)| *observed != Some(*expected))
        || source.pointer("/derivative/upstream_is_qualified_without_patches")
            != Some(&Value::Bool(false))
        || source.pointer("/production_artifacts/sidecar/protocol_version").and_then(Value::as_u64)
            != Some(expected.sidecar_protocol_version.into())
        || source.pointer("/production_artifacts/sidecar/binary/size").and_then(Value::as_u64)
            != Some(expected.sidecar_executable_size)
    {
        return Err(single_finding(
            "strict-wacogo-source-lock-identity-mismatch",
            "the retained source lock does not describe the qualified derivative and sidecar",
        ));
    }
    let patches = source
        .pointer("/patchset/patches")
        .and_then(Value::as_array)
        .map(|patches| {
            patches
                .iter()
                .filter_map(|patch| patch.get("sha256").and_then(Value::as_str))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !patches.iter().copied().eq(expected.patch_sha256s.iter().map(String::as_str)) {
        return Err(single_finding(
            "strict-wacogo-patchset-mismatch",
            "the retained source lock does not name the exact ordered downstream patch set",
        ));
    }
    Ok(())
}

fn validate_build_receipt(
    receipt: &Value,
    source: &Value,
    sidecar: &[u8],
) -> Result<(), Stage2ValidationFinding> {
    let sidecar_digest = sha256_hex(sidecar);
    let source_binary =
        source.pointer("/production_artifacts/sidecar/binary").ok_or_else(|| {
            single_finding("invalid-strict-wacogo-source-lock", "missing binary lock")
        })?;
    let receipt_binary = receipt
        .get("binary")
        .ok_or_else(|| single_finding("invalid-strict-wacogo-build-receipt", "missing binary"))?;
    let exact_binding = pointer_str(receipt, "/schema")
        == Some("visa.wacogo-sidecar-build-receipt.v1")
        && pointer_str(receipt, "/source_lock_sha256")
            == Some(STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256)
        && pointer_str(receipt, "/derivative_id") == pointer_str(source, "/derivative/id")
        && pointer_str(receipt, "/patchset_sha256")
            == pointer_str(source, "/patchset/ordered_concatenation_sha256")
        && pointer_str(receipt, "/patched_source_tree_sha256")
            == pointer_str(source, "/patchset/post_patch_tree/sha256")
        && receipt.get("accepted_component")
            == source.pointer("/production_artifacts/sidecar/accepted_component")
        && receipt.get("execution_host_requirements")
            == source.pointer("/production_artifacts/sidecar/execution_host_requirements")
        && receipt.get("executable_module_closure")
            == source.pointer("/production_artifacts/sidecar/executable_module_closure")
        && receipt.get("protocol_version")
            == source.pointer("/production_artifacts/sidecar/protocol_version")
        && receipt.get("carrier_version")
            == source.pointer("/production_artifacts/sidecar/carrier_version")
        && receipt_binary.get("size") == source_binary.get("size")
        && receipt_binary.get("sha256") == source_binary.get("sha256")
        && receipt_binary.get("size").and_then(Value::as_u64) == Some(sidecar.len() as u64)
        && receipt_binary.get("sha256").and_then(Value::as_str) == Some(sidecar_digest.as_str());
    if !exact_binding {
        return Err(single_finding(
            "strict-wacogo-build-receipt-binding-mismatch",
            "the build receipt is not bound to the retained source lock and actual sidecar bytes",
        ));
    }

    let closure =
        receipt.get("executable_module_closure").and_then(Value::as_array).ok_or_else(|| {
            single_finding(
                "invalid-strict-wacogo-module-closure",
                "build receipt has no executable module closure",
            )
        })?;
    let expected_modules = [
        "github.com/partite-ai/wacogo",
        "github.com/tetratelabs/wazero",
        "golang.org/x/sys",
        "visa.local/wacogo-runtime",
    ];
    if closure.len() != expected_modules.len()
        || closure
            .iter()
            .zip(expected_modules)
            .any(|(module, expected)| module.get("path").and_then(Value::as_str) != Some(expected))
        || closure.iter().any(|module| {
            module
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| path.to_ascii_lowercase().contains("wasmtime"))
        })
    {
        return Err(single_finding(
            "strict-wacogo-wasmtime-lineage-rejected",
            "the Wacogo executable closure must be the exact four-module non-Wasmtime closure",
        ));
    }

    let gates = receipt.get("gates").and_then(Value::as_object).ok_or_else(|| {
        single_finding("invalid-strict-wacogo-build-receipt", "build receipt has no gate results")
    })?;
    if gates.get("no_wasmtime_executable_lineage").and_then(Value::as_str) != Some("passed")
        || gates.values().any(|value| value.as_str() != Some("passed"))
        || receipt.get("independent_builds").and_then(Value::as_u64) != Some(2)
    {
        return Err(single_finding(
            "strict-wacogo-build-gates-not-passed",
            "the retained receipt does not prove both locked builds and every production gate",
        ));
    }
    Ok(())
}

fn read_required(root: &Path, uri: &str) -> Result<Vec<u8>, Stage2ValidationFinding> {
    read_contained(root, uri).map_err(|finding| {
        single_finding(
            "missing-strict-lineage-artifact",
            format!("{uri}: {}: {}", finding.code, finding.detail),
        )
    })
}

fn artifact(uri: &str, bytes: &[u8]) -> Stage2ArtifactReference {
    Stage2ArtifactReference { uri: uri.to_owned(), sha256: sha256_hex(bytes) }
}

fn versioned(name: &str, version: &str) -> Stage1VersionedIdentity {
    Stage1VersionedIdentity { name: name.to_owned(), version: version.to_owned() }
}

fn pointer_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_lock_parser_finds_only_one_package_stanza_at_a_time() {
        let lock = b"version = 4\n\n[[package]]\nname = \"wasmtime\"\nversion = \"43.0.2\"\n\n[[package]]\nname = \"other\"\nversion = \"1\"\n";
        assert!(cargo_lock_contains_package(
            std::str::from_utf8(lock).unwrap(),
            "wasmtime",
            "43.0.2"
        ));
        assert!(!cargo_lock_contains_package(std::str::from_utf8(lock).unwrap(), "wasmtime", "1"));
    }

    #[test]
    fn required_runtime_metadata_names_two_distinct_component_model_lineages() {
        let wasmtime = required_wasmtime_metadata();
        let wacogo = required_wacogo_metadata();
        assert_ne!(wasmtime.implementation, wacogo.implementation);
        assert_ne!(wasmtime.engine, wacogo.engine);
        assert!(wasmtime.implementation_lineage.is_none());
        assert_eq!(
            wacogo.implementation_lineage.unwrap().source_lock_sha256,
            STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256
        );
    }

    #[test]
    fn source_manifest_binding_rejects_a_retained_lock_mutated_without_changing_pins() {
        let original = concat!(
            "version = 4\n\n",
            "[[package]]\nname = \"visa_wasmtime\"\nversion = \"0.2.0\"\n\n",
            "[[package]]\nname = \"wasmtime\"\nversion = \"43.0.2\"\n\n",
            "[[package]]\nname = \"wasmtime-environ\"\nversion = \"43.0.2\"\n",
        )
        .as_bytes();
        let mut mutated = original.to_vec();
        mutated.extend_from_slice(b"\n# unrelated post-capture mutation\n");
        validate_cargo_lock(original).expect("the original pins are valid");
        validate_cargo_lock(&mutated).expect("the mutation deliberately preserves all three pins");

        let original_identity = cargo_lock_identity(original);
        let manifest = serde_json::json!({
            "schema": "visa-stage1-source-manifest-v1",
            "files": [{
                "path": "Cargo.lock",
                "bytes": original_identity.byte_length,
                "sha256": original_identity.sha256,
            }]
        });
        let error = validate_stage1_manifest_cargo_lock_binding(
            &serde_json::to_vec(&manifest).unwrap(),
            &cargo_lock_identity(&mutated),
            "source manifest",
        )
        .expect_err("retained bytes and the executed-cell source lock must be identical");
        assert_eq!(error.code, "stage2-strict-cell-cargo-lock-binding-mismatch");
    }
}
