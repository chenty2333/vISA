use std::{fs, path::Path};

use visa_conformance::STAGE1_CASE_DEFINITIONS;

use super::{
    RunnerError, Stage1RunOutput,
    harness::CaseHarness,
    provenance::{
        source_provenance, toolchain_provenance, unix_time_ms, workspace_root, write_pretty_json,
    },
    registry::prepare_stage1_registry,
    runner_io,
    scenarios::execute_case,
    support::digest_hex,
};
use crate::protocol::RuntimeImplementation;

pub fn run_stage1(
    executable: impl AsRef<Path>,
    output_root: impl AsRef<Path>,
) -> Result<Stage1RunOutput, RunnerError> {
    run_stage1_with_runtimes(
        executable,
        output_root,
        RuntimeImplementation::Wasmtime,
        RuntimeImplementation::Wasmtime,
    )
}

pub fn run_stage1_with_runtimes(
    executable: impl AsRef<Path>,
    output_root: impl AsRef<Path>,
    source_runtime: RuntimeImplementation,
    destination_runtime: RuntimeImplementation,
) -> Result<Stage1RunOutput, RunnerError> {
    let executable = executable.as_ref().to_path_buf();
    let output_root = output_root.as_ref();
    fs::create_dir_all(output_root)
        .map_err(|source| runner_io("create Stage 1 output root", output_root, source))?;
    let started_at_unix_ms = unix_time_ms()?;
    let provenance_root = output_root.join("provenance");
    fs::create_dir_all(&provenance_root)
        .map_err(|source| runner_io("create provenance directory", &provenance_root, source))?;

    let workspace_root = workspace_root()?;
    let (source_digest, source_manifest) = source_provenance(&workspace_root)?;
    let source_manifest_path = provenance_root.join("source-manifest.json");
    write_pretty_json(&source_manifest_path, &source_manifest)?;
    let (toolchain_digest, toolchain_raw) = toolchain_provenance()?;
    let toolchain_provenance_path = provenance_root.join("toolchain.txt");
    fs::write(&toolchain_provenance_path, &toolchain_raw).map_err(|source| {
        runner_io("write toolchain provenance", &toolchain_provenance_path, source)
    })?;

    let prepared_registry = prepare_stage1_registry()?;
    let config_digest = prepared_registry.config_digest;
    let policy_digest = prepared_registry.policy_digest;
    let matrix_manifest = prepared_registry.manifest;
    let plans = prepared_registry.plans;
    let matrix_manifest_path = provenance_root.join("matrix.json");
    write_pretty_json(&matrix_manifest_path, &matrix_manifest)?;

    let work_root = output_root.join(".runner-work");
    fs::create_dir_all(&work_root)
        .map_err(|source| runner_io("create runner work directory", &work_root, source))?;
    let mut records = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    let mut observed_source_runtime = None;
    let mut observed_destination_runtime = None;
    for (definition, plan) in STAGE1_CASE_DEFINITIONS.iter().zip(plans) {
        let mut harness = CaseHarness::new(
            &executable,
            &work_root,
            definition,
            plan,
            source_runtime,
            destination_runtime,
        )?;
        let observed_source =
            harness.source().runtime_identity().cloned().ok_or_else(|| RunnerError::Assertion {
                case_id: definition.id.to_owned(),
                detail: "source worker did not report its runtime identity".to_owned(),
            })?;
        let observed_destination =
            harness.destination().runtime_identity().cloned().ok_or_else(|| {
                RunnerError::Assertion {
                    case_id: definition.id.to_owned(),
                    detail: "destination worker did not report its runtime identity".to_owned(),
                }
            })?;
        require_consistent_runtime(
            &mut observed_source_runtime,
            observed_source,
            definition.id,
            "source",
        )?;
        require_consistent_runtime(
            &mut observed_destination_runtime,
            observed_destination,
            definition.id,
            "destination",
        )?;
        let outcome = execute_case(&mut harness)?;
        records.push(harness.finish(outcome)?);
    }
    let toolchain_text = String::from_utf8(toolchain_raw).map_err(|error| RunnerError::Json {
        context: "decode toolchain provenance as UTF-8".to_owned(),
        detail: error.to_string(),
    })?;
    let provenance_assertion = serde_json::json!({
        "name": "stage1-provenance-inputs",
        "algorithms": {
            "source_digest": "sha-256 over compact deterministic source_manifest JSON bytes",
            "toolchain_digest": "sha-256 over toolchain_raw UTF-8 bytes",
            "config_digest": "sha-256 over postcard-1.1.3 config matrix and provider fault coverage projection",
            "policy_digest": "sha-256 over postcard-1.1.3 policy matrix projection"
        },
        "source_manifest": source_manifest,
        "toolchain_raw": toolchain_text,
        "matrix_manifest": matrix_manifest,
        "digests": {
            "source": digest_hex(source_digest),
            "toolchain": digest_hex(toolchain_digest),
            "config": digest_hex(config_digest),
            "policy": digest_hex(policy_digest)
        }
    });
    let evidence_record = records
        .iter_mut()
        .find(|record| record.case_id == "evidence-verification")
        .ok_or_else(|| RunnerError::Registry {
            detail: "evidence-verification execution record is missing".to_owned(),
        })?;
    serde_json::to_writer(&mut evidence_record.raw_assertions_json, &provenance_assertion)
        .map_err(|error| RunnerError::Json {
            context: "encode provenance assertion".to_owned(),
            detail: error.to_string(),
        })?;
    evidence_record.raw_assertions_json.push(b'\n');
    let finished_at_unix_ms = unix_time_ms()?;
    Ok(Stage1RunOutput {
        records,
        started_at_unix_ms,
        finished_at_unix_ms,
        source_digest,
        toolchain_digest,
        config_digest,
        policy_digest,
        source_manifest_path,
        toolchain_provenance_path,
        matrix_manifest_path,
        source_runtime: observed_source_runtime.ok_or_else(|| RunnerError::Registry {
            detail: "Stage 1 matrix reported no source runtime".to_owned(),
        })?,
        destination_runtime: observed_destination_runtime.ok_or_else(|| RunnerError::Registry {
            detail: "Stage 1 matrix reported no destination runtime".to_owned(),
        })?,
    })
}

fn require_consistent_runtime(
    expected: &mut Option<crate::protocol::RuntimeIdentityView>,
    observed: crate::protocol::RuntimeIdentityView,
    case_id: &str,
    role: &str,
) -> Result<(), RunnerError> {
    match expected {
        Some(identity) if identity != &observed => Err(RunnerError::Assertion {
            case_id: case_id.to_owned(),
            detail: format!(
                "{role} runtime identity changed across the matrix: expected {identity:?}, observed {observed:?}"
            ),
        }),
        Some(_) => Ok(()),
        slot @ None => {
            *slot = Some(observed);
            Ok(())
        }
    }
}
