use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use contract_core::CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION;

use crate::{
    hash::sha256_hex,
    ltp::parse_ltp_results,
    types::{
        Boundary, ConformanceReport, EvidenceArtifact, EvidenceArtifactKind, TestResult,
        ValidationFinding, ValidationReport,
    },
};

pub fn validate_report_artifacts(
    report: &ConformanceReport,
    artifact_root: impl AsRef<Path>,
) -> ValidationReport {
    let artifact_root = artifact_root.as_ref();
    let mut findings = Vec::new();
    for result in &report.results {
        for artifact in &result.evidence_artifacts {
            validate_artifact(result, artifact, artifact_root, &mut findings);
        }
    }
    ValidationReport::new(findings)
}

fn validate_artifact(
    result: &TestResult,
    artifact: &EvidenceArtifact,
    artifact_root: &Path,
    findings: &mut Vec<ValidationFinding>,
) {
    if artifact.uri.contains("://") {
        findings.push(finding(
            "unverifiable-evidence-artifact-uri",
            format!("{} artifact {} is not a local file URI", result.spec_id, artifact.uri),
        ));
        return;
    }

    if relative_artifact_path_escapes_root(&artifact.uri) {
        findings.push(finding(
            "evidence-artifact-path-escape",
            format!("{} artifact {} escapes the artifact root", result.spec_id, artifact.uri),
        ));
        return;
    }

    let path = resolve_artifact_path(artifact_root, &artifact.uri);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            findings.push(finding(
                "missing-evidence-artifact-file",
                format!(
                    "{} artifact {} could not be read: {}",
                    result.spec_id,
                    path.display(),
                    error
                ),
            ));
            return;
        }
    };

    let actual_sha256 = sha256_hex(&bytes);
    if actual_sha256 != artifact.sha256 {
        findings.push(finding(
            "evidence-artifact-sha256-mismatch",
            format!(
                "{} artifact {} sha256 mismatch: report={} actual={}",
                result.spec_id,
                path.display(),
                artifact.sha256,
                actual_sha256
            ),
        ));
    }

    if let Err(error) = validate_artifact_content(artifact.kind, &bytes) {
        findings.push(finding(
            "invalid-evidence-artifact-content",
            format!("{} artifact {} invalid: {}", result.spec_id, path.display(), error),
        ));
        return;
    }

    if let Err(error) = validate_artifact_context(result, artifact.kind, &bytes) {
        findings.push(finding(
            "evidence-artifact-boundary-overclaim",
            format!("{} artifact {} invalid: {}", result.spec_id, path.display(), error),
        ));
    }
}

fn resolve_artifact_path(artifact_root: &Path, uri: &str) -> PathBuf {
    let path = Path::new(uri);
    if path.is_absolute() { path.to_path_buf() } else { artifact_root.join(path) }
}

fn relative_artifact_path_escapes_root(uri: &str) -> bool {
    let path = Path::new(uri);
    !path.is_absolute() && path.components().any(|component| component == Component::ParentDir)
}

fn validate_artifact_content(kind: EvidenceArtifactKind, bytes: &[u8]) -> Result<(), String> {
    match kind {
        EvidenceArtifactKind::ContractGraphSnapshot => validate_contract_graph_snapshot(bytes),
        EvidenceArtifactKind::SubstrateExtractionTrace => validate_extraction_trace(bytes),
        EvidenceArtifactKind::DeviceTrace => validate_device_trace(bytes),
        EvidenceArtifactKind::SerialLog => validate_non_empty_text(bytes, "serial log"),
        EvidenceArtifactKind::BenchmarkRawOutput => validate_criterion_estimates(bytes),
        EvidenceArtifactKind::LtpRawLog => validate_ltp_log(bytes),
    }
}

fn validate_artifact_context(
    result: &TestResult,
    kind: EvidenceArtifactKind,
    bytes: &[u8],
) -> Result<(), String> {
    match kind {
        EvidenceArtifactKind::ContractGraphSnapshot => {
            let claimed = contract_graph_snapshot_claimed_boundary(bytes)?;
            if result.observed_boundary.can_claim(claimed) {
                Ok(())
            } else {
                Err(format!(
                    "contract graph snapshot claims {} but result observed {}",
                    claimed.as_str(),
                    result.observed_boundary.as_str()
                ))
            }
        }
        _ => Ok(()),
    }
}

fn validate_contract_graph_snapshot(bytes: &[u8]) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let object = value.as_object().ok_or_else(|| "expected JSON object".to_string())?;

    let schema_version = object
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing schema_version".to_string())?;
    if schema_version != CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION {
        return Err(format!("unsupported schema_version {schema_version}"));
    }

    let claimed = object
        .get("claimed_evidence_level")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing claimed_evidence_level".to_string())?;
    if Boundary::parse(claimed).is_none() {
        return Err(format!("unknown claimed_evidence_level {claimed}"));
    }

    for field in [
        "artifacts",
        "code_objects",
        "stores",
        "activations",
        "hostcalls",
        "traps",
        "capabilities",
        "waits",
        "cleanup_transactions",
        "tombstones",
        "external_objects",
        "explicit_edges",
    ] {
        if !object.get(field).is_some_and(serde_json::Value::is_array) {
            return Err(format!("missing or non-array {field}"));
        }
    }

    for field in [
        "artifacts",
        "code_objects",
        "stores",
        "activations",
        "hostcalls",
        "traps",
        "capabilities",
        "waits",
        "cleanup_transactions",
    ] {
        validate_identity_array(object, field)?;
    }
    validate_tombstone_array(object)?;
    validate_external_object_array(object)?;
    validate_explicit_edge_array(object)?;

    Ok(())
}

fn snapshot_array<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a Vec<serde_json::Value>, String> {
    object
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("missing or non-array {field}"))
}

fn validate_identity_array(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<(), String> {
    for (index, value) in snapshot_array(object, field)?.iter().enumerate() {
        validate_identity_object(value, field, index)?;
    }
    Ok(())
}

fn validate_identity_object(
    value: &serde_json::Value,
    field: &str,
    index: usize,
) -> Result<(), String> {
    let object = value.as_object().ok_or_else(|| format!("{field}[{index}] must be an object"))?;
    let id = object
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{field}[{index}] missing numeric id"))?;
    let generation = object
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{field}[{index}] missing numeric generation"))?;
    if id == 0 {
        return Err(format!("{field}[{index}] id must be non-zero"));
    }
    if generation == 0 {
        return Err(format!("{field}[{index}] generation must be non-zero"));
    }
    Ok(())
}

fn validate_tombstone_array(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    for (index, value) in snapshot_array(object, "tombstones")?.iter().enumerate() {
        let tombstone =
            value.as_object().ok_or_else(|| format!("tombstones[{index}] must be an object"))?;
        let kind = tombstone
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("tombstones[{index}] missing kind"))?;
        if kind.trim().is_empty() {
            return Err(format!("tombstones[{index}] kind must be non-empty"));
        }
        validate_identity_object(value, "tombstones", index)?;
    }
    Ok(())
}

fn validate_external_object_array(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    for (index, value) in snapshot_array(object, "external_objects")?.iter().enumerate() {
        let external = value
            .as_object()
            .ok_or_else(|| format!("external_objects[{index}] must be an object"))?;
        let object_ref = external
            .get("object")
            .ok_or_else(|| format!("external_objects[{index}] missing object"))?;
        validate_ref_object(object_ref, "external_objects", index)?;
        for field in ["provider", "class"] {
            let value = external
                .get(field)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("external_objects[{index}] missing {field}"))?;
            if value.trim().is_empty() {
                return Err(format!("external_objects[{index}] {field} must be non-empty"));
            }
        }
    }
    Ok(())
}

fn validate_explicit_edge_array(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    for (index, value) in snapshot_array(object, "explicit_edges")?.iter().enumerate() {
        let edge = value
            .as_object()
            .ok_or_else(|| format!("explicit_edges[{index}] must be an object"))?;
        let from =
            edge.get("from").ok_or_else(|| format!("explicit_edges[{index}] missing from"))?;
        let to = edge.get("to").ok_or_else(|| format!("explicit_edges[{index}] missing to"))?;
        validate_ref_object(from, "explicit_edges.from", index)?;
        validate_ref_object(to, "explicit_edges.to", index)?;

        let mode = edge
            .get("mode")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("explicit_edges[{index}] missing mode"))?;
        if !matches!(mode, "live" | "historical" | "cleanup-effect" | "external") {
            return Err(format!("explicit_edges[{index}] unknown mode {mode}"));
        }

        let evidence_level = edge
            .get("evidence_level")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("explicit_edges[{index}] missing evidence_level"))?;
        if Boundary::parse(evidence_level).is_none() {
            return Err(format!("explicit_edges[{index}] unknown evidence_level {evidence_level}"));
        }

        if edge.get("epoch").and_then(serde_json::Value::as_u64).is_none() {
            return Err(format!("explicit_edges[{index}] missing numeric epoch"));
        }
    }
    Ok(())
}

fn validate_ref_object(value: &serde_json::Value, field: &str, index: usize) -> Result<(), String> {
    let object =
        value.as_object().ok_or_else(|| format!("{field}[{index}] ref must be an object"))?;
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{field}[{index}] ref missing kind"))?;
    if kind.trim().is_empty() {
        return Err(format!("{field}[{index}] ref kind must be non-empty"));
    }
    let id = object
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{field}[{index}] ref missing numeric id"))?;
    let generation = object
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{field}[{index}] ref missing numeric generation"))?;
    if id == 0 {
        return Err(format!("{field}[{index}] ref id must be non-zero"));
    }
    if generation == 0 && kind != "external-object" {
        return Err(format!(
            "{field}[{index}] ref generation must be non-zero for internal objects"
        ));
    }
    Ok(())
}

fn contract_graph_snapshot_claimed_boundary(bytes: &[u8]) -> Result<Boundary, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let claimed = value
        .get("claimed_evidence_level")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing claimed_evidence_level".to_string())?;
    Boundary::parse(claimed).ok_or_else(|| format!("unknown claimed_evidence_level {claimed}"))
}

fn validate_extraction_trace(bytes: &[u8]) -> Result<(), String> {
    validate_json_lines(bytes, |value| {
        let authority = value.get("authority").and_then(serde_json::Value::as_str);
        let operation = value.get("operation").and_then(serde_json::Value::as_str);
        let event_id = value.get("event_id").and_then(serde_json::Value::as_u64);
        let event_epoch = value.get("event_epoch").and_then(serde_json::Value::as_u64);
        if authority.is_some_and(|value| !value.trim().is_empty())
            && operation.is_some_and(|value| !value.trim().is_empty())
            && event_id.is_some()
            && event_epoch.is_some()
        {
            Ok(())
        } else {
            Err(
                "substrate extraction trace entries require event_id, event_epoch, authority, and operation"
                    .to_string(),
            )
        }
    })
}

fn validate_device_trace(bytes: &[u8]) -> Result<(), String> {
    validate_json_lines(bytes, |value| {
        let has_device = value
            .get("device")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|device| !device.trim().is_empty())
            || value.get("device_id").is_some();
        let has_operation = value
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|operation| !operation.trim().is_empty());
        let event_id = value.get("event_id").and_then(serde_json::Value::as_u64);
        let event_epoch = value.get("event_epoch").and_then(serde_json::Value::as_u64);
        if has_device && has_operation && event_id.is_some() && event_epoch.is_some() {
            Ok(())
        } else {
            Err(
                "device trace entries require event_id, event_epoch, device/device_id, and operation"
                    .to_string(),
            )
        }
    })
}

fn validate_json_lines<F>(bytes: &[u8], validate_entry: F) -> Result<(), String>
where
    F: Fn(&serde_json::Value) -> Result<(), String>,
{
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let mut entries = 0usize;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| format!("line {} is not JSON: {}", index + 1, error))?;
        if !value.is_object() {
            return Err(format!("line {} is not a JSON object", index + 1));
        }
        validate_entry(&value).map_err(|error| format!("line {}: {}", index + 1, error))?;
        entries += 1;
    }
    if entries == 0 { Err("trace contains no entries".to_string()) } else { Ok(()) }
}

fn validate_non_empty_text(bytes: &[u8], label: &str) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    if text.trim().is_empty() { Err(format!("{label} is empty")) } else { Ok(()) }
}

fn validate_criterion_estimates(bytes: &[u8]) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let estimate = value
        .get("mean")
        .and_then(|mean| mean.get("point_estimate"))
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| "missing mean.point_estimate".to_string())?;
    if estimate.is_finite() && estimate > 0.0 {
        Ok(())
    } else {
        Err("mean.point_estimate must be finite and positive".to_string())
    }
}

fn validate_ltp_log(bytes: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(bytes);
    if parse_ltp_results(&text).is_empty() {
        Err("LTP log contains no parseable case results".to_string())
    } else {
        Ok(())
    }
}

fn finding(code: &str, detail: impl Into<String>) -> ValidationFinding {
    ValidationFinding { code: code.to_string(), detail: detail.into() }
}

#[cfg(test)]
pub(crate) fn write_file_with_sha256(
    path: impl AsRef<Path>,
    bytes: &[u8],
) -> std::io::Result<String> {
    fs::write(path, bytes)?;
    Ok(sha256_hex(bytes))
}
