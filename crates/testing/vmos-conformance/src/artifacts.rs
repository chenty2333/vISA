use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    hash::sha256_hex,
    ltp::parse_ltp_results,
    types::{
        ConformanceReport, EvidenceArtifact, EvidenceArtifactKind, ValidationFinding,
        ValidationReport,
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
            validate_artifact(&result.spec_id, artifact, artifact_root, &mut findings);
        }
    }
    ValidationReport::new(findings)
}

fn validate_artifact(
    spec_id: &str,
    artifact: &EvidenceArtifact,
    artifact_root: &Path,
    findings: &mut Vec<ValidationFinding>,
) {
    if artifact.uri.contains("://") {
        findings.push(finding(
            "unverifiable-evidence-artifact-uri",
            format!("{} artifact {} is not a local file URI", spec_id, artifact.uri),
        ));
        return;
    }

    let path = resolve_artifact_path(artifact_root, &artifact.uri);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            findings.push(finding(
                "missing-evidence-artifact-file",
                format!("{} artifact {} could not be read: {}", spec_id, path.display(), error),
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
                spec_id,
                path.display(),
                artifact.sha256,
                actual_sha256
            ),
        ));
    }

    if let Err(error) = validate_artifact_content(artifact.kind, &bytes) {
        findings.push(finding(
            "invalid-evidence-artifact-content",
            format!("{} artifact {} invalid: {}", spec_id, path.display(), error),
        ));
    }
}

fn resolve_artifact_path(artifact_root: &Path, uri: &str) -> PathBuf {
    let path = Path::new(uri);
    if path.is_absolute() { path.to_path_buf() } else { artifact_root.join(path) }
}

fn validate_artifact_content(kind: EvidenceArtifactKind, bytes: &[u8]) -> Result<(), String> {
    match kind {
        EvidenceArtifactKind::ContractGraphSnapshot => validate_json_object(bytes),
        EvidenceArtifactKind::SubstrateExtractionTrace => validate_extraction_trace(bytes),
        EvidenceArtifactKind::DeviceTrace => validate_device_trace(bytes),
        EvidenceArtifactKind::SerialLog => validate_non_empty_text(bytes, "serial log"),
        EvidenceArtifactKind::BenchmarkRawOutput => validate_criterion_estimates(bytes),
        EvidenceArtifactKind::LtpRawLog => validate_ltp_log(bytes),
    }
}

fn validate_json_object(bytes: &[u8]) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if value.is_object() { Ok(()) } else { Err("expected JSON object".to_string()) }
}

fn validate_extraction_trace(bytes: &[u8]) -> Result<(), String> {
    validate_json_lines(bytes, |value| {
        let authority = value.get("authority").and_then(serde_json::Value::as_str);
        let operation = value.get("operation").and_then(serde_json::Value::as_str);
        if authority.is_some_and(|value| !value.trim().is_empty())
            && operation.is_some_and(|value| !value.trim().is_empty())
        {
            Ok(())
        } else {
            Err("substrate extraction trace entries require authority and operation".to_string())
        }
    })
}

fn validate_device_trace(bytes: &[u8]) -> Result<(), String> {
    validate_json_lines(bytes, |value| {
        let has_device = value.get("device").is_some() || value.get("device_id").is_some();
        let has_operation = value.get("operation").is_some();
        if has_device && has_operation {
            Ok(())
        } else {
            Err("device trace entries require device/device_id and operation".to_string())
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
