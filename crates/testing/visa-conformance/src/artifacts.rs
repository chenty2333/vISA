use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use contract_core::CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION;
use visa_profile::{AuthorityFamily, SubstrateProfile, capabilities_for_reported_profile};

use crate::{
    hash::sha256_hex,
    ltp::parse_ltp_results,
    types::{
        Boundary, ConformanceReport, EvidenceArtifact, EvidenceArtifactKind, TestResult,
        ValidationFinding, ValidationReport,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SnapshotRef<'a> {
    kind: &'a str,
    id: u64,
    generation: u64,
}

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

pub fn artifact_uri_is_bundle_relative(uri: &str) -> bool {
    !uri.trim().is_empty() && !uri.contains("://") && !artifact_path_escapes_root(uri)
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

    if !artifact_uri_is_bundle_relative(&artifact.uri) {
        findings.push(finding(
            "evidence-artifact-path-escape",
            format!(
                "{} artifact {} must be relative to the artifact root and must not escape it",
                result.spec_id, artifact.uri
            ),
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
    artifact_root.join(uri)
}

fn artifact_path_escapes_root(uri: &str) -> bool {
    let path = Path::new(uri);
    path.components().any(|component| {
        matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_))
    })
}

fn validate_artifact_content(kind: EvidenceArtifactKind, bytes: &[u8]) -> Result<(), String> {
    match kind {
        EvidenceArtifactKind::ContractGraphSnapshot => validate_contract_graph_snapshot(bytes),
        EvidenceArtifactKind::ProfileGateTrace => validate_profile_gate_trace(bytes),
        EvidenceArtifactKind::SubstrateExtractionTrace => validate_extraction_trace(bytes),
        EvidenceArtifactKind::SubstrateEventTrace => validate_substrate_event_trace(bytes),
        EvidenceArtifactKind::DeviceTrace => validate_device_trace(bytes),
        EvidenceArtifactKind::SerialLog => validate_non_empty_text(bytes, "serial log"),
        EvidenceArtifactKind::BenchmarkRawOutput => validate_criterion_estimates(bytes),
        EvidenceArtifactKind::LtpRawLog => validate_ltp_log(bytes),
        EvidenceArtifactKind::LinuxPersonalityTrace => validate_linux_personality_trace(bytes),
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
        EvidenceArtifactKind::ProfileGateTrace => {
            validate_profile_gate_trace_context(result, bytes)
        }
        EvidenceArtifactKind::SubstrateEventTrace => {
            validate_substrate_event_trace_context(result, bytes)
        }
        EvidenceArtifactKind::SubstrateExtractionTrace | EvidenceArtifactKind::DeviceTrace
            if result.observed_boundary == Boundary::RealTargetSubstrate =>
        {
            validate_real_target_trace_context(kind, bytes)
        }
        EvidenceArtifactKind::LinuxPersonalityTrace => {
            validate_linux_personality_trace_context(&result.spec_id, bytes)
        }
        _ => Ok(()),
    }
}

fn validate_contract_graph_snapshot(bytes: &[u8]) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let object = value.as_object().ok_or_else(|| "expected JSON object".to_string())?;
    validate_contract_graph_snapshot_fields(object)?;

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
    let claimed_boundary = Boundary::parse(claimed)
        .ok_or_else(|| format!("unknown claimed_evidence_level {claimed}"))?;

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
    if claimed_boundary.can_claim(Boundary::PortableArtifactExecution) {
        validate_portable_artifact_execution_snapshot(object)?;
    }

    Ok(())
}

fn validate_portable_artifact_execution_snapshot(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    for field in ["artifacts", "code_objects", "stores", "activations"] {
        validate_non_empty_snapshot_array(object, field, "portable artifact execution snapshot")?;
    }

    if snapshot_array(object, "hostcalls")?.is_empty()
        && snapshot_array(object, "traps")?.is_empty()
    {
        return Err("portable artifact execution snapshot requires at least one hostcall or trap"
            .to_string());
    }
    validate_portable_artifact_execution_edges(object)?;
    validate_portable_wait_edges(object)?;
    validate_portable_cleanup_edges(object)?;

    Ok(())
}

fn validate_portable_artifact_execution_edges(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    for artifact in snapshot_refs(object, "artifacts", "artifact")? {
        let code_objects = linked_targets(object, artifact, "code-object")?;
        for code_object in code_objects {
            let stores = linked_targets(object, code_object, "store")?;
            for store in stores {
                let activations = linked_targets(object, store, "activation")?;
                for activation in activations {
                    if has_linked_target(object, activation, "hostcall")?
                        || has_linked_target(object, activation, "trap")?
                    {
                        return Ok(());
                    }
                }
            }
        }
    }

    Err(
        "portable artifact execution snapshot requires explicit_edges linking artifact -> code-object -> store -> activation -> hostcall/trap"
            .to_string(),
    )
}

fn validate_portable_wait_edges(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    for wait in snapshot_refs(object, "waits", "wait-token")? {
        if !has_incoming_link(object, wait, "hostcall")?
            && !has_incoming_link(object, wait, "activation")?
        {
            return Err(
                "portable artifact execution snapshot requires wait-token explicit_edges from hostcall or activation"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn validate_portable_cleanup_edges(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    for cleanup in snapshot_refs(object, "cleanup_transactions", "cleanup-transaction")? {
        if !has_incoming_link(object, cleanup, "activation")?
            && !has_incoming_link(object, cleanup, "store")?
        {
            return Err(
                "portable artifact execution snapshot requires cleanup-transaction explicit_edges from activation or store"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn snapshot_refs<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
    kind: &'a str,
) -> Result<Vec<SnapshotRef<'a>>, String> {
    let mut refs = Vec::new();
    for value in snapshot_array(object, field)? {
        let entry = value.as_object().ok_or_else(|| format!("{field} entry must be an object"))?;
        let id = entry
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("{field} entry missing numeric id"))?;
        let generation = entry
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("{field} entry missing numeric generation"))?;
        refs.push(SnapshotRef { kind, id, generation });
    }
    Ok(refs)
}

fn linked_targets<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    from: SnapshotRef<'a>,
    target_kind: &str,
) -> Result<Vec<SnapshotRef<'a>>, String> {
    let mut targets = Vec::new();
    for edge in snapshot_array(object, "explicit_edges")? {
        let edge =
            edge.as_object().ok_or_else(|| "explicit_edges entry must be an object".to_string())?;
        if !edge_mode_can_carry_portable_path(edge) {
            continue;
        }
        let evidence_level = edge
            .get("evidence_level")
            .and_then(serde_json::Value::as_str)
            .and_then(Boundary::parse);
        if !evidence_level.is_some_and(|level| level.can_claim(Boundary::PortableArtifactExecution))
        {
            continue;
        }

        let edge_from = edge
            .get("from")
            .ok_or_else(|| "explicit_edges entry missing from".to_string())
            .and_then(|value| edge_ref(value, "explicit_edges.from"))?;
        if edge_from != from {
            continue;
        }

        let edge_to = edge
            .get("to")
            .ok_or_else(|| "explicit_edges entry missing to".to_string())
            .and_then(|value| edge_ref(value, "explicit_edges.to"))?;
        if edge_to.kind == target_kind && snapshot_ref_exists(object, edge_to)? {
            targets.push(edge_to);
        }
    }

    Ok(targets)
}

fn has_linked_target(
    object: &serde_json::Map<String, serde_json::Value>,
    from: SnapshotRef<'_>,
    target_kind: &str,
) -> Result<bool, String> {
    Ok(!linked_targets(object, from, target_kind)?.is_empty())
}

fn has_incoming_link(
    object: &serde_json::Map<String, serde_json::Value>,
    target: SnapshotRef<'_>,
    source_kind: &str,
) -> Result<bool, String> {
    for edge in snapshot_array(object, "explicit_edges")? {
        let edge =
            edge.as_object().ok_or_else(|| "explicit_edges entry must be an object".to_string())?;
        if !edge_mode_can_carry_portable_path(edge) {
            continue;
        }
        let evidence_level = edge
            .get("evidence_level")
            .and_then(serde_json::Value::as_str)
            .and_then(Boundary::parse);
        if !evidence_level.is_some_and(|level| level.can_claim(Boundary::PortableArtifactExecution))
        {
            continue;
        }
        let edge_from = edge
            .get("from")
            .ok_or_else(|| "explicit_edges entry missing from".to_string())
            .and_then(|value| edge_ref(value, "explicit_edges.from"))?;
        let edge_to = edge
            .get("to")
            .ok_or_else(|| "explicit_edges entry missing to".to_string())
            .and_then(|value| edge_ref(value, "explicit_edges.to"))?;
        if edge_from.kind == source_kind
            && snapshot_ref_exists(object, edge_from)?
            && edge_to == target
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn edge_mode_can_carry_portable_path(edge: &serde_json::Map<String, serde_json::Value>) -> bool {
    matches!(edge.get("mode").and_then(serde_json::Value::as_str), Some("live" | "historical"))
}

fn snapshot_ref_exists(
    object: &serde_json::Map<String, serde_json::Value>,
    reference: SnapshotRef<'_>,
) -> Result<bool, String> {
    let Some(field) = snapshot_field_for_ref_kind(reference.kind) else {
        return Ok(false);
    };
    Ok(snapshot_refs(object, field, reference.kind)?.iter().any(|candidate| {
        candidate.id == reference.id && candidate.generation == reference.generation
    }))
}

fn snapshot_field_for_ref_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "artifact" => Some("artifacts"),
        "code-object" => Some("code_objects"),
        "store" => Some("stores"),
        "activation" => Some("activations"),
        "hostcall" => Some("hostcalls"),
        "trap" => Some("traps"),
        "wait-token" => Some("waits"),
        "cleanup-transaction" => Some("cleanup_transactions"),
        _ => None,
    }
}

fn edge_ref<'a>(value: &'a serde_json::Value, field: &str) -> Result<SnapshotRef<'a>, String> {
    let object = value.as_object().ok_or_else(|| format!("{field} ref must be an object"))?;
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{field} ref missing kind"))?;
    let id = object
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{field} ref missing numeric id"))?;
    let generation = object
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{field} ref missing numeric generation"))?;
    Ok(SnapshotRef { kind, id, generation })
}

fn validate_non_empty_snapshot_array(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    label: &str,
) -> Result<(), String> {
    if snapshot_array(object, field)?.is_empty() {
        return Err(format!("{label} requires non-empty {field}"));
    }
    Ok(())
}

fn validate_contract_graph_snapshot_fields(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let allowed = contract_graph_snapshot_stable_fields();
    for field in object.keys() {
        if !allowed.contains(field.as_str()) {
            return Err(format!("unknown contract graph snapshot field {field}"));
        }
    }
    Ok(())
}

fn contract_graph_snapshot_stable_fields() -> BTreeSet<&'static str> {
    [
        "schema_version",
        "claimed_evidence_level",
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
    ]
    .into_iter()
    .collect()
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
        if !matches!(kind, "code-object" | "store" | "activation" | "trap" | "cleanup") {
            return Err(format!("unsupported tombstone kind {kind}"));
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

fn validate_profile_gate_trace(bytes: &[u8]) -> Result<(), String> {
    validate_json_lines(bytes, |value| {
        validate_u64_field(value, "event_id", "profile gate trace")?;
        validate_u64_field(value, "event_epoch", "profile gate trace")?;
        let event_kind = required_str_field(value, "event_kind", "profile gate trace")?;
        if !matches!(event_kind, "profile-gate-rejected" | "profile-gate-degraded") {
            return Err(format!("profile gate trace unknown event_kind {event_kind}"));
        }
        for field in [
            "package",
            "artifact",
            "required_profile",
            "reported_profile",
            "enforced_profile",
            "reason",
        ] {
            required_str_field(value, field, "profile gate trace")?;
        }
        let required_profile = required_str_field(value, "required_profile", "profile gate trace")?;
        if SubstrateProfile::parse(required_profile).is_none() {
            return Err(format!("profile gate trace unknown required_profile {required_profile}"));
        }
        let reported_profile = required_str_field(value, "reported_profile", "profile gate trace")?;
        if capabilities_for_reported_profile(reported_profile).is_none() {
            return Err(format!("profile gate trace unknown reported_profile {reported_profile}"));
        }
        let enforced_profile = required_str_field(value, "enforced_profile", "profile gate trace")?;
        if SubstrateProfile::parse(enforced_profile).is_none() {
            return Err(format!("profile gate trace unknown enforced_profile {enforced_profile}"));
        }
        for field in ["missing_required", "degraded_optional", "forbidden_present"] {
            validate_optional_string_array(value, field, "profile gate trace")?;
        }
        if event_kind == "profile-gate-rejected"
            && empty_or_missing_string_array(value, "missing_required")
            && empty_or_missing_string_array(value, "forbidden_present")
            && empty_or_missing_string_array(value, "degraded_optional")
        {
            return Err(
                "profile gate rejection trace requires at least one missing, forbidden, or degraded evidence entry"
                    .to_string(),
            );
        }
        if event_kind == "profile-gate-degraded"
            && empty_or_missing_string_array(value, "degraded_optional")
        {
            return Err(
                "profile gate degradation trace requires degraded_optional evidence".to_string()
            );
        }
        Ok(())
    })
}

fn validate_substrate_event_trace(bytes: &[u8]) -> Result<(), String> {
    validate_json_lines(bytes, |value| {
        validate_u64_field(value, "event_id", "substrate event trace")?;
        validate_u64_field(value, "event_epoch", "substrate event trace")?;
        let event_kind = required_str_field(value, "event_kind", "substrate event trace")?;
        if !matches!(
            event_kind,
            "unsupported" | "authority-extracted" | "capability-denied" | "panic"
        ) {
            return Err(format!("substrate event trace unknown event_kind {event_kind}"));
        }
        let authority_family =
            required_str_field(value, "authority_family", "substrate event trace")?;
        let Some(authority_family) = AuthorityFamily::parse(authority_family) else {
            return Err(format!(
                "substrate event trace unknown authority_family {authority_family}"
            ));
        };
        let authority = required_str_field(value, "authority", "substrate event trace")?;
        if let Some(expected_family) = AuthorityFamily::from_authority_trait(authority)
            && expected_family != authority_family
        {
            return Err(format!(
                "substrate event trace authority {authority} does not match authority_family {}",
                authority_family.as_str()
            ));
        }
        let operation = required_str_field(value, "operation", "substrate event trace")?;
        if !authority_family.operations().contains(&operation) {
            return Err(format!(
                "substrate event trace operation {operation} is not declared for authority_family {}",
                authority_family.as_str()
            ));
        }
        if matches!(event_kind, "unsupported" | "capability-denied") {
            let requester = value.get("requester").and_then(serde_json::Value::as_str);
            let artifact = value.get("artifact").and_then(serde_json::Value::as_u64);
            let store = value.get("store").and_then(serde_json::Value::as_u64);
            if requester.is_none_or(|requester| requester.trim().is_empty())
                && artifact.is_none()
                && store.is_none()
            {
                return Err(
                    "unsupported substrate event trace requires requester, artifact, or store attribution"
                        .to_string(),
                );
            }
        }
        if event_kind == "capability-denied" {
            let capability = value.get("capability").and_then(serde_json::Value::as_u64);
            let capability_generation =
                value.get("capability_generation").and_then(serde_json::Value::as_u64);
            if capability.is_some() != capability_generation.is_some() {
                return Err(
                    "capability denied substrate event trace capability and generation must appear together"
                        .to_string(),
                );
            }
        }
        Ok(())
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

fn validate_profile_gate_trace_context(result: &TestResult, bytes: &[u8]) -> Result<(), String> {
    let expected = profile_gate_expected_count(result);
    validate_trace_expected_count(bytes, expected, "profile gate trace", |value| {
        matches!(
            value.get("event_kind").and_then(serde_json::Value::as_str),
            Some("profile-gate-rejected" | "profile-gate-degraded")
        )
    })
}

fn profile_gate_expected_count(result: &TestResult) -> Option<u64> {
    if let Some(count) = positive_metric_count(result, "profile_gate_event_count") {
        return Some(count);
    }
    let rejections = positive_metric_count(result, "profile_gate_rejection_count").unwrap_or(0);
    let degradations = positive_metric_count(result, "profile_gate_degradation_count").unwrap_or(0);
    let total = rejections + degradations;
    (total > 0).then_some(total)
}

fn validate_substrate_event_trace_context(result: &TestResult, bytes: &[u8]) -> Result<(), String> {
    validate_trace_expected_count(
        bytes,
        positive_metric_count(result, "unsupported_substrate_event_count"),
        "unsupported substrate event trace",
        |value| value.get("event_kind").and_then(serde_json::Value::as_str) == Some("unsupported"),
    )?;
    validate_trace_expected_count(
        bytes,
        positive_metric_count(result, "denied_substrate_event_count")
            .or_else(|| positive_metric_count(result, "capability_denied_substrate_event_count")),
        "denied substrate event trace",
        |value| {
            value.get("event_kind").and_then(serde_json::Value::as_str) == Some("capability-denied")
        },
    )?;
    validate_trace_expected_count(
        bytes,
        positive_metric_count(result, "authority_extraction_event_count")
            .or_else(|| positive_metric_count(result, "substrate_authority_extraction_count")),
        "authority extraction substrate event trace",
        |value| {
            value.get("event_kind").and_then(serde_json::Value::as_str)
                == Some("authority-extracted")
        },
    )
}

fn validate_real_target_trace_context(
    kind: EvidenceArtifactKind,
    bytes: &[u8],
) -> Result<(), String> {
    let label = kind.as_str();
    validate_json_lines(bytes, |value| {
        let target_arch = value.get("target_arch").and_then(serde_json::Value::as_str);
        let target_board = value.get("target_board").and_then(serde_json::Value::as_str);
        if target_arch.is_some_and(|value| !value.trim().is_empty())
            && target_board.is_some_and(|value| !value.trim().is_empty())
        {
            Ok(())
        } else {
            Err(format!("{label} real-target entries require target_arch and target_board"))
        }
    })
}

fn validate_trace_expected_count<F>(
    bytes: &[u8],
    expected: Option<u64>,
    label: &str,
    count_entry: F,
) -> Result<(), String>
where
    F: Fn(&serde_json::Value) -> bool,
{
    let Some(expected) = expected else {
        return Ok(());
    };
    let observed = count_json_lines(bytes, count_entry)?;
    if observed >= expected {
        Ok(())
    } else {
        Err(format!("{label} has {observed} matching entries but result reports {expected}"))
    }
}

fn count_json_lines<F>(bytes: &[u8], count_entry: F) -> Result<u64, String>
where
    F: Fn(&serde_json::Value) -> bool,
{
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let mut entries = 0u64;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| format!("line {} is not JSON: {}", index + 1, error))?;
        if count_entry(&value) {
            entries += 1;
        }
    }
    Ok(entries)
}

fn positive_metric_count(result: &TestResult, name: &str) -> Option<u64> {
    let value = result.metrics.get(name).copied()?;
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    Some(value.ceil() as u64)
}

fn validate_linux_personality_trace_context(spec_id: &str, bytes: &[u8]) -> Result<(), String> {
    validate_json_lines(bytes, |value| {
        let trace_spec = value.get("spec_id").and_then(serde_json::Value::as_str);
        if trace_spec == Some(spec_id) {
            Ok(())
        } else {
            Err(format!(
                "linux personality trace spec_id {:?} does not match result {}",
                trace_spec, spec_id
            ))
        }
    })
}

fn required_str_field<'a>(
    value: &'a serde_json::Value,
    field: &str,
    label: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{label} requires non-empty {field}"))
}

fn validate_u64_field(value: &serde_json::Value, field: &str, label: &str) -> Result<(), String> {
    if value.get(field).and_then(serde_json::Value::as_u64).is_some() {
        Ok(())
    } else {
        Err(format!("{label} requires numeric {field}"))
    }
}

fn validate_optional_string_array(
    value: &serde_json::Value,
    field: &str,
    label: &str,
) -> Result<(), String> {
    let Some(array) = value.get(field) else {
        return Ok(());
    };
    let Some(array) = array.as_array() else {
        return Err(format!("{label} {field} must be an array"));
    };
    if array.iter().all(|entry| entry.as_str().is_some_and(|entry| !entry.trim().is_empty())) {
        Ok(())
    } else {
        Err(format!("{label} {field} entries must be non-empty strings"))
    }
}

fn empty_or_missing_string_array(value: &serde_json::Value, field: &str) -> bool {
    value.get(field).and_then(serde_json::Value::as_array).is_none_or(|array| array.is_empty())
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

fn validate_linux_personality_trace(bytes: &[u8]) -> Result<(), String> {
    validate_json_lines(bytes, |value| {
        let schema_version = value.get("schema_version").and_then(serde_json::Value::as_str);
        if schema_version != Some(crate::ltp::LTP_VISA_TRACE_SCHEMA_VERSION) {
            return Err(format!(
                "linux personality trace requires schema_version {}",
                crate::ltp::LTP_VISA_TRACE_SCHEMA_VERSION
            ));
        }
        for field in ["spec_id", "case_id", "test_binary", "runner", "raw_log_uri"] {
            if !value
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|field| !field.trim().is_empty())
            {
                return Err(format!("linux personality trace requires non-empty {field}"));
            }
        }
        if value.get("runner").and_then(serde_json::Value::as_str) != Some("visa-linux-personality")
        {
            return Err("linux personality trace runner must be visa-linux-personality".to_string());
        }
        for field in ["entered_visa_execution", "linux_personality_dispatch"] {
            if value.get(field).and_then(serde_json::Value::as_bool) != Some(true) {
                return Err(format!("linux personality trace requires {field}=true"));
            }
        }
        for field in ["syscalls_observed", "service_syscalls_observed"] {
            if value.get(field).and_then(serde_json::Value::as_u64).unwrap_or(0) == 0 {
                return Err(format!("linux personality trace requires positive {field}"));
            }
        }
        if value.get("exit_status").and_then(serde_json::Value::as_i64).is_none() {
            return Err("linux personality trace requires numeric exit_status".to_string());
        }
        Ok(())
    })
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
