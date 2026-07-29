//! Cost and retained-size characterization for the paper's Stage 3A evidence
//! path.
//!
//! The three timed arms consume the same accepted cross-runtime publication:
//!
//! * `publisher-digest-control` checks only equality of publisher-declared
//!   digests. It is a cost control, not a verifier or semantic result.
//! * `independent-raw-oracle` parses the verdict-free control/candidate
//!   observation-v2 bytes, derives all 12 cases, and compares route-neutral
//!   observable projections. The raw JSON is preloaded before timing.
//! * `production-outer-gate` invokes the production Stage 3A gate, including
//!   retained-file reopening, exact-set, digest, identity, child-bundle,
//!   independent-oracle, and cross-cell checks.
//!
//! This decomposition makes the extra guarantee in each arm explicit instead
//! of comparing against a system that silently performs less semantic work.

use std::{
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    time::Instant,
};

use visa_conformance::{
    STAGE3A_CANDIDATE_OBSERVATION_FILE, STAGE3A_CONTROL_OBSERVATION_FILE,
    STAGE3A_CROSS_RUNTIME_EVIDENCE_FILE, Stage3ArtifactReference, Stage3EvidenceBundle,
    Stage3Profile, Stage3aCrossRuntimeEvidenceBundle,
    gate_stage3_evidence_bundle_json_with_artifacts,
    gate_stage3a_cross_runtime_evidence_bundle_json_with_artifacts,
};
use visa_regular_file_oracle::{
    EQUIVALENCE_REPORT_SCHEMA_VERSION, EquivalenceReport, evaluate_equivalence,
};

use crate::{
    EvalOptions,
    output::{BUILD_GIT_COMMIT, Sample, SampleSink},
};

pub const MEASURE: &str = "evidence-overhead";
const DIGEST_CONTROL_ARM: &str = "publisher-digest-control";
const DIGEST_CONTROL_PHASE: &str = "declared-digest-consistency";
const ORACLE_CORE_ARM: &str = "independent-raw-oracle";
const ORACLE_CORE_PHASE: &str = "observation-projection";
const OUTER_GATE_ARM: &str = "production-outer-gate";
const OUTER_GATE_PHASE: &str = "full-stage3a-cross-runtime-gate";
const VALID_CHILD_COUNTS: [usize; 4] = [1, 4, 8, 12];

pub fn preflight(options: &EvalOptions) -> Result<serde_json::Value, String> {
    let root = evidence_root(options)?;
    let bundle_path = root.join(STAGE3A_CROSS_RUNTIME_EVIDENCE_FILE);
    let bundle_bytes = fs::read(&bundle_path)
        .map_err(|error| format!("cannot read {}: {error}", bundle_path.display()))?;
    let bundle: Stage3aCrossRuntimeEvidenceBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|error| format!("cannot decode {}: {error}", bundle_path.display()))?;
    validate_paper_grade_provenance(options.paper_grade, &bundle.git_sha, bundle.git_dirty)?;
    full_outer_gate(&root, &bundle_bytes)?;
    let children = load_children(&root, &bundle)?;
    let cases_per_cell = cases_per_cell(&children)?;
    if children.len() != *VALID_CHILD_COUNTS.last().expect("nonempty scaling catalog") {
        return Err(format!(
            "evidence input contains {} valid child runs, expected {}",
            children.len(),
            VALID_CHILD_COUNTS.last().expect("nonempty scaling catalog")
        ));
    }
    let filesystem = crate::output::filesystem_for(&root);
    if options.paper_grade
        && filesystem.get("memory_backed").and_then(serde_json::Value::as_bool) == Some(true)
    {
        return Err("--paper-grade refuses a memory-backed evidence input filesystem".to_owned());
    }
    Ok(serde_json::json!({
        "schema_version": bundle.schema_version,
        "bundle_id": bundle.bundle_id,
        "claim_id": bundle.claim_id,
        "git_sha": bundle.git_sha,
        "git_dirty": bundle.git_dirty,
        "bundle_sha256": sha256_hex(&bundle_bytes),
        "matrix_sha256": bundle.matrix_sha256,
        "normalized_semantics_sha256": bundle.normalized_semantics_sha256,
        "cell_runs": children.len(),
        "cases_per_cell": cases_per_cell,
        "cases_per_cell_source": "accepted independent raw-observation oracle reports",
        "measurement_contract": {
            "control": {
                "arm": DIGEST_CONTROL_ARM,
                "phase": DIGEST_CONTROL_PHASE,
                "semantic_verifier": false,
                "input": "publisher-declared digest strings",
            },
            "core": {
                "arm": ORACLE_CORE_ARM,
                "phase": ORACLE_CORE_PHASE,
                "semantic_verifier": true,
                "input": "preloaded verdict-free regular-file observation-v2 control/candidate JSON",
                "oracle_report_schema": EQUIVALENCE_REPORT_SCHEMA_VERSION,
            },
            "full": {
                "arm": OUTER_GATE_ARM,
                "phase": OUTER_GATE_PHASE,
                "semantic_verifier": true,
                "input": "retained Stage3A cross-runtime publication tree",
            },
        },
        "filesystem": filesystem,
    }))
}

fn validate_paper_grade_provenance(
    paper_grade: bool,
    evidence_git_sha: &str,
    evidence_git_dirty: bool,
) -> Result<(), String> {
    if !paper_grade {
        return Ok(());
    }
    if evidence_git_dirty {
        return Err("--paper-grade requires evidence generated from a clean worktree".to_owned());
    }
    if evidence_git_sha != BUILD_GIT_COMMIT {
        return Err(format!(
            "--paper-grade evidence revision {evidence_git_sha} differs from binary build {BUILD_GIT_COMMIT}"
        ));
    }
    Ok(())
}

pub fn run(options: &EvalOptions, sink: &mut SampleSink) -> Result<(), String> {
    let root = evidence_root(options)?;
    let (bundle_bytes, bundle, children) = load_publication(&root)?;
    record_sizes(sink, &root, &bundle_bytes, &bundle, &children)?;

    for run in 0..options.runs {
        // Reload and reparse the retained publication for every independent
        // run. The OS page cache remains warm by design and is recorded.
        let (bundle_bytes, bundle, children) = load_publication(&root)?;
        let cases_per_cell = cases_per_cell(&children)?;
        for _ in 0..options.warmup {
            black_box(declared_digest_control(&bundle)?);
            black_box(evaluate_oracle_projections(&children)?);
            black_box(full_outer_gate(&root, &bundle_bytes)?);
            for count in VALID_CHILD_COUNTS {
                black_box(gate_child_prefix(&children, count)?);
            }
        }

        for iter in 0..options.iters {
            for arm in core_arm_order(run, iter) {
                run_core_arm(
                    arm,
                    &root,
                    &bundle_bytes,
                    &bundle,
                    &children,
                    cases_per_cell,
                    run,
                    iter,
                    sink,
                )?;
            }
            let mut counts = VALID_CHILD_COUNTS;
            if !(u64::from(run) + iter).is_multiple_of(2) {
                counts.reverse();
            }
            for count in counts {
                let started = Instant::now();
                black_box(gate_child_prefix(&children, count)?);
                sink.record(
                    timed_sample(
                        "valid-child-gates",
                        "production-stage3-gate-prefix",
                        run,
                        iter,
                        count,
                        cases_per_cell,
                        "runs the production Stage 3 gate over a prefix of complete valid child publications",
                    )
                    .nanos(elapsed_ns(started, "valid-child-gates")?),
                )?;
            }
        }
    }
    Ok(())
}

fn load_publication(
    root: &Path,
) -> Result<(Vec<u8>, Stage3aCrossRuntimeEvidenceBundle, Vec<ChildBundle>), String> {
    let bundle_path = root.join(STAGE3A_CROSS_RUNTIME_EVIDENCE_FILE);
    let bundle_bytes = fs::read(&bundle_path)
        .map_err(|error| format!("cannot read {}: {error}", bundle_path.display()))?;
    let bundle: Stage3aCrossRuntimeEvidenceBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|error| format!("cannot decode {}: {error}", bundle_path.display()))?;
    full_outer_gate(root, &bundle_bytes)?;
    let children = load_children(root, &bundle)?;
    Ok((bundle_bytes, bundle, children))
}

#[derive(Clone, Copy)]
enum CoreArm {
    DigestControl,
    RawOracle,
    OuterGate,
}

fn core_arm_order(run: u32, iter: u64) -> [CoreArm; 3] {
    match (u64::from(run) + iter) % 3 {
        0 => [CoreArm::DigestControl, CoreArm::RawOracle, CoreArm::OuterGate],
        1 => [CoreArm::OuterGate, CoreArm::DigestControl, CoreArm::RawOracle],
        _ => [CoreArm::RawOracle, CoreArm::OuterGate, CoreArm::DigestControl],
    }
}

#[allow(clippy::too_many_arguments)]
fn run_core_arm(
    arm: CoreArm,
    root: &Path,
    bundle_bytes: &[u8],
    bundle: &Stage3aCrossRuntimeEvidenceBundle,
    children: &[ChildBundle],
    cases_per_cell: usize,
    run: u32,
    iter: u64,
    sink: &mut SampleSink,
) -> Result<(), String> {
    let (name, phase, guarantee, started) = match arm {
        CoreArm::DigestControl => {
            let started = Instant::now();
            black_box(declared_digest_control(bundle)?);
            (
                DIGEST_CONTROL_ARM,
                DIGEST_CONTROL_PHASE,
                "cost control checks only publisher-declared digest equality; not a verifier or semantic result",
                started,
            )
        }
        CoreArm::RawOracle => {
            let started = Instant::now();
            black_box(evaluate_oracle_projections(children)?);
            (
                ORACLE_CORE_ARM,
                ORACLE_CORE_PHASE,
                "independently parses observation-v2 bytes, derives 12-case semantics, and compares route-neutral projections",
                started,
            )
        }
        CoreArm::OuterGate => {
            let started = Instant::now();
            black_box(full_outer_gate(root, bundle_bytes)?);
            (
                OUTER_GATE_ARM,
                OUTER_GATE_PHASE,
                "production Stage3A exact-set, retained-digest, child, identity, independent-oracle, and cross-cell gate",
                started,
            )
        }
    };
    sink.record(
        timed_sample(name, phase, run, iter, bundle.cells.len(), cases_per_cell, guarantee)
            .nanos(elapsed_ns(started, name)?),
    )
}

fn evidence_root(options: &EvalOptions) -> Result<PathBuf, String> {
    let root = options
        .evidence_root
        .as_deref()
        .ok_or("evidence-overhead requires --evidence-root")?
        .canonicalize()
        .map_err(|error| format!("cannot resolve evidence root: {error}"))?;
    if !root.is_dir() {
        return Err(format!("evidence root is not a directory: {}", root.display()));
    }
    Ok(root)
}

fn timed_sample(
    arm: &str,
    phase: &str,
    run: u32,
    iter: u64,
    cell_runs: usize,
    cases_per_cell: usize,
    guarantee: &str,
) -> Sample {
    Sample::new(MEASURE, arm, phase)
        .config("cell_runs", cell_runs as u64)
        .config("cases_per_cell", cases_per_cell as u64)
        .config("guarantee", guarantee)
        .config(
            "cache_state",
            if matches!(arm, OUTER_GATE_ARM | "valid-child-gates") {
                "warm OS page cache; verifier reopens every retained file"
            } else if arm == ORACLE_CORE_ARM {
                "in-memory raw control/candidate observation-v2 JSON; no retained-file reopen in timed region"
            } else {
                "in-memory publisher-declared digest strings"
            },
        )
        .at(run, iter)
}

fn elapsed_ns(started: Instant, label: &str) -> Result<u64, String> {
    u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| format!("{label} duration exceeded u64 nanoseconds"))
}

fn declared_digest_control(bundle: &Stage3aCrossRuntimeEvidenceBundle) -> Result<&str, String> {
    let expected_cells = usize::try_from(bundle.required_runs_per_cell)
        .map_err(|_| "required run count does not fit usize")?
        .checked_mul(4)
        .ok_or("required cell count overflow")?;
    if bundle.cells.len() != expected_cells {
        return Err(format!(
            "publisher-declared digest control contains {} cell runs, expected {expected_cells}",
            bundle.cells.len()
        ));
    }
    if bundle
        .cells
        .iter()
        .any(|cell| cell.normalized_semantics_sha256 != bundle.normalized_semantics_sha256)
    {
        return Err("publisher-declared digests disagree across cell runs".to_owned());
    }
    Ok(&bundle.normalized_semantics_sha256)
}

struct ChildBundle {
    path: PathBuf,
    root: PathBuf,
    bytes: Vec<u8>,
    control_observation: Vec<u8>,
    candidate_observation: Vec<u8>,
}

fn load_children(
    root: &Path,
    bundle: &Stage3aCrossRuntimeEvidenceBundle,
) -> Result<Vec<ChildBundle>, String> {
    bundle
        .cells
        .iter()
        .map(|cell| {
            let path = resolve_reference(root, &cell.relocated_bundle)?;
            let bytes = fs::read(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            let child = serde_json::from_slice(&bytes)
                .map_err(|error| format!("cannot decode {}: {error}", path.display()))?;
            let child_root = path
                .parent()
                .ok_or_else(|| format!("child bundle has no artifact root: {}", path.display()))?
                .to_path_buf();
            let control_observation =
                read_child_observation(&child_root, &child, STAGE3A_CONTROL_OBSERVATION_FILE)?;
            let candidate_observation =
                read_child_observation(&child_root, &child, STAGE3A_CANDIDATE_OBSERVATION_FILE)?;
            Ok(ChildBundle {
                path,
                root: child_root,
                bytes,
                control_observation,
                candidate_observation,
            })
        })
        .collect()
}

fn read_child_observation(
    child_root: &Path,
    child: &Stage3EvidenceBundle,
    uri: &str,
) -> Result<Vec<u8>, String> {
    let mut references = child.raw_observations.iter().filter(|reference| reference.uri == uri);
    let reference = references
        .next()
        .ok_or_else(|| format!("child bundle is missing raw observation {uri}"))?;
    if references.next().is_some() {
        return Err(format!("child bundle repeats raw observation {uri}"));
    }
    let path = resolve_reference(child_root, reference)?;
    fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn cases_per_cell(children: &[ChildBundle]) -> Result<usize, String> {
    let mut observed = Vec::with_capacity(children.len());
    for child in children {
        observed.push(accepted_oracle_report(child)?.cases.len());
    }
    let expected = observed.first().copied().ok_or("no child bundles available".to_owned())?;
    if expected == 0 || observed.iter().any(|count| *count != expected) {
        return Err(
            "independent oracle reports do not have one common nonzero case count".to_owned()
        );
    }
    Ok(expected)
}

fn gate_child_prefix(children: &[ChildBundle], count: usize) -> Result<(), String> {
    if count == 0 || count > children.len() {
        return Err(format!("invalid child-gate prefix {count}"));
    }
    for child in children.iter().take(count) {
        let gate = gate_stage3_evidence_bundle_json_with_artifacts(
            Stage3Profile::RegularFile,
            &child.bytes,
            &child.root,
        );
        if !gate.ok {
            return Err(format!(
                "production child gate rejected {}: {gate:?}",
                child.path.display()
            ));
        }
    }
    Ok(())
}

fn resolve_reference(root: &Path, reference: &Stage3ArtifactReference) -> Result<PathBuf, String> {
    let relative = Path::new(&reference.uri);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!("unsafe artifact URI {}", reference.uri));
    }
    Ok(root.join(relative))
}

fn evaluate_oracle_projections(children: &[ChildBundle]) -> Result<String, String> {
    let mut common: Option<String> = None;
    for child in children {
        let encoded = accepted_oracle_projection(child)?;
        let digest = sha256_hex(&encoded);
        match &common {
            Some(expected) if expected != &digest => {
                return Err(format!(
                    "{} diverged during independent raw-observation projection",
                    child.path.display()
                ));
            }
            None => common = Some(digest),
            _ => {}
        }
    }
    common.ok_or("no child bundles available for independent raw-observation oracle".to_owned())
}

fn accepted_oracle_projection(child: &ChildBundle) -> Result<Vec<u8>, String> {
    let report = accepted_oracle_report(child)?;
    encode_route_neutral_projection(&report)
}

fn accepted_oracle_report(child: &ChildBundle) -> Result<EquivalenceReport, String> {
    let report = evaluate_equivalence(&child.control_observation, &child.candidate_observation);
    if !report.accepted {
        return Err(format!(
            "independent raw-observation oracle rejected {}: {:?}",
            child.path.display(),
            report.findings
        ));
    }
    Ok(report)
}

fn encode_route_neutral_projection(report: &EquivalenceReport) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&report.cases)
        .map_err(|error| format!("cannot encode independent oracle projections: {error}"))
}

fn full_outer_gate(root: &Path, bundle_bytes: &[u8]) -> Result<(), String> {
    let gate = gate_stage3a_cross_runtime_evidence_bundle_json_with_artifacts(bundle_bytes, root);
    if gate.ok {
        Ok(())
    } else {
        Err(format!("production outer gate rejected accepted evidence: {gate:?}"))
    }
}

fn record_sizes(
    sink: &mut SampleSink,
    root: &Path,
    bundle_bytes: &[u8],
    outer: &Stage3aCrossRuntimeEvidenceBundle,
    children: &[ChildBundle],
) -> Result<(), String> {
    let cases_per_cell = cases_per_cell(children)?;
    sink.record(
        Sample::new(MEASURE, "retained-evidence", "accepted-matrix-tree")
            .config("cell_runs", outer.cells.len() as u64)
            .config("cases_per_cell", cases_per_cell as u64)
            .config("valid_claim_bundle", true)
            .bytes(directory_size(root)?),
    )?;
    sink.record(
        Sample::new(MEASURE, "retained-evidence", "outer-bundle-json")
            .config("cell_runs", outer.cells.len() as u64)
            .config("cases_per_cell", cases_per_cell as u64)
            .config("valid_claim_bundle", true)
            .bytes(bundle_bytes.len() as u64),
    )?;

    let child_sizes =
        children.iter().map(|child| directory_size(&child.root)).collect::<Result<Vec<_>, _>>()?;
    for cell_runs in VALID_CHILD_COUNTS {
        let bytes = child_sizes.iter().take(cell_runs).try_fold(0_u64, |total, size| {
            total.checked_add(*size).ok_or("valid child size overflow".to_owned())
        })?;
        sink.record(
            Sample::new(MEASURE, "retained-evidence", "complete-child-prefix")
                .config("cell_runs", cell_runs as u64)
                .config("cases_per_cell", cases_per_cell as u64)
                .config("valid_child_bundles", true)
                .config(
                    "scope_note",
                    "sum of complete valid child publications; excludes outer matrix lineage",
                )
                .bytes(bytes),
        )?;
    }

    let oracle_projection_bytes = children.iter().try_fold(0_u64, |total, child| {
        let len = accepted_oracle_projection(child)?.len() as u64;
        total.checked_add(len).ok_or("oracle projection size overflow".to_owned())
    })?;
    sink.record(
        Sample::new(MEASURE, "retained-evidence", "oracle-projections-total")
            .config("cell_runs", outer.cells.len() as u64)
            .config("cases_per_cell", cases_per_cell as u64)
            .config("valid_claim_bundle", false)
            .config(
                "scope_note",
                "serialized route-neutral CaseEquivalence projections; excludes full oracle reports",
            )
            .bytes(oracle_projection_bytes),
    )?;
    Ok(())
}

fn directory_size(root: &Path) -> Result<u64, String> {
    let mut total = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| {
                format!("cannot enumerate entry in {}: {error}", directory.display())
            })?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
            if kind.is_symlink() {
                return Err(format!("evidence tree contains symlink {}", entry.path().display()));
            }
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                total = total
                    .checked_add(
                        entry
                            .metadata()
                            .map_err(|error| {
                                format!("cannot inspect {}: {error}", entry.path().display())
                            })?
                            .len(),
                    )
                    .ok_or("evidence tree size overflow")?;
            } else {
                return Err(format!(
                    "evidence tree contains non-regular entry {}",
                    entry.path().display()
                ));
            }
        }
    }
    Ok(total)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_references_are_rejected() {
        let reference = Stage3ArtifactReference {
            uri: "../escape.json".to_owned(),
            sha256: "0".repeat(64),
            size: 1,
        };
        assert!(resolve_reference(Path::new("/tmp/root"), &reference).is_err());
    }

    #[test]
    fn directory_size_counts_nested_regular_files() {
        let root = std::env::temp_dir().join(format!(
            "visa-eval-evidence-size-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        fs::create_dir_all(root.join("nested")).expect("create scratch tree");
        fs::write(root.join("a"), b"123").expect("write first file");
        fs::write(root.join("nested/b"), b"4567").expect("write second file");
        assert_eq!(directory_size(&root).expect("measure tree"), 7);
        fs::remove_dir_all(root).expect("remove scratch tree");
    }

    #[test]
    fn paper_grade_rejects_evidence_from_another_revision() {
        let other =
            if BUILD_GIT_COMMIT == "0".repeat(40) { "1".repeat(40) } else { "0".repeat(40) };
        let error = validate_paper_grade_provenance(true, &other, false)
            .expect_err("paper evidence must match the benchmark binary revision");
        assert!(error.contains("differs from binary build"));
    }

    #[test]
    fn paper_grade_rejects_dirty_evidence_explicitly() {
        let error = validate_paper_grade_provenance(true, BUILD_GIT_COMMIT, true)
            .expect_err("paper evidence must come from a clean worktree");
        assert!(error.contains("clean worktree"));
    }

    #[test]
    fn timed_labels_state_the_real_verification_boundary() {
        let control =
            timed_sample(DIGEST_CONTROL_ARM, DIGEST_CONTROL_PHASE, 0, 0, 12, 12, "control");
        assert_eq!(
            control.config.get("cache_state"),
            Some(&serde_json::json!("in-memory publisher-declared digest strings"))
        );

        let oracle = timed_sample(ORACLE_CORE_ARM, ORACLE_CORE_PHASE, 0, 0, 12, 12, "oracle");
        assert_eq!(
            oracle.config.get("cache_state"),
            Some(&serde_json::json!(
                "in-memory raw control/candidate observation-v2 JSON; no retained-file reopen in timed region"
            ))
        );

        let outer = timed_sample(OUTER_GATE_ARM, OUTER_GATE_PHASE, 0, 0, 12, 12, "outer");
        assert_eq!(
            outer.config.get("cache_state"),
            Some(&serde_json::json!("warm OS page cache; verifier reopens every retained file"))
        );
    }
}
