//! Cost and retained-size characterization for the paper's Stage 3A evidence
//! path.
//!
//! The three timed arms consume the same accepted cross-runtime publication:
//!
//! * `publisher-summary-only` trusts the producer's per-cell normalized
//!   digests and checks only that they agree. It is a cost control, not an
//!   equivalent verifier.
//! * `producer-normalization` regenerates the typed normalized projection from
//!   already decoded child bundle records, but does not validate referenced
//!   artifacts.
//! * `outer-recompute` invokes the production outer gate, including exact-set,
//!   identity, artifact digest, child-bundle, and cross-cell checks.
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
    STAGE3A_CROSS_RUNTIME_EVIDENCE_FILE, Stage3ArtifactReference, Stage3EvidenceBundle,
    Stage3Profile, Stage3aCrossRuntimeEvidenceBundle,
    gate_stage3_evidence_bundle_json_with_artifacts,
    gate_stage3a_cross_runtime_evidence_bundle_json_with_artifacts, normalize_stage3a_semantics,
};

use crate::{
    EvalOptions,
    output::{BUILD_GIT_COMMIT, Sample, SampleSink},
};

pub const MEASURE: &str = "evidence-overhead";
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
            black_box(summary_only(&bundle)?);
            black_box(recompute_normalization(&children)?);
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
    Summary,
    Normalization,
    Outer,
}

fn core_arm_order(run: u32, iter: u64) -> [CoreArm; 3] {
    match (u64::from(run) + iter) % 3 {
        0 => [CoreArm::Summary, CoreArm::Normalization, CoreArm::Outer],
        1 => [CoreArm::Outer, CoreArm::Summary, CoreArm::Normalization],
        _ => [CoreArm::Normalization, CoreArm::Outer, CoreArm::Summary],
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
        CoreArm::Summary => {
            let started = Instant::now();
            black_box(summary_only(bundle)?);
            (
                "publisher-summary-only",
                "digest-consistency",
                "trusts producer summaries; no artifact or semantic recomputation",
                started,
            )
        }
        CoreArm::Normalization => {
            let started = Instant::now();
            black_box(recompute_normalization(children)?);
            (
                "producer-normalization",
                "typed-projection",
                "recomputes typed projections from child bundle records; does not read case artifacts",
                started,
            )
        }
        CoreArm::Outer => {
            let started = Instant::now();
            black_box(full_outer_gate(root, bundle_bytes)?);
            (
                "outer-recompute",
                "full-production-gate",
                "production exact-set, digest, child-bundle, identity, and cross-cell verification",
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
            if matches!(arm, "outer-recompute" | "valid-child-gates") {
                "warm OS page cache; verifier reopens every retained file"
            } else {
                "in-memory decoded bundle records"
            },
        )
        .at(run, iter)
}

fn elapsed_ns(started: Instant, label: &str) -> Result<u64, String> {
    u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| format!("{label} duration exceeded u64 nanoseconds"))
}

fn summary_only(bundle: &Stage3aCrossRuntimeEvidenceBundle) -> Result<&str, String> {
    let expected_cells = usize::try_from(bundle.required_runs_per_cell)
        .map_err(|_| "required run count does not fit usize")?
        .checked_mul(4)
        .ok_or("required cell count overflow")?;
    if bundle.cells.len() != expected_cells {
        return Err(format!(
            "publisher summary contains {} cell runs, expected {expected_cells}",
            bundle.cells.len()
        ));
    }
    if bundle
        .cells
        .iter()
        .any(|cell| cell.normalized_semantics_sha256 != bundle.normalized_semantics_sha256)
    {
        return Err("publisher summaries disagree across cell runs".to_owned());
    }
    Ok(&bundle.normalized_semantics_sha256)
}

struct ChildBundle {
    path: PathBuf,
    root: PathBuf,
    bytes: Vec<u8>,
    bundle: Stage3EvidenceBundle,
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
            Ok(ChildBundle { path, root: child_root, bytes, bundle: child })
        })
        .collect()
}

fn cases_per_cell(children: &[ChildBundle]) -> Result<usize, String> {
    let expected = children
        .first()
        .map(|child| child.bundle.cases.len())
        .ok_or("no child bundles available".to_owned())?;
    if expected == 0 || children.iter().any(|child| child.bundle.cases.len() != expected) {
        return Err("child bundles do not have one common nonzero case count".to_owned());
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

fn recompute_normalization(children: &[ChildBundle]) -> Result<String, String> {
    let mut common: Option<String> = None;
    for child in children {
        let normalized = normalize_stage3a_semantics(&child.bundle)?;
        let encoded = serde_json::to_vec(&normalized)
            .map_err(|error| format!("cannot encode normalized projection: {error}"))?;
        let digest = sha256_hex(&encoded);
        match &common {
            Some(expected) if expected != &digest => {
                return Err(format!(
                    "{} diverged during producer normalization",
                    child.path.display()
                ));
            }
            None => common = Some(digest),
            _ => {}
        }
    }
    common.ok_or("no child bundles available for producer normalization".to_owned())
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

    let normalized_bytes = children.iter().try_fold(0_u64, |total, child| {
        let normalized = normalize_stage3a_semantics(&child.bundle)?;
        let len = serde_json::to_vec(&normalized)
            .map_err(|error| format!("cannot encode normalized projection: {error}"))?
            .len() as u64;
        total.checked_add(len).ok_or("normalized projection size overflow".to_owned())
    })?;
    sink.record(
        Sample::new(MEASURE, "retained-evidence", "normalized-projections-total")
            .config("cell_runs", outer.cells.len() as u64)
            .config("cases_per_cell", cases_per_cell as u64)
            .config("valid_claim_bundle", false)
            .bytes(normalized_bytes),
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
}
