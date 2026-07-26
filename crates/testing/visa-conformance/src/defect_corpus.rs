//! Driver for the Stage 1 injected-defect corpus.
//!
//! Each corpus entry is applied to a private copy of a baseline evidence tree,
//! resealed by the mutation library, and then handed to the ordinary Stage 1
//! evidence gate. The resulting report records what the verifier actually said,
//! so detection rates are measured rather than asserted.

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    stage1::{Stage1EvidenceBundle, gate_stage1_evidence_bundle_json_with_artifacts},
    stage1_mutations::{DefectCase, DefectClass, INTEGRITY_FAMILY_CODES, defect_corpus, temp_dir},
};

pub const DEFECT_CORPUS_REPORT_SCHEMA: &str = "visa-stage1-defect-corpus-report-v1";

/// The verifier's judgement on one injected defect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// The gate rejected the bundle with every predicted finding code.
    Detected,
    /// The gate accepted the bundle, as predicted.
    Undetected,
    /// The gate disagreed with the prediction.
    Mismatch,
    /// The mutation was not resealed completely, so the entry measures nothing.
    Void,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExpectedOutcome {
    pub ok: bool,
    pub codes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActualOutcome {
    pub ok: bool,
    pub finding_codes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DefectEntryReport {
    pub id: String,
    pub class: DefectClass,
    pub case_id: String,
    pub mutation: String,
    /// Whether the injected tree still carries a complete integrity seal.
    pub resealed: bool,
    /// Boundary entries are reported but excluded from the rate denominators.
    pub boundary: bool,
    pub expected: ExpectedOutcome,
    pub actual: ActualOutcome,
    pub verdict: Verdict,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct DetectionRate {
    pub n: usize,
    pub detected: usize,
    pub rate: f64,
}

impl DetectionRate {
    fn new(n: usize, detected: usize) -> Self {
        #[expect(clippy::cast_precision_loss, reason = "corpus sizes are far below 2^53")]
        let rate = if n == 0 { 0.0 } else { detected as f64 / n as f64 };
        Self { n, detected, rate }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DefectCorpusSummary {
    pub per_class: Vec<(DefectClass, DetectionRate)>,
    pub overall: DetectionRate,
    pub mismatches: usize,
    pub integrity_family_hits: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct DefectCorpusReport {
    pub schema: String,
    pub bundle: String,
    pub verifier: String,
    pub entries: Vec<DefectEntryReport>,
    pub summary: DefectCorpusSummary,
}

impl DefectCorpusReport {
    /// The corpus is usable as a measurement only when every entry resealed and
    /// every prediction held.
    pub fn is_calibrated(&self) -> bool {
        self.summary.mismatches == 0 && self.summary.integrity_family_hits == 0
    }
}

/// Runs the whole corpus against a baseline bundle and its artifact tree.
pub fn run_defect_corpus(
    bundle: &Stage1EvidenceBundle,
    artifact_root: &Path,
    verifier: &str,
) -> DefectCorpusReport {
    let entries = defect_corpus()
        .iter()
        .map(|case| run_defect_case(case, bundle, artifact_root))
        .collect::<Vec<_>>();
    let summary = summarize(&entries);
    DefectCorpusReport {
        schema: DEFECT_CORPUS_REPORT_SCHEMA.to_owned(),
        bundle: bundle.bundle_id.clone(),
        verifier: verifier.to_owned(),
        entries,
        summary,
    }
}

fn run_defect_case(
    case: &DefectCase,
    bundle: &Stage1EvidenceBundle,
    artifact_root: &Path,
) -> DefectEntryReport {
    let root = temp_dir(&format!("defect-{}", case.id));
    copy_tree(artifact_root, &root);
    let mut injected = bundle.clone();
    (case.apply)(&mut injected, &root);

    let gate = gate_stage1_evidence_bundle_json_with_artifacts(
        &serde_json::to_vec(&injected).unwrap(),
        &root,
    );
    fs::remove_dir_all(&root).unwrap();

    let mut finding_codes = gate.validation.as_ref().map_or_else(
        || gate.load_error.iter().map(|error| error.code.clone()).collect::<Vec<_>>(),
        |validation| {
            validation.findings.iter().map(|finding| finding.code.clone()).collect::<Vec<_>>()
        },
    );
    finding_codes.sort_unstable();
    finding_codes.dedup();

    let resealed =
        !finding_codes.iter().any(|code| INTEGRITY_FAMILY_CODES.contains(&code.as_str()));
    let expected_codes =
        case.expectation.codes.iter().map(|code| (*code).to_owned()).collect::<Vec<_>>();
    let verdict = if resealed { verdict_for(case, gate.ok, &finding_codes) } else { Verdict::Void };

    DefectEntryReport {
        id: case.id.to_owned(),
        class: case.class,
        case_id: case.case_id.to_owned(),
        mutation: case.mutation.to_owned(),
        resealed,
        boundary: case.boundary,
        expected: ExpectedOutcome { ok: case.expectation.ok, codes: expected_codes },
        actual: ActualOutcome { ok: gate.ok, finding_codes },
        verdict,
    }
}

fn verdict_for(case: &DefectCase, ok: bool, finding_codes: &[String]) -> Verdict {
    if case.expectation.ok {
        return if ok { Verdict::Undetected } else { Verdict::Mismatch };
    }
    let complete = !ok
        && case
            .expectation
            .codes
            .iter()
            .all(|code| finding_codes.iter().any(|found| found == code));
    if complete { Verdict::Detected } else { Verdict::Mismatch }
}

fn summarize(entries: &[DefectEntryReport]) -> DefectCorpusSummary {
    let scored = entries.iter().filter(|entry| !entry.boundary && entry.verdict != Verdict::Void);
    let per_class = DefectClass::ALL
        .iter()
        .map(|class| {
            let class_entries =
                scored.clone().filter(|entry| entry.class == *class).collect::<Vec<_>>();
            let detected =
                class_entries.iter().filter(|entry| entry.verdict == Verdict::Detected).count();
            (*class, DetectionRate::new(class_entries.len(), detected))
        })
        .collect::<Vec<_>>();
    let total = scored.clone().count();
    let detected = scored.filter(|entry| entry.verdict == Verdict::Detected).count();
    DefectCorpusSummary {
        per_class,
        overall: DetectionRate::new(total, detected),
        mismatches: entries.iter().filter(|entry| entry.verdict == Verdict::Mismatch).count(),
        integrity_family_hits: entries.iter().filter(|entry| !entry.resealed).count(),
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Writes the report to `path`, creating parent directories as needed.
pub fn write_defect_corpus_report(report: &DefectCorpusReport, path: &Path) {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, serde_json::to_vec_pretty(report).unwrap()).unwrap();
}

/// Convenience entry point for the `visa-defect-corpus` binary.
pub fn run_defect_corpus_from_paths(
    bundle_path: &Path,
    artifact_root: &Path,
) -> Result<DefectCorpusReport, String> {
    let bytes = fs::read(bundle_path)
        .map_err(|error| format!("cannot read {}: {error}", bundle_path.display()))?;
    let bundle = crate::stage1::parse_stage1_evidence_bundle_json(&bytes).map_err(|error| {
        format!("{} is not a Stage 1 bundle: {}", bundle_path.display(), error.code)
    })?;
    Ok(run_defect_corpus(
        &bundle,
        &PathBuf::from(artifact_root),
        "gate_stage1_evidence_bundle_json_with_artifacts",
    ))
}
