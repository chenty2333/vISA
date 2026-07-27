use std::{collections::BTreeSet, env, fs, path::PathBuf};

use crate::{
    defect_corpus::{Verdict, run_defect_corpus, write_defect_corpus_report},
    stage1::gate_stage1_evidence_bundle_json_with_artifacts,
    stage1_mutations::{MutationDisposition, temp_dir},
    stage1_tests::{complete_bundle, materialize_artifacts},
};

/// Measures the Stage 1 verifier against the injected-defect corpus.
///
/// Set `VISA_DEFECT_CORPUS_OUT` to retain the JSON report, and
/// `VISA_DEFECT_CORPUS_BASELINE_OUT` to retain the materialized baseline tree
/// so the `visa-defect-corpus` binary can be driven against the same fixture.
#[test]
fn stage1_verifier_detection_rate_matches_the_defect_corpus() {
    let retained = env::var_os("VISA_DEFECT_CORPUS_BASELINE_OUT").map(PathBuf::from);
    let root = retained.clone().unwrap_or_else(|| temp_dir("defect-corpus-baseline"));
    let mut bundle = complete_bundle();
    materialize_artifacts(&mut bundle, &root);
    let bundle_bytes = serde_json::to_vec(&bundle).unwrap();

    let baseline = gate_stage1_evidence_bundle_json_with_artifacts(&bundle_bytes, &root);
    assert!(
        baseline.ok,
        "baseline evidence must verify before defects are injected: {baseline:#?}"
    );

    let report =
        run_defect_corpus(&bundle, &root, "gate_stage1_evidence_bundle_json_with_artifacts");
    if let Some(retained) = &retained {
        fs::write(retained.join("stage1-evidence.json"), &bundle_bytes).unwrap();
    } else {
        fs::remove_dir_all(&root).unwrap();
    }

    if let Some(out) = env::var_os("VISA_DEFECT_CORPUS_OUT") {
        write_defect_corpus_report(&report, &PathBuf::from(out));
    }

    let voided =
        report.entries.iter().filter(|entry| entry.verdict == Verdict::Void).collect::<Vec<_>>();
    assert!(voided.is_empty(), "incompletely resealed corpus entries: {voided:#?}");

    let mismatched = report
        .entries
        .iter()
        .filter(|entry| entry.verdict == Verdict::Mismatch)
        .collect::<Vec<_>>();
    assert!(
        mismatched.is_empty(),
        "corpus predictions disagree with the verifier: {mismatched:#?}"
    );

    assert!(report.is_calibrated(), "{:#?}", report.summary);
    assert_eq!(report.summary.semantic_defects.n, 22);
    assert_eq!(report.summary.semantic_defects.detected, 22);
    assert_eq!(report.summary.semantic_defects.rate, Some(1.0));
    assert_eq!(report.summary.benign_equivalents.n, 3);
    assert_eq!(report.summary.benign_equivalents.equivalent, 3);
    assert_eq!(report.summary.benign_equivalents.rate, Some(1.0));
    assert_eq!(report.summary.boundary_cases.n, 1);
    assert_eq!(report.summary.boundary_cases.recorded, 1);

    let equivalents = report
        .entries
        .iter()
        .filter(|entry| entry.verdict == Verdict::Equivalent)
        .map(|entry| entry.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        equivalents,
        BTreeSet::from([
            "A3a-commit-event-duplicated",
            "A3b-resume-event-duplicated",
            "A3c-transcript-dump-round-trip-duplicated",
        ])
    );
    let boundaries = report
        .entries
        .iter()
        .filter(|entry| entry.verdict == Verdict::BoundaryRecorded)
        .map(|entry| entry.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(boundaries, ["A7d-resource-profile-digest-restated"]);
}

#[test]
fn defect_corpus_entry_identities_are_unique_and_cover_every_class() {
    let corpus = crate::stage1_mutations::defect_corpus();
    let mut ids = corpus.iter().map(|case| case.id).collect::<Vec<_>>();
    ids.sort_unstable();
    let unique = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), unique, "defect corpus entry identities must be unique");

    for class in crate::stage1_mutations::DefectClass::ALL {
        let variants = corpus.iter().filter(|case| case.class == *class).count();
        assert!((2..=4).contains(&variants), "{class:?} has {variants} variants");
    }

    let count = |disposition| corpus.iter().filter(|case| case.disposition == disposition).count();
    assert_eq!(count(MutationDisposition::SemanticDefect), 22);
    assert_eq!(count(MutationDisposition::BenignEquivalent), 3);
    assert_eq!(count(MutationDisposition::BoundaryCase), 1);
    for case in corpus {
        match case.disposition {
            MutationDisposition::SemanticDefect => {
                assert!(!case.expectation.ok, "{} must be rejected", case.id);
                assert!(!case.expectation.codes.is_empty(), "{} needs a semantic finding", case.id);
            }
            MutationDisposition::BenignEquivalent | MutationDisposition::BoundaryCase => {
                assert!(case.expectation.ok, "{} must remain verifier-accepted", case.id);
                assert!(case.expectation.codes.is_empty(), "{} must not predict findings", case.id);
            }
        }
    }
}
