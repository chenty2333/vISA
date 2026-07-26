use std::{env, fs, path::PathBuf};

use crate::{
    defect_corpus::{Verdict, run_defect_corpus, write_defect_corpus_report},
    stage1::gate_stage1_evidence_bundle_json_with_artifacts,
    stage1_mutations::temp_dir,
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
}
