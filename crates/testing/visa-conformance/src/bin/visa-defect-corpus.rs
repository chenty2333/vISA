//! Applies the Stage 1 injected-defect corpus to a real evidence bundle and
//! writes a detection-rate report. Built only with the `defect-corpus` feature.

use std::{env, path::PathBuf, process::ExitCode};

use visa_conformance::defect_corpus::{run_defect_corpus_from_paths, write_defect_corpus_report};

fn main() -> ExitCode {
    let values = env::args_os().skip(1).collect::<Vec<_>>();
    if values.len() != 3 {
        eprintln!("usage: visa-defect-corpus <bundle.json> <artifact-root> <out.json>");
        return ExitCode::from(64);
    }
    let report = match run_defect_corpus_from_paths(
        &PathBuf::from(&values[0]),
        &PathBuf::from(&values[1]),
    ) {
        Ok(report) => report,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    write_defect_corpus_report(&report, &PathBuf::from(&values[2]));
    if report.is_calibrated() {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "defect corpus is not calibrated: {} mismatches, {} incompletely resealed entries",
            report.summary.mismatches, report.summary.integrity_family_hits
        );
        ExitCode::from(3)
    }
}
