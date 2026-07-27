use std::{env, fs, path::PathBuf, process::ExitCode};

use visa_conformance::{validate_evidence_matrix_json, validate_evidence_matrix_run_json};

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let program = PathBuf::from(arguments.next().unwrap_or_default());
    let Some(matrix_path) = arguments.next().map(PathBuf::from) else {
        usage(&program);
        return ExitCode::from(64);
    };
    let run_path = arguments.next().map(PathBuf::from);
    if arguments.next().is_some() {
        usage(&program);
        return ExitCode::from(64);
    }
    let matrix_bytes = match fs::read(&matrix_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {}: {error}", matrix_path.display());
            return ExitCode::from(2);
        }
    };
    if let Some(run_path) = run_path {
        let run_bytes = match fs::read(&run_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("cannot read {}: {error}", run_path.display());
                return ExitCode::from(2);
            }
        };
        let report = validate_evidence_matrix_run_json(&matrix_bytes, &run_bytes);
        if report.ok {
            println!(
                "evidence matrix run closed: {} claims, sha256={}, git={}",
                report.claim_closures.len(),
                report.matrix_sha256.as_deref().unwrap_or("unavailable"),
                report.git_sha.as_deref().unwrap_or("unavailable")
            );
            return ExitCode::SUCCESS;
        }
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&report)
                .unwrap_or_else(|error| format!("cannot render validation report: {error}"))
        );
        return ExitCode::FAILURE;
    }

    let report = validate_evidence_matrix_json(&matrix_bytes);
    if report.ok {
        println!(
            "evidence matrix valid: {} cells, {} claims, sha256={}",
            report.cell_count,
            report.claim_count,
            report.matrix_sha256.as_deref().unwrap_or("unavailable")
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&report)
                .unwrap_or_else(|error| format!("cannot render validation report: {error}"))
        );
        ExitCode::FAILURE
    }
}

fn usage(program: &std::path::Path) {
    eprintln!("usage: {} <evidence-matrix.json> [evidence-matrix-run.json]", program.display());
}
