use std::{
    env, fs,
    io::{self, Read},
    process::ExitCode,
};

use vmos_conformance::{
    Boundary, EvidenceArtifact, EvidenceArtifactKind, LtpInvocation, attach_evidence_artifact,
    criterion_performance_plan_entries, criterion_performance_report_from_estimates_dir,
    full_catalog, gate_report_json, ltp_report_from_log_dir as build_ltp_report_from_log_dir,
    parse_report_json, sample_ltp_report, sample_performance_report, sample_report,
    validate_catalog, validate_report,
};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "plan-json".to_string());
    match command.as_str() {
        "plan-json" => print_json(&full_catalog()),
        "sample-report-json" => {
            let catalog = full_catalog();
            print_json(&sample_report(&catalog))
        }
        "ltp-plan-json" => print_json(&LtpInvocation::default_plan("target/ltp")),
        "ltp-plan-lines" => {
            let output_dir = args.next().unwrap_or_else(|| "target/ltp".to_string());
            print_ltp_plan_lines(&output_dir)
        }
        "sample-ltp-report-json" => print_json(&sample_ltp_report()),
        "sample-performance-report-json" => print_json(&sample_performance_report()),
        "validate-report" => {
            let path = args.next().unwrap_or_else(|| "-".to_string());
            validate_report_path(&path)
        }
        "write-sample-report" => match args.next() {
            Some(path) => {
                let catalog = full_catalog();
                write_json_file(&path, &sample_report(&catalog))
            }
            None => usage(),
        },
        "write-sample-ltp-report" => match args.next() {
            Some(path) => write_json_file(&path, &sample_ltp_report()),
            None => usage(),
        },
        "write-sample-performance-report" => match args.next() {
            Some(path) => write_json_file(&path, &sample_performance_report()),
            None => usage(),
        },
        "ltp-report-from-logs" => {
            let Some(log_dir) = args.next() else {
                return usage();
            };
            let boundary = match args.next() {
                Some(value) => match Boundary::parse(&value) {
                    Some(boundary) => boundary,
                    None => {
                        eprintln!("unknown boundary {value}");
                        return ExitCode::FAILURE;
                    }
                },
                None => Boundary::PortableArtifactExecution,
            };
            let profile = args.next();
            ltp_report_from_log_dir_command(&log_dir, boundary, profile)
        }
        "performance-report-from-criterion" => {
            let Some(criterion_dir) = args.next() else {
                return usage();
            };
            let boundary = match args.next() {
                Some(value) => match Boundary::parse(&value) {
                    Some(boundary) => boundary,
                    None => {
                        eprintln!("unknown boundary {value}");
                        return ExitCode::FAILURE;
                    }
                },
                None => Boundary::PortableArtifactExecution,
            };
            let profile = args.next();
            let report = criterion_performance_report_from_estimates_dir(
                format!("criterion-dir:{criterion_dir}"),
                "vmos-conformance performance-report-from-criterion",
                boundary,
                profile,
                &criterion_dir,
            );
            print_json(&report)
        }
        "performance-plan-lines" => {
            let criterion_dir = args.next().unwrap_or_else(|| "target/criterion".to_string());
            print_performance_plan_lines(&criterion_dir)
        }
        "attach-evidence-artifact" => {
            let Some(report_path) = args.next() else {
                return usage();
            };
            let Some(spec_id) = args.next() else {
                return usage();
            };
            let Some(kind) = args.next() else {
                return usage();
            };
            let Some(uri) = args.next() else {
                return usage();
            };
            let Some(sha256) = args.next() else {
                return usage();
            };
            let description = args.collect::<Vec<_>>().join(" ");
            if description.trim().is_empty() {
                return usage();
            }
            attach_evidence_artifact_path(&report_path, &spec_id, &kind, uri, sha256, description)
        }
        "validate-sample" => {
            let catalog = full_catalog();
            let catalog_report = validate_catalog(&catalog);
            let sample = sample_report(&catalog);
            let sample_report = validate_report(&sample, &catalog);
            if catalog_report.ok && sample_report.ok {
                println!("vmos-conformance sample report is valid");
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "catalog findings: {}\nsample findings: {}",
                    serde_json::to_string_pretty(&catalog_report).unwrap(),
                    serde_json::to_string_pretty(&sample_report).unwrap()
                );
                ExitCode::FAILURE
            }
        }
        _ => usage(),
    }
}

fn ltp_report_from_log_dir_command(
    log_dir: &str,
    boundary: Boundary,
    profile: Option<String>,
) -> ExitCode {
    let report = match build_ltp_report_from_log_dir(
        format!("ltp-log-dir:{log_dir}"),
        "vmos-conformance ltp-report-from-logs",
        boundary,
        profile,
        log_dir,
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("failed to read LTP log directory {log_dir}: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_json(&report)
}

fn print_ltp_plan_lines(output_dir: &str) -> ExitCode {
    for entry in LtpInvocation::default_plan(output_dir).plan_entries() {
        println!("{}\t{}\t{}", entry.spec_id, entry.scenario_arg, entry.output_log);
    }
    ExitCode::SUCCESS
}

fn print_performance_plan_lines(criterion_dir: &str) -> ExitCode {
    for entry in criterion_performance_plan_entries(criterion_dir) {
        println!(
            "{}\t{}\t{}\t{}",
            entry.spec_id, entry.benchmark_id, entry.metric, entry.estimate_path
        );
    }
    ExitCode::SUCCESS
}

fn attach_evidence_artifact_path(
    report_path: &str,
    spec_id: &str,
    kind: &str,
    uri: String,
    sha256: String,
    description: String,
) -> ExitCode {
    let kind = match EvidenceArtifactKind::parse(kind) {
        Some(kind) => kind,
        None => {
            eprintln!("unknown evidence artifact kind {kind}");
            return ExitCode::FAILURE;
        }
    };
    let bytes = match read_input(report_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read report {report_path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut report = match parse_report_json(&bytes) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("failed to parse report {}: {}", error.code, error.detail);
            return ExitCode::FAILURE;
        }
    };
    let attached = attach_evidence_artifact(
        &mut report,
        spec_id,
        EvidenceArtifact { kind, uri, sha256, description },
    );
    if attached == 0 {
        eprintln!("no report results matched spec id {spec_id}");
        return ExitCode::FAILURE;
    }
    print_json(&report)
}

fn validate_report_path(path: &str) -> ExitCode {
    let bytes = match read_input(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read report {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = full_catalog();
    let gate = gate_report_json(&bytes, &catalog);
    if gate.ok {
        print_json(&gate)
    } else {
        let _ = print_json(&gate);
        ExitCode::FAILURE
    }
}

fn read_input(path: &str) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        Ok(bytes)
    } else {
        fs::read(path)
    }
}

fn write_json_file<T: serde::Serialize>(path: &str, value: &T) -> ExitCode {
    match serde_json::to_vec_pretty(value)
        .map_err(io::Error::other)
        .and_then(|bytes| fs::write(path, bytes))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("failed to write json {path}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: vmos-conformance [plan-json|sample-report-json|ltp-plan-json|ltp-plan-lines [output-dir]|sample-ltp-report-json|sample-performance-report-json|ltp-report-from-logs <dir> [boundary] [profile]|performance-plan-lines [criterion-dir]|performance-report-from-criterion <dir> [boundary] [profile]|attach-evidence-artifact <report path|-> <spec-id|*> <kind> <uri> <sha256> <description...>|validate-report <path|->|write-sample-report <path>|write-sample-ltp-report <path>|write-sample-performance-report <path>|validate-sample]"
    );
    ExitCode::FAILURE
}

fn print_json<T: serde::Serialize>(value: &T) -> ExitCode {
    match serde_json::to_string_pretty(value) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to serialize json: {error}");
            ExitCode::FAILURE
        }
    }
}
