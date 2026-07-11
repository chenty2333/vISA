use std::{
    env, fs,
    io::{self, Read},
    process::ExitCode,
};

use conformance_oracle::{
    Boundary, EvidenceArtifact, EvidenceArtifactKind, LtpInvocation,
    artifact_uri_is_bundle_relative, attach_evidence_artifact, criterion_performance_plan_entries,
    criterion_performance_report_from_estimates_dir,
    criterion_performance_report_from_estimates_dir_with_boundary, default_visa_ltp_plan,
    full_catalog, gate_report_json, linux_ltp_catalog, ltp_raw_log_from_serial,
    ltp_report_from_log_dir as build_ltp_report_from_log_dir, ltp_visa_subset_report_from_log_dir,
    ltp_visa_trace_from_serial, minimum_mature_evidence_matrix, parse_report_json,
    performance_catalog, sample_ltp_report, sample_performance_report, sample_report,
    validate_catalog, validate_evidence_matrix, validate_report, validate_report_artifacts,
    visa_ltp_manifest_plan,
};
use sha2::{Digest, Sha256};

const HOST_LTP_DEFAULT_BOUNDARY: Boundary = Boundary::ReferenceService;
const VISA_LTP_DEFAULT_BOUNDARY: Boundary = Boundary::PortableArtifactExecution;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "plan-json".to_string());
    match command.as_str() {
        "plan-json" => print_json(&full_catalog()),
        "sample-report-json" => {
            let catalog = full_catalog();
            print_json(&sample_report(&catalog))
        }
        "evidence-matrix-json" => print_json(&minimum_mature_evidence_matrix()),
        "ltp-plan-json" => print_json(&LtpInvocation::default_plan("target/ltp")),
        "ltp-plan-lines" => {
            let output_dir = args.next().unwrap_or_else(|| "target/ltp".to_string());
            print_ltp_plan_lines(&output_dir)
        }
        "visa-ltp-plan-lines" => {
            let output_dir = args.next().unwrap_or_else(|| "target/visa-ltp".to_string());
            let binary_root = args.next().unwrap_or_else(|| "target/ltp-bins".to_string());
            print_visa_ltp_plan_lines(&output_dir, &binary_root)
        }
        "visa-ltp-manifest-plan-lines" => {
            let Some(output_dir) = args.next() else {
                return usage();
            };
            let Some(binary_root) = args.next() else {
                return usage();
            };
            let Some(manifest_path) = args.next() else {
                return usage();
            };
            print_visa_ltp_manifest_plan_lines(&output_dir, &binary_root, &manifest_path)
        }
        "sample-ltp-report-json" => print_json(&sample_ltp_report()),
        "sample-performance-report-json" => print_json(&sample_performance_report()),
        "validate-report" => {
            let path = args.next().unwrap_or_else(|| "-".to_string());
            validate_report_path(&path)
        }
        "validate-artifacts" => {
            let path = args.next().unwrap_or_else(|| "-".to_string());
            let artifact_root = args.next().unwrap_or_else(|| ".".to_string());
            validate_artifacts_path(&path, &artifact_root)
        }
        "validate-report-with-artifacts" => {
            let path = args.next().unwrap_or_else(|| "-".to_string());
            let artifact_root = args.next().unwrap_or_else(|| ".".to_string());
            validate_report_with_artifacts_path(&path, &artifact_root)
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
                None => HOST_LTP_DEFAULT_BOUNDARY,
            };
            let profile = args.next();
            ltp_report_from_log_dir_command(&log_dir, boundary, profile)
        }
        "ltp-visa-report-from-logs" => {
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
                None => VISA_LTP_DEFAULT_BOUNDARY,
            };
            let profile = args.next();
            ltp_visa_report_from_log_dir_command(&log_dir, boundary, profile)
        }
        "ltp-raw-log-from-serial" => {
            let Some(case_id) = args.next() else {
                return usage();
            };
            let Some(serial_path) = args.next() else {
                return usage();
            };
            let status = args.next().and_then(|value| value.parse::<i32>().ok()).unwrap_or(1);
            ltp_raw_log_from_serial_command(&case_id, &serial_path, status)
        }
        "ltp-visa-trace-from-serial" => {
            let Some(spec_id) = args.next() else {
                return usage();
            };
            let Some(case_id) = args.next() else {
                return usage();
            };
            let Some(binary_path) = args.next() else {
                return usage();
            };
            let Some(raw_log_uri) = args.next() else {
                return usage();
            };
            let Some(serial_log_uri) = args.next() else {
                return usage();
            };
            let Some(serial_path) = args.next() else {
                return usage();
            };
            let status = args.next().and_then(|value| value.parse::<i32>().ok()).unwrap_or(1);
            ltp_visa_trace_from_serial_command(
                &spec_id,
                &case_id,
                &binary_path,
                &raw_log_uri,
                &serial_log_uri,
                &serial_path,
                status,
            )
        }
        "performance-report-from-criterion" => {
            let Some(criterion_dir) = args.next() else {
                return usage();
            };
            let boundary = match args.next().filter(|value| !value.trim().is_empty()) {
                Some(value) => match Boundary::parse(&value) {
                    Some(boundary) => boundary,
                    None => {
                        eprintln!("unknown boundary {value}");
                        return ExitCode::FAILURE;
                    }
                },
                None => {
                    let profile = args.next().filter(|value| !value.trim().is_empty());
                    let report = criterion_performance_report_from_estimates_dir_with_boundary(
                        format!("criterion-dir:{criterion_dir}"),
                        "visa-conformance performance-report-from-criterion",
                        None,
                        profile,
                        &criterion_dir,
                    );
                    return print_json(&report);
                }
            };
            let profile = args.next().filter(|value| !value.trim().is_empty());
            let report = criterion_performance_report_from_estimates_dir(
                format!("criterion-dir:{criterion_dir}"),
                "visa-conformance performance-report-from-criterion",
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
        "attach-evidence-artifact-file" => {
            let Some(report_path) = args.next() else {
                return usage();
            };
            let Some(spec_id) = args.next() else {
                return usage();
            };
            let Some(kind) = args.next() else {
                return usage();
            };
            let Some(path) = args.next() else {
                return usage();
            };
            let description = args.collect::<Vec<_>>().join(" ");
            if description.trim().is_empty() {
                return usage();
            }
            attach_evidence_artifact_file_path(&report_path, &spec_id, &kind, &path, description)
        }
        "validate-sample" => {
            let catalog = full_catalog();
            let catalog_report = validate_catalog(&catalog);
            let matrix_report =
                validate_evidence_matrix(&minimum_mature_evidence_matrix(), &catalog);
            let layered_sample = sample_report(&catalog);
            let layered_report = validate_report(&layered_sample, &catalog);
            let ltp_catalog = linux_ltp_catalog();
            let ltp_sample = sample_ltp_report();
            let ltp_report = validate_report(&ltp_sample, &ltp_catalog);
            let perf_catalog = performance_catalog();
            let perf_sample = sample_performance_report();
            let perf_report = validate_report(&perf_sample, &perf_catalog);
            if catalog_report.ok
                && matrix_report.ok
                && layered_report.ok
                && ltp_report.ok
                && perf_report.ok
            {
                println!("visa-conformance sample reports are structurally valid");
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "catalog findings: {}\nevidence matrix findings: {}\nlayered sample findings: {}\nltp sample findings: {}\nperformance sample findings: {}",
                    serde_json::to_string_pretty(&catalog_report).unwrap(),
                    serde_json::to_string_pretty(&matrix_report).unwrap(),
                    serde_json::to_string_pretty(&layered_report).unwrap(),
                    serde_json::to_string_pretty(&ltp_report).unwrap(),
                    serde_json::to_string_pretty(&perf_report).unwrap()
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
        "visa-conformance ltp-report-from-logs",
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

fn ltp_visa_report_from_log_dir_command(
    log_dir: &str,
    boundary: Boundary,
    profile: Option<String>,
) -> ExitCode {
    let report = match ltp_visa_subset_report_from_log_dir(
        format!("visa-ltp-log-dir:{log_dir}"),
        "visa-conformance ltp-visa-report-from-logs",
        boundary,
        profile,
        log_dir,
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("failed to read vISA LTP log directory {log_dir}: {error}");
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

fn print_visa_ltp_plan_lines(output_dir: &str, binary_root: &str) -> ExitCode {
    for entry in default_visa_ltp_plan(output_dir, binary_root) {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            entry.spec_id,
            entry.case_id,
            entry.binary_path,
            entry.output_log,
            entry.trace_log,
            entry.serial_log,
            entry.subset.scenario_arg()
        );
    }
    ExitCode::SUCCESS
}

fn print_visa_ltp_manifest_plan_lines(
    output_dir: &str,
    binary_root: &str,
    manifest_path: &str,
) -> ExitCode {
    let manifest = match fs::read_to_string(manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("failed to read vISA LTP manifest {manifest_path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let plan = match visa_ltp_manifest_plan(output_dir, binary_root, &manifest) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("invalid vISA LTP manifest {manifest_path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    for entry in plan {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            entry.spec_id,
            entry.case_id,
            entry.binary_path,
            entry.output_log,
            entry.trace_log,
            entry.serial_log,
            entry.subset.scenario_arg()
        );
    }
    ExitCode::SUCCESS
}

fn ltp_raw_log_from_serial_command(case_id: &str, serial_path: &str, status: i32) -> ExitCode {
    let bytes = match fs::read(serial_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read serial log {serial_path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let serial = String::from_utf8_lossy(&bytes);
    print!("{}", ltp_raw_log_from_serial(case_id, &serial, status));
    ExitCode::SUCCESS
}

fn ltp_visa_trace_from_serial_command(
    spec_id: &str,
    case_id: &str,
    binary_path: &str,
    raw_log_uri: &str,
    serial_log_uri: &str,
    serial_path: &str,
    status: i32,
) -> ExitCode {
    let bytes = match fs::read(serial_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read serial log {serial_path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let serial = String::from_utf8_lossy(&bytes);
    let trace = ltp_visa_trace_from_serial(
        spec_id,
        case_id,
        binary_path,
        raw_log_uri,
        serial_log_uri,
        &serial,
        status,
    );
    match serde_json::to_string(&trace) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to serialize trace: {error}");
            ExitCode::FAILURE
        }
    }
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
    if !artifact_uri_is_bundle_relative(&uri) {
        eprintln!(
            "evidence artifact uri must be relative to the artifact root and must not escape it: {uri}"
        );
        return ExitCode::FAILURE;
    }
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

fn attach_evidence_artifact_file_path(
    report_path: &str,
    spec_id: &str,
    kind: &str,
    path: &str,
    description: String,
) -> ExitCode {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read evidence artifact {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let sha256 = sha256_hex(&bytes);
    attach_evidence_artifact_path(report_path, spec_id, kind, path.to_string(), sha256, description)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
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

fn validate_artifacts_path(path: &str, artifact_root: &str) -> ExitCode {
    let bytes = match read_input(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read report {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let report = match parse_report_json(&bytes) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("failed to parse report {}: {}", error.code, error.detail);
            return ExitCode::FAILURE;
        }
    };
    let validation = validate_report_artifacts(&report, artifact_root);
    if validation.ok {
        print_json(&validation)
    } else {
        let _ = print_json(&validation);
        ExitCode::FAILURE
    }
}

fn validate_report_with_artifacts_path(path: &str, artifact_root: &str) -> ExitCode {
    let bytes = match read_input(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read report {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = full_catalog();
    let report_gate = gate_report_json(&bytes, &catalog);
    let artifact_validation = parse_report_json(&bytes)
        .ok()
        .map(|report| validate_report_artifacts(&report, artifact_root));
    let ok = report_gate.ok && artifact_validation.as_ref().is_some_and(|report| report.ok);
    let output = serde_json::json!({
        "ok": ok,
        "report": report_gate,
        "artifacts": artifact_validation,
    });
    if ok {
        print_json(&output)
    } else {
        let _ = print_json(&output);
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
        "usage: visa-conformance [plan-json|sample-report-json|evidence-matrix-json|ltp-plan-json|ltp-plan-lines [output-dir]|visa-ltp-plan-lines [output-dir] [binary-root]|visa-ltp-manifest-plan-lines <output-dir> <binary-root> <manifest>|sample-ltp-report-json|sample-performance-report-json|ltp-report-from-logs <dir> [boundary] [profile]|ltp-visa-report-from-logs <dir> [boundary] [profile]|ltp-raw-log-from-serial <case-id> <serial-log> [runner-status]|ltp-visa-trace-from-serial <spec-id> <case-id> <binary> <raw-log-uri> <serial-log-uri> <serial-log> [runner-status]|performance-plan-lines [criterion-dir]|performance-report-from-criterion <dir> [boundary] [profile]|attach-evidence-artifact <report path|-> <spec-id|*> <kind> <uri> <sha256> <description...>|attach-evidence-artifact-file <report path|-> <spec-id|*> <kind> <path> <description...>|validate-report <path|->|validate-artifacts <path|-> [artifact-root]|validate-report-with-artifacts <path|-> [artifact-root]|write-sample-report <path>|write-sample-ltp-report <path>|write-sample-performance-report <path>|validate-sample]"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ltp_cli_defaults_keep_host_logs_below_portable_artifact_execution() {
        assert_eq!(HOST_LTP_DEFAULT_BOUNDARY, Boundary::ReferenceService);
        assert_eq!(VISA_LTP_DEFAULT_BOUNDARY, Boundary::PortableArtifactExecution);
    }
}
