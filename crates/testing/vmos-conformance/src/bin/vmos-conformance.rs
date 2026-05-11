use std::{
    env, fs,
    io::{self, Read},
    process::ExitCode,
};

use vmos_conformance::{
    LtpInvocation, full_catalog, gate_report_json, sample_ltp_report, sample_report,
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
        "sample-ltp-report-json" => print_json(&sample_ltp_report()),
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
        "usage: vmos-conformance [plan-json|sample-report-json|ltp-plan-json|sample-ltp-report-json|validate-report <path|->|write-sample-report <path>|write-sample-ltp-report <path>|validate-sample]"
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
