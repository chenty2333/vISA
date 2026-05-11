use std::{env, process::ExitCode};

use vmos_conformance::{
    LtpInvocation, full_catalog, sample_ltp_report, sample_report, validate_catalog,
    validate_report,
};

fn main() -> ExitCode {
    let command = env::args().nth(1).unwrap_or_else(|| "plan-json".to_string());
    match command.as_str() {
        "plan-json" => print_json(&full_catalog()),
        "sample-report-json" => {
            let catalog = full_catalog();
            print_json(&sample_report(&catalog))
        }
        "ltp-plan-json" => print_json(&LtpInvocation::default_plan("target/ltp")),
        "sample-ltp-report-json" => print_json(&sample_ltp_report()),
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
        _ => {
            eprintln!(
                "usage: vmos-conformance [plan-json|sample-report-json|ltp-plan-json|sample-ltp-report-json|validate-sample]"
            );
            ExitCode::FAILURE
        }
    }
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
