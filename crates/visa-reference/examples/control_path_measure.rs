use std::{env, error::Error, process::ExitCode};

use visa_reference::measurement::{MeasurementConfig, MeasurementError, run_reference_measurement};

fn usage() {
    eprintln!(
        "usage: control_path_measure [--warmup N] [--samples N] \
         [--max-coordinator-ratio-pct P]"
    );
}

fn parse_usize(value: Option<&String>, flag: &str) -> Result<usize, MeasurementError> {
    value
        .ok_or_else(|| MeasurementError::Flow(format!("missing value for {flag}")))?
        .parse()
        .map_err(|_| MeasurementError::Flow(format!("invalid value for {flag}")))
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut config = MeasurementConfig::default();
    let mut threshold = None;
    let args: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--warmup" => {
                config.warmup = parse_usize(args.get(index + 1), "--warmup")?;
                index += 2;
            }
            "--samples" => {
                config.samples = parse_usize(args.get(index + 1), "--samples")?;
                index += 2;
            }
            "--max-coordinator-ratio-pct" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    MeasurementError::Flow("missing value for --max-coordinator-ratio-pct".into())
                })?;
                threshold = Some(value.parse::<f64>().map_err(|_| {
                    MeasurementError::Flow("invalid value for --max-coordinator-ratio-pct".into())
                })?);
                index += 2;
            }
            "-h" | "--help" => {
                usage();
                return Ok(());
            }
            unknown => {
                usage();
                return Err(format!("unknown argument {unknown}").into());
            }
        }
    }
    let report = run_reference_measurement(config)?;
    print!("{}", report.render_text());
    if let Some(max_percent) = threshold {
        report.validate_coordinator_ratio(max_percent)?;
        println!("release gate: coordinator p95 ratio <= {max_percent:.2}% (pass)");
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("control-path measurement failed: {error}");
            ExitCode::FAILURE
        }
    }
}
