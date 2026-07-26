use std::{path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let Some(artifact_root) = arguments.next().map(PathBuf::from) else {
        eprintln!("usage: visa-composite-cell <artifact-root> [case-id] [timer-delay-ns]");
        return ExitCode::FAILURE;
    };
    let case_id = arguments.next().unwrap_or_else(|| "composite-continuity".to_owned());
    let timer_delay_ns = match arguments.next() {
        Some(value) => match value.parse() {
            Ok(value) => value,
            Err(error) => {
                eprintln!("invalid timer delay: {error}");
                return ExitCode::FAILURE;
            }
        },
        None => visa_composite_cell::cell::DEFAULT_TIMER_DELAY_NANOS,
    };

    match visa_composite_cell::run(&artifact_root, &case_id, timer_delay_ns) {
        Ok(path) => {
            println!("{}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("composite cell failed: {error}");
            ExitCode::FAILURE
        }
    }
}
