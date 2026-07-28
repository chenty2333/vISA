use std::{
    env,
    ffi::{OsStr, OsString},
    io::{Read as _, Write as _},
    path::PathBuf,
    process::ExitCode,
};

use visa_stage3_system::cross_host::{
    encode_compact, endpoint_hello, max_wire_bytes, parse_destination_request_bytes,
    run_controller, run_destination_role, run_source_role, verify_cross_host_publication,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, error)) => {
            eprintln!("Stage 3A cross-host runner failed: {error}");
            ExitCode::from(code)
        }
    }
}

fn run() -> Result<(), (u8, String)> {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_default();
    let command = arguments.next().and_then(|value| value.into_string().ok());
    let remaining = arguments.collect::<Vec<_>>();
    match command.as_deref() {
        Some("hello") if remaining.is_empty() => {
            write_json(&endpoint_hello().map_err(failure)?, "endpoint hello")
        }
        Some("source") if remaining.len() == 1 => {
            let source = run_source_role(&PathBuf::from(&remaining[0])).map_err(failure)?;
            write_json(&source, "source bundle")
        }
        Some("destination") if remaining.len() == 1 => {
            let mut input = Vec::new();
            std::io::stdin()
                .take(max_wire_bytes() + 1)
                .read_to_end(&mut input)
                .map_err(|error| failure(format!("cannot read destination request: {error}")))?;
            if input.len() as u64 > max_wire_bytes() {
                return Err(failure("destination request exceeds the bounded wire limit"));
            }
            let request = parse_destination_request_bytes(&input).map_err(failure)?;
            let receipt =
                run_destination_role(&request, &PathBuf::from(&remaining[0])).map_err(failure)?;
            write_json(&receipt, "destination receipt")
        }
        Some("controller") => run_controller_command(&remaining),
        Some("verify") if remaining.len() == 1 => {
            verify_cross_host_publication(&PathBuf::from(&remaining[0])).map_err(failure)?;
            println!(
                "Stage 3A cross-host evidence verified: {}",
                PathBuf::from(&remaining[0]).display()
            );
            Ok(())
        }
        _ => Err((64, usage(&program))),
    }
}

fn run_controller_command(arguments: &[OsString]) -> Result<(), (u8, String)> {
    let separator = arguments.iter().position(|argument| argument == OsStr::new("--"));
    let Some(separator) = separator else {
        return Err((
            64,
            "controller command requires `-- <destination-launcher> [args...]`".to_owned(),
        ));
    };
    if separator != 3 || separator + 1 >= arguments.len() {
        return Err((64, "controller usage is `<artifact-root> <source-work-root> <destination-work-root> -- <destination-launcher> [args...]`".to_owned()));
    }
    let path = run_controller(
        &PathBuf::from(&arguments[0]),
        &PathBuf::from(&arguments[1]),
        &PathBuf::from(&arguments[2]),
        &arguments[separator + 1..],
    )
    .map_err(failure)?;
    println!("Stage 3A cross-host evidence bundle: {}", path.display());
    Ok(())
}

fn write_json<T: serde::Serialize>(value: &T, label: &str) -> Result<(), (u8, String)> {
    let bytes = encode_compact(value, label).map_err(failure)?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|error| failure(format!("cannot write {label}: {error}")))
}

fn failure(error: impl Into<String>) -> (u8, String) {
    (1, error.into())
}

fn usage(program: &OsStr) -> String {
    format!(
        "usage: {} <hello | source <work-root> | destination <work-root> | controller <artifact-root> <source-work-root> <destination-work-root> -- <destination-launcher> [args...] | verify <artifact-root>>",
        PathBuf::from(program).display()
    )
}
