#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::{env, fs, path::PathBuf, process::ExitCode};

use visa_sqlite_oracle::evaluate;

const USAGE: &str =
    "usage: visa-sqlite-oracle <namespace.snapshot> <expected-acks.json> <guest-database-path>";

fn main() -> ExitCode {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let [snapshot_path, expected_path, database_path] = arguments.as_slice() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let snapshot_path = PathBuf::from(snapshot_path);
    let expected_path = PathBuf::from(expected_path);
    let snapshot = match fs::read(&snapshot_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read snapshot {}: {error}", snapshot_path.display());
            return ExitCode::from(2);
        }
    };
    let expected = match fs::read(&expected_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read expected acknowledgements {}: {error}", expected_path.display());
            return ExitCode::from(2);
        }
    };
    #[cfg(unix)]
    let database_path = database_path.as_bytes();
    #[cfg(not(unix))]
    let database_path = database_path.to_string_lossy().as_bytes();
    let report = evaluate(&snapshot, &expected, database_path);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("cannot encode oracle report: {error}");
            return ExitCode::from(2);
        }
    }
    if report.accepted { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
