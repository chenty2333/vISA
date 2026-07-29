use std::{env, fs, path::PathBuf, process::ExitCode};

use visa_regular_file_oracle::{
    CarrierProbeExpectation, CarrierProbeRoute, evaluate_carrier_probe, evaluate_equivalence,
};

const USAGE: &str = "\
usage:
  visa-regular-file-oracle <uninterrupted-control.json> <candidate.json>
  visa-regular-file-oracle --carrier-probe <restart|carrier-only|naive-reopen|visa-plus-carrier> \
<artifact-root> <wanco-revision> <uninterrupted-control.json> <candidate.json>";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    CompleteRegistry,
    CarrierProbe { route: CarrierProbeRoute, artifact_root: PathBuf, carrier_revision: String },
}

#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    mode: Mode,
    control: PathBuf,
    candidate: PathBuf,
}

fn parse_arguments(arguments: Vec<String>) -> Result<Arguments, String> {
    match arguments.as_slice() {
        [control, candidate] if !control.starts_with('-') && !candidate.starts_with('-') => {
            Ok(Arguments {
                mode: Mode::CompleteRegistry,
                control: PathBuf::from(control),
                candidate: PathBuf::from(candidate),
            })
        }
        [flag, route, artifact_root, carrier_revision, control, candidate]
            if flag == "--carrier-probe" =>
        {
            Ok(Arguments {
                mode: Mode::CarrierProbe {
                    route: CarrierProbeRoute::parse(route)?,
                    artifact_root: PathBuf::from(artifact_root),
                    carrier_revision: carrier_revision.clone(),
                },
                control: PathBuf::from(control),
                candidate: PathBuf::from(candidate),
            })
        }
        _ => Err(USAGE.to_owned()),
    }
}

fn main() -> ExitCode {
    let arguments = match parse_arguments(env::args().skip(1).collect()) {
        Ok(arguments) => arguments,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let control = match fs::read(&arguments.control) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read control observation {}: {error}", arguments.control.display());
            return ExitCode::from(2);
        }
    };
    let candidate = match fs::read(&arguments.candidate) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!(
                "cannot read candidate observation {}: {error}",
                arguments.candidate.display()
            );
            return ExitCode::from(2);
        }
    };
    let report = match &arguments.mode {
        Mode::CompleteRegistry => evaluate_equivalence(&control, &candidate),
        Mode::CarrierProbe { route, artifact_root, carrier_revision } => evaluate_carrier_probe(
            &control,
            &candidate,
            CarrierProbeExpectation { route: *route, artifact_root, carrier_revision },
        ),
    };
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("cannot encode oracle report: {error}");
            return ExitCode::from(2);
        }
    }
    if report.accepted { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn two_positional_arguments_preserve_complete_registry_mode() {
        let parsed = parse_arguments(strings(&["control.json", "candidate.json"]))
            .expect("two positional arguments remain supported");
        assert_eq!(parsed.mode, Mode::CompleteRegistry);
        assert_eq!(parsed.control, PathBuf::from("control.json"));
        assert_eq!(parsed.candidate, PathBuf::from("candidate.json"));
    }

    #[test]
    fn carrier_probe_mode_is_explicit() {
        let parsed = parse_arguments(strings(&[
            "--carrier-probe",
            "carrier-only",
            "artifacts",
            "11aa",
            "control.json",
            "candidate.json",
        ]))
        .expect("carrier probe mode parses");
        assert_eq!(
            parsed.mode,
            Mode::CarrierProbe {
                route: CarrierProbeRoute::CarrierOnly,
                artifact_root: PathBuf::from("artifacts"),
                carrier_revision: "11aa".to_owned(),
            }
        );
    }

    #[test]
    fn unknown_modes_and_wrong_arity_are_rejected() {
        for arguments in [
            strings(&[]),
            strings(&["--carrier-probe", "control.json"]),
            strings(&["--unknown", "control.json", "candidate.json"]),
        ] {
            assert_eq!(parse_arguments(arguments), Err(USAGE.to_owned()));
        }
        let unsupported = parse_arguments(strings(&[
            "--carrier-probe",
            "handoff",
            "artifacts",
            "11aa",
            "control.json",
            "candidate.json",
        ]));
        assert_eq!(unsupported, Err("unsupported carrier probe route \"handoff\"".to_owned()));
    }
}
