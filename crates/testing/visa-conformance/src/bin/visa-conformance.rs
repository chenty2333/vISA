use std::{env, fs, path::PathBuf, process::ExitCode};

use visa_conformance::{
    gate_stage1_evidence_bundle_json_with_artifacts,
    gate_stage2_evidence_bundle_json_with_artifacts,
    gate_stage2_strict_evidence_bundle_json_with_artifacts,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Stage1,
    Stage2,
    Stage2Strict,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, message)) => {
            eprintln!("{message}");
            ExitCode::from(code)
        }
    }
}

fn run() -> Result<(), (u8, String)> {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_default();
    let command = arguments.next();
    let bundle = arguments.next();
    let artifact_root = arguments.next();
    let command = parse_command(command.as_deref());
    if command.is_none()
        || bundle.is_none()
        || artifact_root.is_none()
        || arguments.next().is_some()
    {
        return Err((
            64,
            format!(
                "usage: {} <stage1|stage2|stage2-strict> <bundle.json> <artifact-root>",
                PathBuf::from(program).display()
            ),
        ));
    }

    let bundle = PathBuf::from(bundle.unwrap());
    let artifact_root = PathBuf::from(artifact_root.unwrap());
    let bytes = fs::read(&bundle)
        .map_err(|error| (2, format!("cannot read {}: {error}", bundle.display())))?;
    let (label, result) = match command {
        Some(Command::Stage1) => (
            "Stage 1",
            serde_json::to_value(gate_stage1_evidence_bundle_json_with_artifacts(
                &bytes,
                &artifact_root,
            )),
        ),
        Some(Command::Stage2) => (
            "Stage 2",
            serde_json::to_value(gate_stage2_evidence_bundle_json_with_artifacts(
                &bytes,
                &artifact_root,
            )),
        ),
        Some(Command::Stage2Strict) => (
            "Strict Stage 2",
            serde_json::to_value(gate_stage2_strict_evidence_bundle_json_with_artifacts(
                &bytes,
                &artifact_root,
            )),
        ),
        _ => unreachable!(),
    };
    let result =
        result.map_err(|error| (2, format!("cannot render validation result: {error}")))?;
    if result.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        println!("{label} evidence verified: {}", bundle.display());
        return Ok(());
    }

    let rendered = serde_json::to_string_pretty(&result)
        .unwrap_or_else(|error| format!("cannot render validation result: {error}"));
    Err((1, rendered))
}

fn parse_command(command: Option<&std::ffi::OsStr>) -> Option<Command> {
    match command.and_then(std::ffi::OsStr::to_str) {
        Some("stage1") => Some(Command::Stage1),
        Some("stage2") => Some(Command::Stage2),
        Some("stage2-strict") => Some(Command::Stage2Strict),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn parser_accepts_only_the_three_exact_verifier_commands() {
        assert_eq!(parse_command(Some(OsStr::new("stage1"))), Some(Command::Stage1));
        assert_eq!(parse_command(Some(OsStr::new("stage2"))), Some(Command::Stage2));
        assert_eq!(parse_command(Some(OsStr::new("stage2-strict"))), Some(Command::Stage2Strict));
        for rejected in [None, Some(OsStr::new("strict-stage2")), Some(OsStr::new("stage2-v3"))] {
            assert_eq!(parse_command(rejected), None);
        }
    }
}
