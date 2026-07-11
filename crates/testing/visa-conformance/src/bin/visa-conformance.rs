use std::{env, fs, path::PathBuf, process::ExitCode};

use visa_conformance::gate_stage1_evidence_bundle_json_with_artifacts;

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
    if command.as_deref() != Some(std::ffi::OsStr::new("stage1"))
        || bundle.is_none()
        || artifact_root.is_none()
        || arguments.next().is_some()
    {
        return Err((
            64,
            format!(
                "usage: {} stage1 <bundle.json> <artifact-root>",
                PathBuf::from(program).display()
            ),
        ));
    }

    let bundle = PathBuf::from(bundle.unwrap());
    let artifact_root = PathBuf::from(artifact_root.unwrap());
    let bytes = fs::read(&bundle)
        .map_err(|error| (2, format!("cannot read {}: {error}", bundle.display())))?;
    let result = gate_stage1_evidence_bundle_json_with_artifacts(&bytes, &artifact_root);
    if result.ok {
        println!("Stage 1 evidence verified: {}", bundle.display());
        return Ok(());
    }

    let rendered = serde_json::to_string_pretty(&result)
        .unwrap_or_else(|error| format!("cannot render validation result: {error}"));
    Err((1, rendered))
}
