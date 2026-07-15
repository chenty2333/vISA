use std::{env, fs, path::PathBuf, process::ExitCode};

use visa_conformance::{
    JointEvidenceExpectations, Stage3Profile,
    gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations,
    gate_stage1_evidence_bundle_json_with_artifacts,
    gate_stage2_evidence_bundle_json_with_artifacts,
    gate_stage2_strict_evidence_bundle_json_with_artifacts,
    gate_stage3_evidence_bundle_json_with_artifacts,
    gate_stage4_evidence_bundle_json_with_artifacts,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Stage1,
    Stage2,
    Stage2Strict,
    Stage3A,
    Stage3B,
    Stage4,
    JointHandoff,
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
    let values = arguments.collect::<Vec<_>>();
    let command = parse_command(values.first().map(std::ffi::OsString::as_os_str));
    let valid_arity = matches!(command, Some(Command::JointHandoff)) && values.len() == 13
        || !matches!(command, Some(Command::JointHandoff)) && values.len() == 3;
    if command.is_none() || !valid_arity {
        return Err((
            64,
            format!(
                "usage: {} <stage1|stage2|stage2-strict|stage3a|stage3b|stage4> <bundle.json> <artifact-root>\n       {} joint-handoff <bundle.json> <artifact-root> <visa-sha> <nexus-sha> <neutral-sha> <neutral-tree> <neutral-bundle-sha256> <source-lock-sha256> <protocol-markdown-sha256> <machine-toml-sha256> <refinement-map-sha256> <abstract-registry-sha256>",
                PathBuf::from(&program).display(),
                PathBuf::from(program).display()
            ),
        ));
    }

    let bundle = PathBuf::from(&values[1]);
    let artifact_root = PathBuf::from(&values[2]);
    let joint_expectations = if matches!(command, Some(Command::JointHandoff)) {
        Some(parse_joint_expectations(&values[3..]).map_err(|error| (64, error))?)
    } else {
        None
    };
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
        Some(Command::Stage3A) => (
            "Stage 3A",
            serde_json::to_value(gate_stage3_evidence_bundle_json_with_artifacts(
                Stage3Profile::RegularFile,
                &bytes,
                &artifact_root,
            )),
        ),
        Some(Command::Stage3B) => (
            "Stage 3B",
            serde_json::to_value(gate_stage3_evidence_bundle_json_with_artifacts(
                Stage3Profile::LogicalRequest,
                &bytes,
                &artifact_root,
            )),
        ),
        Some(Command::Stage4) => (
            "Stage 4",
            serde_json::to_value(gate_stage4_evidence_bundle_json_with_artifacts(
                &bytes,
                &artifact_root,
            )),
        ),
        Some(Command::JointHandoff) => (
            "Joint handoff",
            serde_json::to_value(
                gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations(
                    &bytes,
                    &artifact_root,
                    joint_expectations.as_ref().expect("joint expectations parsed"),
                ),
            ),
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

fn parse_joint_expectations(
    values: &[std::ffi::OsString],
) -> Result<JointEvidenceExpectations, String> {
    if values.len() != 10 {
        return Err(
            "joint-handoff verification requires three revisions, a neutral tree, and six input digests"
                .to_owned(),
        );
    }
    Ok(JointEvidenceExpectations {
        visa_git_sha: utf8(&values[0], "vISA SHA")?,
        nexus_git_sha: utf8(&values[1], "Nexus SHA")?,
        neutral_git_sha: utf8(&values[2], "neutral SHA")?,
        neutral_tree: utf8(&values[3], "neutral tree")?,
        neutral_bundle_sha256: utf8(&values[4], "neutral Git bundle SHA-256")?,
        source_lock_sha256: utf8(&values[5], "source-lock SHA-256")?,
        protocol_schema_sha256: utf8(&values[6], "protocol Markdown SHA-256")?,
        machine_contract_sha256: utf8(&values[7], "machine TOML SHA-256")?,
        refinement_map_sha256: utf8(&values[8], "refinement-map SHA-256")?,
        abstract_registry_sha256: utf8(&values[9], "abstract-registry SHA-256")?,
    })
}

fn utf8(value: &std::ffi::OsStr, label: &str) -> Result<String, String> {
    value.to_str().map(str::to_owned).ok_or_else(|| format!("{label} is not UTF-8"))
}

fn parse_command(command: Option<&std::ffi::OsStr>) -> Option<Command> {
    match command.and_then(std::ffi::OsStr::to_str) {
        Some("stage1") => Some(Command::Stage1),
        Some("stage2") => Some(Command::Stage2),
        Some("stage2-strict") => Some(Command::Stage2Strict),
        Some("stage3a") => Some(Command::Stage3A),
        Some("stage3b") => Some(Command::Stage3B),
        Some("stage4") => Some(Command::Stage4),
        Some("joint-handoff") => Some(Command::JointHandoff),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn parser_accepts_only_the_exact_verifier_commands() {
        assert_eq!(parse_command(Some(OsStr::new("stage1"))), Some(Command::Stage1));
        assert_eq!(parse_command(Some(OsStr::new("stage2"))), Some(Command::Stage2));
        assert_eq!(parse_command(Some(OsStr::new("stage2-strict"))), Some(Command::Stage2Strict));
        assert_eq!(parse_command(Some(OsStr::new("stage3a"))), Some(Command::Stage3A));
        assert_eq!(parse_command(Some(OsStr::new("stage3b"))), Some(Command::Stage3B));
        assert_eq!(parse_command(Some(OsStr::new("stage4"))), Some(Command::Stage4));
        assert_eq!(parse_command(Some(OsStr::new("joint-handoff"))), Some(Command::JointHandoff));
        for rejected in [None, Some(OsStr::new("strict-stage2")), Some(OsStr::new("stage2-v3"))] {
            assert_eq!(parse_command(rejected), None);
        }
    }

    #[test]
    fn joint_parser_requires_the_neutral_tree_and_offline_bundle_digest() {
        let values = [
            "1".repeat(40),
            "2".repeat(40),
            "3".repeat(40),
            "4".repeat(40),
            "5".repeat(64),
            "6".repeat(64),
            "7".repeat(64),
            "8".repeat(64),
            "9".repeat(64),
            "a".repeat(64),
        ]
        .map(std::ffi::OsString::from);
        let parsed = parse_joint_expectations(&values).unwrap();
        assert_eq!(parsed.visa_git_sha, "1".repeat(40));
        assert_eq!(parsed.neutral_tree, "4".repeat(40));
        assert_eq!(parsed.neutral_bundle_sha256, "5".repeat(64));
        assert_eq!(parsed.source_lock_sha256, "6".repeat(64));
        assert_eq!(parsed.abstract_registry_sha256, "a".repeat(64));
        assert!(parse_joint_expectations(&values[..9]).is_err());
    }
}
