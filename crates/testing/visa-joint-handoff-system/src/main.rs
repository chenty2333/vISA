use std::{
    env,
    path::PathBuf,
    process::{Command, ExitCode},
};

use visa_joint_handoff_system::{JointRunInputs, run_joint_handoff_reference};

fn main() -> ExitCode {
    match run() {
        Ok(path) => {
            println!("Joint handoff evidence bundle: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Joint handoff runner failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<PathBuf, String> {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_default();
    let values: Vec<_> = arguments.collect();
    let (root, inputs) = parse_run_arguments(&program, &values)?;
    verify_executed_visa_checkout(&inputs.visa_sha)?;
    run_joint_handoff_reference(root, &inputs)
}

fn parse_run_arguments(
    program: &std::ffi::OsStr,
    values: &[std::ffi::OsString],
) -> Result<(PathBuf, JointRunInputs), String> {
    if values.len() != 11 {
        return Err(format!(
            "usage: {} <artifact-root> <visa-sha> <nexus-sha> <neutral-sha> <neutral-tree> <neutral-bundle-sha256> <source-lock-sha256> <protocol-markdown-sha256> <machine-toml-sha256> <refinement-map-sha256> <abstract-registry-sha256>",
            PathBuf::from(program).display()
        ));
    }
    Ok((
        PathBuf::from(&values[0]),
        JointRunInputs {
            visa_sha: os_string(&values[1], "vISA SHA")?,
            nexus_sha: os_string(&values[2], "Nexus SHA")?,
            neutral_sha: os_string(&values[3], "neutral SHA")?,
            neutral_tree: os_string(&values[4], "neutral tree")?,
            neutral_bundle_sha256: os_string(&values[5], "neutral Git bundle SHA-256")?,
            source_lock_sha256: os_string(&values[6], "source-lock SHA-256")?,
            protocol_schema_sha256: os_string(&values[7], "protocol Markdown SHA-256")?,
            machine_contract_sha256: os_string(&values[8], "machine TOML SHA-256")?,
            refinement_map_sha256: os_string(&values[9], "refinement-map SHA-256")?,
            abstract_registry_sha256: os_string(&values[10], "abstract-registry SHA-256")?,
        },
    ))
}

fn os_string(value: &std::ffi::OsStr, label: &str) -> Result<String, String> {
    value.to_str().map(str::to_owned).ok_or_else(|| format!("{label} is not UTF-8"))
}

fn verify_executed_visa_checkout(expected_sha: &str) -> Result<(), String> {
    let head = git_output(["rev-parse", "--verify", "HEAD"])?;
    if head.trim() != expected_sha {
        return Err(format!(
            "executed vISA checkout HEAD mismatch: actual={}, expected={expected_sha}",
            head.trim(),
        ));
    }
    let status = git_output(["status", "--porcelain=v1", "--untracked-files=normal"])?;
    if !status.is_empty() {
        return Err(
            "executed vISA checkout is not clean, including non-ignored untracked files".to_owned()
        );
    }
    Ok(())
}

fn git_output<const N: usize>(arguments: [&str; N]) -> Result<String, String> {
    let output = Command::new("git")
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot execute git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "git output is not UTF-8".to_owned())
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};

    use super::*;

    fn values() -> Vec<OsString> {
        [
            "artifact",
            &"1".repeat(40),
            &"2".repeat(40),
            &"3".repeat(40),
            &"4".repeat(40),
            &"5".repeat(64),
            &"6".repeat(64),
            &"7".repeat(64),
            &"8".repeat(64),
            &"9".repeat(64),
            &"a".repeat(64),
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn parser_requires_all_exact_revisions_and_input_digests() {
        let values = values();
        let (root, inputs) = parse_run_arguments(OsStr::new("runner"), &values).unwrap();
        assert_eq!(root, PathBuf::from("artifact"));
        assert_eq!(inputs.visa_sha, "1".repeat(40));
        assert_eq!(inputs.neutral_sha, "3".repeat(40));
        assert_eq!(inputs.neutral_tree, "4".repeat(40));
        assert_eq!(inputs.neutral_bundle_sha256, "5".repeat(64));
        assert_eq!(inputs.source_lock_sha256, "6".repeat(64));
        assert_eq!(inputs.abstract_registry_sha256, "a".repeat(64));

        assert!(parse_run_arguments(OsStr::new("runner"), &values[..10]).is_err());
        let mut extra = values;
        extra.push(OsString::from("extra"));
        assert!(parse_run_arguments(OsStr::new("runner"), &extra).is_err());
    }
}
