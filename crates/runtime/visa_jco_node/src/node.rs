use std::{path::Path, process::Command};

/// Construct a Node command without ambient startup-code injection.
pub(crate) fn locked_node_command(node: &Path) -> Command {
    let mut command = Command::new(node);
    command.env_remove("NODE_OPTIONS");
    command
}

#[cfg(test)]
mod tests {
    use std::{env, ffi::OsString, fs, path::PathBuf, process::Command};

    use super::locked_node_command;

    const PROBE_MARKER_ENV: &str = "VISA_JCO_NODE_OPTIONS_PROBE_MARKER";
    const PROBE_COMPLETED_ENV: &str = "VISA_JCO_NODE_OPTIONS_PROBE_COMPLETED";
    const TEST_NAME: &str = "node::tests::locked_node_command_removes_inherited_node_options";

    #[test]
    fn locked_node_command_removes_inherited_node_options() {
        if let Some(marker) = env::var_os(PROBE_MARKER_ENV) {
            run_locked_node_probe(PathBuf::from(marker));
            return;
        }

        let directory = tempfile::tempdir().expect("Node options probe directory");
        for (name, option, extension, source) in [
            (
                "require",
                "--require",
                "cjs",
                concat!(
                    "const { writeFileSync } = require('node:fs');\n",
                    "writeFileSync(process.env.VISA_JCO_NODE_OPTIONS_PROBE_MARKER, 'executed');\n"
                ),
            ),
            (
                "import",
                "--import",
                "mjs",
                concat!(
                    "import { writeFileSync } from 'node:fs';\n",
                    "writeFileSync(process.env.VISA_JCO_NODE_OPTIONS_PROBE_MARKER, 'executed');\n"
                ),
            ),
        ] {
            let hook = directory.path().join(format!("{name}-hook.{extension}"));
            let marker = directory.path().join(format!("{name}-hook-ran"));
            let completed = directory.path().join(format!("{name}-probe-completed"));
            fs::write(&hook, source).expect("write Node options hook");

            let output = Command::new(env::current_exe().expect("current test executable"))
                .arg("--exact")
                .arg(TEST_NAME)
                .arg("--nocapture")
                .env("NODE_OPTIONS", format!("{option}={}", hook.display()))
                .env(PROBE_MARKER_ENV, &marker)
                .env(PROBE_COMPLETED_ENV, &completed)
                .output()
                .expect("run inherited NODE_OPTIONS probe");

            assert!(
                output.status.success(),
                "{name} probe failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(completed.is_file(), "{name} probe test did not execute");
            assert!(!marker.exists(), "{name} hook unexpectedly executed");
        }
    }

    fn run_locked_node_probe(marker: PathBuf) {
        let node = env::var_os("VISA_NODE_BIN").unwrap_or_else(|| OsString::from("node"));
        let output = locked_node_command(PathBuf::from(node).as_path())
            .arg("-e")
            .arg("process.stdout.write('locked')")
            .output()
            .expect("run locked Node command");
        assert!(
            output.status.success(),
            "locked Node command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"locked");
        assert!(!marker.exists(), "inherited NODE_OPTIONS hook executed");

        let completed = env::var_os(PROBE_COMPLETED_ENV).expect("probe completion path");
        fs::write(completed, b"completed").expect("record completed Node options probe");
    }
}
