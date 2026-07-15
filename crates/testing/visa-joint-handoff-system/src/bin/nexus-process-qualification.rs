use std::{
    env, fs,
    fs::OpenOptions,
    io::{self, Write},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use visa_joint_handoff_system::{
    NEXUS_PROCESS_AUTHENTICATION_BOUNDARY, NEXUS_PROCESS_QUALIFICATION_SCHEMA,
    NexusNativeCapability, NexusProcessQualificationInputs, NexusProcessQualificationReport,
    run_nexus_process_qualification_cell, validate_nexus_process_qualification_report,
};

const MANIFEST_SCHEMA: &str = "visa.nexus-process-joint-cell-artifact.v1";
const EVIDENCE_STATUS: &str = "same-boot-clean-exact-sha-nexus-process-joint-cell";
const REPORT_FILE: &str = "nexus-process-qualification-report.json";
const MANIFEST_FILE: &str = "nexus-process-joint-cell-manifest.json";
const INCOMPLETE_FILE: &str = "nexus-process-joint-cell-incomplete";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Run,
    Verify,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Arguments {
    mode: Mode,
    artifact_root: PathBuf,
    provenance: ArtifactProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactProvenance {
    visa_revision: String,
    nexus_revision: String,
    nexus_reference_baseline_revision: String,
    nexus_executable_path: String,
    nexus_executable_sha256: String,
    neutral_revision: String,
    neutral_tree: String,
    neutral_bundle_sha256: String,
    source_lock_sha256: String,
    nexus_qualification_lock_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactManifest {
    schema: String,
    evidence_status: String,
    report: ArtifactFile,
    provenance: ArtifactProvenance,
    limitations: ArtifactLimitations,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactFile {
    path: String,
    bytes: u64,
    sha256: String,
    schema: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactLimitations {
    same_boot_only: bool,
    registry_replacement_supported: bool,
    retained_tombstone_supported: bool,
    remote_ci_observed: bool,
}

impl ArtifactLimitations {
    fn bounded() -> Self {
        Self {
            same_boot_only: true,
            registry_replacement_supported: false,
            retained_tombstone_supported: false,
            remote_ci_observed: false,
        }
    }
}

fn main() -> ExitCode {
    match run_main() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Nexus process qualification artifact failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_main() -> Result<String, String> {
    let mut values = env::args_os();
    let program = values.next().unwrap_or_default();
    let values = values.collect::<Vec<_>>();
    let mut arguments = parse_arguments(&program, &values)?;
    validate_provenance(&arguments.provenance)?;
    arguments.provenance.nexus_executable_path = canonical_executable(
        Path::new(&arguments.provenance.nexus_executable_path),
        &arguments.provenance.nexus_executable_sha256,
    )?
    .into_os_string()
    .into_string()
    .map_err(|_| "canonical Nexus executable path is not UTF-8".to_owned())?;

    match arguments.mode {
        Mode::Run => {
            publish_artifact(&arguments.artifact_root, &arguments.provenance)?;
            Ok(format!(
                "Nexus process qualification artifact: {}",
                arguments.artifact_root.display()
            ))
        }
        Mode::Verify => {
            verify_executed_visa_checkout(&arguments.provenance.visa_revision)?;
            verify_artifact(&arguments.artifact_root, &arguments.provenance)?;
            verify_executed_visa_checkout(&arguments.provenance.visa_revision)?;
            Ok(format!(
                "Verified Nexus process qualification artifact: {}",
                arguments.artifact_root.display()
            ))
        }
    }
}

fn parse_arguments(
    program: &std::ffi::OsStr,
    values: &[std::ffi::OsString],
) -> Result<Arguments, String> {
    if values.len() != 12 {
        return Err(usage(program));
    }
    let mode = match values[0].to_str() {
        Some("run") => Mode::Run,
        Some("verify") => Mode::Verify,
        _ => return Err(usage(program)),
    };
    Ok(Arguments {
        mode,
        artifact_root: PathBuf::from(&values[1]),
        provenance: ArtifactProvenance {
            visa_revision: utf8(&values[2], "vISA revision")?,
            nexus_executable_path: utf8(&values[3], "Nexus executable path")?,
            nexus_executable_sha256: utf8(&values[4], "Nexus executable SHA-256")?,
            nexus_revision: utf8(&values[5], "Nexus revision")?,
            nexus_reference_baseline_revision: utf8(
                &values[6],
                "Nexus reference baseline revision",
            )?,
            neutral_revision: utf8(&values[7], "neutral revision")?,
            neutral_tree: utf8(&values[8], "neutral tree")?,
            neutral_bundle_sha256: utf8(&values[9], "neutral bundle SHA-256")?,
            source_lock_sha256: utf8(&values[10], "source-lock SHA-256")?,
            nexus_qualification_lock_sha256: utf8(&values[11], "Nexus qualification-lock SHA-256")?,
        },
    })
}

fn usage(program: &std::ffi::OsStr) -> String {
    format!(
        "usage: {} <run|verify> <artifact-root> <visa-sha> <nexus-effect-peer-bin> <nexus-bin-sha256> <qualified-nexus-sha> <nexus-reference-baseline-sha> <neutral-sha> <neutral-tree> <neutral-bundle-sha256> <source-lock-sha256> <nexus-qualification-lock-sha256>",
        PathBuf::from(program).display()
    )
}

fn utf8(value: &std::ffi::OsStr, label: &str) -> Result<String, String> {
    value.to_str().map(str::to_owned).ok_or_else(|| format!("{label} is not UTF-8"))
}

fn publish_artifact(root: &Path, provenance: &ArtifactProvenance) -> Result<(), String> {
    verify_executed_visa_checkout(&provenance.visa_revision)?;
    canonical_executable(
        Path::new(&provenance.nexus_executable_path),
        &provenance.nexus_executable_sha256,
    )?;

    let report = run_nexus_process_qualification_cell(NexusProcessQualificationInputs {
        executable: PathBuf::from(&provenance.nexus_executable_path),
        executable_sha256: provenance.nexus_executable_sha256.clone(),
        nexus_revision: provenance.nexus_revision.clone(),
    })?;
    validate_report_provenance(&report, provenance)?;
    canonical_executable(
        Path::new(&provenance.nexus_executable_path),
        &provenance.nexus_executable_sha256,
    )?;
    verify_executed_visa_checkout(&provenance.visa_revision)?;

    let report_bytes = canonical_json(&report, "Nexus process qualification report")?;
    let report_size = u64::try_from(report_bytes.len())
        .map_err(|_| "Nexus process qualification report is too large".to_owned())?;
    let manifest = ArtifactManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        evidence_status: EVIDENCE_STATUS.to_owned(),
        report: ArtifactFile {
            path: REPORT_FILE.to_owned(),
            bytes: report_size,
            sha256: sha256_hex(&report_bytes),
            schema: NEXUS_PROCESS_QUALIFICATION_SCHEMA.to_owned(),
        },
        provenance: provenance.clone(),
        limitations: ArtifactLimitations::bounded(),
    };
    let manifest_bytes = canonical_json(&manifest, "Nexus process qualification manifest")?;

    create_artifact_root(root)?;
    let incomplete = root.join(INCOMPLETE_FILE);
    write_new(&incomplete, b"Nexus process joint cell publication incomplete\n")?;
    let publication = (|| {
        write_new(root.join(REPORT_FILE), &report_bytes)?;
        write_new(root.join(MANIFEST_FILE), &manifest_bytes)?;
        verify_executed_visa_checkout(&provenance.visa_revision)?;
        fs::remove_file(&incomplete)
            .map_err(|error| format!("cannot remove {}: {error}", incomplete.display()))?;
        verify_artifact(root, provenance)
    })();
    if publication.is_err() && !incomplete.exists() {
        let _ = fs::write(&incomplete, b"Nexus process joint cell publication incomplete\n");
    }
    publication
}

fn verify_artifact(root: &Path, expected: &ArtifactProvenance) -> Result<(), String> {
    validate_provenance(expected)?;
    let canonical = canonical_executable(
        Path::new(&expected.nexus_executable_path),
        &expected.nexus_executable_sha256,
    )?;
    require(
        canonical == Path::new(&expected.nexus_executable_path),
        "expected Nexus executable path was not canonical",
    )?;
    validate_artifact_root(root)?;
    let manifest_raw =
        read_stable_regular(&root.join(MANIFEST_FILE), "artifact manifest", MAX_MANIFEST_BYTES)?;
    let report_raw =
        read_stable_regular(&root.join(REPORT_FILE), "raw process report", MAX_REPORT_BYTES)?;
    let manifest: ArtifactManifest =
        decode_canonical(&manifest_raw, "Nexus process qualification manifest")?;
    validate_manifest(&manifest, expected, &report_raw)?;
    let report: NexusProcessQualificationReport =
        decode_canonical(&report_raw, "Nexus process qualification report")?;
    validate_report_provenance(&report, expected)?;
    Ok(())
}

fn validate_manifest(
    manifest: &ArtifactManifest,
    expected: &ArtifactProvenance,
    report_raw: &[u8],
) -> Result<(), String> {
    require(manifest.schema == MANIFEST_SCHEMA, "artifact manifest schema drifted")?;
    require(manifest.evidence_status == EVIDENCE_STATUS, "artifact evidence status drifted")?;
    require(
        manifest.provenance == *expected,
        "artifact provenance differs from the independently supplied expectations",
    )?;
    require(
        manifest.limitations == ArtifactLimitations::bounded(),
        "artifact limitations overclaim same-boot process evidence",
    )?;
    require(
        manifest.report.path == REPORT_FILE
            && manifest.report.schema == NEXUS_PROCESS_QUALIFICATION_SCHEMA
            && manifest.report.bytes == u64::try_from(report_raw.len()).unwrap_or(u64::MAX)
            && manifest.report.sha256 == sha256_hex(report_raw),
        "raw process report does not match its exact manifest entry",
    )
}

fn validate_report_provenance(
    report: &NexusProcessQualificationReport,
    expected: &ArtifactProvenance,
) -> Result<(), String> {
    validate_nexus_process_qualification_report(report)?;
    require(
        report.authentication_boundary == NEXUS_PROCESS_AUTHENTICATION_BOUNDARY
            && report.launch.executable == Path::new(&expected.nexus_executable_path)
            && report.launch.executable_sha256 == expected.nexus_executable_sha256
            && report.launch.nexus_revision == expected.nexus_revision,
        "raw process report launch provenance drifted",
    )?;
    for scenario in &report.scenarios {
        require(
            scenario.process.executable_path == Path::new(&expected.nexus_executable_path)
                && scenario.process.executable_sha256 == expected.nexus_executable_sha256
                && scenario.process.nexus_revision == expected.nexus_revision,
            "raw process report child provenance drifted",
        )?;
    }
    require(
        matches!(
            report.capabilities.registry_replacement,
            NexusNativeCapability::Unsupported { .. }
        ) && matches!(
            report.capabilities.retained_tombstone,
            NexusNativeCapability::Unsupported { .. }
        ),
        "raw process report exceeded the declared capability boundary",
    )
}

fn validate_provenance(value: &ArtifactProvenance) -> Result<(), String> {
    for (label, digest) in [
        ("vISA revision", &value.visa_revision),
        ("qualified Nexus revision", &value.nexus_revision),
        ("Nexus reference baseline revision", &value.nexus_reference_baseline_revision),
        ("neutral revision", &value.neutral_revision),
        ("neutral tree", &value.neutral_tree),
    ] {
        require(is_lower_hex(digest, 40), &format!("{label} is not exact lowercase 40-hex"))?;
    }
    for (label, digest) in [
        ("Nexus executable SHA-256", &value.nexus_executable_sha256),
        ("neutral bundle SHA-256", &value.neutral_bundle_sha256),
        ("source-lock SHA-256", &value.source_lock_sha256),
        ("Nexus qualification-lock SHA-256", &value.nexus_qualification_lock_sha256),
    ] {
        require(is_lower_hex(digest, 64), &format!("{label} is not lowercase SHA-256"))?;
    }
    require(!value.nexus_executable_path.is_empty(), "Nexus executable path is empty")
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_executable(path: &Path, expected_sha256: &str) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| format!("cannot read current directory: {error}"))?
            .join(path)
    };
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
        format!("cannot inspect Nexus executable {}: {error}", absolute.display())
    })?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Nexus executable is not a regular non-symlink file",
    )?;
    require(
        metadata.permissions().mode() & 0o111 != 0,
        "Nexus executable has no executable permission bit",
    )?;
    let canonical = fs::canonicalize(&absolute)
        .map_err(|error| format!("cannot canonicalize Nexus executable: {error}"))?;
    require(
        canonical == absolute,
        "Nexus executable path traverses a symlink or is not canonical",
    )?;
    let bytes = read_stable_regular(&canonical, "Nexus executable", MAX_EXECUTABLE_BYTES)?;
    require(
        sha256_hex(&bytes) == expected_sha256,
        "Nexus executable SHA-256 differs from the explicit identity",
    )?;
    Ok(canonical)
}

fn create_artifact_root(root: &Path) -> Result<(), String> {
    match fs::symlink_metadata(root) {
        Ok(_) => return Err(format!("artifact root already exists: {}", root.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect artifact root: {error}")),
    }
    let parent = root.parent().ok_or_else(|| "artifact root has no parent".to_owned())?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect artifact parent {}: {error}", parent.display()))?;
    require(
        parent_metadata.is_dir() && !parent_metadata.file_type().is_symlink(),
        "artifact parent is not a real directory",
    )?;
    fs::create_dir(root)
        .map_err(|error| format!("cannot create artifact root {}: {error}", root.display()))
}

fn validate_artifact_root(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect artifact root {}: {error}", root.display()))?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "artifact root is not a real directory",
    )?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate artifact root {}: {error}", root.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot enumerate artifact entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "artifact contains a non-UTF-8 entry name".to_owned())?;
        let entry_metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect artifact entry {name}: {error}"))?;
        require(
            entry_metadata.is_file() && !entry_metadata.file_type().is_symlink(),
            "artifact contains a non-regular or symlink entry",
        )?;
        entries.push(name);
    }
    entries.sort();
    require(
        entries == [MANIFEST_FILE.to_owned(), REPORT_FILE.to_owned()],
        "artifact inventory differs from the strict two-file publication",
    )
}

fn read_stable_regular(path: &Path, label: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    require(
        before.is_file() && !before.file_type().is_symlink(),
        &format!("{label} is not a regular non-symlink file"),
    )?;
    require(
        before.len() <= u64::try_from(maximum).unwrap_or(u64::MAX),
        &format!("{label} exceeds {maximum} bytes"),
    )?;
    let bytes = fs::read(path).map_err(|error| format!("cannot read {label}: {error}"))?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot re-inspect {label}: {error}"))?;
    let before_identity =
        (before.dev(), before.ino(), before.len(), before.mtime(), before.mtime_nsec());
    let after_identity = (after.dev(), after.ino(), after.len(), after.mtime(), after.mtime_nsec());
    require(
        before_identity == after_identity
            && bytes.len() == usize::try_from(after.len()).unwrap_or(usize::MAX),
        &format!("{label} changed while being read"),
    )?;
    Ok(bytes)
}

fn canonical_json<T: Serialize>(value: &T, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|error| format!("cannot encode {label}: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode_canonical<T>(raw: &[u8], label: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice::<T>(raw)
        .map_err(|error| format!("cannot decode strict {label}: {error}"))?;
    require(
        canonical_json(&value, label)? == raw,
        &format!("{label} bytes are not canonical compact JSON plus one LF"),
    )?;
    Ok(value)
}

fn write_new(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), String> {
    let path = path.as_ref();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))
}

fn verify_executed_visa_checkout(expected_sha: &str) -> Result<(), String> {
    let head = git_output(["rev-parse", "--verify", "HEAD"])?;
    require(
        head.trim() == expected_sha,
        &format!(
            "executed vISA checkout HEAD mismatch: actual={}, expected={expected_sha}",
            head.trim()
        ),
    )?;
    let status = git_output(["status", "--porcelain=v1", "--untracked-files=all"])?;
    require(
        status.is_empty(),
        "executed vISA checkout is not clean, including non-ignored untracked files",
    )
}

fn git_output<const N: usize>(arguments: [&str; N]) -> Result<String, String> {
    let output = Command::new("git")
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot execute git: {error}"))?;
    require(
        output.status.success(),
        &format!("git command failed: {}", String::from_utf8_lossy(&output.stderr).trim()),
    )?;
    String::from_utf8(output.stdout).map_err(|_| "git output is not UTF-8".to_owned())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};

    use serde_json::Value;

    use super::*;

    fn provenance() -> ArtifactProvenance {
        ArtifactProvenance {
            visa_revision: "1".repeat(40),
            nexus_revision: "2".repeat(40),
            nexus_reference_baseline_revision: "9".repeat(40),
            nexus_executable_path: "/tmp/nexus-effect-peer".to_owned(),
            nexus_executable_sha256: "3".repeat(64),
            neutral_revision: "4".repeat(40),
            neutral_tree: "5".repeat(40),
            neutral_bundle_sha256: "6".repeat(64),
            source_lock_sha256: "7".repeat(64),
            nexus_qualification_lock_sha256: "8".repeat(64),
        }
    }

    fn manifest(report: &[u8]) -> ArtifactManifest {
        ArtifactManifest {
            schema: MANIFEST_SCHEMA.to_owned(),
            evidence_status: EVIDENCE_STATUS.to_owned(),
            report: ArtifactFile {
                path: REPORT_FILE.to_owned(),
                bytes: u64::try_from(report.len()).unwrap(),
                sha256: sha256_hex(report),
                schema: NEXUS_PROCESS_QUALIFICATION_SCHEMA.to_owned(),
            },
            provenance: provenance(),
            limitations: ArtifactLimitations::bounded(),
        }
    }

    #[test]
    fn parser_requires_mode_and_every_exact_provenance_value() {
        let values = [
            "run",
            "artifact",
            &"1".repeat(40),
            "/tmp/nexus-effect-peer",
            &"3".repeat(64),
            &"2".repeat(40),
            &"9".repeat(40),
            &"4".repeat(40),
            &"5".repeat(40),
            &"6".repeat(64),
            &"7".repeat(64),
            &"8".repeat(64),
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        let parsed = parse_arguments(OsStr::new("runner"), &values).unwrap();
        assert_eq!(parsed.mode, Mode::Run);
        assert_eq!(parsed.provenance, provenance());
        assert!(parse_arguments(OsStr::new("runner"), &values[..11]).is_err());
        let mut invalid = values;
        invalid[0] = OsString::from("inspect");
        assert!(parse_arguments(OsStr::new("runner"), &invalid).is_err());
    }

    #[test]
    fn provenance_rejects_moving_or_noncanonical_identities() {
        let mut value = provenance();
        assert_eq!(validate_provenance(&value), Ok(()));
        value.nexus_revision = "main".to_owned();
        assert!(validate_provenance(&value).is_err());
        value.nexus_revision = "2".repeat(40);
        value.source_lock_sha256 = "A".repeat(64);
        assert!(validate_provenance(&value).is_err());
    }

    #[test]
    fn manifest_is_strict_canonical_json() {
        let report = b"{}\n";
        let value = manifest(report);
        let canonical = canonical_json(&value, "manifest").unwrap();
        assert_eq!(decode_canonical::<ArtifactManifest>(&canonical, "manifest").unwrap(), value);

        let mut noncanonical = canonical.clone();
        noncanonical.push(b'\n');
        assert!(decode_canonical::<ArtifactManifest>(&noncanonical, "manifest").is_err());

        let mut unknown: Value = serde_json::from_slice(&canonical).unwrap();
        unknown["unknown"] = Value::Bool(true);
        let unknown = canonical_json(&unknown, "manifest").unwrap();
        assert!(decode_canonical::<ArtifactManifest>(&unknown, "manifest").is_err());
    }

    #[test]
    fn manifest_rejects_provenance_and_limitation_mutations() {
        let report = b"{}\n";
        let expected = provenance();
        let mut value = manifest(report);
        value.provenance.neutral_tree = "9".repeat(40);
        assert!(validate_manifest(&value, &expected, report).is_err());

        let mut value = manifest(report);
        value.limitations.remote_ci_observed = true;
        assert!(validate_manifest(&value, &expected, report).is_err());
    }

    #[test]
    fn manifest_rejects_raw_report_byte_mutation() {
        let report = b"{}\n";
        let value = manifest(report);
        assert_eq!(validate_manifest(&value, &provenance(), report), Ok(()));
        assert!(validate_manifest(&value, &provenance(), b"{ }\n").is_err());
    }
}
