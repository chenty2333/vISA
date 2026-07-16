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

const MANIFEST_SCHEMA: &str = "visa.nexus-process-joint-cell-artifact.v3";
const EVIDENCE_STATUS: &str = "same-boot-clean-exact-sha-nexus-process-joint-cell";
const REPORT_FILE: &str = "nexus-process-qualification-report.json";
const NEXUS_EFFECT_PEER_FILE: &str = "nexus-effect-peer";
const NEXUS_EFFECT_PEER_SCHEMA: &str = "opaque-executable-file-sha256-v1";
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
    execution_executable: Option<PathBuf>,
    provenance: ArtifactProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactProvenance {
    visa_revision: String,
    nexus_revision: String,
    nexus_reference_baseline_revision: String,
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
    nexus_effect_peer: ArtifactFile,
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
    artifact_binary_reexecution_claimed: bool,
    artifact_file_mode_is_evidence: bool,
    source_to_binary_reproducibility_claimed: bool,
    registry_replacement_supported: bool,
    retained_tombstone_supported: bool,
    remote_ci_observed: bool,
}

impl ArtifactLimitations {
    fn bounded() -> Self {
        Self {
            same_boot_only: true,
            artifact_binary_reexecution_claimed: false,
            artifact_file_mode_is_evidence: false,
            source_to_binary_reproducibility_claimed: false,
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
    let arguments = parse_arguments(&program, &values)?;
    validate_provenance(&arguments.provenance)?;

    match arguments.mode {
        Mode::Run => {
            let executable = arguments
                .execution_executable
                .as_deref()
                .ok_or_else(|| "run mode omitted the Nexus executable path".to_owned())?;
            let executable =
                canonical_executable(executable, &arguments.provenance.nexus_executable_sha256)?;
            publish_artifact(&arguments.artifact_root, &executable, &arguments.provenance)?;
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
    let mode = match values.first().and_then(|value| value.to_str()) {
        Some("run") => Mode::Run,
        Some("verify") => Mode::Verify,
        _ => return Err(usage(program)),
    };
    let (execution_executable, identity_offset) = match mode {
        Mode::Run if values.len() == 12 => (Some(PathBuf::from(&values[3])), 1),
        Mode::Verify if values.len() == 11 => (None, 0),
        _ => return Err(usage(program)),
    };
    Ok(Arguments {
        mode,
        artifact_root: PathBuf::from(&values[1]),
        execution_executable,
        provenance: ArtifactProvenance {
            visa_revision: utf8(&values[2], "vISA revision")?,
            nexus_executable_sha256: utf8(
                &values[3 + identity_offset],
                "Nexus executable SHA-256",
            )?,
            nexus_revision: utf8(&values[4 + identity_offset], "Nexus revision")?,
            nexus_reference_baseline_revision: utf8(
                &values[5 + identity_offset],
                "Nexus reference baseline revision",
            )?,
            neutral_revision: utf8(&values[6 + identity_offset], "neutral revision")?,
            neutral_tree: utf8(&values[7 + identity_offset], "neutral tree")?,
            neutral_bundle_sha256: utf8(&values[8 + identity_offset], "neutral bundle SHA-256")?,
            source_lock_sha256: utf8(&values[9 + identity_offset], "source-lock SHA-256")?,
            nexus_qualification_lock_sha256: utf8(
                &values[10 + identity_offset],
                "Nexus qualification-lock SHA-256",
            )?,
        },
    })
}

fn usage(program: &std::ffi::OsStr) -> String {
    format!(
        "usage: {} run <artifact-root> <visa-sha> <nexus-effect-peer-bin> <nexus-bin-sha256> <qualified-nexus-sha> <nexus-reference-baseline-sha> <neutral-sha> <neutral-tree> <neutral-bundle-sha256> <source-lock-sha256> <nexus-qualification-lock-sha256>\n       {} verify <artifact-root> <visa-sha> <nexus-bin-sha256> <qualified-nexus-sha> <nexus-reference-baseline-sha> <neutral-sha> <neutral-tree> <neutral-bundle-sha256> <source-lock-sha256> <nexus-qualification-lock-sha256>",
        PathBuf::from(program).display(),
        PathBuf::from(program).display()
    )
}

fn utf8(value: &std::ffi::OsStr, label: &str) -> Result<String, String> {
    value.to_str().map(str::to_owned).ok_or_else(|| format!("{label} is not UTF-8"))
}

fn publish_artifact(
    root: &Path,
    executable: &Path,
    provenance: &ArtifactProvenance,
) -> Result<(), String> {
    verify_executed_visa_checkout(&provenance.visa_revision)?;
    let canonical = canonical_executable(executable, &provenance.nexus_executable_sha256)?;

    let report = run_nexus_process_qualification_cell(NexusProcessQualificationInputs {
        executable: canonical.clone(),
        executable_sha256: provenance.nexus_executable_sha256.clone(),
        nexus_revision: provenance.nexus_revision.clone(),
    })?;
    validate_report_provenance(&report, provenance)?;
    let executable_bytes = read_stable_executable(&canonical, "executed Nexus executable")?;
    require(
        sha256_hex(&executable_bytes) == provenance.nexus_executable_sha256,
        "executed Nexus executable changed before artifact capture",
    )?;
    require(
        canonical_executable(&canonical, &provenance.nexus_executable_sha256)? == canonical,
        "executed Nexus executable identity changed before artifact capture",
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
        nexus_effect_peer: ArtifactFile {
            path: NEXUS_EFFECT_PEER_FILE.to_owned(),
            bytes: u64::try_from(executable_bytes.len())
                .map_err(|_| "executed Nexus executable is too large".to_owned())?,
            sha256: sha256_hex(&executable_bytes),
            schema: NEXUS_EFFECT_PEER_SCHEMA.to_owned(),
        },
        provenance: provenance.clone(),
        limitations: ArtifactLimitations::bounded(),
    };
    let manifest_bytes = canonical_json(&manifest, "Nexus process qualification manifest")?;

    create_artifact_root(root)?;
    let incomplete = root.join(INCOMPLETE_FILE);
    write_new(&incomplete, b"Nexus process joint cell publication incomplete\n")?;
    let publication = (|| {
        write_new_executable(root.join(NEXUS_EFFECT_PEER_FILE), &executable_bytes)?;
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
    validate_artifact_root(root)?;
    let manifest_raw =
        read_stable_regular(&root.join(MANIFEST_FILE), "artifact manifest", MAX_MANIFEST_BYTES)?;
    let report_raw =
        read_stable_regular(&root.join(REPORT_FILE), "raw process report", MAX_REPORT_BYTES)?;
    let executable_raw = read_stable_artifact_binary(
        &root.join(NEXUS_EFFECT_PEER_FILE),
        "artifact Nexus executable bytes",
    )?;
    let manifest: ArtifactManifest =
        decode_canonical(&manifest_raw, "Nexus process qualification manifest")?;
    validate_manifest(&manifest, expected, &report_raw, &executable_raw)?;
    let report: NexusProcessQualificationReport =
        decode_canonical(&report_raw, "Nexus process qualification report")?;
    validate_report_provenance(&report, expected)?;
    Ok(())
}

fn validate_manifest(
    manifest: &ArtifactManifest,
    expected: &ArtifactProvenance,
    report_raw: &[u8],
    executable_raw: &[u8],
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
    )?;
    require(
        manifest.nexus_effect_peer.path == NEXUS_EFFECT_PEER_FILE
            && manifest.nexus_effect_peer.schema == NEXUS_EFFECT_PEER_SCHEMA
            && manifest.nexus_effect_peer.bytes
                == u64::try_from(executable_raw.len()).unwrap_or(u64::MAX)
            && manifest.nexus_effect_peer.sha256 == sha256_hex(executable_raw)
            && manifest.nexus_effect_peer.sha256 == expected.nexus_executable_sha256,
        "artifact Nexus executable does not match its exact manifest and provenance identity",
    )
}

fn validate_report_provenance(
    report: &NexusProcessQualificationReport,
    expected: &ArtifactProvenance,
) -> Result<(), String> {
    validate_nexus_process_qualification_report(report)?;
    require(
        report.authentication_boundary == NEXUS_PROCESS_AUTHENTICATION_BOUNDARY
            && report.launch.executable.is_absolute()
            && report.launch.executable_sha256 == expected.nexus_executable_sha256
            && report.launch.nexus_revision == expected.nexus_revision,
        "raw process report launch provenance drifted",
    )?;
    for scenario in &report.scenarios {
        require(
            scenario.process.executable_path == report.launch.executable
                && scenario.process.executable_sha256 == expected.nexus_executable_sha256
                && scenario.process.nexus_revision == expected.nexus_revision,
            "raw process report child provenance differs from its historical launch observation",
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
    Ok(())
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
    let bytes = read_stable_executable(&canonical, "Nexus executable")?;
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
        entries
            == [
                NEXUS_EFFECT_PEER_FILE.to_owned(),
                MANIFEST_FILE.to_owned(),
                REPORT_FILE.to_owned(),
            ],
        "artifact inventory differs from the strict three-file publication",
    )
}

fn read_stable_executable(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        &format!("{label} is not a regular non-symlink file"),
    )?;
    require(
        metadata.permissions().mode() & 0o111 != 0,
        &format!("{label} has no executable permission bit"),
    )?;
    read_stable_regular(path, label, MAX_EXECUTABLE_BYTES)
}

fn read_stable_artifact_binary(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    require(
        before.is_file() && !before.file_type().is_symlink() && before.nlink() == 1,
        &format!("{label} is not a single-link regular non-symlink file"),
    )?;
    require(
        before.len() <= u64::try_from(MAX_EXECUTABLE_BYTES).unwrap_or(u64::MAX),
        &format!("{label} exceeds {MAX_EXECUTABLE_BYTES} bytes"),
    )?;
    let bytes = fs::read(path).map_err(|error| format!("cannot read {label}: {error}"))?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot re-inspect {label}: {error}"))?;
    require(
        after.is_file()
            && !after.file_type().is_symlink()
            && after.nlink() == 1
            && (before.dev(), before.ino(), before.len())
                == (after.dev(), after.ino(), after.len())
            && bytes.len() == usize::try_from(after.len()).unwrap_or(usize::MAX),
        &format!("{label} changed while being read"),
    )?;
    Ok(bytes)
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
    let before_identity = (
        before.dev(),
        before.ino(),
        before.mode(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
    );
    let after_identity =
        (after.dev(), after.ino(), after.mode(), after.len(), after.mtime(), after.mtime_nsec());
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

fn write_new_executable(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), String> {
    let path = path.as_ref();
    write_new(path, bytes)?;
    let mut permissions = fs::symlink_metadata(path)
        .map_err(|error| {
            format!("cannot inspect published executable {}: {error}", path.display())
        })?
        .permissions();
    permissions.set_mode(0o500);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("cannot set executable mode on {}: {error}", path.display()))?;
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| format!("cannot reopen {} after chmod: {error}", path.display()))?;
    file.sync_all().map_err(|error| format!("cannot sync executable {}: {error}", path.display()))
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
    use std::{
        ffi::{OsStr, OsString},
        os::unix::fs::{PermissionsExt as _, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::Value;

    use super::*;

    const EXECUTABLE_BYTES: &[u8] = b"exact Nexus executable fixture bytes";
    static NEXT_TEMP_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            loop {
                let sequence = NEXT_TEMP_ROOT.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir().join(format!(
                    "visa-nexus-process-artifact-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create temporary artifact root: {error}"),
                }
            }
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn provenance() -> ArtifactProvenance {
        ArtifactProvenance {
            visa_revision: "1".repeat(40),
            nexus_revision: "2".repeat(40),
            nexus_reference_baseline_revision: "9".repeat(40),
            nexus_executable_sha256: sha256_hex(EXECUTABLE_BYTES),
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
            nexus_effect_peer: ArtifactFile {
                path: NEXUS_EFFECT_PEER_FILE.to_owned(),
                bytes: u64::try_from(EXECUTABLE_BYTES.len()).unwrap(),
                sha256: sha256_hex(EXECUTABLE_BYTES),
                schema: NEXUS_EFFECT_PEER_SCHEMA.to_owned(),
            },
            provenance: provenance(),
            limitations: ArtifactLimitations::bounded(),
        }
    }

    #[test]
    fn parser_requires_mode_and_every_exact_provenance_value() {
        let run_values = [
            "run",
            "artifact",
            &"1".repeat(40),
            "/tmp/nexus-effect-peer",
            &sha256_hex(EXECUTABLE_BYTES),
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
        let parsed_run = parse_arguments(OsStr::new("runner"), &run_values).unwrap();
        assert_eq!(parsed_run.mode, Mode::Run);
        assert_eq!(parsed_run.execution_executable, Some("/tmp/nexus-effect-peer".into()));
        assert_eq!(parsed_run.provenance, provenance());

        let mut verify_values = run_values.clone();
        verify_values[0] = OsString::from("verify");
        verify_values.remove(3);
        let parsed_verify = parse_arguments(OsStr::new("runner"), &verify_values).unwrap();
        assert_eq!(parsed_verify.mode, Mode::Verify);
        assert_eq!(parsed_verify.execution_executable, None);
        assert_eq!(parsed_verify.provenance, provenance());
        assert!(parse_arguments(OsStr::new("runner"), &[]).is_err());
        assert!(parse_arguments(OsStr::new("runner"), &run_values[..11]).is_err());
        assert!(parse_arguments(OsStr::new("runner"), &verify_values[..10]).is_err());
        let mut invalid = run_values;
        invalid[0] = OsString::from("inspect");
        assert!(parse_arguments(OsStr::new("runner"), &invalid).is_err());
    }

    #[test]
    fn canonical_provenance_does_not_include_the_historical_execution_path() {
        let mut first = [
            "run",
            "artifact",
            &"1".repeat(40),
            "/tmp/first/nexus-effect-peer",
            &sha256_hex(EXECUTABLE_BYTES),
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
        let first_parsed = parse_arguments(OsStr::new("runner"), &first).unwrap();
        first[3] = OsString::from("/tmp/second/nexus-effect-peer");
        let second_parsed = parse_arguments(OsStr::new("runner"), &first).unwrap();
        assert_ne!(first_parsed.execution_executable, second_parsed.execution_executable);
        assert_eq!(first_parsed.provenance, second_parsed.provenance);
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
        value.schema = "visa.nexus-process-joint-cell-artifact.v2".to_owned();
        assert!(validate_manifest(&value, &expected, report, EXECUTABLE_BYTES).is_err());

        let mut value = manifest(report);
        value.provenance.neutral_tree = "9".repeat(40);
        assert!(validate_manifest(&value, &expected, report, EXECUTABLE_BYTES).is_err());

        let mut value = manifest(report);
        value.limitations.remote_ci_observed = true;
        assert!(validate_manifest(&value, &expected, report, EXECUTABLE_BYTES).is_err());

        let mut value = manifest(report);
        value.limitations.artifact_file_mode_is_evidence = true;
        assert!(validate_manifest(&value, &expected, report, EXECUTABLE_BYTES).is_err());
    }

    #[test]
    fn manifest_rejects_raw_report_or_executable_byte_mutation() {
        let report = b"{}\n";
        let value = manifest(report);
        assert_eq!(validate_manifest(&value, &provenance(), report, EXECUTABLE_BYTES), Ok(()));
        assert!(validate_manifest(&value, &provenance(), b"{ }\n", EXECUTABLE_BYTES).is_err());
        assert!(validate_manifest(&value, &provenance(), report, b"mutated").is_err());
    }

    #[test]
    fn manifest_rejects_executable_path_size_digest_and_schema_mutations() {
        let report = b"{}\n";
        let expected = provenance();
        let mut mutations = Vec::new();

        let mut value = manifest(report);
        value.nexus_effect_peer.path = "../nexus-effect-peer".to_owned();
        mutations.push(value);
        let mut value = manifest(report);
        value.nexus_effect_peer.bytes += 1;
        mutations.push(value);
        let mut value = manifest(report);
        value.nexus_effect_peer.sha256 = "a".repeat(64);
        mutations.push(value);
        let mut value = manifest(report);
        value.nexus_effect_peer.schema = "opaque-executable-file-sha256-v2".to_owned();
        mutations.push(value);

        for value in mutations {
            assert!(validate_manifest(&value, &expected, report, EXECUTABLE_BYTES).is_err());
        }
    }

    #[test]
    fn artifact_binary_accepts_0644_and_rejects_symlink_hardlink_and_tamper() {
        let root = TempRoot::new();
        fs::write(root.0.join(MANIFEST_FILE), b"manifest").unwrap();
        fs::write(root.0.join(REPORT_FILE), b"report").unwrap();
        let binary = root.0.join(NEXUS_EFFECT_PEER_FILE);
        write_new_executable(&binary, EXECUTABLE_BYTES).unwrap();
        let mut permissions = fs::symlink_metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&binary, permissions).unwrap();
        assert_eq!(validate_artifact_root(&root.0), Ok(()));
        assert_eq!(read_stable_artifact_binary(&binary, "fixture").unwrap(), EXECUTABLE_BYTES);
        assert!(read_stable_executable(&binary, "execution fixture").is_err());

        fs::write(root.0.join("unexpected"), b"extra").unwrap();
        assert!(validate_artifact_root(&root.0).is_err());
        fs::remove_file(root.0.join("unexpected")).unwrap();

        let hardlink = root.0.join("hardlink");
        fs::hard_link(&binary, &hardlink).unwrap();
        assert!(read_stable_artifact_binary(&binary, "fixture").is_err());
        fs::remove_file(hardlink).unwrap();

        fs::write(&binary, b"tampered executable bytes").unwrap();
        let tampered = read_stable_artifact_binary(&binary, "fixture").unwrap();
        assert!(validate_manifest(&manifest(b"{}\n"), &provenance(), b"{}\n", &tampered).is_err());

        fs::remove_file(&binary).unwrap();
        symlink(REPORT_FILE, &binary).unwrap();
        assert!(validate_artifact_root(&root.0).is_err());
        assert!(read_stable_artifact_binary(&binary, "fixture").is_err());
    }
}
