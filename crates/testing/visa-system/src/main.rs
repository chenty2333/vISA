use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use visa_conformance::{
    STAGE1_CASE_DEFINITIONS, Stage1AuthorityEnforcementIdentity, Stage1ExecutionEnvironment,
    Stage1IsaIdentity, Stage1ProviderIdentity, Stage1ResourceKind, Stage1ResourceProfile,
    Stage1VersionedIdentity,
};
use visa_runtime::canonical_digest;
use visa_system::{
    build_info, component,
    evidence::{
        EVIDENCE_BUNDLE_FILE, EvidenceContext, EvidenceErrorKind, EvidenceProvenanceFiles,
        EvidenceWriter,
    },
    fixture::FixtureSpec,
    protocol::{RuntimeIdentityView, RuntimeImplementation},
    runner::{
        RoleLaunchers, Stage1RunOutput, Stage2StrictLineageSources, run_stage1,
        run_stage1_with_launchers, run_stage1_with_runtimes, run_stage2_matrix,
        run_stage2_strict_matrix,
    },
    target::{TargetHelloV1, observe_target},
    worker::{RunExit, run_stdio},
};

mod stage4_command;

const EXPECTED_STAGE1_CASES: usize = 31;
const BASELINE_CASE_ID: &str = "evidence-verification";
const REPORT_FAILURE_CASE_ID: &str = "report-generation-fails-after-commit";
const SUBSTRATE_HOST_VERSION: &str = "0.1.0";
const RUSQLITE_VERSION: &str = "0.40.1";
const WIT_COMPONENT_VERSION: &str = "0.244.0";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err((code, message)) => {
            eprintln!("{message}");
            ExitCode::from(code)
        }
    }
}

fn run() -> Result<ExitCode, (u8, String)> {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_default();
    let arguments = arguments.collect::<Vec<_>>();
    match parse_mode(&program, &arguments)? {
        Mode::TargetHello { nonce } => run_target_hello_command(&nonce),
        Mode::Worker => match run_stdio() {
            Ok(RunExit::EndOfInput) => Ok(ExitCode::SUCCESS),
            Ok(RunExit::Requested(code)) => requested_exit_code(code),
            Err(error) => Err((2, format!("worker I/O failed: {error}"))),
        },
        Mode::Stage1(artifact_root) => run_stage1_command(&artifact_root),
        Mode::Stage2(artifact_root) => run_stage2_command(&artifact_root),
        Mode::Stage2Strict(artifact_root) => run_stage2_strict_command(&artifact_root),
        Mode::Stage4(artifact_root) => stage4_command::run_stage4_command(&artifact_root),
        Mode::Cell { source, destination, artifact_root } => {
            run_cell_command(&artifact_root, source, destination)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    TargetHello {
        nonce: String,
    },
    Worker,
    Stage1(PathBuf),
    Stage2(PathBuf),
    Stage2Strict(PathBuf),
    Stage4(PathBuf),
    Cell {
        source: RuntimeImplementation,
        destination: RuntimeImplementation,
        artifact_root: PathBuf,
    },
}

fn parse_mode(program: &OsStr, arguments: &[OsString]) -> Result<Mode, (u8, String)> {
    match arguments {
        [command, nonce] if command == "target-hello" => {
            let nonce = nonce
                .to_str()
                .ok_or_else(|| (64, "target hello nonce must be valid UTF-8".to_owned()))?;
            visa_system::target::validate_target_nonce(nonce)
                .map_err(|error| (64, error.to_string()))?;
            Ok(Mode::TargetHello { nonce: nonce.to_owned() })
        }
        [command] if command == "worker" => Ok(Mode::Worker),
        [command, artifact_root]
            if command == "stage1" && !artifact_root.as_os_str().is_empty() =>
        {
            Ok(Mode::Stage1(PathBuf::from(artifact_root)))
        }
        [command, artifact_root]
            if command == "stage2" && !artifact_root.as_os_str().is_empty() =>
        {
            Ok(Mode::Stage2(PathBuf::from(artifact_root)))
        }
        [command, artifact_root]
            if command == "stage2-strict" && !artifact_root.as_os_str().is_empty() =>
        {
            Ok(Mode::Stage2Strict(PathBuf::from(artifact_root)))
        }
        [command, artifact_root]
            if command == "stage4" && !artifact_root.as_os_str().is_empty() =>
        {
            Ok(Mode::Stage4(PathBuf::from(artifact_root)))
        }
        [command, source, destination, artifact_root]
            if command == "cell" && !artifact_root.as_os_str().is_empty() =>
        {
            Ok(Mode::Cell {
                source: parse_runtime(source)?,
                destination: parse_runtime(destination)?,
                artifact_root: PathBuf::from(artifact_root),
            })
        }
        _ => Err((64, usage(program))),
    }
}

fn usage(program: &OsStr) -> String {
    format!(
        "usage: {} target-hello <64-lowercase-hex-nonce>\n       {} worker\n       {} stage1 <artifact-root>\n       {} stage2 <artifact-root>\n       {} stage2-strict <artifact-root>\n       {} stage4 <artifact-root>\n       {} cell <wasmtime|jco-node|wacogo> <wasmtime|jco-node|wacogo> <artifact-root>",
        PathBuf::from(program).display(),
        PathBuf::from(program).display(),
        PathBuf::from(program).display(),
        PathBuf::from(program).display(),
        PathBuf::from(program).display(),
        PathBuf::from(program).display(),
        PathBuf::from(program).display()
    )
}

fn run_target_hello_command(nonce: &str) -> Result<ExitCode, (u8, String)> {
    let hello = observe_target(nonce)
        .map_err(|error| (2, format!("target hello observation failed: {error}")))?;
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer(&mut writer, &hello)
        .map_err(|error| (2, format!("cannot encode target hello: {error}")))?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|error| (2, format!("cannot write target hello: {error}")))?;
    Ok(ExitCode::SUCCESS)
}

fn parse_runtime(value: &OsStr) -> Result<RuntimeImplementation, (u8, String)> {
    match value.to_str() {
        Some("wasmtime") => Ok(RuntimeImplementation::Wasmtime),
        Some("jco-node") => Ok(RuntimeImplementation::JcoNode),
        Some("wacogo") => Ok(RuntimeImplementation::Wacogo),
        _ => Err((64, format!("unknown runtime implementation: {}", value.to_string_lossy()))),
    }
}

fn run_stage1_command(artifact_root: &Path) -> Result<ExitCode, (u8, String)> {
    let executable = current_executable()?;
    run_evidence_cell(
        artifact_root,
        &executable,
        RuntimeImplementation::Wasmtime,
        RuntimeImplementation::Wasmtime,
        true,
        None,
    )?;
    Ok(ExitCode::SUCCESS)
}

fn run_stage2_command(artifact_root: &Path) -> Result<ExitCode, (u8, String)> {
    let artifact_root = usable_artifact_root(artifact_root)?;
    let executable = current_executable()?;
    let output = run_stage2_matrix(&artifact_root, |plan| {
        run_evidence_cell(
            &plan.artifact_root,
            &executable,
            plan.source_runtime,
            plan.destination_runtime,
            false,
            Some(&plan.common_input_sha256),
        )
        .map(|_| ())
        .map_err(|(_, message)| message)
    })
    .map_err(|error| (1, format!("Stage 2 runner failed: {error}")))?;

    println!("Stage 2 evidence bundle: {}", output.evidence_path.display());
    println!("Stage 2 matrix manifest: {}", output.matrix_manifest_path.display());
    println!("Stage 2 artifact root: {}", output.artifact_root.display());
    println!("Stage 2 bundle id: {}", output.bundle_id);
    println!("Stage 2 bundle sha256: {}", output.bundle_sha256);
    println!("Stage 2 cases: 124/124 (31 cases x 4 cells)");
    Ok(ExitCode::SUCCESS)
}

fn run_stage2_strict_command(artifact_root: &Path) -> Result<ExitCode, (u8, String)> {
    let artifact_root = usable_artifact_root(artifact_root)?;
    let executable = current_executable()?;
    let sidecar = env::var_os("VISA_WACOGO_BIN").map(PathBuf::from).ok_or_else(|| {
        (
            64,
            "stage2-strict requires VISA_WACOGO_BIN to name the locked production sidecar"
                .to_owned(),
        )
    })?;
    let build_receipt =
        env::var_os("VISA_WACOGO_BUILD_RECEIPT").map(PathBuf::from).unwrap_or_else(|| {
            sidecar.parent().unwrap_or_else(|| Path::new(".")).join("build-receipt.json")
        });
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let lineage = Stage2StrictLineageSources {
        cargo_lock: workspace_root.join("Cargo.lock"),
        wacogo_source_lock: workspace_root.join("third_party/wacogo/source-lock.json"),
        wacogo_build_receipt: build_receipt,
        wacogo_sidecar: sidecar,
    };
    let output = run_stage2_strict_matrix(&artifact_root, &lineage, |plan| {
        run_evidence_cell(
            &plan.artifact_root,
            &executable,
            plan.source_runtime,
            plan.destination_runtime,
            false,
            Some(&plan.common_input_sha256),
        )
        .map(|_| ())
        .map_err(|(_, message)| message)
    })
    .map_err(|error| (1, format!("Strict Stage 2 runner failed: {error}")))?;

    println!("Strict Stage 2 evidence bundle: {}", output.evidence_path.display());
    println!("Strict Stage 2 matrix manifest: {}", output.matrix_manifest_path.display());
    println!("Strict Stage 2 artifact root: {}", output.artifact_root.display());
    println!("Strict Stage 2 bundle id: {}", output.bundle_id);
    println!("Strict Stage 2 bundle sha256: {}", output.bundle_sha256);
    println!("Strict Stage 2 cases: 124/124 (31 cases x 4 Wasmtime/Wacogo cells)");
    Ok(ExitCode::SUCCESS)
}

fn run_cell_command(
    artifact_root: &Path,
    source: RuntimeImplementation,
    destination: RuntimeImplementation,
) -> Result<ExitCode, (u8, String)> {
    let executable = current_executable()?;
    run_evidence_cell(artifact_root, &executable, source, destination, false, None)?;
    Ok(ExitCode::SUCCESS)
}

fn run_evidence_cell(
    artifact_root: &Path,
    executable: &Path,
    source: RuntimeImplementation,
    destination: RuntimeImplementation,
    stage1_default: bool,
    stage2_common_input_sha256: Option<&str>,
) -> Result<Stage1RunOutput, (u8, String)> {
    let artifact_root = usable_artifact_root(artifact_root)?;
    let output = if stage1_default {
        run_stage1(executable, &artifact_root)
    } else {
        run_stage1_with_runtimes(executable, &artifact_root, source, destination)
    }
    .map_err(|error| (1, format!("Stage 1 runner failed: {error}")))?;
    publish_stage1_run(&artifact_root, executable, &output, stage2_common_input_sha256)?;
    Ok(output)
}

fn run_evidence_cell_with_launchers(
    artifact_root: &Path,
    provenance_executable: &Path,
    launchers: RoleLaunchers,
) -> Result<Stage1RunOutput, (u8, String)> {
    let artifact_root = usable_artifact_root(artifact_root)?;
    let output = run_stage1_with_launchers(
        launchers,
        &artifact_root,
        RuntimeImplementation::Wasmtime,
        RuntimeImplementation::Wasmtime,
    )
    .map_err(|error| (1, format!("Stage 1 runner failed: {error}")))?;
    publish_stage1_run(&artifact_root, provenance_executable, &output, None)?;
    Ok(output)
}

fn publish_stage1_run(
    artifact_root: &Path,
    executable: &Path,
    output: &Stage1RunOutput,
    stage2_common_input_sha256: Option<&str>,
) -> Result<(), (u8, String)> {
    if STAGE1_CASE_DEFINITIONS.len() != EXPECTED_STAGE1_CASES {
        return Err((
            1,
            format!(
                "Stage 1 registry contains {} cases, expected {EXPECTED_STAGE1_CASES}",
                STAGE1_CASE_DEFINITIONS.len()
            ),
        ));
    }
    if output.records.len() != EXPECTED_STAGE1_CASES {
        return Err((
            1,
            format!(
                "Stage 1 runner produced {} records, expected {EXPECTED_STAGE1_CASES}",
                output.records.len()
            ),
        ));
    }

    let baseline = FixtureSpec::new(BASELINE_CASE_ID)
        .map_err(|error| (1, format!("cannot construct Stage 1 baseline profile: {error}")))?;
    let provenance_files = prepare_provenance_files(artifact_root, executable, &baseline, output)?;
    let timer_profile_digest = canonical_digest(&baseline.profile.timer)
        .map_err(|_| (1, "cannot digest Stage 1 timer profile".to_owned()))?;
    let key_value_profile_digest = canonical_digest(&baseline.profile.key_value)
        .map_err(|_| (1, "cannot digest Stage 1 key-value profile".to_owned()))?;
    let profile_version =
        format!("{}.{}", baseline.profile.version.major, baseline.profile.version.minor);
    let environment = execution_environment(
        &profile_version,
        timer_profile_digest,
        key_value_profile_digest,
        output.policy_digest,
        output,
    );
    let bundle_id =
        format!("stage1-{}-{}", output.started_at_unix_ms, &digest_hex(output.config_digest)[..16]);
    let context = EvidenceContext::new(
        bundle_id,
        output.started_at_unix_ms,
        output.finished_at_unix_ms,
        environment,
        baseline.component_digest,
        baseline.profile_digest,
        output.config_digest,
        output.policy_digest,
        output.source_digest,
        output.toolchain_digest,
        provenance_files,
    );
    let writer = EvidenceWriter::new(artifact_root);
    let bundle_path = writer.bundle_path();
    install_bundle_failure_directory(artifact_root, &bundle_path)?;
    let publish_error = match writer.write_prepublication(&context, &output.records) {
        Err(error) => error,
        Ok(_) => {
            return Err((
                1,
                "injected bundle-path directory did not reject the first bundle publication"
                    .to_owned(),
            ));
        }
    };
    if publish_error.kind != EvidenceErrorKind::Io {
        return Err((
            1,
            format!(
                "injected Stage 1 report publication failed as {:?}, expected Io: {}",
                publish_error.kind, publish_error
            ),
        ));
    }
    let manifest_count = STAGE1_CASE_DEFINITIONS
        .iter()
        .filter(|definition| {
            artifact_root.join("cases").join(definition.id).join("manifest.json").is_file()
        })
        .count();
    if manifest_count != EXPECTED_STAGE1_CASES {
        return Err((
            1,
            format!(
                "report failure occurred after {manifest_count} case manifests, expected {EXPECTED_STAGE1_CASES}"
            ),
        ));
    }
    let manifest_set_sha256 = writer
        .manifest_set_sha256()
        .map_err(|error| (1, format!("cannot digest committed Stage 1 case manifests: {error}")))?;
    let report_state_sha256 = output
        .records
        .iter()
        .find(|record| record.case_id == REPORT_FAILURE_CASE_ID)
        .map(|record| digest_hex(record.state_digest))
        .ok_or_else(|| (1, "report-failure execution record is missing".to_owned()))?;
    remove_injected_bundle_directory(artifact_root, &bundle_path)?;
    let regenerated = writer.regenerate_prepublication(&context).map_err(|error| {
        (1, format!("Stage 1 evidence regeneration from committed artifacts failed: {error}"))
    })?;
    let regenerated_bundle_sha256 = writer.bundle_sha256().map_err(|error| {
        (1, format!("cannot digest regenerated Stage 1 evidence bundle: {error}"))
    })?;
    writer
        .append_case_assertion(
            REPORT_FAILURE_CASE_ID,
            "report-publication-failed-and-regenerated",
            serde_json::json!({
                "publish_error_kind": "io",
                "publish_error_message": publish_error.message,
                "bundle_path": EVIDENCE_BUNDLE_FILE,
                "case_manifest_count": manifest_count,
                "case_manifest_set_sha256": manifest_set_sha256,
                "regenerated_bundle_sha256": regenerated_bundle_sha256,
                "committed_state_sha256_before": report_state_sha256.clone(),
                "committed_state_sha256_after": report_state_sha256,
            }),
        )
        .map_err(|error| {
            (1, format!("cannot append report-failure execution observation: {error}"))
        })?;
    if let Some(common_input_sha256) = stage2_common_input_sha256 {
        writer
            .append_case_assertion(
                BASELINE_CASE_ID,
                "stage2-common-input-identity-bound",
                serde_json::json!({
                    "uri": visa_conformance::STAGE2_COMMON_INPUT_FILE,
                    "sha256": common_input_sha256,
                }),
            )
            .map_err(|error| {
                (1, format!("cannot append Stage 2 common-input observation: {error}"))
            })?;
    }
    let bundle = writer
        .regenerate(&context)
        .map_err(|error| (1, format!("final Stage 1 evidence publication failed: {error}")))?;
    if regenerated.cases.len() != EXPECTED_STAGE1_CASES {
        return Err((
            1,
            format!(
                "intermediate regenerated evidence contains {} cases, expected {EXPECTED_STAGE1_CASES}",
                regenerated.cases.len()
            ),
        ));
    }
    if bundle.cases.len() != EXPECTED_STAGE1_CASES {
        return Err((
            1,
            format!(
                "Stage 1 evidence contains {} cases, expected {EXPECTED_STAGE1_CASES}",
                bundle.cases.len()
            ),
        ));
    }

    println!("Stage 1 evidence bundle: {}", writer.bundle_path().display());
    println!("Stage 1 artifact root: {}", artifact_root.display());
    println!("Stage 1 cases: {EXPECTED_STAGE1_CASES}/{EXPECTED_STAGE1_CASES}");
    Ok(())
}

fn current_executable() -> Result<PathBuf, (u8, String)> {
    env::current_exe()
        .map_err(|error| (2, format!("cannot resolve current visa-system executable: {error}")))
}

fn prepare_provenance_files(
    artifact_root: &Path,
    executable: &Path,
    baseline: &FixtureSpec,
    output: &visa_system::runner::Stage1RunOutput,
) -> Result<EvidenceProvenanceFiles, (u8, String)> {
    let source_sha256 = digest_hex(output.source_digest);
    if source_sha256 != build_info::SOURCE_SHA256 {
        return Err((
            1,
            format!(
                "executed visa-system was built from source {}, but the runtime workspace is {}",
                build_info::SOURCE_SHA256,
                source_sha256
            ),
        ));
    }
    let toolchain_sha256 = digest_hex(output.toolchain_digest);
    if toolchain_sha256 != build_info::TOOLCHAIN_SHA256 {
        return Err((
            1,
            format!(
                "executed visa-system was built with toolchain {}, but the runtime toolchain is {}",
                build_info::TOOLCHAIN_SHA256,
                toolchain_sha256
            ),
        ));
    }
    if component::digest() != baseline.component_digest {
        return Err((1, "embedded component digest differs from the Stage 1 fixture".to_owned()));
    }

    let provenance_root = artifact_root.join("provenance");
    let component_path = provenance_root.join("component.wasm");
    write_provenance_file(&component_path, component::bytes())?;
    let profile_path = provenance_root.join("profile.json");
    let mut profile_bytes = serde_json::to_vec_pretty(&baseline.profile)
        .map_err(|error| (1, format!("cannot encode Stage 1 profile artifact: {error}")))?;
    profile_bytes.push(b'\n');
    write_provenance_file(&profile_path, &profile_bytes)?;
    let build_source_manifest_path = provenance_root.join("build-source-manifest.json");
    write_provenance_file(&build_source_manifest_path, build_info::SOURCE_MANIFEST_JSON)?;
    let build_toolchain_path = provenance_root.join("build-toolchain.txt");
    write_provenance_file(&build_toolchain_path, build_info::TOOLCHAIN_RAW)?;
    let executable_path = provenance_root.join("visa-system-executable");
    fs::copy(executable, &executable_path).map_err(|error| {
        (1, format!("cannot copy executed binary to {}: {error}", executable_path.display()))
    })?;
    fs::File::open(&executable_path).and_then(|file| file.sync_all()).map_err(|error| {
        (1, format!("cannot sync executable artifact {}: {error}", executable_path.display()))
    })?;

    Ok(EvidenceProvenanceFiles {
        component: component_path,
        profile: profile_path,
        source_manifest: output.source_manifest_path.clone(),
        toolchain: output.toolchain_provenance_path.clone(),
        build_source_manifest: build_source_manifest_path,
        build_toolchain: build_toolchain_path,
        executable: executable_path,
        matrix_manifest: output.matrix_manifest_path.clone(),
    })
}

fn write_provenance_file(path: &Path, bytes: &[u8]) -> Result<(), (u8, String)> {
    fs::write(path, bytes).map_err(|error| {
        (1, format!("cannot write provenance artifact {}: {error}", path.display()))
    })?;
    fs::File::open(path).and_then(|file| file.sync_all()).map_err(|error| {
        (1, format!("cannot sync provenance artifact {}: {error}", path.display()))
    })
}

fn usable_artifact_root(path: &Path) -> Result<PathBuf, (u8, String)> {
    let metadata = path.metadata().map_err(|error| {
        (2, format!("cannot inspect artifact root {}: {error}", path.display()))
    })?;
    if !metadata.is_dir() {
        return Err((2, format!("artifact root is not a directory: {}", path.display())));
    }
    let canonical = path.canonicalize().map_err(|error| {
        (2, format!("cannot resolve artifact root {}: {error}", path.display()))
    })?;

    let mut probe = None;
    for sequence in 0_u8..100 {
        let candidate =
            canonical.join(format!(".visa-system-write-probe-{}-{sequence}", std::process::id()));
        match OpenOptions::new().create_new(true).write(true).open(&candidate) {
            Ok(file) => {
                drop(file);
                probe = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err((
                    2,
                    format!("artifact root is not writable {}: {error}", canonical.display()),
                ));
            }
        }
    }
    let probe = probe.ok_or_else(|| {
        (2, format!("cannot allocate write probe under artifact root {}", canonical.display()))
    })?;
    std::fs::remove_file(&probe).map_err(|error| {
        (2, format!("cannot remove artifact-root write probe {}: {error}", probe.display()))
    })?;
    Ok(canonical)
}

fn install_bundle_failure_directory(
    artifact_root: &Path,
    bundle_path: &Path,
) -> Result<(), (u8, String)> {
    require_exact_bundle_path(artifact_root, bundle_path)?;
    match std::fs::symlink_metadata(bundle_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err((
                2,
                format!("Stage 1 bundle path already exists: {}", bundle_path.display()),
            ));
        }
        Err(error) => {
            return Err((
                2,
                format!("cannot inspect Stage 1 bundle path {}: {error}", bundle_path.display()),
            ));
        }
    }
    std::fs::create_dir(bundle_path).map_err(|error| {
        (2, format!("cannot install report failure at {}: {error}", bundle_path.display()))
    })
}

fn remove_injected_bundle_directory(
    artifact_root: &Path,
    bundle_path: &Path,
) -> Result<(), (u8, String)> {
    require_exact_bundle_path(artifact_root, bundle_path)?;
    let metadata = std::fs::symlink_metadata(bundle_path).map_err(|error| {
        (2, format!("cannot inspect injected bundle path {}: {error}", bundle_path.display()))
    })?;
    if !metadata.file_type().is_dir() {
        return Err((
            2,
            format!("refusing to remove non-directory bundle path {}", bundle_path.display()),
        ));
    }
    let mut entries = std::fs::read_dir(bundle_path).map_err(|error| {
        (2, format!("cannot read injected bundle directory {}: {error}", bundle_path.display()))
    })?;
    if entries
        .next()
        .transpose()
        .map_err(|error| {
            (
                2,
                format!(
                    "cannot inspect injected bundle directory {}: {error}",
                    bundle_path.display()
                ),
            )
        })?
        .is_some()
    {
        return Err((
            2,
            format!("refusing to remove non-empty bundle directory {}", bundle_path.display()),
        ));
    }
    std::fs::remove_dir(bundle_path).map_err(|error| {
        (2, format!("cannot remove injected bundle directory {}: {error}", bundle_path.display()))
    })
}

fn require_exact_bundle_path(artifact_root: &Path, bundle_path: &Path) -> Result<(), (u8, String)> {
    let expected = artifact_root.join(EVIDENCE_BUNDLE_FILE);
    if bundle_path != expected {
        return Err((
            2,
            format!(
                "refusing report-failure mutation at {}, expected {}",
                bundle_path.display(),
                expected.display()
            ),
        ));
    }
    Ok(())
}

fn execution_environment(
    profile_version: &str,
    timer_profile_digest: contract_core::Digest,
    key_value_profile_digest: contract_core::Digest,
    policy_digest: contract_core::Digest,
    output: &visa_system::runner::Stage1RunOutput,
) -> Stage1ExecutionEnvironment {
    Stage1ExecutionEnvironment {
        carrier: versioned("wit-component ComponentEncoder", WIT_COMPONENT_VERSION),
        source_runtime: runtime_versioned(&output.source_runtime),
        destination_runtime: runtime_versioned(&output.destination_runtime),
        source_isa: isa_identity(&output.source_target.hello),
        destination_isa: isa_identity(&output.destination_target.hello),
        substrate: versioned("host-process-isolation", env!("CARGO_PKG_VERSION")),
        provider: Stage1ProviderIdentity {
            implementation: versioned(
                "substrate_host SqliteProvider with bundled rusqlite",
                &format!("{SUBSTRATE_HOST_VERSION}+rusqlite.{RUSQLITE_VERSION}"),
            ),
            durable: true,
            mock: false,
        },
        authority_enforcement: Stage1AuthorityEnforcementIdentity {
            implementation: versioned(
                "substrate_host authority and lease enforcement",
                SUBSTRATE_HOST_VERSION,
            ),
            policy_sha256: digest_hex(policy_digest),
        },
        resource_profiles: vec![
            Stage1ResourceProfile {
                resource: Stage1ResourceKind::PausedDurationTimer,
                profile_id: "paused-duration-monotonic-timer".to_owned(),
                version: profile_version.to_owned(),
                profile_sha256: digest_hex(timer_profile_digest),
            },
            Stage1ResourceProfile {
                resource: Stage1ResourceKind::DurableKeyValue,
                profile_id: "durable-versioned-kv".to_owned(),
                version: profile_version.to_owned(),
                profile_sha256: digest_hex(key_value_profile_digest),
            },
        ],
    }
}

fn isa_identity(target: &TargetHelloV1) -> Stage1IsaIdentity {
    Stage1IsaIdentity { architecture: target.architecture.clone(), abi: target.abi.clone() }
}

fn runtime_versioned(runtime: &RuntimeIdentityView) -> Stage1VersionedIdentity {
    versioned(
        &format!("{} adapter with {}", runtime.implementation, runtime.engine),
        &format!(
            "{}+{}.{}",
            runtime.implementation_version, runtime.engine, runtime.engine_version
        ),
    )
}

fn versioned(name: &str, version: &str) -> Stage1VersionedIdentity {
    Stage1VersionedIdentity { name: name.to_owned(), version: version.to_owned() }
}

fn digest_hex(digest: contract_core::Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(digest.0.len() * 2);
    for byte in digest.0 {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn requested_exit_code(code: i32) -> Result<ExitCode, (u8, String)> {
    let code = u8::try_from(code)
        .map_err(|_| (64, format!("worker requested invalid exit code {code}")))?;
    Ok(ExitCode::from(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parser_accepts_only_exact_worker_and_stage1_forms() {
        let program = OsStr::new("visa-system");
        assert_eq!(
            parse_mode(program, &[OsString::from("target-hello"), OsString::from(TARGET_NONCE)]),
            Ok(Mode::TargetHello { nonce: TARGET_NONCE.to_owned() })
        );
        assert_eq!(parse_mode(program, &[OsString::from("worker")]), Ok(Mode::Worker));
        assert_eq!(
            parse_mode(program, &[OsString::from("stage1"), OsString::from("target/evidence")]),
            Ok(Mode::Stage1(PathBuf::from("target/evidence")))
        );
        assert_eq!(
            parse_mode(program, &[OsString::from("stage2"), OsString::from("target/matrix")]),
            Ok(Mode::Stage2(PathBuf::from("target/matrix")))
        );
        assert_eq!(
            parse_mode(
                program,
                &[OsString::from("stage2-strict"), OsString::from("target/strict-matrix")]
            ),
            Ok(Mode::Stage2Strict(PathBuf::from("target/strict-matrix")))
        );
        assert_eq!(
            parse_mode(program, &[OsString::from("stage4"), OsString::from("target/stage4")]),
            Ok(Mode::Stage4(PathBuf::from("target/stage4")))
        );
        assert_eq!(
            parse_mode(
                program,
                &[
                    OsString::from("cell"),
                    OsString::from("jco-node"),
                    OsString::from("wasmtime"),
                    OsString::from("target/cell"),
                ],
            ),
            Ok(Mode::Cell {
                source: RuntimeImplementation::JcoNode,
                destination: RuntimeImplementation::Wasmtime,
                artifact_root: PathBuf::from("target/cell"),
            })
        );
        for (source, destination, expected_source, expected_destination, root) in [
            (
                "wacogo",
                "wacogo",
                RuntimeImplementation::Wacogo,
                RuntimeImplementation::Wacogo,
                "target/wacogo-to-wacogo",
            ),
            (
                "wasmtime",
                "wacogo",
                RuntimeImplementation::Wasmtime,
                RuntimeImplementation::Wacogo,
                "target/wasmtime-to-wacogo",
            ),
            (
                "wacogo",
                "wasmtime",
                RuntimeImplementation::Wacogo,
                RuntimeImplementation::Wasmtime,
                "target/wacogo-to-wasmtime",
            ),
        ] {
            assert_eq!(
                parse_mode(
                    program,
                    &[
                        OsString::from("cell"),
                        OsString::from(source),
                        OsString::from(destination),
                        OsString::from(root),
                    ],
                ),
                Ok(Mode::Cell {
                    source: expected_source,
                    destination: expected_destination,
                    artifact_root: PathBuf::from(root),
                })
            );
        }
        for invalid in [
            Vec::new(),
            vec![OsString::from("target-hello")],
            vec![OsString::from("target-hello"), OsString::from("short")],
            vec![
                OsString::from("target-hello"),
                OsString::from(TARGET_NONCE),
                OsString::from("extra"),
            ],
            vec![OsString::from("stage1")],
            vec![OsString::from("stage1"), OsString::new()],
            vec![OsString::from("stage2")],
            vec![OsString::from("stage2"), OsString::new()],
            vec![OsString::from("stage2-strict")],
            vec![OsString::from("stage2-strict"), OsString::new()],
            vec![OsString::from("stage4")],
            vec![OsString::from("stage4"), OsString::new()],
            vec![OsString::from("worker"), OsString::from("extra")],
            vec![OsString::from("stage1"), OsString::from("root"), OsString::from("extra")],
            vec![
                OsString::from("cell"),
                OsString::from("unknown"),
                OsString::from("wasmtime"),
                OsString::from("root"),
            ],
        ] {
            assert_eq!(parse_mode(program, &invalid).unwrap_err().0, 64);
        }
    }

    #[test]
    fn wacogo_runtime_identity_maps_to_the_pinned_stage1_environment_identity() {
        let runtime = RuntimeIdentityView {
            implementation: "visa_wacogo".to_owned(),
            implementation_version: visa_wacogo::VISA_WACOGO_VERSION.to_owned(),
            engine: "partite-ai/wacogo+wazero".to_owned(),
            engine_version: visa_wacogo::ENGINE_VERSION.to_owned(),
            translation_provenance: None,
            implementation_lineage: None,
        };

        assert_eq!(
            runtime_versioned(&runtime),
            Stage1VersionedIdentity {
                name: visa_conformance::STAGE2_WACOGO_ENVIRONMENT_NAME.to_owned(),
                version: visa_conformance::STAGE2_WACOGO_ENVIRONMENT_VERSION.to_owned(),
            }
        );
    }

    #[test]
    fn stage1_isa_identities_come_from_each_target_hello() {
        let target = |architecture: &str, target_triple: &str| TargetHelloV1 {
            schema_version: visa_system::target::TARGET_HELLO_SCHEMA_VERSION.to_owned(),
            nonce: TARGET_NONCE.to_owned(),
            target_triple: target_triple.to_owned(),
            architecture: architecture.to_owned(),
            os: "linux".to_owned(),
            abi: "linux-gnu".to_owned(),
            endianness: visa_system::target::TargetEndianness::Little,
            pointer_width_bits: 64,
            executable_sha256: "0".repeat(64),
            executable_size: 1,
            build_source_sha256: "1".repeat(64),
            build_toolchain_sha256: "2".repeat(64),
            worker_protocol_version: visa_system::protocol::PROTOCOL_VERSION,
        };
        let source = target("x86_64", "x86_64-unknown-linux-gnu");
        let destination = target("aarch64", "aarch64-unknown-linux-gnu");

        assert_eq!(
            isa_identity(&source),
            Stage1IsaIdentity { architecture: "x86_64".to_owned(), abi: "linux-gnu".to_owned() }
        );
        assert_eq!(
            isa_identity(&destination),
            Stage1IsaIdentity { architecture: "aarch64".to_owned(), abi: "linux-gnu".to_owned() }
        );
    }
}
