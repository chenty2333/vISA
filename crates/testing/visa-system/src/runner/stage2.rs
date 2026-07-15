use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::Serialize;
use visa_conformance::{
    STAGE1_CASE_DEFINITIONS, STAGE1_EVIDENCE_SCHEMA_VERSION, STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION,
    STAGE2_ACCEPTED_REGISTRY_SHA256, STAGE2_AUTHORITY_POLICY_CANONICAL_ENCODING,
    STAGE2_AUTHORITY_POLICY_INPUT_SCHEMA_VERSION, STAGE2_COMMON_INPUT_FILE,
    STAGE2_COMMON_INPUT_SCHEMA_VERSION, STAGE2_COMPONENT_STATE_CODEC_NAME,
    STAGE2_COMPONENT_STATE_CODEC_VERSION, STAGE2_EVIDENCE_FILE, STAGE2_INCOMPLETE_MARKER_FILE,
    STAGE2_MATRIX_MANIFEST_FILE, STAGE2_STRICT_CARGO_LOCK_URI, STAGE2_STRICT_LINEAGE_ROOT,
    STAGE2_STRICT_WACOGO_BUILD_RECEIPT_URI, STAGE2_STRICT_WACOGO_SIDECAR_URI,
    STAGE2_STRICT_WACOGO_SOURCE_LOCK_URI, STAGE2_WIT_WORLD_NAME, STAGE2_WIT_WORLD_SHA256,
    Stage1VersionedIdentity, Stage2ArtifactReference, Stage2AuthorityPolicyCaseInput,
    Stage2AuthorityPolicyInput, Stage2CellId, Stage2ClaimSet, Stage2CommonCaseInput,
    Stage2CommonInputManifest, Stage2Runtime, Stage2WitWorldInput, Stage2WriteResult,
    canonical_stage2_json_bytes, canonical_stage2_sha256, sha256_hex, stage2_cell_descriptors,
    write_stage2_evidence_artifacts, write_stage2_strict_evidence_artifacts,
};

use super::{
    RunnerError,
    provenance::pretty_json_bytes,
    registry::{fault_schedule, prepare_stage1_registry},
    support::digest_hex,
};
use crate::{component, fixture::FixtureSpec, protocol::RuntimeImplementation};

const STAGE2_INPUT_ROOT: &str = "inputs";
const STAGE2_COMPONENT_URI: &str = "inputs/component.wasm";
const STAGE2_WIT_WORLD_URI: &str = "inputs/world.wit";
const STAGE2_PROFILE_URI: &str = "inputs/profile.json";
const STAGE2_CONFIGURATION_URI: &str = "inputs/configuration.json";
const STAGE2_AUTHORITY_POLICY_URI: &str = "inputs/authority-policy.json";
const STAGE2_BASELINE_CASE_ID: &str = "evidence-verification";
const STAGE2_WIT_WORLD_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../wit/cooperative-handoff/world.wit"
));

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage2CellPlan {
    pub cell_id: Stage2CellId,
    pub source_runtime: RuntimeImplementation,
    pub destination_runtime: RuntimeImplementation,
    pub artifact_root: PathBuf,
    pub common_input_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage2RunOutput {
    pub artifact_root: PathBuf,
    pub common_input_path: PathBuf,
    pub matrix_manifest_path: PathBuf,
    pub evidence_path: PathBuf,
    pub bundle_id: String,
    pub bundle_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage2StrictLineageSources {
    pub cargo_lock: PathBuf,
    pub wacogo_source_lock: PathBuf,
    pub wacogo_build_receipt: PathBuf,
    pub wacogo_sidecar: PathBuf,
}

#[derive(Debug)]
pub enum Stage2RunnerError {
    Io { operation: &'static str, path: PathBuf, source: io::Error },
    RootNotEmpty { path: PathBuf, entry: PathBuf },
    CommonInput { detail: String },
    Cell { cell_id: Stage2CellId, detail: String },
    MissingCellBundle { cell_id: Stage2CellId, path: PathBuf },
    Publication { detail: String },
}

impl fmt::Display for Stage2RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, path, source } => {
                write!(formatter, "{operation} {}: {source}", path.display())
            }
            Self::RootNotEmpty { path, entry } => write!(
                formatter,
                "Stage 2 artifact root {} is not empty (found {})",
                path.display(),
                entry.display()
            ),
            Self::CommonInput { detail } => write!(formatter, "Stage 2 common input: {detail}"),
            Self::Cell { cell_id, detail } => {
                write!(formatter, "Stage 2 cell {} failed: {detail}", cell_id.as_str())
            }
            Self::MissingCellBundle { cell_id, path } => write!(
                formatter,
                "Stage 2 cell {} did not publish a regular Stage 1 bundle at {}",
                cell_id.as_str(),
                path.display()
            ),
            Self::Publication { detail } => {
                write!(formatter, "Stage 2 outer evidence publication failed: {detail}")
            }
        }
    }
}

impl std::error::Error for Stage2RunnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn run_stage2_matrix<F>(
    artifact_root: impl AsRef<Path>,
    execute_cell: F,
) -> Result<Stage2RunOutput, Stage2RunnerError>
where
    F: FnMut(&Stage2CellPlan) -> Result<(), String>,
{
    run_stage2_matrix_with_publisher(artifact_root.as_ref(), execute_cell, |root| {
        write_stage2_evidence_artifacts(root).map_err(|error| error.to_string())
    })
}

pub fn run_stage2_strict_matrix<F>(
    artifact_root: impl AsRef<Path>,
    lineage_sources: &Stage2StrictLineageSources,
    execute_cell: F,
) -> Result<Stage2RunOutput, Stage2RunnerError>
where
    F: FnMut(&Stage2CellPlan) -> Result<(), String>,
{
    run_stage2_matrix_with_claim_and_publisher(
        artifact_root.as_ref(),
        Stage2ClaimSet::StrictCrossRuntimeContinuity,
        |root| capture_strict_lineage(root, lineage_sources),
        execute_cell,
        |root| write_stage2_strict_evidence_artifacts(root).map_err(|error| error.to_string()),
    )
}

fn run_stage2_matrix_with_publisher<F, P>(
    artifact_root: &Path,
    execute_cell: F,
    publish: P,
) -> Result<Stage2RunOutput, Stage2RunnerError>
where
    F: FnMut(&Stage2CellPlan) -> Result<(), String>,
    P: FnOnce(&Path) -> Result<Stage2WriteResult, String>,
{
    run_stage2_matrix_with_claim_and_publisher(
        artifact_root,
        Stage2ClaimSet::CrossExecutionPathPortability,
        |_| Ok(()),
        execute_cell,
        publish,
    )
}

fn run_stage2_matrix_with_claim_and_publisher<F, S, P>(
    artifact_root: &Path,
    claim_set: Stage2ClaimSet,
    setup: S,
    mut execute_cell: F,
    publish: P,
) -> Result<Stage2RunOutput, Stage2RunnerError>
where
    F: FnMut(&Stage2CellPlan) -> Result<(), String>,
    S: FnOnce(&Path) -> Result<(), Stage2RunnerError>,
    P: FnOnce(&Path) -> Result<Stage2WriteResult, String>,
{
    let artifact_root = canonical_empty_root(artifact_root)?;
    let marker_path = artifact_root.join(STAGE2_INCOMPLETE_MARKER_FILE);
    let mut status = Stage2RunStatus::preparing();
    replace_json(&marker_path, &status)?;

    let common_input_path = match write_common_input(&artifact_root) {
        Ok(path) => path,
        Err(error) => {
            status.fail(None, error.to_string());
            replace_json(&marker_path, &status)?;
            return Err(error);
        }
    };
    let common_input_sha256 = file_sha256(&common_input_path)?;
    status.common_input_sha256 = Some(common_input_sha256.clone());
    if let Err(error) = setup(&artifact_root) {
        status.fail(None, error.to_string());
        replace_json(&marker_path, &status)?;
        return Err(error);
    }

    let cells_root = artifact_root.join("cells");
    fs::create_dir(&cells_root)
        .map_err(|source| stage2_io("create Stage 2 cells root", &cells_root, source))?;
    for descriptor in stage2_cell_descriptors(claim_set) {
        let cell_id = descriptor.id;
        let cell_root = cell_id.cell_root(&artifact_root);
        fs::create_dir(&cell_root)
            .map_err(|source| stage2_io("create Stage 2 cell root", &cell_root, source))?;
        let plan = Stage2CellPlan {
            cell_id,
            source_runtime: runtime_implementation(descriptor.source_runtime),
            destination_runtime: runtime_implementation(descriptor.destination_runtime),
            artifact_root: cell_root.clone(),
            common_input_sha256: common_input_sha256.clone(),
        };
        status.start_cell(cell_id);
        replace_json(&marker_path, &status)?;
        if let Err(detail) = execute_cell(&plan) {
            status.fail(Some(cell_id), detail.clone());
            replace_json(&marker_path, &status)?;
            return Err(Stage2RunnerError::Cell { cell_id, detail });
        }
        let bundle_path = cell_root.join("stage1-evidence.json");
        if !is_regular_file(&bundle_path) {
            status.fail(
                Some(cell_id),
                format!("missing regular Stage 1 bundle at {}", bundle_path.display()),
            );
            replace_json(&marker_path, &status)?;
            return Err(Stage2RunnerError::MissingCellBundle { cell_id, path: bundle_path });
        }
        status.complete_cell(cell_id);
        replace_json(&marker_path, &status)?;
    }

    status.phase = Stage2RunPhase::Publishing;
    status.active_cell = None;
    replace_json(&marker_path, &status)?;
    let publication = match publish(&artifact_root) {
        Ok(publication) => publication,
        Err(detail) => {
            status.fail(None, detail.clone());
            replace_json(&marker_path, &status)?;
            return Err(Stage2RunnerError::Publication { detail });
        }
    };
    let expected_manifest = artifact_root.join(STAGE2_MATRIX_MANIFEST_FILE);
    let expected_evidence = artifact_root.join(STAGE2_EVIDENCE_FILE);
    if publication.manifest_path != expected_manifest
        || publication.evidence_path != expected_evidence
        || !is_regular_file(&expected_manifest)
        || !is_regular_file(&expected_evidence)
    {
        let detail = format!(
            "writer returned manifest {} and evidence {}, expected {} and {}",
            publication.manifest_path.display(),
            publication.evidence_path.display(),
            expected_manifest.display(),
            expected_evidence.display()
        );
        status.fail(None, detail.clone());
        replace_json(&marker_path, &status)?;
        return Err(Stage2RunnerError::Publication { detail });
    }

    if marker_path.exists() {
        return Err(Stage2RunnerError::Publication {
            detail: format!(
                "outer writer returned success while {} is still present",
                marker_path.display()
            ),
        });
    }
    sync_directory(&artifact_root)?;
    Ok(Stage2RunOutput {
        artifact_root,
        common_input_path,
        matrix_manifest_path: publication.manifest_path,
        evidence_path: publication.evidence_path,
        bundle_id: publication.bundle_id,
        bundle_sha256: publication.bundle_sha256,
    })
}

fn capture_strict_lineage(
    root: &Path,
    sources: &Stage2StrictLineageSources,
) -> Result<(), Stage2RunnerError> {
    let lineage_root = root.join(STAGE2_STRICT_LINEAGE_ROOT);
    fs::create_dir(&lineage_root)
        .map_err(|source| stage2_io("create Strict Stage 2 lineage root", &lineage_root, source))?;
    for (source, uri) in [
        (&sources.cargo_lock, STAGE2_STRICT_CARGO_LOCK_URI),
        (&sources.wacogo_source_lock, STAGE2_STRICT_WACOGO_SOURCE_LOCK_URI),
        (&sources.wacogo_build_receipt, STAGE2_STRICT_WACOGO_BUILD_RECEIPT_URI),
        (&sources.wacogo_sidecar, STAGE2_STRICT_WACOGO_SIDECAR_URI),
    ] {
        let bytes = read_regular_snapshot(source)?;
        publish_new(&root.join(uri), &bytes)?;
    }
    sync_directory(&lineage_root)
}

fn read_regular_snapshot(path: &Path) -> Result<Vec<u8>, Stage2RunnerError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| stage2_io("inspect Strict Stage 2 lineage source", path, source))?;
    if !path_metadata.file_type().is_file() || path_metadata.file_type().is_symlink() {
        return Err(Stage2RunnerError::CommonInput {
            detail: format!(
                "Strict Stage 2 lineage source is not a non-symlink regular file: {}",
                path.display()
            ),
        });
    }
    let mut file = fs::File::open(path)
        .map_err(|source| stage2_io("open Strict Stage 2 lineage source", path, source))?;
    let before = file.metadata().map_err(|source| {
        stage2_io("inspect opened Strict Stage 2 lineage source", path, source)
    })?;
    if !before.is_file() {
        return Err(Stage2RunnerError::CommonInput {
            detail: format!("opened lineage source is not regular: {}", path.display()),
        });
    }
    let expected_len =
        usize::try_from(before.len()).map_err(|_| Stage2RunnerError::CommonInput {
            detail: format!("lineage source is too large: {}", path.display()),
        })?;
    let mut bytes = Vec::with_capacity(expected_len);
    file.read_to_end(&mut bytes)
        .map_err(|source| stage2_io("read Strict Stage 2 lineage source", path, source))?;
    let after = file
        .metadata()
        .map_err(|source| stage2_io("reinspect Strict Stage 2 lineage source", path, source))?;
    if before.len() != after.len() || bytes.len() != expected_len {
        return Err(Stage2RunnerError::CommonInput {
            detail: format!("lineage source changed while captured: {}", path.display()),
        });
    }
    Ok(bytes)
}

fn write_common_input(root: &Path) -> Result<PathBuf, Stage2RunnerError> {
    let baseline = FixtureSpec::new(STAGE2_BASELINE_CASE_ID).map_err(|error| {
        Stage2RunnerError::CommonInput {
            detail: format!("cannot construct baseline profile: {error}"),
        }
    })?;
    let prepared = prepare_stage1_registry().map_err(common_runner_error)?;
    if prepared.manifest.entries.len() != STAGE1_CASE_DEFINITIONS.len()
        || prepared.plans.len() != STAGE1_CASE_DEFINITIONS.len()
        || prepared.authority_policy_cases.len() != STAGE1_CASE_DEFINITIONS.len()
    {
        return Err(Stage2RunnerError::CommonInput {
            detail: "prepared registry is not the exact Stage 1 case catalog".to_owned(),
        });
    }

    let component_bytes = component::bytes();
    let component_sha256 = sha256_hex(component_bytes);
    if component_sha256 != digest_hex(component::digest())
        || component::digest() != baseline.component_digest
    {
        return Err(Stage2RunnerError::CommonInput {
            detail: "embedded Component bytes do not match the fixture digest".to_owned(),
        });
    }
    if sha256_hex(STAGE2_WIT_WORLD_BYTES) != STAGE2_WIT_WORLD_SHA256 {
        return Err(Stage2RunnerError::CommonInput {
            detail: "embedded WIT world bytes do not match the accepted Stage 2 lock".to_owned(),
        });
    }
    let profile_bytes = pretty_json_bytes(&baseline.profile, "encode Stage 2 common profile")
        .map_err(common_runner_error)?;
    let configuration_bytes =
        pretty_json_bytes(&prepared.manifest, "encode Stage 2 common configuration")
            .map_err(common_runner_error)?;
    let authority_policy = Stage2AuthorityPolicyInput {
        schema_version: STAGE2_AUTHORITY_POLICY_INPUT_SCHEMA_VERSION.to_owned(),
        canonical_encoding: STAGE2_AUTHORITY_POLICY_CANONICAL_ENCODING.to_owned(),
        cases: prepared
            .authority_policy_cases
            .iter()
            .map(|policy| Stage2AuthorityPolicyCaseInput {
                case_id: policy.case_id.clone(),
                policy_sha256: digest_hex(policy.policy_digest),
                canonical_policy_bytes_hex: bytes_hex(&policy.canonical_bytes),
            })
            .collect(),
    };
    let authority_policy_bytes =
        pretty_json_bytes(&authority_policy, "encode Stage 2 common authority policy")
            .map_err(common_runner_error)?;

    let input_root = root.join(STAGE2_INPUT_ROOT);
    fs::create_dir(&input_root)
        .map_err(|source| stage2_io("create Stage 2 input root", &input_root, source))?;
    publish_new(&root.join(STAGE2_COMPONENT_URI), component_bytes)?;
    publish_new(&root.join(STAGE2_WIT_WORLD_URI), STAGE2_WIT_WORLD_BYTES)?;
    publish_new(&root.join(STAGE2_PROFILE_URI), &profile_bytes)?;
    publish_new(&root.join(STAGE2_CONFIGURATION_URI), &configuration_bytes)?;
    publish_new(&root.join(STAGE2_AUTHORITY_POLICY_URI), &authority_policy_bytes)?;

    let cases = STAGE1_CASE_DEFINITIONS
        .iter()
        .zip(&prepared.plans)
        .zip(&prepared.manifest.entries)
        .map(|((definition, plan), entry)| Stage2CommonCaseInput {
            case_id: definition.id.to_owned(),
            class: definition.class,
            allowed_outcomes: definition.allowed_outcomes.to_vec(),
            case_config_sha256: digest_hex(entry.config_digest),
            case_policy_sha256: digest_hex(entry.policy_digest),
            snapshot_timer_strategy: plan.snapshot_timer_strategy,
            fault_schedule: fault_schedule(definition, plan),
        })
        .collect::<Vec<_>>();
    let registry_sha256 = canonical_stage2_sha256(&cases)
        .map_err(|error| Stage2RunnerError::CommonInput { detail: error.to_string() })?;
    if registry_sha256 != STAGE2_ACCEPTED_REGISTRY_SHA256 {
        return Err(Stage2RunnerError::CommonInput {
            detail: format!(
                "prepared Stage 2 case registry digest is {registry_sha256}, expected accepted catalog lock {STAGE2_ACCEPTED_REGISTRY_SHA256}"
            ),
        });
    }
    let manifest = Stage2CommonInputManifest {
        schema_version: STAGE2_COMMON_INPUT_SCHEMA_VERSION.to_owned(),
        original_component: artifact_reference(STAGE2_COMPONENT_URI, component_bytes),
        wit_world: Stage2WitWorldInput {
            world_name: STAGE2_WIT_WORLD_NAME.to_owned(),
            artifact: artifact_reference(STAGE2_WIT_WORLD_URI, STAGE2_WIT_WORLD_BYTES),
        },
        profile: artifact_reference(STAGE2_PROFILE_URI, &profile_bytes),
        profile_sha256: digest_hex(baseline.profile_digest),
        configuration: artifact_reference(STAGE2_CONFIGURATION_URI, &configuration_bytes),
        config_sha256: digest_hex(prepared.config_digest),
        authority_policy: artifact_reference(STAGE2_AUTHORITY_POLICY_URI, &authority_policy_bytes),
        authority_policy_sha256: digest_hex(prepared.policy_digest),
        component_state_codec: Stage1VersionedIdentity {
            name: STAGE2_COMPONENT_STATE_CODEC_NAME.to_owned(),
            version: STAGE2_COMPONENT_STATE_CODEC_VERSION.to_owned(),
        },
        stage1_evidence_schema_version: STAGE1_EVIDENCE_SCHEMA_VERSION.to_owned(),
        stage1_semantic_trace_schema_version: STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION.to_owned(),
        cases,
    };
    let bytes = canonical_stage2_json_bytes(&manifest)
        .map_err(|error| Stage2RunnerError::CommonInput { detail: error.to_string() })?;
    let path = root.join(STAGE2_COMMON_INPUT_FILE);
    publish_new(&path, &bytes)?;
    Ok(path)
}

fn artifact_reference(uri: &str, bytes: &[u8]) -> Stage2ArtifactReference {
    Stage2ArtifactReference { uri: uri.to_owned(), sha256: sha256_hex(bytes) }
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const fn runtime_implementation(runtime: Stage2Runtime) -> RuntimeImplementation {
    match runtime {
        Stage2Runtime::Wasmtime => RuntimeImplementation::Wasmtime,
        Stage2Runtime::JcoNode => RuntimeImplementation::JcoNode,
        Stage2Runtime::Wacogo => RuntimeImplementation::Wacogo,
    }
}

fn canonical_empty_root(path: &Path) -> Result<PathBuf, Stage2RunnerError> {
    let root = path
        .canonicalize()
        .map_err(|source| stage2_io("resolve Stage 2 artifact root", path, source))?;
    let metadata = fs::metadata(&root)
        .map_err(|source| stage2_io("inspect Stage 2 artifact root", &root, source))?;
    if !metadata.is_dir() {
        return Err(Stage2RunnerError::CommonInput {
            detail: format!("artifact root is not a directory: {}", root.display()),
        });
    }
    let mut entries = fs::read_dir(&root)
        .map_err(|source| stage2_io("read Stage 2 artifact root", &root, source))?;
    if let Some(entry) = entries
        .next()
        .transpose()
        .map_err(|source| stage2_io("inspect Stage 2 artifact root", &root, source))?
    {
        return Err(Stage2RunnerError::RootNotEmpty { path: root, entry: entry.path() });
    }
    Ok(root)
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn publish_new(path: &Path, bytes: &[u8]) -> Result<(), Stage2RunnerError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(Stage2RunnerError::CommonInput {
                detail: format!("refusing to overwrite {}", path.display()),
            });
        }
        Err(source) => return Err(stage2_io("inspect publication target", path, source)),
    }
    replace_bytes(path, bytes)
}

fn replace_json(path: &Path, value: &impl Serialize) -> Result<(), Stage2RunnerError> {
    let bytes = canonical_stage2_json_bytes(value)
        .map_err(|error| Stage2RunnerError::CommonInput { detail: error.to_string() })?;
    replace_bytes(path, &bytes)
}

fn replace_bytes(path: &Path, bytes: &[u8]) -> Result<(), Stage2RunnerError> {
    let parent = path.parent().ok_or_else(|| Stage2RunnerError::CommonInput {
        detail: format!("publication path has no parent: {}", path.display()),
    })?;
    let file_name = path.file_name().ok_or_else(|| Stage2RunnerError::CommonInput {
        detail: format!("publication path has no file name: {}", path.display()),
    })?;
    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{sequence}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|source| stage2_io("create temporary Stage 2 artifact", &temporary, source))?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(stage2_io("write temporary Stage 2 artifact", &temporary, source));
    }
    drop(file);
    if let Err(source) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(stage2_io("publish Stage 2 artifact", path, source));
    }
    sync_directory(parent)
}

fn file_sha256(path: &Path) -> Result<String, Stage2RunnerError> {
    fs::read(path)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|source| stage2_io("hash Stage 2 artifact", path, source))
}

fn sync_directory(path: &Path) -> Result<(), Stage2RunnerError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| stage2_io("sync Stage 2 directory", path, source))
}

fn stage2_io(
    operation: &'static str,
    path: impl AsRef<Path>,
    source: io::Error,
) -> Stage2RunnerError {
    Stage2RunnerError::Io { operation, path: path.as_ref().to_path_buf(), source }
}

fn common_runner_error(error: RunnerError) -> Stage2RunnerError {
    Stage2RunnerError::CommonInput { detail: error.to_string() }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Stage2RunPhase {
    Preparing,
    Executing,
    Publishing,
    Failed,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct Stage2RunStatus {
    schema_version: &'static str,
    phase: Stage2RunPhase,
    common_input_sha256: Option<String>,
    completed_cells: Vec<Stage2CellId>,
    active_cell: Option<Stage2CellId>,
    failed_cell: Option<Stage2CellId>,
    failure_detail: Option<String>,
}

impl Stage2RunStatus {
    fn preparing() -> Self {
        Self {
            schema_version: "visa-system-stage2-incomplete-v1",
            phase: Stage2RunPhase::Preparing,
            common_input_sha256: None,
            completed_cells: Vec::new(),
            active_cell: None,
            failed_cell: None,
            failure_detail: None,
        }
    }

    fn start_cell(&mut self, cell_id: Stage2CellId) {
        self.phase = Stage2RunPhase::Executing;
        self.active_cell = Some(cell_id);
    }

    fn complete_cell(&mut self, cell_id: Stage2CellId) {
        self.completed_cells.push(cell_id);
        self.active_cell = None;
    }

    fn fail(&mut self, cell_id: Option<Stage2CellId>, detail: String) {
        self.phase = Stage2RunPhase::Failed;
        self.active_cell = None;
        self.failed_cell = cell_id;
        self.failure_detail = Some(detail);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn matrix_orchestrator_runs_the_exact_four_cells_in_order() {
        let root = test_root("exact-matrix");
        let seen = Mutex::new(Vec::new());
        let output = run_stage2_matrix_with_publisher(
            &root,
            |plan| {
                assert!(root.join(STAGE2_COMMON_INPUT_FILE).is_file());
                assert!(root.join(STAGE2_AUTHORITY_POLICY_URI).is_file());
                seen.lock().unwrap().push((
                    plan.cell_id,
                    plan.source_runtime,
                    plan.destination_runtime,
                ));
                fs::write(plan.artifact_root.join("stage1-evidence.json"), b"{}")
                    .map_err(|error| error.to_string())
            },
            |artifact_root| {
                let manifest_path = artifact_root.join(STAGE2_MATRIX_MANIFEST_FILE);
                let evidence_path = artifact_root.join(STAGE2_EVIDENCE_FILE);
                fs::write(&manifest_path, b"{}").map_err(|error| error.to_string())?;
                fs::write(&evidence_path, b"{}").map_err(|error| error.to_string())?;
                fs::remove_file(artifact_root.join(STAGE2_INCOMPLETE_MARKER_FILE))
                    .map_err(|error| error.to_string())?;
                Ok(Stage2WriteResult {
                    evidence_path,
                    manifest_path,
                    bundle_id: "test-stage2".to_owned(),
                    bundle_sha256: sha256_hex(b"{}"),
                })
            },
        )
        .expect("exact matrix orchestration succeeds");

        assert_eq!(
            seen.into_inner().unwrap(),
            vec![
                (
                    Stage2CellId::WasmtimeToWasmtime,
                    RuntimeImplementation::Wasmtime,
                    RuntimeImplementation::Wasmtime,
                ),
                (
                    Stage2CellId::JcoNodeToJcoNode,
                    RuntimeImplementation::JcoNode,
                    RuntimeImplementation::JcoNode,
                ),
                (
                    Stage2CellId::WasmtimeToJcoNode,
                    RuntimeImplementation::Wasmtime,
                    RuntimeImplementation::JcoNode,
                ),
                (
                    Stage2CellId::JcoNodeToWasmtime,
                    RuntimeImplementation::JcoNode,
                    RuntimeImplementation::Wasmtime,
                ),
            ]
        );
        assert!(!root.join(STAGE2_INCOMPLETE_MARKER_FILE).exists());
        assert_eq!(output.bundle_id, "test-stage2");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_matrix_orchestrator_runs_the_exact_wasmtime_wacogo_cells_in_order() {
        let root = test_root("exact-strict-matrix");
        let seen = Mutex::new(Vec::new());
        let output = run_stage2_matrix_with_claim_and_publisher(
            &root,
            Stage2ClaimSet::StrictCrossRuntimeContinuity,
            |artifact_root| {
                assert!(artifact_root.join(STAGE2_COMMON_INPUT_FILE).is_file());
                Ok(())
            },
            |plan| {
                seen.lock().unwrap().push((
                    plan.cell_id,
                    plan.source_runtime,
                    plan.destination_runtime,
                ));
                fs::write(plan.artifact_root.join("stage1-evidence.json"), b"{}")
                    .map_err(|error| error.to_string())
            },
            |artifact_root| {
                let manifest_path = artifact_root.join(STAGE2_MATRIX_MANIFEST_FILE);
                let evidence_path = artifact_root.join(STAGE2_EVIDENCE_FILE);
                fs::write(&manifest_path, b"{}").map_err(|error| error.to_string())?;
                fs::write(&evidence_path, b"{}").map_err(|error| error.to_string())?;
                fs::remove_file(artifact_root.join(STAGE2_INCOMPLETE_MARKER_FILE))
                    .map_err(|error| error.to_string())?;
                Ok(Stage2WriteResult {
                    evidence_path,
                    manifest_path,
                    bundle_id: "test-stage2-strict".to_owned(),
                    bundle_sha256: sha256_hex(b"{}"),
                })
            },
        )
        .expect("strict matrix orchestration succeeds");

        assert_eq!(
            seen.into_inner().unwrap(),
            vec![
                (
                    Stage2CellId::WasmtimeToWasmtime,
                    RuntimeImplementation::Wasmtime,
                    RuntimeImplementation::Wasmtime,
                ),
                (
                    Stage2CellId::WacogoToWacogo,
                    RuntimeImplementation::Wacogo,
                    RuntimeImplementation::Wacogo,
                ),
                (
                    Stage2CellId::WasmtimeToWacogo,
                    RuntimeImplementation::Wasmtime,
                    RuntimeImplementation::Wacogo,
                ),
                (
                    Stage2CellId::WacogoToWasmtime,
                    RuntimeImplementation::Wacogo,
                    RuntimeImplementation::Wasmtime,
                ),
            ]
        );
        assert_eq!(output.bundle_id, "test-stage2-strict");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_matrix_failure_retains_completed_and_active_cell_evidence() {
        let root = test_root("strict-partial-evidence");
        let mut executed = 0_u8;
        let error = run_stage2_matrix_with_claim_and_publisher(
            &root,
            Stage2ClaimSet::StrictCrossRuntimeContinuity,
            |artifact_root| {
                fs::write(artifact_root.join("lineage-retained.txt"), b"locked lineage")
                    .map_err(|source| stage2_io("write test lineage", artifact_root, source))
            },
            |plan| {
                executed += 1;
                if executed == 1 {
                    fs::write(plan.artifact_root.join("stage1-evidence.json"), b"{}")
                        .map_err(|error| error.to_string())?;
                    return Ok(());
                }

                assert_eq!(executed, 2, "the matrix must stop at the failed cell");
                fs::write(plan.artifact_root.join("partial-transcript.json"), b"partial")
                    .map_err(|error| error.to_string())?;
                Err("injected Wacogo same-path failure".to_owned())
            },
            |_| panic!("outer evidence must not publish after a cell failure"),
        )
        .expect_err("the injected strict cell failure must fail closed");

        assert!(matches!(
            error,
            Stage2RunnerError::Cell { cell_id: Stage2CellId::WacogoToWacogo, .. }
        ));
        assert_eq!(executed, 2);

        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join(STAGE2_INCOMPLETE_MARKER_FILE)).unwrap())
                .unwrap();
        assert_eq!(status["schema_version"], "visa-system-stage2-incomplete-v1");
        assert_eq!(status["phase"], "failed");
        assert!(status["common_input_sha256"].as_str().is_some());
        assert_eq!(status["completed_cells"], serde_json::json!(["wasmtime-to-wasmtime"]));
        assert!(status["active_cell"].is_null());
        assert_eq!(status["failed_cell"], "wacogo-to-wacogo");
        assert_eq!(status["failure_detail"], "injected Wacogo same-path failure");

        assert!(root.join("cells/wasmtime-to-wasmtime/stage1-evidence.json").is_file());
        assert_eq!(
            fs::read(root.join("cells/wacogo-to-wacogo/partial-transcript.json")).unwrap(),
            b"partial"
        );
        assert!(!root.join("cells/wasmtime-to-wacogo").exists());
        assert_eq!(fs::read(root.join("lineage-retained.txt")).unwrap(), b"locked lineage");
        assert!(!root.join(STAGE2_MATRIX_MANIFEST_FILE).exists());
        assert!(!root.join(STAGE2_EVIDENCE_FILE).exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn matrix_orchestrator_rejects_a_nonempty_root_without_mutating_it() {
        let root = test_root("nonempty");
        let sentinel = root.join("keep.txt");
        fs::write(&sentinel, b"user data").unwrap();
        let error = run_stage2_matrix_with_publisher(
            &root,
            |_| panic!("a cell must not run"),
            |_| panic!("publication must not run"),
        )
        .unwrap_err();
        assert!(matches!(error, Stage2RunnerError::RootNotEmpty { .. }));
        assert_eq!(fs::read(&sentinel).unwrap(), b"user data");
        fs::remove_dir_all(root).unwrap();
    }

    fn test_root(label: &str) -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("visa-system-stage2-{label}-{}-{sequence}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }
}
