use std::{
    collections::BTreeSet,
    env,
    ffi::{OsStr, OsString},
    fmt, fs,
    io::{Read, Write},
    path::{Component as PathComponent, Path, PathBuf},
    process::Stdio,
};

use contract_core::Digest;
use js_component_bindgen::{BindingsMode, ExportKind, InstantiationMode, TranspileOpts};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use visa_component_adapter::{
    AdapterError, PreflightExpectations, RuntimeIdentity, validate_preflight_contract,
};
use visa_profile::{CooperativeHandoffProfile, ProviderSupport};

use crate::{
    carrier::{GraphFileKind, PreparedExecutionGraph},
    node::locked_node_command,
};

pub const VISA_JCO_NODE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const JCO_VERSION: &str = "1.25.2";
pub const JS_COMPONENT_BINDGEN_VERSION: &str = "2.0.11";
pub const WASMTIME_ENVIRON_VERSION: &str = "45.0.1";
pub const NODE_VERSION: &str = "24.15.0";
pub const V8_VERSION: &str = "13.6.233.17-node.48";
pub const TRANSLATION_OPTIONS_SCHEMA: &str = "visa-jco-node-transpile-options-v1";
pub const JCO_NODE_RPC_PROTOCOL_VERSION: u32 = crate::protocol::PROTOCOL_VERSION;
pub const JCO_NODE_EXECUTION_CARRIER: &str = crate::carrier::EXECUTION_CARRIER;

const COMPONENT_NAME: &str = "handoff-component.component";
const DRIVER_NAME: &str = "visa-jco-node-driver.mjs";
const PREFLIGHT_NAME: &str = "visa-jco-node-preflight.mjs";
const EXPECTED_IMPORTS: [&str; 2] = ["visa:continuity/key-value", "visa:continuity/timers"];
const EXPECTED_EXPORT: &str = "workload";
const EXPECTED_COMPONENT_IMPORTS: [&str; 2] =
    ["visa:continuity/key-value@0.1.0", "visa:continuity/timers@0.1.0"];
const EXPECTED_COMPONENT_EXPORT: &str = "visa:continuity/workload@0.1.0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRuntimeProvenance {
    pub jco_version: String,
    pub js_component_bindgen_version: String,
    pub translator: String,
    pub translator_version: String,
    pub translation_options: String,
    pub node_executable_path: String,
    pub node_executable_digest: Digest,
    pub node_version: String,
    pub v8_version: String,
    pub rpc_protocol_version: u32,
    pub execution_carrier: String,
}

/// Non-portable evidence describing one deterministic Jco translation graph.
///
/// This value is runtime provenance only. It must never enter canonical state,
/// a snapshot, or the cooperative-handoff profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JcoTranslationProvenance {
    pub generated_digest: Digest,
    pub driver_digest: Digest,
    pub core_module_digests: Vec<Digest>,
    pub runtime: NodeRuntimeProvenance,
}

/// Role of one byte object in the runtime-bound prepared execution graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedArtifactKind {
    GeneratedJavaScript,
    GeneratedCoreWasm,
    GeneratedOther,
    Driver,
    PreflightHelper,
}

/// One immutable byte object expected in a prepared Jco execution carrier.
///
/// This manifest is local runtime provenance. It is deliberately not serializable
/// and must never enter canonical state, a snapshot, or a handoff profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedArtifactManifestEntry {
    pub relative_path: String,
    pub byte_len: u64,
    pub digest: Digest,
    pub kind: PreparedArtifactKind,
}

/// Runtime-bound, non-portable result of a non-executing Jco/Node preflight.
pub struct PreparedJcoComponent {
    pub(crate) graph: PreparedExecutionGraph,
    pub(crate) node_bin: PathBuf,
    pub(crate) node_bin_digest: Digest,
    pub(crate) component_digest: Digest,
    pub(crate) profile_digest: Digest,
    pub(crate) generated_digest: Digest,
    pub(crate) driver_digest: Digest,
    pub(crate) core_module_digests: Vec<Digest>,
    pub(crate) artifact_manifest: Vec<PreparedArtifactManifestEntry>,
    pub(crate) identity: RuntimeIdentity,
    pub(crate) provenance: NodeRuntimeProvenance,
}

impl fmt::Debug for PreparedJcoComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedJcoComponent")
            .field("component_digest", &self.component_digest)
            .field("profile_digest", &self.profile_digest)
            .field("generated_digest", &self.generated_digest)
            .field("driver_digest", &self.driver_digest)
            .field("core_module_digests", &self.core_module_digests)
            .field("artifact_manifest", &self.artifact_manifest)
            .field("identity", &self.identity)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl PreparedJcoComponent {
    pub const fn component_digest(&self) -> Digest {
        self.component_digest
    }

    pub const fn profile_digest(&self) -> Digest {
        self.profile_digest
    }

    pub const fn generated_digest(&self) -> Digest {
        self.generated_digest
    }

    pub const fn driver_digest(&self) -> Digest {
        self.driver_digest
    }

    pub fn core_module_digests(&self) -> &[Digest] {
        &self.core_module_digests
    }

    pub fn artifact_manifest(&self) -> &[PreparedArtifactManifestEntry] {
        &self.artifact_manifest
    }

    pub fn runtime_identity(&self) -> &RuntimeIdentity {
        &self.identity
    }

    pub fn provenance(&self) -> &NodeRuntimeProvenance {
        &self.provenance
    }

    pub fn translation_provenance(&self) -> JcoTranslationProvenance {
        JcoTranslationProvenance {
            generated_digest: self.generated_digest,
            driver_digest: self.driver_digest,
            core_module_digests: self.core_module_digests.clone(),
            runtime: self.provenance.clone(),
        }
    }

    /// Revalidate the exact path-free graph immediately before instantiation.
    pub fn revalidate_for_instantiation(&self) -> Result<(), AdapterError> {
        self.graph.validate()?;
        revalidate_prepared_manifest(&self.graph, &self.artifact_manifest)?;
        revalidate_node_executable(&self.node_bin, self.node_bin_digest)
    }
}

pub(crate) fn static_identity() -> RuntimeIdentity {
    RuntimeIdentity::new(
        "visa_jco_node+jco+js-component-bindgen",
        format!(
            "{VISA_JCO_NODE_VERSION}/jco-{JCO_VERSION}/bindgen-{JS_COMPONENT_BINDGEN_VERSION}/translator-{WASMTIME_ENVIRON_VERSION}"
        ),
        "node+v8",
        format!("{NODE_VERSION}/v8-{V8_VERSION}"),
    )
}

pub(crate) fn preflight(
    component_bytes: &[u8],
    profile: &CooperativeHandoffProfile,
    support: &ProviderSupport,
    expectations: PreflightExpectations,
) -> Result<PreparedJcoComponent, AdapterError> {
    let component_digest =
        validate_preflight_contract(component_bytes, profile, support, expectations)?;
    validate_component_world(component_bytes)?;
    let transpiled = js_component_bindgen::transpile(component_bytes, transpile_options())
        .map_err(|error| AdapterError::InvalidComponent(error.to_string()))?;
    validate_surface(&transpiled.imports, &transpiled.exports)?;

    let expected_entrypoint = format!("{COMPONENT_NAME}.js");
    let mut entrypoint = None;
    let mut core_modules = Vec::new();
    let mut generated_paths = BTreeSet::new();
    let mut files = transpiled.files;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    for (name, bytes) in files {
        let (relative, canonical_name) = safe_relative_path(&name)?;
        if canonical_name == DRIVER_NAME || canonical_name == PREFLIGHT_NAME {
            return Err(AdapterError::InvalidComponent(format!(
                "Jco emitted an artifact using reserved path {canonical_name}"
            )));
        }
        if !generated_paths.insert(canonical_name.clone()) {
            return Err(AdapterError::InvalidComponent(format!(
                "Jco emitted duplicate artifact path {canonical_name}"
            )));
        }
        if canonical_name == expected_entrypoint {
            if entrypoint.replace((canonical_name, bytes)).is_some() {
                return Err(AdapterError::InvalidComponent(
                    "Jco emitted the expected JS entrypoint more than once".into(),
                ));
            }
        } else if relative.extension().and_then(|extension| extension.to_str()) == Some("wasm") {
            core_modules.push((canonical_name, bytes));
        } else {
            return Err(AdapterError::InvalidComponent(format!(
                "Jco emitted unsupported artifact {name}; the locked sync graph permits exactly one JS entrypoint and core Wasm modules"
            )));
        }
    }
    let (entrypoint_name, entrypoint_bytes) = entrypoint.ok_or_else(|| {
        AdapterError::InvalidComponent("Jco did not emit the expected JS entrypoint".into())
    })?;
    let graph = PreparedExecutionGraph::new(entrypoint_name, entrypoint_bytes, core_modules)?;
    let generated_digest = graph.generated_digest();
    let core_module_digests = graph.core_module_digests();

    let driver_bytes = include_bytes!("driver.mjs");
    let preflight_bytes = include_bytes!("preflight.mjs");
    let artifact_manifest = expected_prepared_manifest(&graph);

    let node_bin = node_binary()?;
    let node_bin_digest = hash_file(&node_bin)?;
    check_javascript(&node_bin, graph.entrypoint().bytes(), "generated entrypoint")?;
    check_javascript(&node_bin, driver_bytes, "Node driver")?;
    check_javascript(&node_bin, preflight_bytes, "Node preflight helper")?;
    let versions = compile_core_modules(&node_bin, &graph)?;
    if versions.node != NODE_VERSION || versions.v8 != V8_VERSION {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "this reference cell requires Node {NODE_VERSION} / V8 {V8_VERSION}, found Node {} / V8 {}",
            versions.node, versions.v8
        )));
    }
    revalidate_node_executable(&node_bin, node_bin_digest)?;
    let translation_options = locked_translation_options_json()?;
    let node_executable_path = node_bin
        .to_str()
        .ok_or_else(|| {
            AdapterError::UnsupportedRuntimeFeature(
                "the selected Node executable path is not valid UTF-8".into(),
            )
        })?
        .to_owned();
    let provenance = NodeRuntimeProvenance {
        jco_version: JCO_VERSION.into(),
        js_component_bindgen_version: JS_COMPONENT_BINDGEN_VERSION.into(),
        translator: "wasmtime-environ component translator (shared by js-component-bindgen)".into(),
        translator_version: WASMTIME_ENVIRON_VERSION.into(),
        translation_options,
        node_executable_path,
        node_executable_digest: node_bin_digest,
        node_version: versions.node.clone(),
        v8_version: versions.v8.clone(),
        rpc_protocol_version: JCO_NODE_RPC_PROTOCOL_VERSION,
        execution_carrier: JCO_NODE_EXECUTION_CARRIER.into(),
    };
    let identity = RuntimeIdentity::new(
        "visa_jco_node+jco+js-component-bindgen",
        format!(
            "{VISA_JCO_NODE_VERSION}/jco-{JCO_VERSION}/bindgen-{JS_COMPONENT_BINDGEN_VERSION}/translator-{WASMTIME_ENVIRON_VERSION}"
        ),
        "node+v8",
        format!("{}/v8-{}", versions.node, versions.v8),
    );

    let prepared = PreparedJcoComponent {
        graph,
        node_bin,
        node_bin_digest,
        component_digest,
        profile_digest: expectations.profile_digest,
        generated_digest,
        driver_digest: hash(driver_bytes),
        core_module_digests,
        artifact_manifest,
        identity,
        provenance,
    };
    prepared.revalidate_for_instantiation()?;
    Ok(prepared)
}

fn transpile_options() -> TranspileOpts {
    let options = &LOCKED_TRANSLATION_OPTIONS;
    TranspileOpts::builder()
        .name(options.name.to_owned())
        .no_typescript(options.no_typescript)
        .instantiation_mode(InstantiationMode::Sync)
        .import_bindings(BindingsMode::Js)
        .nodejs_compat_disabled(options.nodejs_compat_disabled)
        .base64_cutoff(options.base64_cutoff)
        .tla_compat(options.tla_compat)
        .valid_lifting_optimization(options.valid_lifting_optimization)
        .tracing(options.tracing)
        .no_namespaced_exports(options.no_namespaced_exports)
        .multi_memory(options.multi_memory)
        .guest(options.guest)
        .strict(options.strict)
        .asmjs(options.asmjs)
        .build()
}

#[derive(Serialize)]
struct LockedTranslationOptions {
    schema: &'static str,
    name: &'static str,
    no_typescript: bool,
    instantiation_mode: &'static str,
    import_bindings: &'static str,
    nodejs_compat_disabled: bool,
    base64_cutoff: usize,
    tla_compat: bool,
    valid_lifting_optimization: bool,
    tracing: bool,
    no_namespaced_exports: bool,
    multi_memory: bool,
    guest: bool,
    strict: bool,
    asmjs: bool,
}

const LOCKED_TRANSLATION_OPTIONS: LockedTranslationOptions = LockedTranslationOptions {
    schema: TRANSLATION_OPTIONS_SCHEMA,
    name: COMPONENT_NAME,
    no_typescript: true,
    instantiation_mode: "sync",
    import_bindings: "js",
    nodejs_compat_disabled: false,
    base64_cutoff: 0,
    tla_compat: false,
    valid_lifting_optimization: false,
    tracing: false,
    no_namespaced_exports: true,
    multi_memory: false,
    guest: false,
    strict: true,
    asmjs: false,
};

fn locked_translation_options_json() -> Result<String, AdapterError> {
    serde_json::to_string(&LOCKED_TRANSLATION_OPTIONS)
        .map_err(|error| AdapterError::Engine(format!("encoding translation options: {error}")))
}

fn validate_component_world(component_bytes: &[u8]) -> Result<(), AdapterError> {
    use wit_component::{DecodedWasm, decode};

    let (resolve, world_id) = match decode(component_bytes).map_err(|error| {
        AdapterError::InvalidComponent(format!("decoding Component WIT: {error}"))
    })? {
        DecodedWasm::Component(resolve, world_id) => (resolve, world_id),
        DecodedWasm::WitPackage(..) => {
            return Err(AdapterError::InvalidComponent(
                "JcoNode requires a concrete WebAssembly Component, not an encoded WIT package"
                    .into(),
            ));
        }
    };
    // A concrete Component synthesizes a root world name when decoded. The
    // portable lock is therefore the exact qualified interface surface; the
    // caller's component digest separately fixes the complete artifact bytes.
    let world = &resolve.worlds[world_id];
    let imports = exact_named_interfaces(&resolve, &world.imports, "import")?;
    let exports = exact_named_interfaces(&resolve, &world.exports, "export")?;
    let expected_imports =
        EXPECTED_COMPONENT_IMPORTS.into_iter().map(str::to_owned).collect::<BTreeSet<_>>();
    let expected_exports = BTreeSet::from([EXPECTED_COMPONENT_EXPORT.to_owned()]);
    if imports != expected_imports || exports != expected_exports {
        return Err(AdapterError::Link(format!(
            "unexpected original Component world: expected imports {expected_imports:?} and exports {expected_exports:?}, got imports {imports:?} and exports {exports:?}"
        )));
    }
    Ok(())
}

fn exact_named_interfaces<'a>(
    resolve: &wit_parser::Resolve,
    items: impl IntoIterator<Item = (&'a wit_parser::WorldKey, &'a wit_parser::WorldItem)>,
    direction: &str,
) -> Result<BTreeSet<String>, AdapterError> {
    items
        .into_iter()
        .map(|(key, item)| {
            let (
                wit_parser::WorldKey::Interface(key_id),
                wit_parser::WorldItem::Interface { id, .. },
            ) = (key, item)
            else {
                return Err(AdapterError::Link(format!(
                    "Component world {direction} is not one exact named WIT interface"
                )));
            };
            if key_id != id {
                return Err(AdapterError::Link(format!(
                    "Component world {direction} uses an alias or implements-qualified name"
                )));
            }
            resolve.id_of(*id).ok_or_else(|| {
                AdapterError::Link(format!("Component world {direction} is anonymous"))
            })
        })
        .collect()
}

fn validate_surface(
    imports: &[String],
    exports: &[(String, ExportKind)],
) -> Result<(), AdapterError> {
    let imports = imports.iter().map(|name| normalize_interface(name)).collect::<BTreeSet<_>>();
    let expected = EXPECTED_IMPORTS.into_iter().map(str::to_owned).collect::<BTreeSet<_>>();
    if imports != expected {
        return Err(AdapterError::Link(format!(
            "unexpected component imports: expected {expected:?}, got {imports:?}"
        )));
    }
    let normalized_exports = exports
        .iter()
        .map(|(name, kind)| (normalize_export(name).to_owned(), kind))
        .collect::<Vec<_>>();
    let export_names =
        normalized_exports.iter().map(|(name, _)| name.as_str()).collect::<BTreeSet<_>>();
    if export_names != BTreeSet::from([EXPECTED_EXPORT])
        || normalized_exports.iter().any(|(_, kind)| **kind != ExportKind::Instance)
    {
        let names = exports.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>();
        return Err(AdapterError::Link(format!(
            "unexpected component exports: expected one workload instance, got {names:?}"
        )));
    }
    Ok(())
}

fn normalize_interface(name: &str) -> String {
    name.rsplit_once('@').map_or(name, |(base, _)| base).to_owned()
}

fn normalize_export(name: &str) -> &str {
    let unversioned = name.rsplit_once('@').map_or(name, |(base, _)| base);
    unversioned.rsplit('/').next().unwrap_or(unversioned)
}

fn safe_relative_path(name: &str) -> Result<(PathBuf, String), AdapterError> {
    let path = Path::new(name);
    let canonical = canonical_relative_path(path).map_err(|_| {
        AdapterError::InvalidComponent(format!("Jco emitted an unsafe artifact path: {name}"))
    })?;
    if canonical != name {
        return Err(AdapterError::InvalidComponent(format!(
            "Jco emitted a non-canonical artifact path: {name}"
        )));
    }
    Ok((path.to_path_buf(), canonical))
}

fn canonical_relative_path(path: &Path) -> Result<String, ()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(());
    }
    let mut components = Vec::new();
    for component in path.components() {
        let PathComponent::Normal(component) = component else {
            return Err(());
        };
        let component = component.to_str().ok_or(())?;
        if component.is_empty() {
            return Err(());
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err(());
    }
    Ok(components.join("/"))
}

fn manifest_entry(
    relative_path: String,
    bytes: &[u8],
    kind: PreparedArtifactKind,
) -> PreparedArtifactManifestEntry {
    PreparedArtifactManifestEntry {
        relative_path,
        byte_len: bytes.len() as u64,
        digest: hash(bytes),
        kind,
    }
}

fn expected_prepared_manifest(
    graph: &PreparedExecutionGraph,
) -> Vec<PreparedArtifactManifestEntry> {
    let mut manifest = graph
        .files()
        .iter()
        .map(|file| PreparedArtifactManifestEntry {
            relative_path: file.name().to_owned(),
            byte_len: file.bytes().len() as u64,
            digest: file.digest(),
            kind: match file.kind() {
                GraphFileKind::Entrypoint => PreparedArtifactKind::GeneratedJavaScript,
                GraphFileKind::CoreModule => PreparedArtifactKind::GeneratedCoreWasm,
            },
        })
        .collect::<Vec<_>>();
    manifest.push(manifest_entry(
        DRIVER_NAME.into(),
        include_bytes!("driver.mjs"),
        PreparedArtifactKind::Driver,
    ));
    manifest.push(manifest_entry(
        PREFLIGHT_NAME.into(),
        include_bytes!("preflight.mjs"),
        PreparedArtifactKind::PreflightHelper,
    ));
    manifest.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    manifest
}

fn revalidate_prepared_manifest(
    graph: &PreparedExecutionGraph,
    manifest: &[PreparedArtifactManifestEntry],
) -> Result<(), AdapterError> {
    for (index, entry) in manifest.iter().enumerate() {
        let canonical = canonical_relative_path(Path::new(&entry.relative_path))
            .map_err(|()| invalid_artifact("manifest contains a non-canonical relative path"))?;
        if canonical != entry.relative_path {
            return Err(invalid_artifact(format!(
                "manifest path is not canonical: {}",
                entry.relative_path
            )));
        }
        if index > 0 && manifest[index - 1].relative_path >= entry.relative_path {
            return Err(invalid_artifact("artifact manifest is not strictly sorted"));
        }
    }
    let expected = expected_prepared_manifest(graph);
    if manifest != expected {
        return Err(invalid_artifact(
            "manifest does not describe the exact owned graph and embedded helpers",
        ));
    }
    Ok(())
}

fn invalid_artifact(message: impl Into<String>) -> AdapterError {
    AdapterError::InvalidComponent(format!(
        "prepared Jco artifacts failed validation: {}",
        message.into()
    ))
}

fn node_binary() -> Result<PathBuf, AdapterError> {
    let configured = env::var_os("VISA_NODE_BIN").unwrap_or_else(|| OsString::from("node"));
    let path = env::var_os("PATH").unwrap_or_default();
    resolve_node_binary_from(&configured, &path)
}

fn resolve_node_binary_from(
    configured: &OsStr,
    search_path: &OsStr,
) -> Result<PathBuf, AdapterError> {
    let configured_path = Path::new(configured);
    let is_bare_name = !configured_path.is_absolute()
        && matches!(
            configured_path.components().collect::<Vec<_>>().as_slice(),
            [PathComponent::Normal(_)]
        );
    let candidate = if is_bare_name {
        env::split_paths(search_path)
            .map(|directory| directory.join(configured_path))
            .find(|candidate| fs::metadata(candidate).is_ok_and(|metadata| metadata.is_file()))
            .ok_or_else(|| {
                AdapterError::UnsupportedRuntimeFeature(format!(
                    "cannot resolve Node executable {configured:?} through PATH"
                ))
            })?
    } else {
        configured_path.to_path_buf()
    };
    let canonical = candidate.canonicalize().map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "resolving Node executable {}: {error}",
            candidate.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "inspecting Node executable {}: {error}",
            canonical.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "Node executable is not a canonical regular file: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn hash_file(path: &Path) -> Result<Digest, AdapterError> {
    let mut file = fs::File::open(path).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "opening Node executable {}: {error}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            AdapterError::UnsupportedRuntimeFeature(format!(
                "hashing Node executable {}: {error}",
                path.display()
            ))
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(Digest::from_bytes(hasher.finalize().into()))
}

fn revalidate_node_executable(path: &Path, expected: Digest) -> Result<(), AdapterError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "revalidating Node executable {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || hash_file(path)? != expected {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "Node executable changed after preflight: {}",
            path.display()
        )));
    }
    Ok(())
}

fn check_javascript(node: &Path, source: &[u8], label: &str) -> Result<(), AdapterError> {
    let mut child = locked_node_command(node)
        .args(["--input-type=module", "--check", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| AdapterError::Engine(format!("starting Node --check: {error}")))?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| AdapterError::Engine("Node --check stdin was unavailable".into()))?
        .write_all(source);
    let output = child
        .wait_with_output()
        .map_err(|error| AdapterError::Engine(format!("waiting for Node --check: {error}")))?;
    if !output.status.success() {
        return Err(AdapterError::InvalidComponent(format!(
            "Node --check rejected {label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    write_result
        .map_err(|error| AdapterError::Engine(format!("writing {label} to Node --check: {error}")))
}

#[derive(Deserialize)]
struct NodeVersions {
    node: String,
    v8: String,
}

fn compile_core_modules(
    node: &Path,
    graph: &PreparedExecutionGraph,
) -> Result<NodeVersions, AdapterError> {
    let mut child = locked_node_command(node)
        .args([
            "--input-type=module",
            "--eval",
            include_str!("preflight.mjs"),
            "--",
            graph.generated_digest_hex().as_str(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| AdapterError::Engine(format!("starting Node core preflight: {error}")))?;
    let write_result =
        graph.write_frame(&mut child.stdin.take().ok_or_else(|| {
            AdapterError::Engine("Node core preflight stdin was unavailable".into())
        })?);
    let output = child.wait_with_output().map_err(|error| {
        AdapterError::Engine(format!("waiting for Node core preflight: {error}"))
    })?;
    if !output.status.success() {
        return Err(AdapterError::InvalidComponent(format!(
            "Node/V8 rejected transpiled core modules: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    write_result.map_err(|error| {
        AdapterError::Engine(format!("writing the Node core preflight carrier: {error}"))
    })?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| AdapterError::Engine(format!("decoding Node runtime provenance: {error}")))
}

fn hash(bytes: &[u8]) -> Digest {
    Digest::from_bytes(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_ENTRYPOINT: &str = "handoff-component.component.js";
    const FIXTURE_CORE: &str = "handoff-component.component.core.wasm";

    #[test]
    fn surface_check_accepts_only_the_version_normalized_stage1_world() {
        let imports = vec![
            "visa:continuity/key-value@0.1.0".to_owned(),
            "visa:continuity/timers@0.1.0".to_owned(),
        ];
        let exports = vec![
            ("workload".to_owned(), ExportKind::Instance),
            ("visa:continuity/workload@0.1.0".to_owned(), ExportKind::Instance),
        ];
        validate_surface(&imports, &exports).expect("the exact Stage 1 world is accepted");

        let mut unexpected = imports;
        unexpected.push("wasi:filesystem/types@0.2.0".into());
        assert!(validate_surface(&unexpected, &exports).is_err());
    }

    #[test]
    fn original_component_world_requires_the_exact_continuity_versions() {
        validate_component_world(&component_world_fixture("0.1.0"))
            .expect("the exact versioned Component world is accepted");

        for version in ["0.2.0", "999.0.0"] {
            let error = validate_component_world(&component_world_fixture(version))
                .expect_err("a different WIT package version must fail before translation");
            assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::Link);
        }
    }

    #[test]
    fn generated_artifact_names_must_be_safe_and_canonical() {
        assert_eq!(
            safe_relative_path("component.core.wasm").unwrap(),
            (PathBuf::from("component.core.wasm"), "component.core.wasm".into())
        );
        assert!(safe_relative_path("../component.core.wasm").is_err());
        assert!(safe_relative_path("/tmp/component.core.wasm").is_err());
        assert!(safe_relative_path("./component.core.wasm").is_err());
        assert!(safe_relative_path("nested//component.core.wasm").is_err());
    }

    #[test]
    fn prepared_artifact_manifest_accepts_only_the_exact_owned_graph() {
        let prepared = prepared_fixture();
        prepared.revalidate_for_instantiation().expect("the original fixture is valid");
        assert!(
            prepared
                .artifact_manifest()
                .windows(2)
                .all(|pair| pair[0].relative_path < pair[1].relative_path)
        );
    }

    #[test]
    fn prepared_artifact_manifest_rejects_any_identity_or_shape_change() {
        for (name, mutate) in
            [("digest", 0_u8), ("size", 1_u8), ("kind", 2_u8), ("missing", 3_u8), ("extra", 4_u8)]
        {
            let mut prepared = prepared_fixture();
            match mutate {
                0 => prepared.artifact_manifest[0].digest = Digest::ZERO,
                1 => prepared.artifact_manifest[0].byte_len += 1,
                2 => prepared.artifact_manifest[0].kind = PreparedArtifactKind::GeneratedOther,
                3 => {
                    prepared.artifact_manifest.pop();
                }
                4 => prepared.artifact_manifest.push(manifest_entry(
                    "unexpected".into(),
                    b"unexpected",
                    PreparedArtifactKind::GeneratedOther,
                )),
                _ => unreachable!(),
            }
            assert_invalid_artifact(prepared.revalidate_for_instantiation().expect_err(name), name);
        }
    }

    #[test]
    fn prepared_artifact_manifest_rejects_non_canonical_manifest_paths() {
        let mut prepared = prepared_fixture();
        prepared.artifact_manifest[0].relative_path = "../escape".into();
        assert_invalid_artifact(
            prepared
                .revalidate_for_instantiation()
                .expect_err("non-canonical manifest path must fail"),
            "non-canonical",
        );
    }

    #[test]
    fn prepared_component_rejects_a_changed_node_executable() {
        let mut prepared = prepared_fixture();
        let node = tempfile::NamedTempFile::new().expect("temporary Node executable");
        fs::write(node.path(), b"node-v1").expect("write initial executable bytes");
        prepared.node_bin = node.path().canonicalize().expect("canonical executable path");
        prepared.node_bin_digest = hash_file(&prepared.node_bin).expect("hash executable");
        prepared
            .revalidate_for_instantiation()
            .expect("the initially bound executable is accepted");

        fs::write(&prepared.node_bin, b"node-v2").expect("replace executable bytes");
        let error = prepared
            .revalidate_for_instantiation()
            .expect_err("an executable changed after preflight must fail");
        assert_eq!(
            error.kind(),
            visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
        );
    }

    #[test]
    fn bare_node_name_is_resolved_once_to_a_canonical_regular_file() {
        let directory = tempfile::tempdir().expect("temporary PATH directory");
        let node = directory.path().join("node");
        fs::write(&node, b"node").expect("write PATH executable");
        let resolved = resolve_node_binary_from(OsStr::new("node"), directory.path().as_os_str())
            .expect("bare Node name resolves through the supplied PATH");
        assert!(resolved.is_absolute());
        assert_eq!(resolved, node.canonicalize().expect("canonical fixture path"));
    }

    #[test]
    fn locked_translation_options_are_explicit_and_canonical() {
        assert_eq!(
            locked_translation_options_json().expect("encode locked options"),
            concat!(
                "{\"schema\":\"visa-jco-node-transpile-options-v1\",",
                "\"name\":\"handoff-component.component\",",
                "\"no_typescript\":true,\"instantiation_mode\":\"sync\",",
                "\"import_bindings\":\"js\",\"nodejs_compat_disabled\":false,",
                "\"base64_cutoff\":0,\"tla_compat\":false,",
                "\"valid_lifting_optimization\":false,\"tracing\":false,",
                "\"no_namespaced_exports\":true,\"multi_memory\":false,",
                "\"guest\":false,\"strict\":true,\"asmjs\":false}"
            )
        );
    }

    #[test]
    fn pinned_node_cell_checks_js_and_compiles_core_wasm_without_instantiation() {
        let node = node_binary().expect("resolve pinned Node executable");
        check_javascript(&node, include_bytes!("preflight.mjs"), "preflight helper")
            .expect("preflight JS parses");
        check_javascript(&node, include_bytes!("driver.mjs"), "driver").expect("driver JS parses");
        let graph = fixture_graph();
        let versions = compile_core_modules(&node, &graph)
            .expect("Node/V8 compiles a core module without instantiating it");
        assert_eq!(versions.node, NODE_VERSION);
        assert_eq!(versions.v8, V8_VERSION);
    }

    fn prepared_fixture() -> PreparedJcoComponent {
        let graph = fixture_graph();
        let artifact_manifest = expected_prepared_manifest(&graph);
        let node_bin = std::env::current_exe()
            .expect("current test executable")
            .canonicalize()
            .expect("canonical test executable");
        let node_bin_digest = hash_file(&node_bin).expect("hash test executable");
        PreparedJcoComponent {
            generated_digest: graph.generated_digest(),
            core_module_digests: graph.core_module_digests(),
            graph,
            node_bin: node_bin.clone(),
            node_bin_digest,
            component_digest: Digest::ZERO,
            profile_digest: Digest::ZERO,
            driver_digest: hash(include_bytes!("driver.mjs")),
            artifact_manifest,
            identity: static_identity(),
            provenance: NodeRuntimeProvenance {
                jco_version: JCO_VERSION.into(),
                js_component_bindgen_version: JS_COMPONENT_BINDGEN_VERSION.into(),
                translator: "fixture".into(),
                translator_version: WASMTIME_ENVIRON_VERSION.into(),
                translation_options: locked_translation_options_json()
                    .expect("translation options"),
                node_executable_path: node_bin.to_string_lossy().into_owned(),
                node_executable_digest: node_bin_digest,
                node_version: NODE_VERSION.into(),
                v8_version: V8_VERSION.into(),
                rpc_protocol_version: JCO_NODE_RPC_PROTOCOL_VERSION,
                execution_carrier: JCO_NODE_EXECUTION_CARRIER.into(),
            },
        }
    }

    fn fixture_graph() -> PreparedExecutionGraph {
        PreparedExecutionGraph::new(
            FIXTURE_ENTRYPOINT.into(),
            b"export function instantiate() { return {}; }\n".to_vec(),
            vec![(FIXTURE_CORE.into(), b"\0asm\x01\0\0\0".to_vec())],
        )
        .expect("valid path-free prepared graph")
    }

    fn assert_invalid_artifact(error: AdapterError, name: &str) {
        assert_eq!(
            error.kind(),
            visa_component_adapter::AdapterFailureKind::InvalidComponent,
            "{name}: {error}"
        );
    }

    fn component_world_fixture(version: &str) -> Vec<u8> {
        use wit_component::{
            ComponentEncoder, StringEncoding, dummy_module, embed_component_metadata,
        };
        use wit_parser::{ManglingAndAbi, Resolve};

        const ACCEPTED_WIT: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../wit/cooperative-handoff/world.wit"
        ));
        const ACCEPTED_PACKAGE: &str = "package visa:continuity@0.1.0;";
        assert!(
            ACCEPTED_WIT.starts_with(ACCEPTED_PACKAGE),
            "accepted WIT must start with its locked package declaration"
        );
        let source = ACCEPTED_WIT.replacen(
            ACCEPTED_PACKAGE,
            &format!("package visa:continuity@{version};"),
            1,
        );
        assert!(
            source.starts_with(&format!("package visa:continuity@{version};")),
            "fixture package declaration must use the requested version"
        );

        let mut resolve = Resolve::default();
        let package = resolve.push_str("fixture.wit", &source).expect("parse fixture WIT");
        let world = resolve
            .select_world(&[package], Some("cooperative-handoff"))
            .expect("select fixture world");
        let mut module = dummy_module(&resolve, world, ManglingAndAbi::Standard32);
        embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8)
            .expect("embed fixture WIT metadata");
        ComponentEncoder::default()
            .module(&module)
            .expect("register fixture core module")
            .validate(true)
            .encode()
            .expect("encode valid fixture Component")
    }
}
