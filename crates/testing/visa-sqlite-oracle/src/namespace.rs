#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use visa_wasi_protocol::{
    BarrierPhase, LockLevel, NamespaceObject, NamespaceSnapshot, ProviderMode,
    encode_namespace_snapshot,
};

use crate::{OracleFinding, SnapshotSummary};

const FILE_TYPE_DIRECTORY: u8 = 3;
const FILE_TYPE_REGULAR: u8 = 4;
const FILE_TYPE_SYMLINK: u8 = 7;
const MAX_PATH_BYTES: usize = 4096;
const SUPPORTED_NAMESPACE_SNAPSHOT_VERSION: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteString {
    pub hex: String,
    pub utf8: Option<String>,
}

impl ByteString {
    fn new(bytes: &[u8]) -> Self {
        Self { hex: hex::encode(bytes), utf8: std::str::from_utf8(bytes).ok().map(str::to_owned) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathReport {
    pub path: ByteString,
    pub object_hex: String,
    pub kind: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorReport {
    pub fd: u32,
    pub object_hex: String,
    pub directory_path: ByteString,
    pub offset: u64,
    pub flags: u16,
    pub rights_base: u64,
    pub rights_inheriting: u64,
    pub preopen: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockReport {
    pub object_hex: String,
    pub owner_hex: String,
    pub level: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlinkedObjectReport {
    pub object_hex: String,
    pub kind: String,
    pub size: u64,
    pub open_descriptors: Vec<u32>,
    pub representation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceReport {
    pub private_temp_tree: bool,
    pub database_path: ByteString,
    pub sqlite_sidecars: Vec<ByteString>,
    pub paths: Vec<PathReport>,
    pub descriptors: Vec<DescriptorReport>,
    pub locks: Vec<LockReport>,
    pub unlinked_objects: Vec<UnlinkedObjectReport>,
}

pub(crate) struct MaterializedNamespace {
    _temporary: TempDir,
    analysis_database: PathBuf,
    report: NamespaceReport,
}

impl MaterializedNamespace {
    pub(crate) fn analysis_database(&self) -> &Path {
        &self.analysis_database
    }

    pub(crate) fn report(&self) -> &NamespaceReport {
        &self.report
    }

    pub(crate) fn namespace_root(&self) -> PathBuf {
        self._temporary.path().join("namespace")
    }

    #[cfg(test)]
    pub(crate) fn unlinked_root(&self) -> PathBuf {
        self._temporary.path().join("unlinked")
    }
}

pub(crate) fn snapshot_summary(snapshot: &NamespaceSnapshot) -> SnapshotSummary {
    SnapshotSummary {
        version: snapshot.version,
        session_hex: hex::encode(snapshot.session.0),
        authority_epoch: snapshot.authority_epoch,
        mode: format!("{:?}", snapshot.mode).to_ascii_lowercase(),
        barrier: format!("{:?}", snapshot.barrier).to_ascii_lowercase(),
        effect_frontier_hex: hex::encode(snapshot.effect_frontier),
        effects: snapshot.effects,
        objects: snapshot.objects.len() as u64,
        paths: snapshot.paths.len() as u64,
        descriptors: snapshot.descriptors.len() as u64,
        locks: snapshot.locks.len() as u64,
    }
}

pub(crate) fn namespace_report(
    snapshot: &NamespaceSnapshot,
    database_path: &[u8],
) -> NamespaceReport {
    let objects =
        snapshot.objects.iter().map(|object| (object.object, object)).collect::<BTreeMap<_, _>>();
    let linked = snapshot.paths.iter().map(|path| path.object).collect::<BTreeSet<_>>();
    let paths = snapshot
        .paths
        .iter()
        .map(|path| {
            let object = objects.get(&path.object);
            PathReport {
                path: ByteString::new(&path.path),
                object_hex: hex::encode(path.object.0),
                kind: object.map_or_else(|| "missing".to_owned(), |value| kind_name(value.kind)),
                size: object.map_or(0, |value| value.size),
            }
        })
        .collect();
    let descriptors = snapshot
        .descriptors
        .iter()
        .map(|descriptor| DescriptorReport {
            fd: descriptor.fd,
            object_hex: hex::encode(descriptor.object.0),
            directory_path: ByteString::new(&descriptor.directory_path),
            offset: descriptor.offset,
            flags: descriptor.flags,
            rights_base: descriptor.rights_base,
            rights_inheriting: descriptor.rights_inheriting,
            preopen: descriptor.preopen,
        })
        .collect();
    let locks = snapshot
        .locks
        .iter()
        .map(|lock| LockReport {
            object_hex: hex::encode(lock.object.0),
            owner_hex: hex::encode(lock.owner.0),
            level: lock_name(lock.level).to_owned(),
        })
        .collect();
    let unlinked_objects = snapshot
        .objects
        .iter()
        .filter(|object| !linked.contains(&object.object))
        .map(|object| {
            let object_hex = hex::encode(object.object.0);
            UnlinkedObjectReport {
                object_hex: object_hex.clone(),
                kind: kind_name(object.kind),
                size: object.size,
                open_descriptors: snapshot
                    .descriptors
                    .iter()
                    .filter(|descriptor| descriptor.object == object.object)
                    .map(|descriptor| descriptor.fd)
                    .collect(),
                representation: format!("unlinked/{object_hex}"),
            }
        })
        .collect();
    let sqlite_sidecars = sqlite_sidecar_paths(snapshot, database_path)
        .into_iter()
        .map(|path| ByteString::new(&path))
        .collect();
    NamespaceReport {
        private_temp_tree: true,
        database_path: ByteString::new(database_path),
        sqlite_sidecars,
        paths,
        descriptors,
        locks,
        unlinked_objects,
    }
}

pub(crate) fn validate_snapshot(
    encoded: &[u8],
    snapshot: &NamespaceSnapshot,
) -> Vec<OracleFinding> {
    let mut findings = Vec::new();
    if snapshot.version != SUPPORTED_NAMESPACE_SNAPSHOT_VERSION {
        findings.push(OracleFinding::new(
            "snapshot-version",
            format!(
                "expected NamespaceSnapshot version {SUPPORTED_NAMESPACE_SNAPSHOT_VERSION}, got {}",
                snapshot.version
            ),
        ));
    }
    if snapshot.session.is_zero() {
        findings.push(OracleFinding::new("snapshot-session-zero", "session identity is zero"));
    }
    if snapshot.authority_epoch == 0 {
        findings.push(OracleFinding::new(
            "snapshot-authority-epoch-zero",
            "authority_epoch must be nonzero",
        ));
    }
    if snapshot.barrier != BarrierPhase::CheckpointReleased {
        findings.push(OracleFinding::new(
            "snapshot-barrier-phase",
            format!(
                "namespace snapshots must be captured at checkpoint_released, got {:?}",
                snapshot.barrier
            ),
        ));
    }
    if !matches!(snapshot.mode, ProviderMode::Active | ProviderMode::Frozen) {
        findings.push(OracleFinding::new(
            "snapshot-provider-mode",
            format!(
                "namespace snapshots require active or frozen provider mode, got {:?}",
                snapshot.mode
            ),
        ));
    }
    if snapshot.effects > 0 && snapshot.effect_frontier == [0; 32] {
        findings.push(OracleFinding::new(
            "snapshot-effect-frontier-zero",
            "effect_frontier must be nonzero when effects is nonzero",
        ));
    }
    match encode_namespace_snapshot(snapshot) {
        Ok(canonical) if canonical != encoded => findings.push(OracleFinding::new(
            "snapshot-noncanonical-encoding",
            "input is not the canonical postcard encoding of the decoded snapshot",
        )),
        Err(error) => findings.push(OracleFinding::new(
            "snapshot-reencode",
            format!("cannot re-encode decoded snapshot: {error}"),
        )),
        Ok(_) => {}
    }

    let mut objects = BTreeMap::new();
    let mut previous_object = None;
    for object in &snapshot.objects {
        if object.object.is_zero() {
            findings.push(OracleFinding::new(
                "snapshot-object-zero",
                "object identity must be nonzero",
            ));
        }
        if previous_object.is_some_and(|previous| previous >= object.object) {
            findings.push(OracleFinding::new(
                "snapshot-objects-noncanonical",
                "objects must have unique identities in strictly increasing order",
            ));
        }
        previous_object = Some(object.object);
        if objects.insert(object.object, object).is_some() {
            findings.push(OracleFinding::new(
                "snapshot-object-duplicate",
                format!("duplicate object {}", hex::encode(object.object.0)),
            ));
        }
        validate_object(object, &mut findings);
    }

    let mut paths = BTreeMap::new();
    let mut previous_path: Option<&[u8]> = None;
    for path in &snapshot.paths {
        if previous_path.is_some_and(|previous| previous >= path.path.as_slice()) {
            findings.push(OracleFinding::new(
                "snapshot-paths-noncanonical",
                "paths must be unique and in strictly increasing byte order",
            ));
        }
        previous_path = Some(&path.path);
        if !is_canonical_path(&path.path) {
            findings.push(OracleFinding::new(
                "snapshot-path-noncanonical",
                format!(
                    "path {} is not a canonical relative namespace path",
                    display_bytes(&path.path)
                ),
            ));
        }
        if paths.insert(path.path.as_slice(), path.object).is_some() {
            findings.push(OracleFinding::new(
                "snapshot-path-duplicate",
                format!("duplicate path {}", display_bytes(&path.path)),
            ));
        }
        if !objects.contains_key(&path.object) {
            findings.push(OracleFinding::new(
                "snapshot-path-object-missing",
                format!(
                    "path {} references missing object {}",
                    display_bytes(&path.path),
                    hex::encode(path.object.0)
                ),
            ));
        }
    }
    validate_path_graph(&paths, &objects, &mut findings);

    let mut descriptors = BTreeSet::new();
    let mut previous_fd = None;
    for descriptor in &snapshot.descriptors {
        if previous_fd.is_some_and(|previous| previous >= descriptor.fd) {
            findings.push(OracleFinding::new(
                "snapshot-descriptors-noncanonical",
                "descriptors must have unique fds in strictly increasing order",
            ));
        }
        previous_fd = Some(descriptor.fd);
        if !descriptors.insert(descriptor.fd) {
            findings.push(OracleFinding::new(
                "snapshot-descriptor-duplicate",
                format!("duplicate descriptor fd {}", descriptor.fd),
            ));
        }
        if descriptor.fd < 3 {
            findings.push(OracleFinding::new(
                "snapshot-descriptor-fd",
                format!("descriptor fd {} is below the namespace preopen range", descriptor.fd),
            ));
        }
        let Some(object) = objects.get(&descriptor.object) else {
            findings.push(OracleFinding::new(
                "snapshot-descriptor-object-missing",
                format!(
                    "descriptor fd {} references missing object {}",
                    descriptor.fd,
                    hex::encode(descriptor.object.0)
                ),
            ));
            continue;
        };
        if object.kind == FILE_TYPE_DIRECTORY {
            if !is_canonical_path(&descriptor.directory_path)
                || paths.get(descriptor.directory_path.as_slice()) != Some(&descriptor.object)
            {
                findings.push(OracleFinding::new(
                    "snapshot-descriptor-directory-binding",
                    format!(
                        "directory descriptor fd {} has an invalid path binding",
                        descriptor.fd
                    ),
                ));
            }
        } else if !descriptor.directory_path.is_empty() {
            findings.push(OracleFinding::new(
                "snapshot-descriptor-file-directory-path",
                format!("non-directory descriptor fd {} carries a directory_path", descriptor.fd),
            ));
        }
        if descriptor.preopen
            && (descriptor.fd != 3
                || object.kind != FILE_TYPE_DIRECTORY
                || !descriptor.directory_path.is_empty())
        {
            findings.push(OracleFinding::new(
                "snapshot-preopen-binding",
                "the only preopen must be fd 3 bound to the root directory",
            ));
        }
    }
    if snapshot.descriptors.iter().filter(|descriptor| descriptor.preopen).count() != 1 {
        findings.push(OracleFinding::new(
            "snapshot-preopen-count",
            "snapshot must contain exactly one root preopen descriptor",
        ));
    }

    let mut previous_lock = None;
    let mut lock_keys = BTreeSet::new();
    for lock in &snapshot.locks {
        let key = (lock.object, lock.owner);
        if previous_lock.is_some_and(|previous| previous >= key) {
            findings.push(OracleFinding::new(
                "snapshot-locks-noncanonical",
                "locks must be unique and in strictly increasing object/owner order",
            ));
        }
        previous_lock = Some(key);
        if !lock_keys.insert(key) {
            findings.push(OracleFinding::new(
                "snapshot-lock-duplicate",
                format!(
                    "duplicate lock for object {} and owner {}",
                    hex::encode(lock.object.0),
                    hex::encode(lock.owner.0)
                ),
            ));
        }
        if lock.owner.is_zero() || lock.level == LockLevel::None {
            findings.push(OracleFinding::new(
                "snapshot-lock-invalid",
                "lock owner must be nonzero and level must not be none",
            ));
        }
        match objects.get(&lock.object) {
            None => findings.push(OracleFinding::new(
                "snapshot-lock-object-missing",
                format!("lock references missing object {}", hex::encode(lock.object.0)),
            )),
            Some(object) if object.kind != FILE_TYPE_REGULAR => findings.push(OracleFinding::new(
                "snapshot-lock-object-kind",
                format!("lock object {} is not a regular file", hex::encode(lock.object.0)),
            )),
            Some(_) => {}
        }
        if !snapshot.descriptors.iter().any(|descriptor| descriptor.object == lock.object) {
            findings.push(OracleFinding::new(
                "snapshot-lock-descriptor-missing",
                format!("lock object {} has no open descriptor", hex::encode(lock.object.0)),
            ));
        }
    }
    validate_lock_compatibility(snapshot, &mut findings);

    let linked = snapshot.paths.iter().map(|path| path.object).collect::<BTreeSet<_>>();
    for object in &snapshot.objects {
        if !linked.contains(&object.object)
            && !snapshot.descriptors.iter().any(|descriptor| descriptor.object == object.object)
        {
            findings.push(OracleFinding::new(
                "snapshot-object-unreachable",
                format!(
                    "unlinked object {} is not preserved by an open descriptor",
                    hex::encode(object.object.0)
                ),
            ));
        }
    }
    findings
}

fn validate_object(object: &NamespaceObject, findings: &mut Vec<OracleFinding>) {
    let id = hex::encode(object.object.0);
    match object.kind {
        FILE_TYPE_REGULAR => {
            if object.symlink_target.is_some() {
                findings.push(OracleFinding::new(
                    "snapshot-regular-symlink-target",
                    format!("regular object {id} carries a symlink target"),
                ));
            }
            if usize::try_from(object.size).ok() != Some(object.bytes.len()) {
                findings.push(OracleFinding::new(
                    "snapshot-object-size-bytes",
                    format!(
                        "regular object {id} declares {} bytes but carries {}",
                        object.size,
                        object.bytes.len()
                    ),
                ));
            }
        }
        FILE_TYPE_DIRECTORY => {
            if object.size != 0 || !object.bytes.is_empty() || object.symlink_target.is_some() {
                findings.push(OracleFinding::new(
                    "snapshot-directory-payload",
                    format!("directory object {id} must have zero size and no payload"),
                ));
            }
        }
        FILE_TYPE_SYMLINK => {
            if object.size != 0 || !object.bytes.is_empty() {
                findings.push(OracleFinding::new(
                    "snapshot-symlink-payload",
                    format!("symlink object {id} must have zero size and no file bytes"),
                ));
            }
            match object.symlink_target.as_deref() {
                None | Some([]) => findings.push(OracleFinding::new(
                    "snapshot-symlink-target",
                    format!("symlink object {id} has no target"),
                )),
                Some(target) if target.len() > MAX_PATH_BYTES || target.contains(&0) => {
                    findings.push(OracleFinding::new(
                        "snapshot-symlink-target",
                        format!("symlink object {id} has an invalid target"),
                    ));
                }
                Some(_) => {}
            }
        }
        other => findings.push(OracleFinding::new(
            "snapshot-object-kind",
            format!("object {id} has unsupported WASI file type {other}"),
        )),
    }
    if object.mode > 0o7777 {
        findings.push(OracleFinding::new(
            "snapshot-object-mode",
            format!("object {id} mode exceeds 0o7777"),
        ));
    }
}

fn validate_path_graph(
    paths: &BTreeMap<&[u8], visa_wasi_protocol::ObjectId>,
    objects: &BTreeMap<visa_wasi_protocol::ObjectId, &NamespaceObject>,
    findings: &mut Vec<OracleFinding>,
) {
    let Some(root_id) = paths.get(b"".as_slice()) else {
        findings
            .push(OracleFinding::new("snapshot-root-missing", "namespace root path is missing"));
        return;
    };
    if objects.get(root_id).is_none_or(|object| object.kind != FILE_TYPE_DIRECTORY) {
        findings.push(OracleFinding::new(
            "snapshot-root-kind",
            "namespace root path must reference a directory object",
        ));
    }
    let mut directory_links = BTreeMap::new();
    for (path, object_id) in paths {
        let Some(object) = objects.get(object_id) else { continue };
        if object.kind == FILE_TYPE_DIRECTORY {
            *directory_links.entry(*object_id).or_insert(0_u64) += 1;
        }
        if path.is_empty() {
            continue;
        }
        let parent = parent_path(path);
        let parent_is_directory = paths
            .get(parent)
            .and_then(|parent_id| objects.get(parent_id))
            .is_some_and(|parent_object| parent_object.kind == FILE_TYPE_DIRECTORY);
        if !parent_is_directory {
            findings.push(OracleFinding::new(
                "snapshot-path-parent",
                format!("path {} has no directory parent", display_bytes(path)),
            ));
        }
        if object.kind == FILE_TYPE_SYMLINK {
            let target = object.symlink_target.as_deref().unwrap_or_default();
            if normalize_path(parent, target).is_none() {
                findings.push(OracleFinding::new(
                    "snapshot-symlink-escape",
                    format!("symlink at {} escapes the private namespace", display_bytes(path)),
                ));
            }
        }
    }
    for (object, links) in directory_links {
        if links != 1 {
            findings.push(OracleFinding::new(
                "snapshot-directory-hardlink",
                format!(
                    "directory object {} has {links} paths; native materialization requires one",
                    hex::encode(object.0)
                ),
            ));
        }
    }
}

fn validate_lock_compatibility(snapshot: &NamespaceSnapshot, findings: &mut Vec<OracleFinding>) {
    let mut by_object = BTreeMap::<_, Vec<_>>::new();
    for lock in &snapshot.locks {
        by_object.entry(lock.object).or_default().push(lock.level);
    }
    for (object, levels) in by_object {
        let writers = levels.iter().filter(|level| **level >= LockLevel::Reserved).count();
        let exclusive = levels.iter().filter(|level| **level == LockLevel::Exclusive).count();
        if writers > 1 || (exclusive == 1 && levels.len() != 1) {
            findings.push(OracleFinding::new(
                "snapshot-lock-conflict",
                format!("object {} has incompatible lock owners", hex::encode(object.0)),
            ));
        }
    }
}

pub(crate) fn validate_database_path(
    snapshot: &NamespaceSnapshot,
    database_path: &[u8],
) -> Vec<OracleFinding> {
    let mut findings = Vec::new();
    if database_path.is_empty() || !is_canonical_path(database_path) {
        findings.push(OracleFinding::new(
            "database-path-noncanonical",
            "database path must be a nonempty canonical guest-namespace path",
        ));
        return findings;
    }
    let Some(binding) = snapshot.paths.iter().find(|path| path.path == database_path) else {
        findings.push(OracleFinding::new(
            "database-path-missing",
            format!("database path {} is absent from the snapshot", display_bytes(database_path)),
        ));
        return findings;
    };
    if snapshot
        .objects
        .iter()
        .find(|object| object.object == binding.object)
        .is_none_or(|object| object.kind != FILE_TYPE_REGULAR)
    {
        findings.push(OracleFinding::new(
            "database-object-kind",
            "database path does not reference a regular file",
        ));
    }
    for sidecar in sqlite_sidecar_paths(snapshot, database_path) {
        let regular = snapshot
            .paths
            .iter()
            .find(|path| path.path == sidecar)
            .and_then(|path| snapshot.objects.iter().find(|object| object.object == path.object))
            .is_some_and(|object| object.kind == FILE_TYPE_REGULAR);
        if !regular {
            findings.push(OracleFinding::new(
                "database-sidecar-object-kind",
                format!("SQLite sidecar {} is not a regular file", display_bytes(&sidecar)),
            ));
        }
    }
    findings
}

pub(crate) fn materialize(
    snapshot: &NamespaceSnapshot,
    database_path: &[u8],
) -> Result<MaterializedNamespace, OracleFinding> {
    #[cfg(not(unix))]
    {
        let _ = (snapshot, database_path);
        return Err(OracleFinding::new(
            "materialize-platform",
            "raw byte-path namespace materialization requires Unix",
        ));
    }
    #[cfg(unix)]
    {
        let temporary = tempfile::Builder::new()
            .prefix("visa-sqlite-oracle-")
            .tempdir()
            .map_err(|error| io_finding("materialize-tempdir", error))?;
        let namespace_root = temporary.path().join("namespace");
        let unlinked_root = temporary.path().join("unlinked");
        let analysis_root = temporary.path().join("analysis");
        fs::create_dir(&namespace_root)
            .and_then(|_| fs::create_dir(&unlinked_root))
            .and_then(|_| fs::create_dir(&analysis_root))
            .map_err(|error| io_finding("materialize-layout", error))?;
        materialize_linked(snapshot, &namespace_root)?;
        materialize_unlinked(snapshot, &unlinked_root)?;
        let report = namespace_report(snapshot, database_path);
        let state = serde_json::to_vec_pretty(&report).map_err(|error| {
            OracleFinding::new(
                "materialize-state-json",
                format!("cannot encode namespace state: {error}"),
            )
        })?;
        fs::write(temporary.path().join("namespace-state.json"), state)
            .map_err(|error| io_finding("materialize-state-write", error))?;
        let analysis_database = analysis_root.join("database.sqlite");
        let source_database = join_guest_path(&namespace_root, database_path);
        fs::copy(&source_database, &analysis_database)
            .map_err(|error| io_finding("materialize-database-copy", error))?;
        for sidecar in sqlite_sidecar_paths(snapshot, database_path) {
            let suffix = &sidecar[database_path.len()..];
            let destination_name =
                bytes_os_string(&[b"database.sqlite".as_slice(), suffix].concat());
            fs::copy(
                join_guest_path(&namespace_root, &sidecar),
                analysis_root.join(destination_name),
            )
            .map_err(|error| io_finding("materialize-sidecar-copy", error))?;
        }
        Ok(MaterializedNamespace { _temporary: temporary, analysis_database, report })
    }
}

#[cfg(unix)]
fn materialize_linked(snapshot: &NamespaceSnapshot, root: &Path) -> Result<(), OracleFinding> {
    let objects =
        snapshot.objects.iter().map(|object| (object.object, object)).collect::<BTreeMap<_, _>>();
    let mut directories = snapshot
        .paths
        .iter()
        .filter(|path| {
            !path.path.is_empty()
                && objects
                    .get(&path.object)
                    .is_some_and(|object| object.kind == FILE_TYPE_DIRECTORY)
        })
        .collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        path_depth(&left.path).cmp(&path_depth(&right.path)).then(left.path.cmp(&right.path))
    });
    for path in directories {
        fs::create_dir(join_guest_path(root, &path.path))
            .map_err(|error| io_finding("materialize-directory", error))?;
    }
    let mut first_link = BTreeMap::new();
    for path in snapshot.paths.iter().filter(|path| !path.path.is_empty()) {
        let object = objects[&path.object];
        if object.kind == FILE_TYPE_DIRECTORY {
            continue;
        }
        let destination = join_guest_path(root, &path.path);
        if let Some(first) = first_link.get(&path.object) {
            fs::hard_link(first, &destination)
                .map_err(|error| io_finding("materialize-hard-link", error))?;
            continue;
        }
        match object.kind {
            FILE_TYPE_REGULAR => fs::write(&destination, &object.bytes)
                .map_err(|error| io_finding("materialize-regular-file", error))?,
            FILE_TYPE_SYMLINK => {
                let target = object.symlink_target.as_deref().unwrap_or_default();
                std::os::unix::fs::symlink(OsStr::from_bytes(target), &destination)
                    .map_err(|error| io_finding("materialize-symlink", error))?;
            }
            _ => unreachable!("validated object kind"),
        }
        first_link.insert(path.object, destination);
    }
    Ok(())
}

#[cfg(unix)]
fn materialize_unlinked(snapshot: &NamespaceSnapshot, root: &Path) -> Result<(), OracleFinding> {
    let linked = snapshot.paths.iter().map(|path| path.object).collect::<BTreeSet<_>>();
    for object in snapshot.objects.iter().filter(|object| !linked.contains(&object.object)) {
        let destination = root.join(hex::encode(object.object.0));
        match object.kind {
            FILE_TYPE_REGULAR => fs::write(destination, &object.bytes)
                .map_err(|error| io_finding("materialize-unlinked-file", error))?,
            FILE_TYPE_DIRECTORY => fs::create_dir(destination)
                .map_err(|error| io_finding("materialize-unlinked-directory", error))?,
            FILE_TYPE_SYMLINK => {
                fs::write(destination, object.symlink_target.as_deref().unwrap_or_default())
                    .map_err(|error| io_finding("materialize-unlinked-symlink-target", error))?
            }
            _ => unreachable!("validated object kind"),
        }
    }
    Ok(())
}

fn sqlite_sidecar_paths(snapshot: &NamespaceSnapshot, database_path: &[u8]) -> Vec<Vec<u8>> {
    [b"-journal".as_slice(), b"-wal".as_slice(), b"-shm".as_slice()]
        .into_iter()
        .filter_map(|suffix| {
            let mut candidate = database_path.to_vec();
            candidate.extend_from_slice(suffix);
            snapshot.paths.iter().any(|path| path.path == candidate).then_some(candidate)
        })
        .collect()
}

fn is_canonical_path(path: &[u8]) -> bool {
    path.len() <= MAX_PATH_BYTES
        && !path.contains(&0)
        && path.first() != Some(&b'/')
        && (path.is_empty()
            || path
                .split(|byte| *byte == b'/')
                .all(|part| !part.is_empty() && part != b"." && part != b".."))
}

fn normalize_path(base: &[u8], path: &[u8]) -> Option<Vec<u8>> {
    if path.len() > MAX_PATH_BYTES || path.contains(&0) || path.first() == Some(&b'/') {
        return None;
    }
    let mut components = Vec::<Vec<u8>>::new();
    for component in base.split(|byte| *byte == b'/').chain(path.split(|byte| *byte == b'/')) {
        match component {
            b"" | b"." => {}
            b".." => {
                components.pop()?;
            }
            value => components.push(value.to_vec()),
        }
    }
    let mut normalized = Vec::new();
    for component in components {
        if !normalized.is_empty() {
            normalized.push(b'/');
        }
        normalized.extend_from_slice(&component);
    }
    (normalized.len() <= MAX_PATH_BYTES).then_some(normalized)
}

fn parent_path(path: &[u8]) -> &[u8] {
    path.iter().rposition(|byte| *byte == b'/').map_or(&[], |index| &path[..index])
}

fn path_depth(path: &[u8]) -> usize {
    usize::from(!path.is_empty()) + path.iter().filter(|byte| **byte == b'/').count()
}

#[cfg(unix)]
fn join_guest_path(root: &Path, path: &[u8]) -> PathBuf {
    root.join(bytes_os_string(path))
}

#[cfg(unix)]
fn bytes_os_string(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

fn kind_name(kind: u8) -> String {
    match kind {
        FILE_TYPE_DIRECTORY => "directory",
        FILE_TYPE_REGULAR => "regular_file",
        FILE_TYPE_SYMLINK => "symbolic_link",
        _ => "unknown",
    }
    .to_owned()
}

fn lock_name(level: LockLevel) -> &'static str {
    match level {
        LockLevel::None => "none",
        LockLevel::Shared => "shared",
        LockLevel::Reserved => "reserved",
        LockLevel::Pending => "pending",
        LockLevel::Exclusive => "exclusive",
    }
}

fn display_bytes(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes)
        .map(|value| format!("{value:?}"))
        .unwrap_or_else(|_| format!("hex:{}", hex::encode(bytes)))
}

fn io_finding(code: &'static str, error: std::io::Error) -> OracleFinding {
    OracleFinding::new(code, error.to_string())
}
