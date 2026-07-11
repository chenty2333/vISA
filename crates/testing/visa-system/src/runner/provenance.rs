use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::{RunnerError, runner_io, worker_client::exit_status_text};

include!("../../source_roots.rs");

#[derive(Serialize)]
pub(super) struct SourceManifest {
    schema: &'static str,
    files: Vec<SourceFileManifest>,
}

#[derive(Serialize)]
pub(super) struct SourceFileManifest {
    path: String,
    bytes: u64,
    sha256: String,
}

pub(super) fn source_provenance(
    workspace_root: &Path,
) -> Result<(contract_core::Digest, SourceManifest), RunnerError> {
    let mut paths = Vec::new();
    for relative in SOURCE_ROOTS {
        collect_source_files(&workspace_root.join(relative), &mut paths)?;
    }
    paths.sort_by_key(|path| {
        path.strip_prefix(workspace_root).unwrap_or(path).to_string_lossy().into_owned()
    });
    paths.dedup();
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let relative = path.strip_prefix(workspace_root).map_err(|_| RunnerError::Registry {
            detail: format!("source path {} escaped workspace", path.display()),
        })?;
        let relative = relative.to_string_lossy().replace('\u{5c}', "/");
        let bytes = fs::read(&path)
            .map_err(|source| runner_io("read source provenance input", &path, source))?;
        files.push(SourceFileManifest {
            path: relative,
            bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        });
    }
    let manifest = SourceManifest { schema: "visa-stage1-source-manifest-v1", files };
    let canonical_json = serde_json::to_vec(&manifest).map_err(|error| RunnerError::Json {
        context: "encode deterministic source manifest".to_owned(),
        detail: error.to_string(),
    })?;
    Ok((sha256_digest(&canonical_json), manifest))
}

fn collect_source_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), RunnerError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| runner_io("inspect source provenance input", path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(RunnerError::Registry {
            detail: format!("source provenance path {} is a symlink", path.display()),
        });
    }
    if metadata.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }
    let mut entries = fs::read_dir(path)
        .map_err(|source| runner_io("read source provenance directory", path, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| runner_io("read source provenance entry", path, source))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_source_files(&entry.path(), files)?;
    }
    Ok(())
}

pub(super) fn toolchain_provenance() -> Result<(contract_core::Digest, Vec<u8>), RunnerError> {
    let mut raw = Vec::new();
    for (program, argument) in [("rustc", "-vV"), ("cargo", "-V")] {
        let output = Command::new(program)
            .arg(argument)
            .output()
            .map_err(|source| runner_io("run toolchain provenance command", program, source))?;
        raw.extend_from_slice(format!("$ {program} {argument}\n").as_bytes());
        raw.extend_from_slice(&output.stdout);
        raw.extend_from_slice(&output.stderr);
        if !output.status.success() {
            return Err(RunnerError::Registry {
                detail: format!(
                    "{program} {argument} exited as {}",
                    exit_status_text(output.status)
                ),
            });
        }
    }
    Ok((sha256_digest(&raw), raw))
}

pub(super) fn workspace_root() -> Result<PathBuf, RunnerError> {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3).map(Path::to_path_buf).ok_or_else(
        || RunnerError::Registry {
            detail: "cannot resolve workspace root from CARGO_MANIFEST_DIR".to_owned(),
        },
    )
}

pub(super) fn write_pretty_json(path: &Path, value: &impl Serialize) -> Result<(), RunnerError> {
    let bytes = pretty_json_bytes(value, format!("encode {}", path.display()))?;
    fs::write(path, bytes).map_err(|source| runner_io("write JSON artifact", path, source))
}

pub(super) fn pretty_json_bytes(
    value: &impl Serialize,
    context: impl Into<String>,
) -> Result<Vec<u8>, RunnerError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| RunnerError::Json {
        context: context.into(),
        detail: error.to_string(),
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(super) fn unix_time_ms() -> Result<u64, RunnerError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| RunnerError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| RunnerError::Clock)
}

fn sha256_digest(bytes: &[u8]) -> contract_core::Digest {
    contract_core::Digest::from_bytes(Sha256::digest(bytes).into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_and_build_source_provenance_are_identical() {
        let root = workspace_root().expect("workspace root");
        let (runtime_digest, runtime_manifest) =
            source_provenance(&root).expect("runtime source provenance");
        let runtime_json = serde_json::to_vec(&runtime_manifest).expect("runtime manifest JSON");

        assert_eq!(runtime_json, crate::build_info::SOURCE_MANIFEST_JSON);
        assert_eq!(
            runtime_digest.0.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            crate::build_info::SOURCE_SHA256
        );
    }
}
