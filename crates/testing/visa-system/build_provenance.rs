use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

const SOURCE_ROOTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "wit/cooperative-handoff",
    "crates/core/contract_core",
    "crates/core/semantic_core",
    "crates/core/visa_profile",
    "crates/backend/substrate_api",
    "crates/backend/substrate_host",
    "crates/runtime/visa_runtime",
    "crates/runtime/visa_wasmtime",
    "crates/testing/handoff-component",
    "crates/testing/visa-conformance",
    "crates/testing/visa-system",
    "scripts/check-dependency-direction.py",
    "scripts/ci-gate.sh",
    "scripts/run-report-gates.sh",
    "scripts/check-conformance-report.sh",
];

#[derive(Serialize)]
struct SourceManifest {
    schema: &'static str,
    files: Vec<SourceFileManifest>,
}

#[derive(Serialize)]
struct SourceFileManifest {
    path: String,
    bytes: u64,
    sha256: String,
}

pub struct BuildProvenance {
    pub source_digest: String,
    pub source_manifest_json: Vec<u8>,
    pub source_paths: Vec<PathBuf>,
    pub toolchain_digest: String,
    pub toolchain_raw: Vec<u8>,
}

pub fn collect(workspace_root: &Path) -> Result<BuildProvenance, Box<dyn Error>> {
    let mut source_paths = Vec::new();
    for relative in SOURCE_ROOTS {
        collect_source_files(&workspace_root.join(relative), &mut source_paths)?;
    }
    source_paths.sort_by_key(|path| {
        path.strip_prefix(workspace_root).unwrap_or(path).to_string_lossy().into_owned()
    });
    source_paths.dedup();

    let mut files = Vec::with_capacity(source_paths.len());
    for path in &source_paths {
        let relative = path.strip_prefix(workspace_root)?.to_string_lossy().replace('\\', "/");
        let bytes = fs::read(path)?;
        files.push(SourceFileManifest {
            path: relative,
            bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        });
    }
    let source_manifest = SourceManifest { schema: "visa-stage1-source-manifest-v1", files };
    let source_manifest_json = serde_json::to_vec(&source_manifest)?;
    let toolchain_raw = toolchain_provenance()?;

    Ok(BuildProvenance {
        source_digest: sha256_hex(&source_manifest_json),
        source_manifest_json,
        source_paths,
        toolchain_digest: sha256_hex(&toolchain_raw),
        toolchain_raw,
    })
}

fn collect_source_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(format!("source provenance path is a symlink: {}", path.display()).into());
    }
    if metadata.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }

    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_source_files(&entry.path(), files)?;
    }
    Ok(())
}

fn toolchain_provenance() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut raw = Vec::new();
    for (program, argument) in [("rustc", "-vV"), ("cargo", "-V")] {
        let output = Command::new(program).arg(argument).output()?;
        raw.extend_from_slice(format!("$ {program} {argument}\n").as_bytes());
        raw.extend_from_slice(&output.stdout);
        raw.extend_from_slice(&output.stderr);
        if !output.status.success() {
            return Err(format!("{program} {argument} failed with {}", output.status).into());
        }
    }
    Ok(raw)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
