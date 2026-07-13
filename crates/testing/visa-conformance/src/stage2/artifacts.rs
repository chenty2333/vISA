use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    STAGE2_INCOMPLETE_MARKER_FILE, Stage2ArtifactReference, Stage2ClaimSet,
    Stage2ValidationFinding, Stage2WriteError, stage2_cell_descriptors,
};
use crate::{
    artifact_io::{SecureArtifactErrorKind, SecureArtifactRoot},
    sha256_hex,
};

static NEXT_STAGE2_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

pub(super) fn validate_cell_directory_set(
    root: &Path,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let cells_root = root.join("cells");
    let observed = match read_directory_entry_set(
        &cells_root,
        "Stage 2 cells",
        "missing-stage2-cells-root",
        findings,
    ) {
        Some(observed) => observed,
        None => return,
    };
    let descriptors = stage2_cell_descriptors(Stage2ClaimSet::CrossExecutionPathPortability);
    let expected = descriptors
        .clone()
        .map(|descriptor| descriptor.id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if observed != expected {
        finding(
            findings,
            "unmanifested-or-missing-stage2-cell",
            "cells/ must contain exactly the four fixed cell directories",
        );
    }
    for descriptor in descriptors {
        let path = cells_root.join(descriptor.id.as_str());
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => finding(
                findings,
                "invalid-stage2-cell-entry-type",
                format!("{} is not a regular directory", path.display()),
            ),
            Err(source) => finding(
                findings,
                "unreadable-stage2-cell-entry",
                format!("cannot inspect {}: {source}", path.display()),
            ),
        }
    }
}

fn read_directory_entry_set(
    directory: &Path,
    label: &str,
    read_error_code: &str,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> Option<BTreeSet<String>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) => {
            finding(
                findings,
                read_error_code,
                format!("cannot read {label} directory {}: {source}", directory.display()),
            );
            return None;
        }
    };

    let mut observed = BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => {
                finding(
                    findings,
                    "unreadable-stage2-directory-entry",
                    format!("cannot enumerate {label} directory {}: {source}", directory.display()),
                );
                return None;
            }
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => {
                finding(
                    findings,
                    "non-utf8-stage2-directory-entry",
                    format!("{label} directory {} contains a non-UTF-8 entry", directory.display()),
                );
                return None;
            }
        };
        observed.insert(name);
    }
    Some(observed)
}

pub(super) fn validate_normalized_directory_set(
    root: &Path,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let normalized_root = root.join("normalized");
    let observed = match read_directory_entry_set(
        &normalized_root,
        "Stage 2 normalized",
        "missing-stage2-normalized-root",
        findings,
    ) {
        Some(observed) => observed,
        None => return,
    };
    let descriptors = stage2_cell_descriptors(Stage2ClaimSet::CrossExecutionPathPortability);
    let expected = descriptors
        .clone()
        .map(|descriptor| format!("{}.json", descriptor.id.as_str()))
        .collect::<BTreeSet<_>>();
    if observed != expected {
        finding(
            findings,
            "unmanifested-or-missing-stage2-normalized-cache",
            "normalized/ must contain exactly the four fixed cell caches",
        );
    }
    for descriptor in descriptors {
        let path = normalized_root.join(format!("{}.json", descriptor.id.as_str()));
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => finding(
                findings,
                "invalid-stage2-normalized-entry-type",
                format!("{} is not a regular file", path.display()),
            ),
            Err(source) => finding(
                findings,
                "unreadable-stage2-normalized-entry",
                format!("cannot inspect {}: {source}", path.display()),
            ),
        }
    }
}

pub(super) fn read_and_hash(
    root: &Path,
    reference: &Stage2ArtifactReference,
    label: &str,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> Option<Vec<u8>> {
    let bytes = match read_contained(root, &reference.uri) {
        Ok(bytes) => bytes,
        Err(source) => {
            findings.push(source);
            return None;
        }
    };
    let observed = sha256_hex(&bytes);
    if observed != reference.sha256 {
        finding(
            findings,
            "stage2-artifact-digest-mismatch",
            format!("{label} {} is {observed}, expected {}", reference.uri, reference.sha256),
        );
        return None;
    }
    Some(bytes)
}

pub(crate) fn read_contained(root: &Path, uri: &str) -> Result<Vec<u8>, Stage2ValidationFinding> {
    if !safe_relative_uri(uri) {
        return Err(single_finding(
            "invalid-stage2-artifact-uri",
            format!("unsafe artifact URI {uri}"),
        ));
    }
    let secure = SecureArtifactRoot::open(root).map_err(|source| {
        let code = if source.kind == SecureArtifactErrorKind::Unsupported {
            "stage2-secure-artifact-reader-unavailable"
        } else {
            "invalid-stage2-artifact-root"
        };
        single_finding(code, source.detail)
    })?;
    secure.read_regular(uri).map_err(|source| {
        let code = match source.kind {
            SecureArtifactErrorKind::UnsafeUri => "invalid-stage2-artifact-uri",
            SecureArtifactErrorKind::Missing => "missing-stage2-artifact",
            SecureArtifactErrorKind::Symlink => "stage2-artifact-symlink-rejected",
            SecureArtifactErrorKind::Escape => "stage2-artifact-path-escape",
            SecureArtifactErrorKind::NotRegular => "invalid-stage2-artifact-type",
            SecureArtifactErrorKind::TooLarge => "stage2-artifact-too-large",
            SecureArtifactErrorKind::ResourceExhausted => "unreadable-stage2-artifact",
            SecureArtifactErrorKind::ConcurrentMutation => "stage2-artifact-concurrent-mutation",
            SecureArtifactErrorKind::Unsupported => "stage2-secure-artifact-reader-unavailable",
            SecureArtifactErrorKind::Io => "unreadable-stage2-artifact",
        };
        single_finding(code, source.detail)
    })
}

pub(super) fn remove_if_exists(path: &Path) -> Result<(), Stage2WriteError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(write_error(
            "cannot-remove-stage2-incomplete-marker",
            format!("cannot remove {}: {source}", path.display()),
        )),
    }
}

pub(super) fn ensure_incomplete_marker(root: &Path) -> Result<(), Stage2WriteError> {
    let path = root.join(STAGE2_INCOMPLETE_MARKER_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(write_error(
            "invalid-stage2-incomplete-marker",
            format!("{} is not a regular file", path.display()),
        )),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            publish_atomic(root, STAGE2_INCOMPLETE_MARKER_FILE, b"incomplete\n")
        }
        Err(source) => Err(write_error(
            "cannot-inspect-stage2-incomplete-marker",
            format!("cannot inspect {}: {source}", path.display()),
        )),
    }
}

fn safe_relative_uri(uri: &str) -> bool {
    let path = Path::new(uri);
    !uri.is_empty()
        && !path.is_absolute()
        && path.components().all(|component| matches!(component, Component::Normal(_)))
}

pub(crate) fn publish_atomic(root: &Path, uri: &str, bytes: &[u8]) -> Result<(), Stage2WriteError> {
    if !safe_relative_uri(uri) {
        return Err(write_error(
            "invalid-stage2-publication-uri",
            format!("unsafe publication URI {uri}"),
        ));
    }
    reject_existing_symlink_components(root, uri)?;
    let destination = root.join(uri);
    let parent = destination.parent().ok_or_else(|| {
        write_error(
            "invalid-stage2-publication-uri",
            format!("{} has no parent", destination.display()),
        )
    })?;
    fs::create_dir_all(parent).map_err(|source| {
        write_error(
            "cannot-create-stage2-publication-parent",
            format!("cannot create {}: {source}", parent.display()),
        )
    })?;
    reject_existing_symlink_components(root, uri)?;
    let file_name = destination.file_name().and_then(|name| name.to_str()).ok_or_else(|| {
        write_error(
            "invalid-stage2-publication-uri",
            format!("{} has no UTF-8 file name", destination.display()),
        )
    })?;
    let nonce = NEXT_STAGE2_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let mut file =
        fs::OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(|source| {
            write_error(
                "cannot-create-stage2-temporary-artifact",
                format!("cannot create {}: {source}", temporary.display()),
            )
        })?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(write_error(
            "cannot-write-stage2-temporary-artifact",
            format!("cannot write {}: {source}", temporary.display()),
        ));
    }
    drop(file);
    if let Err(source) = fs::hard_link(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        let (code, detail) = if source.kind() == std::io::ErrorKind::AlreadyExists {
            ("stage2-publication-conflict", format!("{} already exists", destination.display()))
        } else {
            (
                "cannot-publish-stage2-artifact",
                format!("cannot link {}: {source}", destination.display()),
            )
        };
        return Err(write_error(code, detail));
    }
    if let Err(source) = fs::remove_file(&temporary) {
        return Err(write_error(
            "cannot-remove-stage2-temporary-artifact",
            format!("cannot remove {}: {source}", temporary.display()),
        ));
    }
    sync_directory(parent)
}

pub(super) fn sync_directory(path: &Path) -> Result<(), Stage2WriteError> {
    let directory = fs::File::open(path).map_err(|source| {
        write_error(
            "cannot-open-stage2-publication-directory",
            format!("cannot open {}: {source}", path.display()),
        )
    })?;
    directory.sync_all().map_err(|source| {
        write_error(
            "cannot-sync-stage2-publication-directory",
            format!("cannot sync {}: {source}", path.display()),
        )
    })
}

fn reject_existing_symlink_components(root: &Path, uri: &str) -> Result<(), Stage2WriteError> {
    let mut prefix = root.to_path_buf();
    for component in Path::new(uri).components() {
        let Component::Normal(component) = component else { unreachable!() };
        prefix.push(component);
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(write_error(
                    "stage2-publication-symlink-rejected",
                    format!("publication path contains symlink component {}", prefix.display()),
                ));
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(write_error(
                    "cannot-inspect-stage2-publication-path",
                    format!("cannot inspect {}: {source}", prefix.display()),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn finding(
    findings: &mut Vec<Stage2ValidationFinding>,
    code: impl Into<String>,
    detail: impl Into<String>,
) {
    findings.push(single_finding(code, detail));
}

pub(super) fn single_finding(
    code: impl Into<String>,
    detail: impl Into<String>,
) -> Stage2ValidationFinding {
    Stage2ValidationFinding { code: code.into(), detail: detail.into() }
}

pub(super) fn write_error(code: impl Into<String>, detail: impl Into<String>) -> Stage2WriteError {
    Stage2WriteError { code: code.into(), detail: detail.into() }
}

pub(super) fn write_from_finding(finding: Stage2ValidationFinding) -> Stage2WriteError {
    write_error(finding.code, finding.detail)
}

pub(super) fn render_findings(findings: &[Stage2ValidationFinding]) -> String {
    findings
        .iter()
        .map(|finding| format!("{}: {}", finding.code, finding.detail))
        .collect::<Vec<_>>()
        .join("; ")
}
