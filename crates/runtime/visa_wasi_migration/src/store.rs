use std::{
    ffi::OsString,
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use rustix::{
    fs::{CWD, FileType, Mode, OFlags, fstat, open, renameat},
    process::geteuid,
};
use visa_durable_sqlite::{StoreLock, sync_file, sync_parent_directory};

use crate::{DriverRecord, MigrationError};

pub trait DriverRecordStore {
    fn load(&mut self) -> Result<Option<DriverRecord>, MigrationError>;
    fn save(&mut self, record: &DriverRecord) -> Result<(), MigrationError>;
}

/// A single-writer, crash-stable canonical JSON record.
///
/// The lifetime-held lock serializes writers. Each update is written to a
/// private regular file, fsynced, atomically renamed over the previous record,
/// and followed by a parent-directory fsync.
pub struct FileDriverRecordStore {
    path: PathBuf,
    temporary_path: PathBuf,
    _lock: StoreLock,
}

impl FileDriverRecordStore {
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, MigrationError> {
        let path = path.as_ref().to_path_buf();
        let lock = StoreLock::acquire(suffixed_path(&path, ".lock"))
            .map_err(|error| MigrationError::Durability(error.to_string()))?;
        Ok(Self { temporary_path: suffixed_path(&path, ".next"), path, _lock: lock })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_path(path: &Path) -> Result<Option<Vec<u8>>, MigrationError> {
        let fd =
            match open(path, OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW, Mode::empty()) {
                Ok(fd) => fd,
                Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
                Err(error) => return Err(MigrationError::Io(io_error(error))),
            };
        validate_private_regular(&fd)?;
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(MigrationError::Io)?;
        validate_private_regular(&file)?;
        Ok(Some(bytes))
    }

    fn remove_stale_temporary(&self) -> Result<(), MigrationError> {
        let Some(_) = Self::read_path(&self.temporary_path)? else {
            return Ok(());
        };
        fs::remove_file(&self.temporary_path).map_err(MigrationError::Io)?;
        sync_parent_directory(&self.temporary_path)
            .map_err(|error| MigrationError::Durability(error.to_string()))
    }
}

impl DriverRecordStore for FileDriverRecordStore {
    fn load(&mut self) -> Result<Option<DriverRecord>, MigrationError> {
        let Some(bytes) = Self::read_path(&self.path)? else {
            return Ok(None);
        };
        DriverRecord::decode_canonical(&bytes).map(Some)
    }

    fn save(&mut self, record: &DriverRecord) -> Result<(), MigrationError> {
        let bytes = record.canonical_bytes()?;
        self.remove_stale_temporary()?;
        let fd = open(
            &self.temporary_path,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| MigrationError::Io(io_error(error)))?;
        let mut temporary = File::from(fd);
        let result = (|| {
            validate_private_regular(&temporary)?;
            temporary.write_all(&bytes).map_err(MigrationError::Io)?;
            temporary.flush().map_err(MigrationError::Io)?;
            validate_private_regular(&temporary)?;
            sync_file(&temporary).map_err(|error| MigrationError::Durability(error.to_string()))?;

            if Self::read_path(&self.path)?.is_some() {
                // `read_path` rejects symlinks, directories, hard links, and
                // non-private files before the replacing rename.
            }
            renameat(CWD, &self.temporary_path, CWD, &self.path)
                .map_err(|error| MigrationError::Io(io_error(error)))?;
            sync_parent_directory(&self.path)
                .map_err(|error| MigrationError::Durability(error.to_string()))
        })();
        if result.is_err() {
            cleanup_owned(&self.temporary_path, &temporary);
        }
        result
    }
}

fn validate_private_regular(fd: &impl std::os::fd::AsFd) -> Result<(), MigrationError> {
    let stat = fstat(fd).map_err(|error| MigrationError::Io(io_error(error)))?;
    let permissions = Mode::from_raw_mode(stat.st_mode) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != geteuid().as_raw()
        || stat.st_nlink != 1
        || permissions != Mode::RUSR | Mode::WUSR
    {
        return Err(MigrationError::Integrity(
            "driver record is not a private, singly-linked regular file",
        ));
    }
    Ok(())
}

fn cleanup_owned(path: &Path, file: &File) {
    let Ok(stat) = fstat(file) else {
        return;
    };
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_file()
        && metadata.dev() == stat.st_dev
        && metadata.ino() == stat.st_ino
    {
        let _ = fs::remove_file(path);
    }
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}
