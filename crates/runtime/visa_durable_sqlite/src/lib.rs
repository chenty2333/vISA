//! Schema-independent durability mechanics for vISA SQLite stores.
//!
//! This crate intentionally has no vISA state or wire dependencies. Callers
//! provide their own schema audit and identity checks, then use these helpers
//! for the private single-writer filesystem lifecycle and SQLite WAL
//! publication boundary.

use std::{
    fs::{self, File},
    os::unix::{
        fs::{DirBuilderExt, FileExt, MetadataExt, PermissionsExt},
        io::AsFd,
    },
    path::{Path, PathBuf},
};

use rusqlite::Connection;
use rustix::{
    fs::{
        CWD, FileType, FlockOperation, Mode, OFlags, RenameFlags, flock, fstat, fsync, open,
        renameat_with,
    },
    process::geteuid,
};

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// Errors returned by the schema-independent durability boundary.
#[derive(Debug)]
pub enum DurableStoreError {
    /// The path has no usable parent directory or violates a path invariant.
    InvalidPath,
    /// Another process currently owns the non-blocking store lock.
    Busy,
    /// A create-new or `RENAME_NOREPLACE` operation found an existing path.
    AlreadyExists,
    /// An expected existing path was absent.
    Missing,
    /// A path or descriptor was not a private, current-user-owned object.
    Insecure,
    /// A file that should be SQLite did not contain the SQLite header.
    NotSqlite,
    /// A SQLite `-wal`, `-shm`, or `-journal` sidecar already existed.
    SidecarExists,
    /// A filesystem operation failed.
    Io(std::io::Error),
    /// A SQLite operation failed.
    Sqlite(rusqlite::Error),
    /// A completed operation returned an internally inconsistent result.
    Integrity,
}

impl std::fmt::Display for DurableStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath => formatter.write_str("invalid durability path"),
            Self::Busy => formatter.write_str("durable store is busy"),
            Self::AlreadyExists => formatter.write_str("durable store path already exists"),
            Self::Missing => formatter.write_str("durable store path is missing"),
            Self::Insecure => formatter.write_str("durable store path is not private and regular"),
            Self::NotSqlite => formatter.write_str("durable store file is not SQLite"),
            Self::SidecarExists => formatter.write_str("SQLite sidecar already exists"),
            Self::Io(error) => write!(formatter, "durable filesystem operation failed: {error}"),
            Self::Sqlite(error) => write!(formatter, "durable SQLite operation failed: {error}"),
            Self::Integrity => formatter.write_str("durable operation returned inconsistent state"),
        }
    }
}

impl std::error::Error for DurableStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for DurableStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// Result alias for durability operations.
pub type Result<T> = std::result::Result<T, DurableStoreError>;

/// Ensure that the immediate database parent is a private directory owned by
/// the current uid. A missing immediate parent is created with `0700`; its
/// own parent must already exist.
pub fn ensure_private_parent(database_path: &Path) -> Result<()> {
    let parent = database_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or(DurableStoreError::InvalidPath)?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) => verify_private_directory_metadata(&metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(parent).map_err(map_io)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(map_io)?;
            let metadata = fs::symlink_metadata(parent).map_err(map_io)?;
            verify_private_directory_metadata(&metadata)
        }
        Err(error) => Err(map_io(error)),
    }
}

/// A lifetime-held non-blocking exclusive store lock.
pub struct StoreLock {
    file: File,
    path: PathBuf,
}

impl StoreLock {
    /// Open/create `path` with `0600` and acquire a non-blocking exclusive
    /// `flock`. The returned file remains locked until dropped.
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        ensure_private_parent(path)?;
        let fd = open(
            path,
            OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(map_open_error)?;
        verify_private_regular_fd(&fd)?;
        flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN {
                DurableStoreError::Busy
            } else {
                map_errno(error)
            }
        })?;
        Ok(Self { file: fd.into(), path: path.to_path_buf() })
    }

    /// Return the lock path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the locked file descriptor for optional caller-side fsyncs.
    pub fn file(&self) -> &File {
        &self.file
    }
}

/// A descriptor-bound private regular database file.
///
/// `create_new` intentionally does not require an SQLite header: SQLite adds
/// that header during caller-owned schema initialization. `open_existing` and
/// publication do require the header.
pub struct DatabaseGuard {
    file: File,
    path: PathBuf,
}

impl DatabaseGuard {
    /// Create a new private `0600` database file with `O_EXCL|O_NOFOLLOW`.
    pub fn create_new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        ensure_private_parent(path)?;
        ensure_sqlite_sidecars_absent(path)?;
        let fd = open(
            path,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(map_open_error)?;
        verify_private_regular_fd(&fd)?;
        Ok(Self { file: fd.into(), path: path.to_path_buf() })
    }

    /// Open an existing private `0600` SQLite database with `O_NOFOLLOW`.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        ensure_private_parent(path)?;
        let fd = open(path, OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW, Mode::empty())
            .map_err(map_open_error)?;
        verify_private_regular_fd(&fd)?;
        let guard = Self { file: fd.into(), path: path.to_path_buf() };
        guard.verify_sqlite_header()?;
        Ok(guard)
    }

    /// Return the descriptor-bound database file.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Return the path used to open the descriptor.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify the descriptor is still a private regular file with a complete
    /// SQLite header. The check is descriptor-based for permissions/identity,
    /// and offset reads are used for the header.
    pub fn verify_sqlite_header(&self) -> Result<()> {
        verify_private_regular_fd(&self.file)?;
        let stat = fstat(&self.file).map_err(map_errno)?;
        if stat.st_size < SQLITE_HEADER.len() as i64 {
            return Err(DurableStoreError::NotSqlite);
        }
        let mut header = [0_u8; SQLITE_HEADER.len()];
        self.file.read_exact_at(&mut header, 0).map_err(map_io)?;
        if &header != SQLITE_HEADER {
            return Err(DurableStoreError::NotSqlite);
        }
        Ok(())
    }

    /// Fsync the descriptor while it remains bound to this inode.
    pub fn sync(&self) -> Result<()> {
        sync_file(&self.file)
    }

    /// Publish this closed SQLite file at `final_path` without replacement.
    /// The caller must close all SQLite connections before calling this method.
    pub fn publish_noreplace(&self, final_path: impl AsRef<Path>) -> Result<()> {
        publish_noreplace(&self.path, final_path.as_ref(), &self.file)
    }

    /// Best-effort, inode-bound cleanup of this initialization path and its
    /// SQLite sidecars. A changed path is never removed.
    pub fn cleanup_owned(&self) {
        cleanup_owned_initialization_files(&self.path, &self.file)
    }
}

/// Build the nonce-named temporary path used for an initialization attempt.
pub fn initialization_path(database_path: &Path, nonce: [u8; 16]) -> PathBuf {
    let nonce = u128::from_be_bytes(nonce);
    let mut value = database_path.as_os_str().to_os_string();
    value.push(format!(".init-{nonce:032x}"));
    PathBuf::from(value)
}

/// Build one SQLite sidecar path. Callers should pass only `-wal`, `-shm`, or
/// `-journal` as `suffix`.
pub fn sqlite_sidecar_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

/// Require that no SQLite sidecar exists for `database_path`.
pub fn ensure_sqlite_sidecars_absent(database_path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        match fs::symlink_metadata(sqlite_sidecar_path(database_path, suffix)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_io(error)),
            Ok(_) => return Err(DurableStoreError::SidecarExists),
        }
    }
    Ok(())
}

/// Fsync a file or descriptor.
pub fn sync_file(file: &impl AsFd) -> Result<()> {
    fsync(file).map_err(map_errno)
}

/// Fsync the private parent directory containing `database_path`.
pub fn sync_parent_directory(database_path: &Path) -> Result<()> {
    let parent = database_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or(DurableStoreError::InvalidPath)?;
    let directory = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(map_open_error)?;
    verify_private_directory_fd(&directory)?;
    fsync(&directory).map_err(map_errno)
}

/// Publish a closed SQLite initialization file with `RENAME_NOREPLACE`.
///
/// The descriptor is checked and fsynced before the rename. Both the source
/// and destination parents are fsynced after it, which also handles callers
/// that deliberately use distinct directories.
pub fn publish_noreplace(
    temporary_path: &Path,
    final_path: &Path,
    temporary_file: &File,
) -> Result<()> {
    ensure_private_parent(final_path)?;
    ensure_sqlite_sidecars_absent(temporary_path)?;
    ensure_sqlite_sidecars_absent(final_path)?;
    verify_private_regular_fd(temporary_file)?;
    verify_sqlite_header_fd(temporary_file)?;
    sync_file(temporary_file)?;
    renameat_with(CWD, temporary_path, CWD, final_path, RenameFlags::NOREPLACE).map_err(
        |error| {
            if error == rustix::io::Errno::EXIST {
                DurableStoreError::AlreadyExists
            } else if error == rustix::io::Errno::NOENT {
                DurableStoreError::Missing
            } else {
                map_errno(error)
            }
        },
    )?;
    sync_parent_directory(temporary_path)?;
    if temporary_path.parent() != final_path.parent() {
        sync_parent_directory(final_path)?;
    }
    Ok(())
}

/// Best-effort cleanup for an initialization path, guarded by the inode held
/// by `temporary_file`. This intentionally has no error result because it is
/// normally called while reporting an earlier initialization failure.
pub fn cleanup_owned_initialization_files(temporary_path: &Path, temporary_file: &impl AsFd) {
    let Ok(guard_stat) = fstat(temporary_file) else {
        return;
    };
    let Ok(path_metadata) = fs::symlink_metadata(temporary_path) else {
        return;
    };
    if !path_metadata.file_type().is_file()
        || path_metadata.dev() != guard_stat.st_dev
        || path_metadata.ino() != guard_stat.st_ino
    {
        return;
    }
    for suffix in ["-wal", "-shm", "-journal", ""] {
        let _ = fs::remove_file(sqlite_sidecar_path(temporary_path, suffix));
    }
}

/// Checkpoint and truncate a WAL before a database is closed and published.
pub fn checkpoint_truncate(connection: &Connection) -> Result<()> {
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(DurableStoreError::Sqlite)?;
    if busy != 0 {
        return Err(DurableStoreError::Busy);
    }
    if log_frames != 0 || checkpointed_frames != 0 {
        return Err(DurableStoreError::Integrity);
    }
    Ok(())
}

fn verify_private_regular_fd(fd: &impl AsFd) -> Result<()> {
    let stat = fstat(fd).map_err(map_errno)?;
    let permissions = Mode::from_raw_mode(stat.st_mode) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != geteuid().as_raw()
        || stat.st_nlink != 1
        || permissions != Mode::RUSR | Mode::WUSR
    {
        return Err(DurableStoreError::Insecure);
    }
    Ok(())
}

fn verify_private_directory_metadata(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(DurableStoreError::Insecure);
    }
    Ok(())
}

fn verify_private_directory_fd(fd: &impl AsFd) -> Result<()> {
    let stat = fstat(fd).map_err(map_errno)?;
    let permissions = Mode::from_raw_mode(stat.st_mode) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != geteuid().as_raw()
        || permissions != Mode::RWXU
    {
        return Err(DurableStoreError::Insecure);
    }
    Ok(())
}

fn verify_sqlite_header_fd(file: &File) -> Result<()> {
    let stat = fstat(file).map_err(map_errno)?;
    if stat.st_size < SQLITE_HEADER.len() as i64 {
        return Err(DurableStoreError::NotSqlite);
    }
    let mut header = [0_u8; SQLITE_HEADER.len()];
    file.read_exact_at(&mut header, 0).map_err(map_io)?;
    if &header != SQLITE_HEADER {
        return Err(DurableStoreError::NotSqlite);
    }
    Ok(())
}

fn map_open_error(error: rustix::io::Errno) -> DurableStoreError {
    match error {
        rustix::io::Errno::EXIST => DurableStoreError::AlreadyExists,
        rustix::io::Errno::NOENT => DurableStoreError::Missing,
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR | rustix::io::Errno::ACCESS => {
            DurableStoreError::Insecure
        }
        other => map_errno(other),
    }
}

fn map_errno(error: rustix::io::Errno) -> DurableStoreError {
    DurableStoreError::Io(error.into())
}

fn map_io(error: std::io::Error) -> DurableStoreError {
    DurableStoreError::Io(error)
}

#[cfg(test)]
mod tests;
