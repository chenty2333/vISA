use std::path::{Component, Path};
#[cfg(all(test, target_os = "linux"))]
use std::{cell::RefCell, collections::BTreeMap};

#[cfg(target_os = "linux")]
use {
    rustix::{
        fs::{CWD, FileType, Mode, OFlags, ResolveFlags, fstat, openat2},
        io::Errno,
    },
    sha2::{Digest as _, Sha256},
    std::{
        fs::{self, File},
        io::{self, Read},
        os::{fd::AsRawFd as _, unix::fs::MetadataExt as _},
        path::PathBuf,
    },
};

#[cfg(target_os = "linux")]
pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum SecureArtifactErrorKind {
    UnsafeUri,
    Missing,
    Symlink,
    Escape,
    NotRegular,
    TooLarge,
    ResourceExhausted,
    ConcurrentMutation,
    Unsupported,
    Io,
}

#[derive(Debug)]
pub struct SecureArtifactError {
    pub kind: SecureArtifactErrorKind,
    pub detail: String,
}

impl std::fmt::Display for SecureArtifactError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for SecureArtifactError {}

/// A capability-style handle to one concrete artifact directory.
///
/// The directory is opened once. All child artifacts are resolved relative to
/// this descriptor, so renaming or replacing the ambient root pathname cannot
/// redirect later reads.
pub struct SecureArtifactRoot {
    #[cfg(target_os = "linux")]
    directory: File,
    #[cfg(target_os = "linux")]
    display: PathBuf,
    #[cfg(all(test, target_os = "linux"))]
    successful_regular_opens: RefCell<BTreeMap<String, usize>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureArtifactFile {
    pub bytes: Vec<u8>,
    pub device: u64,
    pub inode: u64,
    pub links: u64,
}

impl SecureArtifactRoot {
    #[cfg(target_os = "linux")]
    pub fn open(path: &Path) -> Result<Self, SecureArtifactError> {
        let descriptor = openat2(
            CWD,
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|source| SecureArtifactError {
            kind: if source == Errno::LOOP {
                SecureArtifactErrorKind::Symlink
            } else if source == Errno::NOENT || source == Errno::NOTDIR {
                SecureArtifactErrorKind::Missing
            } else if source == Errno::NOSYS || source == Errno::INVAL {
                SecureArtifactErrorKind::Unsupported
            } else {
                SecureArtifactErrorKind::Io
            },
            detail: format!("cannot securely open artifact root {}: {source}", path.display()),
        })?;
        let metadata = fstat(&descriptor).map_err(|source| SecureArtifactError {
            kind: SecureArtifactErrorKind::Io,
            detail: format!("cannot inspect artifact root {}: {source}", path.display()),
        })?;
        if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
            return Err(SecureArtifactError {
                kind: SecureArtifactErrorKind::NotRegular,
                detail: format!("artifact root is not a directory: {}", path.display()),
            });
        }
        Ok(Self {
            directory: descriptor.into(),
            display: path.to_path_buf(),
            #[cfg(test)]
            successful_regular_opens: RefCell::new(BTreeMap::new()),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open(path: &Path) -> Result<Self, SecureArtifactError> {
        Err(Self::unsupported_root(path))
    }

    #[cfg(target_os = "linux")]
    pub fn read_regular(&self, uri: &str) -> Result<Vec<u8>, SecureArtifactError> {
        let file = self.open_regular(uri)?;
        self.read_open_regular(file, uri)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn read_regular(&self, uri: &str) -> Result<Vec<u8>, SecureArtifactError> {
        validate_uri(uri)?;
        Err(Self::unsupported_artifact(uri))
    }

    #[cfg(target_os = "linux")]
    pub fn read_single_link_regular(
        &self,
        uri: &str,
        maximum: u64,
    ) -> Result<SecureArtifactFile, SecureArtifactError> {
        let file = self.open_regular(uri)?;
        self.read_open_regular_bounded(file, uri, maximum, true)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn read_single_link_regular(
        &self,
        uri: &str,
        _maximum: u64,
    ) -> Result<SecureArtifactFile, SecureArtifactError> {
        validate_uri(uri)?;
        Err(Self::unsupported_artifact(uri))
    }

    #[cfg(target_os = "linux")]
    pub fn inventory(&self) -> Result<Vec<String>, SecureArtifactError> {
        let descriptor_path =
            PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()));
        let entries = fs::read_dir(&descriptor_path).map_err(|source| SecureArtifactError {
            kind: SecureArtifactErrorKind::Io,
            detail: format!(
                "cannot enumerate securely opened artifact root {}: {source}",
                self.display.display()
            ),
        })?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| SecureArtifactError {
                kind: SecureArtifactErrorKind::Io,
                detail: format!("cannot enumerate artifact entry: {source}"),
            })?;
            let name = entry.file_name().into_string().map_err(|_| SecureArtifactError {
                kind: SecureArtifactErrorKind::UnsafeUri,
                detail: "artifact contains a non-UTF-8 entry name".to_owned(),
            })?;
            validate_uri(&name)?;
            let descriptor = self.inspect_relative(&name)?;
            let metadata = fstat(&descriptor).map_err(|source| SecureArtifactError {
                kind: SecureArtifactErrorKind::Io,
                detail: format!("cannot inspect artifact {name}: {source}"),
            })?;
            if !FileType::from_raw_mode(metadata.st_mode).is_file() || metadata.st_nlink != 1 {
                return Err(SecureArtifactError {
                    kind: SecureArtifactErrorKind::NotRegular,
                    detail: format!("artifact entry is not a single-link regular file: {name}"),
                });
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn inventory(&self) -> Result<Vec<String>, SecureArtifactError> {
        Err(Self::unsupported_root(Path::new(".")))
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn read_regular_after_open(
        &self,
        uri: &str,
        after_open: impl FnOnce(),
    ) -> Result<Vec<u8>, SecureArtifactError> {
        let file = self.open_regular(uri)?;
        after_open();
        self.read_open_regular(file, uri)
    }

    #[cfg(target_os = "linux")]
    fn read_open_regular(&self, file: File, uri: &str) -> Result<Vec<u8>, SecureArtifactError> {
        self.read_open_regular_bounded(file, uri, MAX_ARTIFACT_BYTES, false)
            .map(|artifact| artifact.bytes)
    }

    #[cfg(target_os = "linux")]
    fn read_open_regular_bounded(
        &self,
        mut file: File,
        uri: &str,
        maximum: u64,
        require_single_link: bool,
    ) -> Result<SecureArtifactFile, SecureArtifactError> {
        let before = file.metadata().map_err(|source| self.io_error(uri, source))?;
        if !before.file_type().is_file() || (require_single_link && before.nlink() != 1) {
            return Err(SecureArtifactError {
                kind: SecureArtifactErrorKind::NotRegular,
                detail: format!("artifact is not a single-link regular file: {uri}"),
            });
        }
        if before.len() > maximum {
            return Err(self.too_large_bounded(uri, maximum));
        }
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = match file.read(&mut buffer) {
                Ok(read) => read,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(self.io_error(uri, source)),
            };
            if read == 0 {
                break;
            }
            let new_len = bytes.len().checked_add(read).ok_or_else(|| self.too_large(uri))?;
            if u64::try_from(new_len).unwrap_or(u64::MAX) > maximum {
                return Err(self.too_large_bounded(uri, maximum));
            }
            bytes.try_reserve(read).map_err(|source| SecureArtifactError {
                kind: SecureArtifactErrorKind::ResourceExhausted,
                detail: format!("cannot reserve memory for artifact {uri}: {source}"),
            })?;
            bytes.extend_from_slice(&buffer[..read]);
        }
        let after = file.metadata().map_err(|source| self.io_error(uri, source))?;
        let before_identity = (
            before.dev(),
            before.ino(),
            before.nlink(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        );
        let after_identity = (
            after.dev(),
            after.ino(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        );
        if before_identity != after_identity
            || bytes.len() != usize::try_from(after.len()).unwrap_or(usize::MAX)
        {
            return Err(SecureArtifactError {
                kind: SecureArtifactErrorKind::ConcurrentMutation,
                detail: format!("artifact changed while being read: {uri}"),
            });
        }
        Ok(SecureArtifactFile {
            bytes,
            device: after.dev(),
            inode: after.ino(),
            links: after.nlink(),
        })
    }

    #[cfg(target_os = "linux")]
    pub fn sha256_regular(&self, uri: &str) -> Result<String, SecureArtifactError> {
        let file = self.open_regular(uri)?;
        self.sha256_open_regular(file, uri, || {})
    }

    #[cfg(all(test, target_os = "linux"))]
    fn sha256_regular_after_metadata(
        &self,
        uri: &str,
        after_metadata: impl FnOnce(),
    ) -> Result<String, SecureArtifactError> {
        let file = self.open_regular(uri)?;
        self.sha256_open_regular(file, uri, after_metadata)
    }

    #[cfg(target_os = "linux")]
    fn sha256_open_regular(
        &self,
        mut file: File,
        uri: &str,
        after_metadata: impl FnOnce(),
    ) -> Result<String, SecureArtifactError> {
        let before = file.metadata().map_err(|source| self.io_error(uri, source))?;
        if before.len() > MAX_ARTIFACT_BYTES {
            return Err(self.too_large(uri));
        }
        after_metadata();
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = match file.read(&mut buffer) {
                Ok(read) => read,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(self.io_error(uri, source)),
            };
            if read == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
                .ok_or_else(|| self.too_large(uri))?;
            if total > MAX_ARTIFACT_BYTES {
                return Err(self.too_large(uri));
            }
            digest.update(&buffer[..read]);
        }
        let after = file.metadata().map_err(|source| self.io_error(uri, source))?;
        let before_identity = (
            before.dev(),
            before.ino(),
            before.nlink(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        );
        let after_identity = (
            after.dev(),
            after.ino(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        );
        if before_identity != after_identity || total != after.len() {
            return Err(SecureArtifactError {
                kind: SecureArtifactErrorKind::ConcurrentMutation,
                detail: format!("artifact changed while being hashed: {uri}"),
            });
        }
        Ok(format!("{:x}", digest.finalize()))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn sha256_regular(&self, uri: &str) -> Result<String, SecureArtifactError> {
        validate_uri(uri)?;
        Err(Self::unsupported_artifact(uri))
    }

    #[cfg(target_os = "linux")]
    fn open_regular(&self, uri: &str) -> Result<File, SecureArtifactError> {
        validate_uri(uri)?;
        let descriptor = self.open_relative(uri)?;
        let metadata = fstat(&descriptor).map_err(|source| SecureArtifactError {
            kind: SecureArtifactErrorKind::Io,
            detail: format!("cannot inspect artifact {uri}: {source}"),
        })?;
        if !FileType::from_raw_mode(metadata.st_mode).is_file() {
            return Err(SecureArtifactError {
                kind: SecureArtifactErrorKind::NotRegular,
                detail: format!("artifact is not a regular file: {uri}"),
            });
        }
        self.record_successful_regular_open(uri);
        Ok(descriptor.into())
    }

    #[cfg(all(test, target_os = "linux"))]
    fn record_successful_regular_open(&self, uri: &str) {
        *self.successful_regular_opens.borrow_mut().entry(uri.to_owned()).or_default() += 1;
    }

    #[cfg(all(not(test), target_os = "linux"))]
    fn record_successful_regular_open(&self, _uri: &str) {}

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn successful_regular_open_counts(&self) -> BTreeMap<String, usize> {
        self.successful_regular_opens.borrow().clone()
    }

    #[cfg(target_os = "linux")]
    fn open_relative(&self, uri: &str) -> Result<rustix::fd::OwnedFd, SecureArtifactError> {
        self.open_relative_with_flags(
            uri,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        )
    }

    #[cfg(target_os = "linux")]
    fn inspect_relative(&self, uri: &str) -> Result<rustix::fd::OwnedFd, SecureArtifactError> {
        self.open_relative_with_flags(uri, OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW)
    }

    #[cfg(target_os = "linux")]
    fn open_relative_with_flags(
        &self,
        uri: &str,
        flags: OFlags,
    ) -> Result<rustix::fd::OwnedFd, SecureArtifactError> {
        let mut last = Errno::AGAIN;
        for attempt in 0..3 {
            match openat2(
                &self.directory,
                uri,
                flags,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            ) {
                Ok(descriptor) => return Ok(descriptor),
                Err(source) if source == Errno::AGAIN && attempt < 2 => last = source,
                Err(source) => {
                    last = source;
                    break;
                }
            }
        }
        Err({
            let source = last;
            let kind = if source == Errno::LOOP {
                SecureArtifactErrorKind::Symlink
            } else if source == Errno::XDEV {
                SecureArtifactErrorKind::Escape
            } else if source == Errno::NOENT || source == Errno::NOTDIR {
                SecureArtifactErrorKind::Missing
            } else if source == Errno::AGAIN {
                SecureArtifactErrorKind::ConcurrentMutation
            } else if source == Errno::NOSYS || source == Errno::INVAL {
                SecureArtifactErrorKind::Unsupported
            } else {
                SecureArtifactErrorKind::Io
            };
            SecureArtifactError {
                kind,
                detail: format!(
                    "cannot securely open artifact {uri} beneath {}: {source}",
                    self.display.display()
                ),
            }
        })
    }

    #[cfg(target_os = "linux")]
    fn io_error(&self, uri: &str, source: io::Error) -> SecureArtifactError {
        SecureArtifactError {
            kind: SecureArtifactErrorKind::Io,
            detail: format!("cannot read artifact {uri}: {source}"),
        }
    }

    #[cfg(target_os = "linux")]
    fn too_large(&self, uri: &str) -> SecureArtifactError {
        self.too_large_bounded(uri, MAX_ARTIFACT_BYTES)
    }

    #[cfg(target_os = "linux")]
    fn too_large_bounded(&self, uri: &str, maximum: u64) -> SecureArtifactError {
        SecureArtifactError {
            kind: SecureArtifactErrorKind::TooLarge,
            detail: format!("artifact {uri} exceeds the {maximum}-byte limit"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn unsupported_root(path: &Path) -> SecureArtifactError {
        SecureArtifactError {
            kind: SecureArtifactErrorKind::Unsupported,
            detail: format!(
                "secure artifact root resolution is unsupported on this platform: {}",
                path.display()
            ),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn unsupported_artifact(uri: &str) -> SecureArtifactError {
        SecureArtifactError {
            kind: SecureArtifactErrorKind::Unsupported,
            detail: format!("secure artifact resolution for {uri} is unsupported on this platform"),
        }
    }
}

fn validate_uri(uri: &str) -> Result<(), SecureArtifactError> {
    let path = Path::new(uri);
    if uri.trim().is_empty()
        || path.is_absolute()
        || path.components().any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SecureArtifactError {
            kind: SecureArtifactErrorKind::UnsafeUri,
            detail: format!("unsafe artifact URI {uri}"),
        });
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        fs,
        os::{fd::AsRawFd, unix::fs::symlink},
        path::{Path, PathBuf},
        sync::mpsc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use rustix::fs::{Mode, mkfifoat};

    use super::{MAX_ARTIFACT_BYTES, SecureArtifactErrorKind, SecureArtifactRoot};

    #[test]
    fn reader_opens_a_relative_root_against_the_process_cwd() {
        let name = temp_dir("relative-root").file_name().unwrap().to_owned();
        let root = PathBuf::from(name);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("item"), b"relative-root").unwrap();

        let reader = SecureArtifactRoot::open(&root).unwrap();

        assert_eq!(reader.read_regular("item").unwrap(), b"relative-root");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inventory_is_root_anchored_sorted_and_single_link_only() {
        let root = temp_dir("inventory");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("zeta"), b"z").unwrap();
        fs::write(root.join("alpha"), b"a").unwrap();
        let reader = SecureArtifactRoot::open(&root).unwrap();

        assert_eq!(reader.inventory().unwrap(), ["alpha", "zeta"]);
        assert_eq!(reader.read_single_link_regular("alpha", 1).unwrap().bytes, b"a");

        fs::hard_link(root.join("alpha"), root.join("linked")).unwrap();
        assert_eq!(
            reader.read_single_link_regular("alpha", 1).unwrap_err().kind,
            SecureArtifactErrorKind::NotRegular
        );
        assert_eq!(reader.inventory().unwrap_err().kind, SecureArtifactErrorKind::NotRegular);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn single_link_reader_enforces_the_caller_limit() {
        let root = temp_dir("caller-limit");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("item"), b"bounded").unwrap();
        let reader = SecureArtifactRoot::open(&root).unwrap();

        assert_eq!(
            reader.read_single_link_regular("item", 6).unwrap_err().kind,
            SecureArtifactErrorKind::TooLarge
        );
        assert_eq!(reader.read_single_link_regular("item", 7).unwrap().bytes, b"bounded");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reader_remains_anchored_to_the_open_root_directory() {
        let root = temp_dir("root-anchor");
        let moved = root.with_extension("opened");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/item"), b"opened-root").unwrap();
        let reader = SecureArtifactRoot::open(&root).unwrap();

        fs::rename(&root, &moved).unwrap();
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/item"), b"replacement-root").unwrap();

        assert_eq!(reader.read_regular("nested/item").unwrap(), b"opened-root");
        assert_eq!(fs::read(root.join("nested/item")).unwrap(), b"replacement-root");
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[test]
    fn reader_rejects_intermediate_and_final_symlink_replacements() {
        let root = temp_dir("symlink-swap");
        let outside = temp_dir("symlink-outside");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("nested/item"), b"inside").unwrap();
        fs::write(outside.join("item"), b"outside").unwrap();
        let reader = SecureArtifactRoot::open(&root).unwrap();

        fs::rename(root.join("nested"), root.join("original-nested")).unwrap();
        symlink(&outside, root.join("nested")).unwrap();
        let intermediate = reader.read_regular("nested/item").unwrap_err();
        assert!(matches!(
            intermediate.kind,
            SecureArtifactErrorKind::Symlink | SecureArtifactErrorKind::Escape
        ));

        fs::remove_file(root.join("nested")).unwrap();
        fs::rename(root.join("original-nested"), root.join("nested")).unwrap();
        fs::rename(root.join("nested/item"), root.join("nested/original-item")).unwrap();
        symlink(outside.join("item"), root.join("nested/item")).unwrap();
        let final_item = reader.read_regular("nested/item").unwrap_err();
        assert!(matches!(
            final_item.kind,
            SecureArtifactErrorKind::Symlink | SecureArtifactErrorKind::Escape
        ));

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn reader_consumes_the_opened_inode_after_a_final_path_swap() {
        let root = temp_dir("opened-inode");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("item"), b"opened-inode").unwrap();
        fs::write(root.join("replacement"), b"replacement-path").unwrap();
        let reader = SecureArtifactRoot::open(&root).unwrap();
        let bytes = reader
            .read_regular_after_open("item", || {
                fs::rename(root.join("replacement"), root.join("item")).unwrap();
            })
            .unwrap();

        assert_eq!(bytes, b"opened-inode");
        assert_eq!(fs::read(root.join("item")).unwrap(), b"replacement-path");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reader_rejects_a_fifo_without_blocking() {
        let root = temp_dir("fifo");
        fs::create_dir_all(&root).unwrap();
        let reader = SecureArtifactRoot::open(&root).unwrap();
        mkfifoat(&reader.directory, "pipe", Mode::RUSR | Mode::WUSR).unwrap();
        let (sender, receiver) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            sender.send(reader.read_regular("pipe").map_err(|error| error.kind)).unwrap();
        });

        let result = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("secure artifact open blocked on a FIFO");
        assert_eq!(result.unwrap_err(), SecureArtifactErrorKind::NotRegular);
        handle.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reader_rejects_oversized_regular_files_before_allocation() {
        let root = temp_dir("oversized");
        fs::create_dir_all(&root).unwrap();
        let file = fs::File::create(root.join("item")).unwrap();
        file.set_len(MAX_ARTIFACT_BYTES + 1).unwrap();
        let reader = SecureArtifactRoot::open(&root).unwrap();

        assert_eq!(
            reader.read_regular("item").unwrap_err().kind,
            SecureArtifactErrorKind::TooLarge
        );
        assert_eq!(
            reader.sha256_regular("item").unwrap_err().kind,
            SecureArtifactErrorKind::TooLarge
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hasher_rejects_same_length_mutation_after_initial_metadata() {
        let root = temp_dir("hash-mutation");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("item"), b"before").unwrap();
        let reader = SecureArtifactRoot::open(&root).unwrap();

        let error = reader
            .sha256_regular_after_metadata("item", || {
                fs::write(root.join("item"), b"after!").unwrap();
            })
            .unwrap_err();

        assert_eq!(error.kind, SecureArtifactErrorKind::ConcurrentMutation);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reader_rejects_proc_fd_magic_links() {
        let root = temp_dir("magic-link");
        let outside = temp_dir("magic-link-outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let outside_file = fs::File::create(outside.join("secret")).unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&outside_file);
        symlink(format!("/proc/self/fd/{fd}"), root.join("item")).unwrap();
        let reader = SecureArtifactRoot::open(&root).unwrap();

        let error = reader.read_regular("item").unwrap_err();
        assert!(matches!(
            error.kind,
            SecureArtifactErrorKind::Symlink | SecureArtifactErrorKind::Escape
        ));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn reader_rejects_a_proc_fd_magic_link_as_the_root() {
        let root = temp_dir("magic-link-root");
        fs::create_dir_all(&root).unwrap();
        let root_file = fs::File::open(&root).unwrap();
        let magic_root = PathBuf::from(format!("/proc/self/fd/{}", root_file.as_raw_fd()));

        let error = SecureArtifactRoot::open(&magic_root).err().expect("magic root must fail");

        assert_eq!(error.kind, SecureArtifactErrorKind::Symlink);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reader_rejects_crossing_a_mount_beneath_the_root() {
        if !Path::new("/proc/version").is_file() {
            return;
        }
        let reader = SecureArtifactRoot::open(Path::new("/")).unwrap();

        let error = reader.read_regular("proc/version").unwrap_err();

        assert_eq!(error.kind, SecureArtifactErrorKind::Escape);
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir()
            .join(format!("visa-secure-artifact-{label}-{}-{nonce}", std::process::id()))
    }
}
