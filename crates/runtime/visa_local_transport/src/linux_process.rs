use std::{fs::File, io::Read, os::fd::AsFd};

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{FileType, Mode, OFlags, PROC_SUPER_MAGIC, fstat, fstatfs, open, openat},
    process::Pid,
};
use sha2::{Digest as _, Sha256};

use crate::PeerVerificationError;

const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutableObservation {
    identity: ExecutableIdentity,
    sha256: [u8; 32],
}

impl ExecutableObservation {
    pub(crate) const fn sha256(self) -> [u8; 32] {
        self.sha256
    }
}

pub(crate) fn require_live_pidfd(fd: &impl AsFd) -> Result<(), PeerVerificationError> {
    let mut descriptor =
        [PollFd::new(fd, PollFlags::IN | PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)];
    let ready = poll(&mut descriptor, Some(&Timespec::default()))
        .map_err(|_| PeerVerificationError::Host)?;
    if ready == 0 && descriptor[0].revents().is_empty() {
        Ok(())
    } else {
        Err(PeerVerificationError::ProcessExited)
    }
}

pub(crate) fn observe_executable(pid: Pid) -> Result<ExecutableObservation, PeerVerificationError> {
    let proc_root = open(
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| PeerVerificationError::InvalidProcfs)?;
    if fstatfs(&proc_root).map_err(|_| PeerVerificationError::InvalidProcfs)?.f_type
        != PROC_SUPER_MAGIC
    {
        return Err(PeerVerificationError::InvalidProcfs);
    }
    let pid_directory = openat(
        &proc_root,
        pid.as_raw_pid().to_string(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| PeerVerificationError::ProcessExited)?;
    let first = open_executable(&pid_directory)?;
    let first_identity = executable_identity(&first)?;
    let mut file = File::from(first);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|_| PeerVerificationError::InvalidExecutable)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or(PeerVerificationError::InvalidExecutable)?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(PeerVerificationError::InvalidExecutable);
        }
        hasher.update(&buffer[..read]);
    }
    if total != first_identity.size {
        return Err(PeerVerificationError::ExecutableChanged);
    }
    let after_hash = executable_identity(&file)?;
    if after_hash != first_identity {
        return Err(PeerVerificationError::ExecutableChanged);
    }
    let reopened = open_executable(&pid_directory)?;
    if executable_identity(&reopened)? != first_identity {
        return Err(PeerVerificationError::ExecutableChanged);
    }
    Ok(ExecutableObservation { identity: first_identity, sha256: hasher.finalize().into() })
}

fn open_executable(
    pid_directory: &impl AsFd,
) -> Result<std::os::fd::OwnedFd, PeerVerificationError> {
    // `/proc/<pid>/exe` is intentionally a procfs magic link. Safety comes
    // from the verified procfs dirfd, pinned process, opened fd, and repeated
    // identity checks rather than NOFOLLOW on the final component.
    openat(pid_directory, "exe", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| PeerVerificationError::InvalidExecutable)
}

fn executable_identity(fd: &impl AsFd) -> Result<ExecutableIdentity, PeerVerificationError> {
    let stat = fstat(fd).map_err(|_| PeerVerificationError::InvalidExecutable)?;
    let size = u64::try_from(stat.st_size).map_err(|_| PeerVerificationError::InvalidExecutable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_nlink != 1
        || stat.st_mode & 0o111 == 0
        || size == 0
        || size > MAX_EXECUTABLE_BYTES
    {
        return Err(PeerVerificationError::InvalidExecutable);
    }
    Ok(ExecutableIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
        size,
        mode: stat.st_mode,
        links: stat.st_nlink as u64,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec as u64,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec as u64,
    })
}

#[cfg(test)]
mod tests {
    use rustix::process::{PidfdFlags, getpid, pidfd_open};

    use super::*;

    #[test]
    fn current_process_pidfd_and_proc_exe_are_coherent() {
        let pid = getpid();
        let pidfd = pidfd_open(pid, PidfdFlags::NONBLOCK).expect("open self pidfd");
        require_live_pidfd(&pidfd).expect("self is live");
        let first = observe_executable(pid).expect("observe current executable");
        let second = observe_executable(pid).expect("re-observe current executable");
        assert_eq!(first, second);
        assert_ne!(first.sha256(), [0; 32]);
    }
}
