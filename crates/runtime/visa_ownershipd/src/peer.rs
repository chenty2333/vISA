use std::{fs::File, io::Read, os::fd::AsFd};

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{FileType, Mode, OFlags, PROC_SUPER_MAGIC, fstat, fstatfs, open, openat},
    process::{Pid, PidfdFlags, geteuid, pidfd_open},
};
use sha2::{Digest as _, Sha256};
use visa_local_rpc::{
    MAX_INNER_REQUEST_BYTES,
    common::{AgentBinding, AgentRole},
    ownership,
};
use zbus::{
    Connection,
    fdo::{ConnectionCredentials, DBusProxy},
    message::Header,
    names::{BusName, UniqueName, WellKnownName},
};

use crate::config::{PinnedAgent, RuntimeConfig};

const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerAdmissionError {
    RequestTooLarge,
    BusinessFileDescriptors,
    MissingSender,
    InvalidRequest,
    BindingMismatch,
    RoleOwnerMismatch,
    MissingCredential,
    WrongUid,
    InvalidPid,
    CredentialChanged,
    StrongerCredentialAppeared,
    ProcessExited,
    InvalidProcfs,
    InvalidExecutable,
    ExecutableChanged,
    ExecutableDigestMismatch,
    Bus,
    Host,
}

#[derive(Debug)]
pub(crate) struct AdmittedPeer {
    pub(crate) caller: AgentBinding,
    pub(crate) bus_epoch: u64,
    /// Keeps the bus-provided ProcessFD or fallback pidfd live until the
    /// service has crossed the final queue-admission barrier.
    pub(crate) process_fd: std::os::fd::OwnedFd,
}

#[derive(Clone, Debug)]
pub(crate) struct LivePeerAdmission {
    source: PinnedAgent,
    destination: PinnedAgent,
    bus_guid: String,
    bus_epoch: u64,
}

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
struct ExecutableObservation {
    identity: ExecutableIdentity,
    sha256: [u8; 32],
}

impl LivePeerAdmission {
    pub(crate) fn new(connection: &Connection, config: &RuntimeConfig, bus_epoch: u64) -> Self {
        Self {
            bus_guid: connection.server_guid().as_str().to_owned(),
            source: config.source_agent,
            destination: config.destination_agent,
            bus_epoch,
        }
    }

    pub(crate) async fn admit(
        &self,
        connection: &Connection,
        header: &Header<'_>,
        exact_request_bytes: &[u8],
    ) -> Result<AdmittedPeer, PeerAdmissionError> {
        if exact_request_bytes.len() > MAX_INNER_REQUEST_BYTES {
            return Err(PeerAdmissionError::RequestTooLarge);
        }
        if header.unix_fds().unwrap_or(0) != 0 {
            return Err(PeerAdmissionError::BusinessFileDescriptors);
        }
        let sender = header.sender().ok_or(PeerAdmissionError::MissingSender)?.to_owned();
        let request = ownership::decode_request(exact_request_bytes)
            .map_err(|_| PeerAdmissionError::InvalidRequest)?;
        let expected = self.expected_agent(request.caller.role);
        if request.caller != expected.binding {
            return Err(PeerAdmissionError::BindingMismatch);
        }

        if connection.server_guid().as_str() != self.bus_guid {
            return Err(PeerAdmissionError::CredentialChanged);
        }
        let proxy = DBusProxy::new(connection).await.map_err(|_| PeerAdmissionError::Bus)?;
        self.require_role_owner(&proxy, request.caller.role, &sender).await?;
        let first = proxy
            .get_connection_credentials(sender.as_ref().into())
            .await
            .map_err(|_| PeerAdmissionError::Bus)?;
        let (uid, pid) = required_uid_pid(&first)?;
        if uid != geteuid().as_raw() {
            return Err(PeerAdmissionError::WrongUid);
        }
        let pid_value = checked_pid(pid)?;

        let process_fd = if let Some(process_fd) = first.process_fd() {
            require_live_pidfd(process_fd)?;
            process_fd.as_fd().try_clone_to_owned().map_err(|_| PeerAdmissionError::Host)?
        } else {
            let process_fd = pidfd_open(pid_value, PidfdFlags::NONBLOCK)
                .map_err(|_| PeerAdmissionError::Host)?;
            require_live_pidfd(&process_fd)?;
            let second = proxy
                .get_connection_credentials(sender.as_ref().into())
                .await
                .map_err(|_| PeerAdmissionError::Bus)?;
            if second.process_fd().is_some() {
                // Do not combine two credential strengths from different
                // observations. The caller may retry and take ProcessFD from
                // one coherent credentials result.
                return Err(PeerAdmissionError::StrongerCredentialAppeared);
            }
            let (second_uid, second_pid) = required_uid_pid(&second)?;
            if second_uid != uid || second_pid != pid {
                return Err(PeerAdmissionError::CredentialChanged);
            }
            process_fd
        };

        require_live_pidfd(&process_fd)?;
        let observation = observe_executable(pid_value)?;
        require_live_pidfd(&process_fd)?;
        if observation.sha256 != expected.executable_sha256 {
            return Err(PeerAdmissionError::ExecutableDigestMismatch);
        }
        if connection.server_guid().as_str() != self.bus_guid {
            return Err(PeerAdmissionError::CredentialChanged);
        }
        let final_observation = observe_executable(pid_value)?;
        require_live_pidfd(&process_fd)?;
        if final_observation != observation {
            return Err(PeerAdmissionError::ExecutableChanged);
        }
        self.require_role_owner(&proxy, request.caller.role, &sender).await?;
        Ok(AdmittedPeer { caller: request.caller, bus_epoch: self.bus_epoch, process_fd })
    }

    fn expected_agent(&self, role: AgentRole) -> &PinnedAgent {
        match role {
            AgentRole::Source => &self.source,
            AgentRole::Destination => &self.destination,
        }
    }

    async fn require_role_owner(
        &self,
        proxy: &DBusProxy<'_>,
        role: AgentRole,
        sender: &UniqueName<'_>,
    ) -> Result<(), PeerAdmissionError> {
        let name: WellKnownName<'_> =
            role_name(role).try_into().map_err(|_| PeerAdmissionError::InvalidRequest)?;
        let owner =
            proxy.get_name_owner(BusName::from(name)).await.map_err(|_| PeerAdmissionError::Bus)?;
        if owner.as_str() == sender.as_str() {
            Ok(())
        } else {
            Err(PeerAdmissionError::RoleOwnerMismatch)
        }
    }
}

fn role_name(role: AgentRole) -> &'static str {
    match role {
        AgentRole::Source => visa_local_rpc::agent_control::SOURCE_WELL_KNOWN_NAME,
        AgentRole::Destination => visa_local_rpc::agent_control::DESTINATION_WELL_KNOWN_NAME,
    }
}

fn required_uid_pid(credentials: &ConnectionCredentials) -> Result<(u32, u32), PeerAdmissionError> {
    let uid = credentials.unix_user_id().ok_or(PeerAdmissionError::MissingCredential)?;
    let pid = credentials.process_id().ok_or(PeerAdmissionError::MissingCredential)?;
    checked_pid(pid)?;
    Ok((uid, pid))
}

fn checked_pid(pid: u32) -> Result<Pid, PeerAdmissionError> {
    let raw = i32::try_from(pid).map_err(|_| PeerAdmissionError::InvalidPid)?;
    Pid::from_raw(raw).ok_or(PeerAdmissionError::InvalidPid)
}

fn require_live_pidfd(fd: &impl AsFd) -> Result<(), PeerAdmissionError> {
    let mut descriptor =
        [PollFd::new(fd, PollFlags::IN | PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)];
    let ready =
        poll(&mut descriptor, Some(&Timespec::default())).map_err(|_| PeerAdmissionError::Host)?;
    if ready == 0 && descriptor[0].revents().is_empty() {
        Ok(())
    } else {
        Err(PeerAdmissionError::ProcessExited)
    }
}

fn observe_executable(pid: Pid) -> Result<ExecutableObservation, PeerAdmissionError> {
    let proc_root = open(
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| PeerAdmissionError::InvalidProcfs)?;
    if fstatfs(&proc_root).map_err(|_| PeerAdmissionError::InvalidProcfs)?.f_type
        != PROC_SUPER_MAGIC
    {
        return Err(PeerAdmissionError::InvalidProcfs);
    }
    let pid_directory = openat(
        &proc_root,
        pid.as_raw_pid().to_string(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| PeerAdmissionError::ProcessExited)?;
    let first = open_executable(&pid_directory)?;
    let first_identity = executable_identity(&first)?;
    let mut file = File::from(first);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|_| PeerAdmissionError::InvalidExecutable)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or(PeerAdmissionError::InvalidExecutable)?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(PeerAdmissionError::InvalidExecutable);
        }
        hasher.update(&buffer[..read]);
    }
    if total != first_identity.size {
        return Err(PeerAdmissionError::ExecutableChanged);
    }
    let after_hash = executable_identity(&file)?;
    if after_hash != first_identity {
        return Err(PeerAdmissionError::ExecutableChanged);
    }
    let reopened = open_executable(&pid_directory)?;
    if executable_identity(&reopened)? != first_identity {
        return Err(PeerAdmissionError::ExecutableChanged);
    }
    Ok(ExecutableObservation { identity: first_identity, sha256: hasher.finalize().into() })
}

fn open_executable(pid_directory: &impl AsFd) -> Result<std::os::fd::OwnedFd, PeerAdmissionError> {
    // `/proc/<pid>/exe` is intentionally a procfs magic link. NOFOLLOW or
    // RESOLVE_NO_MAGICLINKS would reject the kernel object we need; safety is
    // instead derived from the verified procfs dirfd, pinned process, opened
    // executable fd, and identity/hash rechecks.
    openat(pid_directory, "exe", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| PeerAdmissionError::InvalidExecutable)
}

fn executable_identity(fd: &impl AsFd) -> Result<ExecutableIdentity, PeerAdmissionError> {
    let stat = fstat(fd).map_err(|_| PeerAdmissionError::InvalidExecutable)?;
    let size = u64::try_from(stat.st_size).map_err(|_| PeerAdmissionError::InvalidExecutable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_nlink != 1
        || stat.st_mode & 0o111 == 0
        || size == 0
        || size > MAX_EXECUTABLE_BYTES
    {
        return Err(PeerAdmissionError::InvalidExecutable);
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
    use super::*;

    #[test]
    fn current_process_pidfd_and_proc_exe_are_coherent() {
        let pid = rustix::process::getpid();
        let pidfd = pidfd_open(pid, PidfdFlags::NONBLOCK).expect("open self pidfd");
        require_live_pidfd(&pidfd).expect("self is live");
        let first = observe_executable(pid).expect("observe current executable");
        let second = observe_executable(pid).expect("re-observe current executable");
        assert_eq!(first, second);
        assert_ne!(first.sha256, [0; 32]);
    }

    #[test]
    fn zero_and_out_of_range_pids_are_rejected() {
        assert_eq!(checked_pid(0), Err(PeerAdmissionError::InvalidPid));
        assert_eq!(checked_pid(u32::MAX), Err(PeerAdmissionError::InvalidPid));
    }

    #[test]
    fn role_names_are_frozen_wire_constants() {
        assert_eq!(
            role_name(AgentRole::Source),
            visa_local_rpc::agent_control::SOURCE_WELL_KNOWN_NAME
        );
        assert_eq!(
            role_name(AgentRole::Destination),
            visa_local_rpc::agent_control::DESTINATION_WELL_KNOWN_NAME
        );
    }
}
