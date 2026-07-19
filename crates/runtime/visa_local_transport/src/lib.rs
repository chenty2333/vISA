//! Mechanical same-host peer verification for vISA's fixed user-bus endpoints.

mod linux_process;

use std::{
    fmt,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use rustix::process::{Pid, PidfdFlags, geteuid, pidfd_open};
use zbus::{
    Connection,
    fdo::DBusProxy,
    names::{BusName, UniqueName, WellKnownName},
};

use crate::linux_process::{ExecutableObservation, require_live_pidfd};

/// Failure while binding a bus-controlled unique name to one live local
/// process and an exact executable digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerVerificationError {
    InvalidWellKnownName,
    NameOwnerMismatch,
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

impl fmt::Display for PeerVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidWellKnownName => "invalid well-known D-Bus name",
            Self::NameOwnerMismatch => "well-known D-Bus name owner changed",
            Self::MissingCredential => "D-Bus peer credential is missing",
            Self::WrongUid => "D-Bus peer belongs to a different uid",
            Self::InvalidPid => "D-Bus peer pid is invalid",
            Self::CredentialChanged => "D-Bus peer credential changed during verification",
            Self::StrongerCredentialAppeared => {
                "D-Bus ProcessFD appeared during fallback verification"
            }
            Self::ProcessExited => "D-Bus peer process exited during verification",
            Self::InvalidProcfs => "local procfs identity is invalid",
            Self::InvalidExecutable => "D-Bus peer executable is invalid",
            Self::ExecutableChanged => "D-Bus peer executable changed during verification",
            Self::ExecutableDigestMismatch => "D-Bus peer executable digest does not match",
            Self::Bus => "D-Bus peer verification failed",
            Self::Host => "local process verification failed",
        })
    }
}

impl std::error::Error for PeerVerificationError {}

/// One verified peer whose pidfd remains owned by this value.
#[derive(Debug)]
pub struct VerifiedLocalPeer {
    pid: u32,
    process_fd: OwnedFd,
    executable: ExecutableObservation,
}

impl VerifiedLocalPeer {
    /// Returns the bus-controlled process identifier used for procfs lookup.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the verified exact executable digest.
    pub const fn executable_sha256(&self) -> [u8; 32] {
        self.executable.sha256()
    }

    /// Rechecks that the pinned process has not exited.
    pub fn require_live(&self) -> Result<(), PeerVerificationError> {
        require_live_pidfd(&self.process_fd)
    }

    /// Borrows the process handle for a higher-level admission check.
    pub fn process_fd(&self) -> BorrowedFd<'_> {
        self.process_fd.as_fd()
    }

    /// Transfers the pidfd to the caller's admission lease.
    pub fn into_process_fd(self) -> OwnedFd {
        self.process_fd
    }
}

/// Verifies peers only on the exact user-bus connection epoch captured at
/// construction.
#[derive(Clone)]
pub struct LocalPeerVerifier {
    connection: Connection,
    bus_guid: String,
}

impl fmt::Debug for LocalPeerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("LocalPeerVerifier").field("bus_guid", &self.bus_guid).finish()
    }
}

impl LocalPeerVerifier {
    /// Captures the current bus GUID and a cheap clone of the connection.
    pub fn new(connection: &Connection) -> Self {
        Self {
            connection: connection.clone(),
            bus_guid: connection.server_guid().as_str().to_owned(),
        }
    }

    /// Verifies that `unique_name` owns `well_known_name` before and after
    /// credential, pidfd, and executable inspection.
    pub async fn verify_named_peer(
        &self,
        well_known_name: &str,
        unique_name: &UniqueName<'_>,
        expected_executable_sha256: [u8; 32],
    ) -> Result<VerifiedLocalPeer, PeerVerificationError> {
        self.require_bus_epoch()?;
        let well_known: WellKnownName<'_> =
            well_known_name.try_into().map_err(|_| PeerVerificationError::InvalidWellKnownName)?;
        let proxy =
            DBusProxy::new(&self.connection).await.map_err(|_| PeerVerificationError::Bus)?;
        require_name_owner(&proxy, &well_known, unique_name).await?;

        let first = proxy
            .get_connection_credentials(unique_name.as_ref().into())
            .await
            .map_err(|_| PeerVerificationError::Bus)?;
        let uid = first.unix_user_id().ok_or(PeerVerificationError::MissingCredential)?;
        let pid = first.process_id().ok_or(PeerVerificationError::MissingCredential)?;
        let pid_value = checked_pid(pid)?;
        if uid != geteuid().as_raw() {
            return Err(PeerVerificationError::WrongUid);
        }

        let process_fd = if let Some(process_fd) = first.process_fd() {
            require_live_pidfd(process_fd)?;
            process_fd.as_fd().try_clone_to_owned().map_err(|_| PeerVerificationError::Host)?
        } else {
            let process_fd = pidfd_open(pid_value, PidfdFlags::NONBLOCK)
                .map_err(|_| PeerVerificationError::Host)?;
            require_live_pidfd(&process_fd)?;
            let second = proxy
                .get_connection_credentials(unique_name.as_ref().into())
                .await
                .map_err(|_| PeerVerificationError::Bus)?;
            if second.process_fd().is_some() {
                // Do not combine credential strengths from two observations.
                // A retry can use the coherent ProcessFD-bearing result.
                return Err(PeerVerificationError::StrongerCredentialAppeared);
            }
            let second_uid =
                second.unix_user_id().ok_or(PeerVerificationError::MissingCredential)?;
            let second_pid = second.process_id().ok_or(PeerVerificationError::MissingCredential)?;
            checked_pid(second_pid)?;
            if second_uid != uid || second_pid != pid {
                return Err(PeerVerificationError::CredentialChanged);
            }
            process_fd
        };

        require_live_pidfd(&process_fd)?;
        let executable = linux_process::observe_executable(pid_value)?;
        require_live_pidfd(&process_fd)?;
        if executable.sha256() != expected_executable_sha256 {
            return Err(PeerVerificationError::ExecutableDigestMismatch);
        }
        self.require_bus_epoch()?;
        let final_executable = linux_process::observe_executable(pid_value)?;
        require_live_pidfd(&process_fd)?;
        if final_executable != executable {
            return Err(PeerVerificationError::ExecutableChanged);
        }
        require_name_owner(&proxy, &well_known, unique_name).await?;

        Ok(VerifiedLocalPeer { pid, process_fd, executable })
    }

    /// Rechecks that one bus-controlled unique name still owns an expected
    /// role name on the captured connection epoch.
    pub async fn require_named_owner(
        &self,
        well_known_name: &str,
        unique_name: &UniqueName<'_>,
    ) -> Result<(), PeerVerificationError> {
        self.require_bus_epoch()?;
        let well_known: WellKnownName<'_> =
            well_known_name.try_into().map_err(|_| PeerVerificationError::InvalidWellKnownName)?;
        let proxy =
            DBusProxy::new(&self.connection).await.map_err(|_| PeerVerificationError::Bus)?;
        require_name_owner(&proxy, &well_known, unique_name).await?;
        self.require_bus_epoch()
    }

    fn require_bus_epoch(&self) -> Result<(), PeerVerificationError> {
        if self.connection.server_guid().as_str() == self.bus_guid {
            Ok(())
        } else {
            Err(PeerVerificationError::CredentialChanged)
        }
    }
}

async fn require_name_owner(
    proxy: &DBusProxy<'_>,
    well_known_name: &WellKnownName<'_>,
    expected_owner: &UniqueName<'_>,
) -> Result<(), PeerVerificationError> {
    let owner = proxy
        .get_name_owner(BusName::from(well_known_name.clone()))
        .await
        .map_err(|_| PeerVerificationError::Bus)?;
    if owner.as_str() == expected_owner.as_str() {
        Ok(())
    } else {
        Err(PeerVerificationError::NameOwnerMismatch)
    }
}

fn checked_pid(pid: u32) -> Result<Pid, PeerVerificationError> {
    let raw = i32::try_from(pid).map_err(|_| PeerVerificationError::InvalidPid)?;
    Pid::from_raw(raw).ok_or(PeerVerificationError::InvalidPid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_out_of_range_pids_are_rejected() {
        assert_eq!(checked_pid(0), Err(PeerVerificationError::InvalidPid));
        assert_eq!(checked_pid(u32::MAX), Err(PeerVerificationError::InvalidPid));
    }
}
