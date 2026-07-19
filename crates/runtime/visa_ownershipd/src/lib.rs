//! Process boundary for the vISA 0.1 ownership authority service.

mod config;
mod fence;
mod peer;
mod sequencer;
mod service;

use std::{fmt, fs, io, path::Path};

pub use config::{
    BOOTSTRAP_SCHEMA, ConfigError, LoadedRuntimeConfig, RuntimeConfig, StoreOpenPolicy,
    load_digest_pinned,
};
use rustix::rand::{GetRandomFlags, getrandom};
pub use service::ServiceError;
use visa_local_rpc::common::ProcessNonce;
use visa_ownership_service::{AuthorityStore, OwnershipServiceError};

/// Stable process exit classes used by the operational daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitClass {
    /// Command-line usage was invalid (`EX_USAGE`).
    Usage = 64,
    /// Digest-pinned bootstrap input was invalid (`EX_DATAERR`).
    Data = 65,
    /// An internal invariant or integrity audit failed (`EX_SOFTWARE`).
    Software = 70,
    /// A transient host, bus, lock, or worker failure occurred (`EX_TEMPFAIL`).
    Temporary = 75,
    /// The installed/runtime configuration could not be used (`EX_CONFIG`).
    Configuration = 78,
}

impl ExitClass {
    /// Returns the conventional process exit status.
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Failure before or during the long-running ownership service loop.
#[derive(Debug)]
pub enum RunError {
    Config(ConfigError),
    InspectStore(io::Error),
    Random(io::Error),
    Store(OwnershipServiceError),
    Worker(io::Error),
    Service(ServiceError),
}

impl RunError {
    /// Maps a typed failure to a stable operational exit class.
    pub fn exit_class(&self) -> ExitClass {
        match self {
            Self::Config(_) => ExitClass::Data,
            Self::InspectStore(_) => ExitClass::Configuration,
            Self::Random(_) | Self::Worker(_) => ExitClass::Temporary,
            Self::Store(OwnershipServiceError::StoreBusy) => ExitClass::Temporary,
            Self::Store(OwnershipServiceError::StoreMismatch) => ExitClass::Configuration,
            Self::Store(
                OwnershipServiceError::Integrity
                | OwnershipServiceError::InvalidRequest
                | OwnershipServiceError::RequestIdConflict
                | OwnershipServiceError::Capacity,
            ) => ExitClass::Software,
            Self::Store(OwnershipServiceError::Storage) => ExitClass::Temporary,
            Self::Service(
                ServiceError::Bus(_) | ServiceError::Fdo(_) | ServiceError::Notify(_),
            ) => ExitClass::Temporary,
            Self::Service(
                ServiceError::NameNotAcquired(_)
                | ServiceError::MissingNotifySocket
                | ServiceError::EmptyNotifySocket,
            ) => ExitClass::Configuration,
            Self::Service(ServiceError::Gate) => ExitClass::Software,
            Self::Service(ServiceError::AuthorityTerminated(error)) => {
                ownership_error_exit_class(*error)
            }
            Self::Service(ServiceError::WorkerStopped) => ExitClass::Software,
        }
    }
}

const fn ownership_error_exit_class(error: OwnershipServiceError) -> ExitClass {
    match error {
        OwnershipServiceError::StoreBusy | OwnershipServiceError::Storage => ExitClass::Temporary,
        OwnershipServiceError::StoreMismatch => ExitClass::Configuration,
        OwnershipServiceError::Integrity
        | OwnershipServiceError::InvalidRequest
        | OwnershipServiceError::RequestIdConflict
        | OwnershipServiceError::Capacity => ExitClass::Software,
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "bootstrap rejected: {error}"),
            Self::InspectStore(error) => {
                write!(formatter, "cannot inspect ownership store: {error}")
            }
            Self::Random(error) => write!(formatter, "cannot generate process nonce: {error}"),
            Self::Store(error) => write!(formatter, "ownership store failed: {error:?}"),
            Self::Worker(error) => write!(formatter, "cannot start ownership worker: {error}"),
            Self::Service(error) => write!(formatter, "ownership service failed: {error}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::InspectStore(error) | Self::Random(error) | Self::Worker(error) => Some(error),
            Self::Service(error) => Some(error),
            Self::Store(_) => None,
        }
    }
}

/// Loads one digest-pinned bootstrap, opens and audits O1 exactly once, and
/// runs the D-Bus process layer until it encounters a terminal failure.
pub fn run_from_digest_pinned_config(
    bootstrap_path: impl AsRef<Path>,
    bootstrap_sha256: &str,
) -> Result<(), RunError> {
    let loaded = load_digest_pinned(bootstrap_path, bootstrap_sha256).map_err(RunError::Config)?;
    let runtime = loaded.runtime;
    let process_nonce = fresh_process_nonce().map_err(RunError::Random)?;
    let create_identity = select_create_identity(&runtime).map_err(RunError::InspectStore)?;
    let store_bootstrap =
        runtime.store_bootstrap(process_nonce, create_identity).map_err(RunError::Config)?;
    let authenticator = runtime.receipt_authenticator().map_err(RunError::Config)?;
    let store = AuthorityStore::open(&runtime.database_path, store_bootstrap, authenticator)
        .map_err(RunError::Store)?;
    let sequencer = sequencer::StoreSequencer::start(store).map_err(RunError::Worker)?;
    let gate = fence::AdmissionGate::new_closed();
    let result = service::run(gate, sequencer.clone(), runtime).map_err(RunError::Service);
    sequencer.shutdown();
    result
}

fn select_create_identity(
    runtime: &RuntimeConfig,
) -> Result<Option<visa_ownership_service::OwnershipServiceIdentity>, io::Error> {
    if runtime.store_open_policy == StoreOpenPolicy::ReopenExisting {
        return Ok(None);
    }
    match fs::symlink_metadata(&runtime.database_path) {
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(Some(runtime.ownership_identity))
        }
        Err(error) => Err(error),
    }
}

fn fresh_process_nonce() -> Result<ProcessNonce, io::Error> {
    loop {
        let mut bytes = [0_u8; 16];
        let mut filled = 0;
        while filled < bytes.len() {
            let initialized = getrandom(&mut bytes[filled..], GetRandomFlags::empty())?;
            if initialized == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "getrandom returned no process-nonce bytes",
                ));
            }
            filled += initialized;
        }
        let nonce = ProcessNonce::from_bytes(bytes);
        if nonce != ProcessNonce::ZERO {
            return Ok(nonce);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_nonce_is_nonzero() {
        assert_ne!(fresh_process_nonce().expect("fresh nonce"), ProcessNonce::ZERO);
    }

    #[test]
    fn exit_codes_are_stable_sysexits_values() {
        assert_eq!(ExitClass::Usage.code(), 64);
        assert_eq!(ExitClass::Data.code(), 65);
        assert_eq!(ExitClass::Software.code(), 70);
        assert_eq!(ExitClass::Temporary.code(), 75);
        assert_eq!(ExitClass::Configuration.code(), 78);
    }

    #[test]
    fn terminal_authority_causes_retain_their_operational_exit_class() {
        assert_eq!(
            RunError::Service(ServiceError::AuthorityTerminated(OwnershipServiceError::Storage))
                .exit_class(),
            ExitClass::Temporary
        );
        assert_eq!(
            RunError::Service(ServiceError::AuthorityTerminated(
                OwnershipServiceError::StoreMismatch,
            ))
            .exit_class(),
            ExitClass::Configuration
        );
        assert_eq!(
            RunError::Service(ServiceError::AuthorityTerminated(OwnershipServiceError::Integrity))
                .exit_class(),
            ExitClass::Software
        );
    }
}
