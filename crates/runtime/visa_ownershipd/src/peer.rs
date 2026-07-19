use visa_local_rpc::{
    MAX_INNER_REQUEST_BYTES,
    common::{AgentBinding, AgentRole},
    ownership,
};
use visa_local_transport::{LocalPeerVerifier, PeerVerificationError};
use zbus::{Connection, message::Header};

use crate::config::{PinnedAgent, RuntimeConfig};

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
    verifier: LocalPeerVerifier,
    bus_epoch: u64,
}

impl LivePeerAdmission {
    pub(crate) fn new(connection: &Connection, config: &RuntimeConfig, bus_epoch: u64) -> Self {
        Self {
            source: config.source_agent,
            destination: config.destination_agent,
            verifier: LocalPeerVerifier::new(connection),
            bus_epoch,
        }
    }

    pub(crate) async fn admit(
        &self,
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

        let peer = self
            .verifier
            .verify_named_peer(role_name(request.caller.role), &sender, expected.executable_sha256)
            .await
            .map_err(map_peer_verification_error)?;
        Ok(AdmittedPeer {
            caller: request.caller,
            bus_epoch: self.bus_epoch,
            process_fd: peer.into_process_fd(),
        })
    }

    fn expected_agent(&self, role: AgentRole) -> &PinnedAgent {
        match role {
            AgentRole::Source => &self.source,
            AgentRole::Destination => &self.destination,
        }
    }
}

fn role_name(role: AgentRole) -> &'static str {
    match role {
        AgentRole::Source => visa_local_rpc::agent_control::SOURCE_WELL_KNOWN_NAME,
        AgentRole::Destination => visa_local_rpc::agent_control::DESTINATION_WELL_KNOWN_NAME,
    }
}

const fn map_peer_verification_error(error: PeerVerificationError) -> PeerAdmissionError {
    match error {
        PeerVerificationError::InvalidWellKnownName => PeerAdmissionError::InvalidRequest,
        PeerVerificationError::NameOwnerMismatch => PeerAdmissionError::RoleOwnerMismatch,
        PeerVerificationError::MissingCredential => PeerAdmissionError::MissingCredential,
        PeerVerificationError::WrongUid => PeerAdmissionError::WrongUid,
        PeerVerificationError::InvalidPid => PeerAdmissionError::InvalidPid,
        PeerVerificationError::CredentialChanged => PeerAdmissionError::CredentialChanged,
        PeerVerificationError::StrongerCredentialAppeared => {
            PeerAdmissionError::StrongerCredentialAppeared
        }
        PeerVerificationError::ProcessExited => PeerAdmissionError::ProcessExited,
        PeerVerificationError::InvalidProcfs => PeerAdmissionError::InvalidProcfs,
        PeerVerificationError::InvalidExecutable => PeerAdmissionError::InvalidExecutable,
        PeerVerificationError::ExecutableChanged => PeerAdmissionError::ExecutableChanged,
        PeerVerificationError::ExecutableDigestMismatch => {
            PeerAdmissionError::ExecutableDigestMismatch
        }
        PeerVerificationError::Bus => PeerAdmissionError::Bus,
        PeerVerificationError::Host => PeerAdmissionError::Host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
