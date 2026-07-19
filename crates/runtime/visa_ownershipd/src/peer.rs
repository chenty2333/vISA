use visa_local_rpc::{
    MAX_INNER_REQUEST_BYTES,
    common::{AgentBinding, AgentRole},
    ownership,
};
use visa_local_transport::{LocalPeerVerifier, PeerVerificationError, VerifiedLocalPeer};
use zbus::{Connection, message::Header};

use crate::{
    config::{PinnedAgent, RuntimeConfig},
    systemd::{SystemdAgentAttestor, SystemdAttestationError},
};

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
    SystemdAttestation,
    SystemdAttestationChanged,
    Bus,
    Host,
}

#[derive(Debug)]
pub(crate) struct AdmittedPeer {
    pub(crate) caller: AgentBinding,
    pub(crate) bus_epoch: u64,
    /// Keeps the bus-provided ProcessFD or fallback pidfd available for one
    /// final synchronous liveness check at the queue-admission barrier.
    pub(crate) peer: VerifiedLocalPeer,
}

impl AdmittedPeer {
    pub(crate) fn require_live(&self) -> Result<(), PeerAdmissionError> {
        self.peer.require_live().map_err(map_peer_verification_error)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LivePeerAdmission {
    source: PinnedAgent,
    destination: PinnedAgent,
    verifier: LocalPeerVerifier,
    systemd: SystemdAgentAttestor,
    bus_epoch: u64,
}

impl LivePeerAdmission {
    pub(crate) fn new(connection: &Connection, config: &RuntimeConfig, bus_epoch: u64) -> Self {
        Self {
            source: config.source_agent,
            destination: config.destination_agent,
            verifier: LocalPeerVerifier::new(connection),
            systemd: SystemdAgentAttestor::new(connection),
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
        if has_business_file_descriptors(header) {
            return Err(PeerAdmissionError::BusinessFileDescriptors);
        }
        let sender = header.sender().ok_or(PeerAdmissionError::MissingSender)?.to_owned();
        let request = ownership::decode_request(exact_request_bytes)
            .map_err(|_| PeerAdmissionError::InvalidRequest)?;
        let expected = self.expected_agent(request.caller.role);
        if !expected.stable_identity.matches(request.caller) {
            return Err(PeerAdmissionError::BindingMismatch);
        }

        let role_name = role_name(request.caller.role);
        let peer = self
            .verifier
            .verify_named_peer(role_name, &sender, expected.executable_sha256)
            .await
            .map_err(map_peer_verification_error)?;
        peer.require_live().map_err(map_peer_verification_error)?;
        let first_systemd = self
            .systemd
            .observe(peer.pid(), request.caller)
            .await
            .map_err(map_systemd_attestation_error)?;
        peer.require_live().map_err(map_peer_verification_error)?;
        self.verifier
            .require_named_owner(role_name, &sender)
            .await
            .map_err(map_peer_verification_error)?;
        peer.require_live().map_err(map_peer_verification_error)?;
        let final_systemd = self
            .systemd
            .observe(peer.pid(), request.caller)
            .await
            .map_err(map_systemd_attestation_error)?;
        peer.require_live().map_err(map_peer_verification_error)?;
        self.verifier
            .require_named_owner(role_name, &sender)
            .await
            .map_err(map_peer_verification_error)?;
        if final_systemd != first_systemd {
            return Err(PeerAdmissionError::SystemdAttestationChanged);
        }
        Ok(AdmittedPeer { caller: request.caller, bus_epoch: self.bus_epoch, peer })
    }

    fn expected_agent(&self, role: AgentRole) -> &PinnedAgent {
        match role {
            AgentRole::Source => &self.source,
            AgentRole::Destination => &self.destination,
        }
    }
}

pub(crate) fn has_business_file_descriptors(header: &Header<'_>) -> bool {
    header.unix_fds().unwrap_or(0) != 0
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

const fn map_systemd_attestation_error(error: SystemdAttestationError) -> PeerAdmissionError {
    match error {
        SystemdAttestationError::WrongManagerUid
        | SystemdAttestationError::ManagerChanged
        | SystemdAttestationError::UnitMismatch
        | SystemdAttestationError::InvocationMismatch
        | SystemdAttestationError::MainPidMismatch => PeerAdmissionError::SystemdAttestation,
        SystemdAttestationError::Bus => PeerAdmissionError::Bus,
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd as StdOwnedFd;

    use zbus::{message::Message, zvariant::OwnedFd};

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

    #[test]
    fn attached_business_file_descriptors_are_detected_from_the_message_header() {
        let body = Vec::<u8>::new();
        let body_message = Message::method_call("/", "Execute")
            .expect("method call builder")
            .build(&body)
            .expect("message body");
        let body = body_message.body();
        let file = std::fs::File::open("/dev/null").expect("open harmless test descriptor");
        let descriptor = OwnedFd::from(StdOwnedFd::from(file));
        // SAFETY: the exact serialized `ay` body and matching dynamic signature
        // come from zbus; only one intentionally unused descriptor is added.
        let with_descriptor = unsafe {
            Message::method_call("/", "Execute")
                .expect("method call builder")
                .build_raw_body(body.data().bytes(), body.signature().clone(), vec![descriptor])
                .expect("message with attached descriptor")
        };
        assert!(has_business_file_descriptors(&with_descriptor.header()));
        assert!(!has_business_file_descriptors(&body_message.header()));
    }
}
