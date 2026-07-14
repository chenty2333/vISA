use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use contract_core::{
    DeliveryPolicy, EffectKind, EffectOutcome, EffectRequest, EffectResult, EntityRef, Extension,
    Identity, NodeIdentity, Rights,
};
use hmac::{Hmac, Mac};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use substrate_api::{ProviderError, ProviderErrorKind};
use visa_profile::{
    LOGICAL_REQUEST_EXTENSION_ID, LogicalRequestIdempotency, LogicalRequestOperation,
    LogicalRequestPhase, LogicalRequestRejection, LogicalRequestReplay, LogicalRequestResult,
    LogicalRequestState, LogicalResponseMetadata, MAX_LOGICAL_REQUEST_BYTES,
    MAX_LOGICAL_RESPONSE_BYTES, decode_logical_request_operation, encode_logical_request_result,
    logical_request_extension, logical_request_state, validate_profile_effect,
};

use crate::{
    FaultPoint, SqliteProvider, authority::authorize_effect_on, database_error, deserialize, error,
    generation, lease::check_lease_on, serialize, write_outcome,
};

const MAX_PEER_IDENTITY_BYTES: usize = 1024;
const MAX_CREDENTIAL_BYTES: usize = 4 * 1024;
const WIRE_MAGIC: &[u8; 8] = b"VISALR03";
const AUTH_NONCE_BYTES: usize = 32;
const AUTH_TAG_BYTES: usize = 32;
const MAX_WIRE_REQUEST_BYTES: usize = MAX_LOGICAL_REQUEST_BYTES as usize + 32 * 1024;
const MAX_WIRE_RESPONSE_BYTES: usize = MAX_LOGICAL_RESPONSE_BYTES as usize + 32 * 1024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LedgerPhase {
    Prepared,
    Pending,
    UnknownCompletion,
    Completed,
    TimedOut,
    Cancelled,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogicalLedgerRecord {
    #[serde(default)]
    revision: u64,
    resource: EntityRef,
    operation_id: Identity,
    peer_identity: Vec<u8>,
    credential_reference: Identity,
    request_size: u32,
    request_digest: contract_core::Digest,
    request: Option<Vec<u8>>,
    phase: LedgerPhase,
    response: Option<Vec<u8>>,
    #[serde(default)]
    response_metadata: Option<LogicalResponseMetadata>,
    delivered_cursor: u32,
    rejection: Option<LogicalRequestRejection>,
    cleaned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LogicalResource {
    peer_identity: Vec<u8>,
    credential_reference: Identity,
}

#[derive(Clone, PartialEq, Eq)]
struct LogicalPeerConfig {
    peer_identity: Vec<u8>,
    credential_reference: Identity,
    endpoint: SocketAddr,
    credential: Vec<u8>,
}

#[derive(Clone, Copy)]
struct LogicalRequestFence<'a> {
    effect: &'a EffectRequest,
    state: &'a LogicalRequestState,
    required: Rights,
}

impl SqliteProvider {
    /// Provision a logical request resource and the current node's peer
    /// endpoint. Credential material remains process-local.
    pub fn provision_logical_request(
        &mut self,
        state: &LogicalRequestState,
        endpoint: SocketAddr,
        credential_material: &[u8],
    ) -> Result<(), ProviderError> {
        logical_request_extension(state).map_err(profile_payload_error)?;
        validate_peer_provisioning(
            self.scope.node,
            &state.claim.peer_identity,
            endpoint,
            state.claim.credential_reference,
            credential_material,
        )?;
        validate_local_credential(
            &self.logical_credentials,
            self.scope.node,
            state.claim.credential_reference,
            credential_material,
        )?;

        let node = self.scope.node;
        let transaction = self.immediate_transaction()?;
        install_logical_resource_on(&transaction, state)?;
        install_logical_peer_on(
            &transaction,
            node,
            &state.claim.peer_identity,
            endpoint,
            state.claim.credential_reference,
        )?;
        transaction.commit().map_err(database_error)?;
        self.logical_credentials
            .entry((node, state.claim.credential_reference))
            .or_insert_with(|| credential_material.to_vec());
        Ok(())
    }

    /// Make a peer available to another node. Only the reference and endpoint
    /// are durable; material must be reacquired after process restart.
    pub fn provision_logical_request_peer(
        &mut self,
        node: NodeIdentity,
        peer_identity: &[u8],
        endpoint: SocketAddr,
        credential_reference: Identity,
        credential_material: &[u8],
    ) -> Result<(), ProviderError> {
        validate_peer_provisioning(
            node,
            peer_identity,
            endpoint,
            credential_reference,
            credential_material,
        )?;
        validate_local_credential(
            &self.logical_credentials,
            node,
            credential_reference,
            credential_material,
        )?;
        install_logical_peer_on(
            &self.connection,
            node,
            peer_identity,
            endpoint,
            credential_reference,
        )?;
        self.logical_credentials
            .entry((node, credential_reference))
            .or_insert_with(|| credential_material.to_vec());
        Ok(())
    }

    /// Test-control fault: model a destination provider that must rebind from
    /// canonical state without inheriting the source provider's operation
    /// ledger or effect-to-operation index.
    #[cfg(any(test, feature = "test-control"))]
    pub fn forget_logical_request_operation(
        &mut self,
        operation_id: Identity,
    ) -> Result<(), ProviderError> {
        let transaction = self.immediate_transaction()?;
        transaction
            .execute(
                "DELETE FROM logical_request_effect WHERE logical_operation = ?1",
                params![operation_id.0.as_slice()],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM logical_request_ledger WHERE operation_id = ?1",
                params![operation_id.0.as_slice()],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    pub(crate) fn validate_logical_request_binding_material(
        &self,
        resource: EntityRef,
        node: NodeIdentity,
    ) -> Result<(), ProviderError> {
        let resource = require_logical_resource_on(&self.connection, resource)?;
        let peer = load_peer_on(&self.connection, node, &resource.peer_identity)?;
        if peer.credential_reference != resource.credential_reference {
            return Err(error(ProviderErrorKind::Conflict, false));
        }
        if !self.logical_credentials.contains_key(&(node, peer.credential_reference)) {
            return Err(error(ProviderErrorKind::Denied, false));
        }
        Ok(())
    }

    pub(crate) fn execute_logical_request(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
    ) -> Result<EffectOutcome, ProviderError> {
        let EffectKind::Profile { profile, access, payload } = &request.kind else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };
        if *profile != LOGICAL_REQUEST_EXTENSION_ID {
            return Err(error(ProviderErrorKind::Unsupported, false));
        }
        let required = validate_profile_effect(
            std::slice::from_ref(extension),
            *profile,
            request.resource,
            *access,
            payload,
        )
        .map_err(profile_payload_error)?;
        let state = logical_request_state(extension).map_err(profile_payload_error)?;
        let operation = decode_logical_request_operation(payload).map_err(profile_payload_error)?;
        let peer = self.logical_peer_for(request.node, request.resource, &state)?;
        let fence = LogicalRequestFence { effect: request, state: &state, required };

        {
            let transaction = self.immediate_transaction()?;
            let intent = crate::ensure_intent(&transaction, request)?;
            if let Some(outcome) = intent.record.outcome {
                transaction.commit().map_err(database_error)?;
                return Ok(outcome);
            }
            authorize_effect_on(&transaction, request, required)?;
            check_lease_on(&transaction, request.resource, request.node, request.lease_epoch)?;
            validate_logical_resource_on(&transaction, request.resource, &state)?;
            transaction.commit().map_err(database_error)?;
        }

        if self.take_fault(FaultPoint::BeforeLogicalRequestIo) {
            return Err(error(ProviderErrorKind::Unavailable, true));
        }

        match operation {
            LogicalRequestOperation::Start { request: body } => {
                self.start_logical_request(request, extension, &state, &peer, fence, body)
            }
            LogicalRequestOperation::Observe { max_bytes } => {
                self.observe_logical_request(request, extension, &state, &peer, fence, max_bytes)
            }
            LogicalRequestOperation::Reconcile => {
                self.reconcile_logical_request(request, extension, &state, &peer, fence)
            }
            LogicalRequestOperation::Cancel => {
                self.cancel_logical_request(request, extension, &state, &peer, fence)
            }
        }
    }

    pub(crate) fn cleanup_logical_request_operation(
        &mut self,
        request: &EffectRequest,
    ) -> Result<(), ProviderError> {
        let transaction = self.immediate_transaction()?;
        let observation = crate::ensure_intent(&transaction, request)?;
        if observation.record.outcome.as_ref().is_none_or(EffectOutcome::is_indeterminate) {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        let state_operation = logical_operation_for_effect_on(&transaction, request.operation)?;
        if let Some(state_operation) = state_operation
            && let Some(mut record) = load_ledger_on(&transaction, state_operation)?
            && !record.cleaned
        {
            record.cleaned = true;
            let _ = save_ledger_on(&transaction, &record)?;
        }
        transaction.commit().map_err(database_error)
    }

    fn logical_peer_for(
        &self,
        node: NodeIdentity,
        resource: EntityRef,
        state: &LogicalRequestState,
    ) -> Result<LogicalPeerConfig, ProviderError> {
        let stored = require_logical_resource_on(&self.connection, resource)?;
        if stored.peer_identity != state.claim.peer_identity
            || stored.credential_reference != state.claim.credential_reference
        {
            return Err(error(ProviderErrorKind::Conflict, false));
        }
        let mut peer = load_peer_on(&self.connection, node, &stored.peer_identity)?;
        if peer.credential_reference != stored.credential_reference {
            return Err(error(ProviderErrorKind::Conflict, false));
        }
        peer.credential = self
            .logical_credentials
            .get(&(node, peer.credential_reference))
            .cloned()
            .ok_or_else(|| error(ProviderErrorKind::Denied, false))?;
        Ok(peer)
    }

    fn start_logical_request(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
        state: &LogicalRequestState,
        peer: &LogicalPeerConfig,
        fence: LogicalRequestFence<'_>,
        body: Vec<u8>,
    ) -> Result<EffectOutcome, ProviderError> {
        let mut record = {
            let transaction = self.immediate_transaction()?;
            let record = match load_ledger_on(&transaction, state.operation_id)? {
                Some(mut record) => {
                    validate_ledger(&record, state)?;
                    if record.request.as_deref().is_some_and(|stored| stored != body) {
                        return Err(error(ProviderErrorKind::Conflict, false));
                    }
                    if record.request.is_none() {
                        record.request = Some(body.clone());
                        record = save_ledger_on(&transaction, &record)?;
                    }
                    record
                }
                None => {
                    let record = ledger_from_state(state, Some(body));
                    save_ledger_on(&transaction, &record)?
                }
            };
            transaction.commit().map_err(database_error)?;
            record
        };

        if record.phase == LedgerPhase::Prepared {
            let mut stream = match connect_peer(peer, state.claim.timeout_millis) {
                Ok(stream) => stream,
                Err(ConnectFailure::TimedOut) => {
                    record.phase = LedgerPhase::TimedOut;
                    let observation = ledger_observation(&record)?;
                    return self.commit_logical_result(
                        request,
                        extension,
                        &mut record,
                        LogicalRequestResult::Started { observation },
                        false,
                    );
                }
                Err(ConnectFailure::Unavailable) => {
                    return Err(error(ProviderErrorKind::Unavailable, true));
                }
            };
            let pre_send_phase = record.phase.clone();
            record.phase = LedgerPhase::UnknownCompletion;
            self.persist_ledger(&mut record)?;
            let abandon = self.take_fault(FaultPoint::AfterLogicalRequestSend);
            let wire = WireRequest::Execute {
                operation_id: state.operation_id,
                request: record
                    .request
                    .clone()
                    .ok_or_else(|| error(ProviderErrorKind::Integrity, false))?,
            };
            if abandon {
                let disposition =
                    match send_wire_without_reply(self, &mut stream, peer, &wire, fence) {
                        Ok(disposition) => disposition,
                        Err(source) if source.kind != ProviderErrorKind::OutcomeUnknown => {
                            record.phase = pre_send_phase;
                            self.persist_ledger(&mut record)?;
                            return Err(source);
                        }
                        Err(source) => return Err(source),
                    };
                match disposition {
                    SendDisposition::Sent => {}
                    SendDisposition::Rejected(rejection) => {
                        apply_wire_status(
                            &mut record,
                            WireStatus::Rejected(rejection),
                            state.claim.max_response_size,
                        )?;
                        let result = LogicalRequestResult::Started {
                            observation: ledger_observation(&record)?,
                        };
                        return self.commit_logical_result(
                            request,
                            extension,
                            &mut record,
                            result,
                            false,
                        );
                    }
                }
                let result =
                    LogicalRequestResult::Started { observation: ledger_observation(&record)? };
                let outcome =
                    self.commit_logical_result(request, extension, &mut record, result, false)?;
                let _ = outcome;
                return Err(error(ProviderErrorKind::OutcomeUnknown, true));
            }
            match exchange_connected(self, &mut stream, peer, &wire, fence) {
                Ok(status) => {
                    apply_wire_status(&mut record, status, state.claim.max_response_size)?;
                }
                Err(ExchangeFailure::BeforeSend(source)) => {
                    record.phase = pre_send_phase;
                    self.persist_ledger(&mut record)?;
                    return Err(source);
                }
                Err(ExchangeFailure::Unknown) => {
                    record.phase = LedgerPhase::UnknownCompletion;
                }
                Err(ExchangeFailure::Protocol) => {
                    record.phase = pre_send_phase;
                    self.persist_ledger(&mut record)?;
                    return Err(error(ProviderErrorKind::Integrity, false));
                }
            }
        }

        let result = LogicalRequestResult::Started { observation: ledger_observation(&record)? };
        self.commit_logical_result(request, extension, &mut record, result, true)
    }

    fn observe_logical_request(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
        state: &LogicalRequestState,
        peer: &LogicalPeerConfig,
        fence: LogicalRequestFence<'_>,
        max_bytes: u32,
    ) -> Result<EffectOutcome, ProviderError> {
        let mut record = self.load_or_seed_ledger(state)?;
        validate_ledger(&record, state)?;
        if record.delivered_cursor != state.response_cursor {
            return Err(error(ProviderErrorKind::Conflict, false));
        }
        if matches!(record.phase, LedgerPhase::Pending | LedgerPhase::UnknownCompletion) {
            let status = self.lookup_peer(peer, state, fence)?;
            apply_wire_status(&mut record, status, state.claim.max_response_size)?;
        } else if record.phase == LedgerPhase::Completed && record.response.is_none() {
            let expected = ledger_response_metadata(&record)?
                .ok_or_else(|| error(ProviderErrorKind::Integrity, false))?;
            if state.response_cursor < expected.size && max_bytes != 0 {
                let status = self.lookup_peer(peer, state, fence)?;
                if !matches!(&status, WireStatus::Completed { .. }) {
                    return Err(error(ProviderErrorKind::Unavailable, true));
                }
                let mut with_material = record.clone();
                apply_wire_status(&mut with_material, status, state.claim.max_response_size)?;
                if ledger_response_metadata(&with_material)? != Some(expected) {
                    return Err(error(ProviderErrorKind::Conflict, false));
                }
                record = with_material;
            }
        }
        let (bytes, next_cursor) = if record.phase == LedgerPhase::Completed {
            if let Some(response) = record.response.as_ref() {
                let start = state.response_cursor as usize;
                let end = start.saturating_add(max_bytes as usize).min(response.len());
                (response[start..end].to_vec(), end as u32)
            } else {
                let metadata = ledger_response_metadata(&record)?
                    .ok_or_else(|| error(ProviderErrorKind::Integrity, false))?;
                if max_bytes != 0 && state.response_cursor < metadata.size {
                    return Err(error(ProviderErrorKind::Unavailable, true));
                }
                (Vec::new(), state.response_cursor)
            }
        } else {
            (Vec::new(), state.response_cursor)
        };
        record.delivered_cursor = next_cursor;
        let result = LogicalRequestResult::Observed {
            observation: ledger_observation(&record)?,
            bytes,
            response_cursor: next_cursor,
        };
        self.commit_logical_result(request, extension, &mut record, result, true)
    }

    fn reconcile_logical_request(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
        state: &LogicalRequestState,
        peer: &LogicalPeerConfig,
        fence: LogicalRequestFence<'_>,
    ) -> Result<EffectOutcome, ProviderError> {
        let mut record = self.load_or_seed_ledger(state)?;
        validate_ledger(&record, state)?;
        if matches!(
            record.phase,
            LedgerPhase::Completed
                | LedgerPhase::TimedOut
                | LedgerPhase::Cancelled
                | LedgerPhase::Rejected
        ) {
            let result =
                LogicalRequestResult::Reconciled { observation: ledger_observation(&record)? };
            return self.commit_logical_result(request, extension, &mut record, result, true);
        }
        let mut status = self.lookup_peer(peer, state, fence)?;
        if matches!(status, WireStatus::NotFound) {
            if replay_after_unknown_is_safe(state) {
                if let Some(body) = record.request.clone() {
                    record.phase = LedgerPhase::UnknownCompletion;
                    self.persist_ledger(&mut record)?;
                    status = self.execute_peer(peer, state, fence, body)?;
                } else {
                    record.phase = LedgerPhase::Rejected;
                    record.rejection = Some(LogicalRequestRejection::UnsafeReplay);
                }
            } else {
                record.phase = LedgerPhase::Rejected;
                record.rejection = Some(LogicalRequestRejection::UnsafeReplay);
            }
        }
        if record.phase != LedgerPhase::Rejected {
            apply_wire_status(&mut record, status, state.claim.max_response_size)?;
        }
        let result = LogicalRequestResult::Reconciled { observation: ledger_observation(&record)? };
        self.commit_logical_result(request, extension, &mut record, result, true)
    }

    fn cancel_logical_request(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
        state: &LogicalRequestState,
        peer: &LogicalPeerConfig,
        fence: LogicalRequestFence<'_>,
    ) -> Result<EffectOutcome, ProviderError> {
        let mut record = self.load_or_seed_ledger(state)?;
        validate_ledger(&record, state)?;
        if ledger_phase_is_terminal(&record.phase) {
            let result =
                LogicalRequestResult::Cancelled { observation: ledger_observation(&record)? };
            return self.commit_logical_result(request, extension, &mut record, result, true);
        }
        let mut stream = connect_peer(peer, state.claim.timeout_millis).map_err(|failure| {
            error(
                ProviderErrorKind::Unavailable,
                matches!(failure, ConnectFailure::Unavailable | ConnectFailure::TimedOut),
            )
        })?;
        let pre_send_phase = record.phase.clone();
        record.phase = LedgerPhase::UnknownCompletion;
        self.persist_ledger(&mut record)?;
        let wire = WireRequest::Cancel {
            operation_id: state.operation_id,
            request_digest: state.request_digest,
        };
        let abandon = self.take_fault(FaultPoint::AfterLogicalCancelSend);
        let mut sent_without_reply = false;
        if abandon {
            let disposition = match send_wire_without_reply(self, &mut stream, peer, &wire, fence) {
                Ok(disposition) => disposition,
                Err(source) if source.kind != ProviderErrorKind::OutcomeUnknown => {
                    record.phase = pre_send_phase;
                    self.persist_ledger(&mut record)?;
                    return Err(source);
                }
                Err(source) => return Err(source),
            };
            match disposition {
                SendDisposition::Sent => sent_without_reply = true,
                SendDisposition::Rejected(rejection) => apply_wire_status(
                    &mut record,
                    WireStatus::Rejected(rejection),
                    state.claim.max_response_size,
                )?,
            }
        } else {
            match exchange_connected(self, &mut stream, peer, &wire, fence) {
                Ok(status) => {
                    apply_wire_status(&mut record, status, state.claim.max_response_size)?;
                }
                Err(ExchangeFailure::BeforeSend(source)) => {
                    record.phase = pre_send_phase;
                    self.persist_ledger(&mut record)?;
                    return Err(source);
                }
                Err(ExchangeFailure::Unknown) => {
                    record.phase = LedgerPhase::UnknownCompletion;
                }
                Err(ExchangeFailure::Protocol) => {
                    record.phase = pre_send_phase;
                    self.persist_ledger(&mut record)?;
                    return Err(error(ProviderErrorKind::Integrity, false));
                }
            }
        }
        let result = LogicalRequestResult::Cancelled { observation: ledger_observation(&record)? };
        let outcome = self.commit_logical_result(
            request,
            extension,
            &mut record,
            result,
            !sent_without_reply,
        )?;
        if sent_without_reply {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        Ok(outcome)
    }

    fn load_or_seed_ledger(
        &mut self,
        state: &LogicalRequestState,
    ) -> Result<LogicalLedgerRecord, ProviderError> {
        if let Some(record) = load_ledger_on(&self.connection, state.operation_id)? {
            return Ok(record);
        }
        let mut record = ledger_from_state(state, None);
        self.persist_ledger(&mut record)?;
        Ok(record)
    }

    fn persist_ledger(&mut self, record: &mut LogicalLedgerRecord) -> Result<(), ProviderError> {
        let transaction = self.immediate_transaction()?;
        let saved = save_ledger_on(&transaction, record)?;
        transaction.commit().map_err(database_error)?;
        *record = saved;
        Ok(())
    }

    fn lookup_peer(
        &mut self,
        peer: &LogicalPeerConfig,
        state: &LogicalRequestState,
        fence: LogicalRequestFence<'_>,
    ) -> Result<WireStatus, ProviderError> {
        let wire = WireRequest::Lookup {
            operation_id: state.operation_id,
            request_digest: state.request_digest,
        };
        exchange(self, peer, state.claim.timeout_millis, &wire, fence)
    }

    fn execute_peer(
        &mut self,
        peer: &LogicalPeerConfig,
        state: &LogicalRequestState,
        fence: LogicalRequestFence<'_>,
        body: Vec<u8>,
    ) -> Result<WireStatus, ProviderError> {
        let wire = WireRequest::Execute { operation_id: state.operation_id, request: body };
        exchange(self, peer, state.claim.timeout_millis, &wire, fence)
    }

    fn commit_logical_result(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
        record: &mut LogicalLedgerRecord,
        result: LogicalRequestResult,
        inject_commit_fault: bool,
    ) -> Result<EffectOutcome, ProviderError> {
        let payload = encode_logical_request_result(&result)
            .map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?;
        let result = EffectResult::Profile { profile: LOGICAL_REQUEST_EXTENSION_ID, payload };
        let mut next = extension.clone();
        visa_profile::apply_profile_result(
            std::slice::from_mut(&mut next),
            &request.kind,
            &result,
            request.operation,
        )
        .map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?;

        // A peer application frame may already have executed before this
        // local result is made durable. Any failure in the local commit phase
        // is therefore indeterminate, never a definitive failed effect.
        let transaction = self
            .immediate_transaction()
            .map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?;
        let intent = crate::ensure_intent(&transaction, request)
            .map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?;
        if let Some(outcome) = intent.record.outcome {
            transaction.commit().map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?;
            return Ok(outcome);
        }
        let saved = save_ledger_on(&transaction, record)
            .map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?;
        associate_effect_on(&transaction, request.operation, record.operation_id)
            .map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?;
        let outcome = EffectOutcome::Succeeded {
            evidence: crate::effect_evidence(&transaction, request, &result)
                .map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?,
            result,
        };
        write_outcome(&transaction, request.operation, &outcome)
            .map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?;
        transaction.commit().map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?;
        *record = saved;
        if inject_commit_fault && self.take_fault(FaultPoint::AfterLogicalRequestCommit) {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        Ok(outcome)
    }
}

fn associate_effect_on(
    connection: &rusqlite::Connection,
    effect_operation: Identity,
    logical_operation: Identity,
) -> Result<(), ProviderError> {
    let existing = connection
        .query_row(
            "SELECT logical_operation FROM logical_request_effect
             WHERE effect_operation = ?1",
            params![effect_operation.0.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(database_error)?
        .map(crate::decode_identity)
        .transpose()
        .map_err(database_error)?;
    if let Some(existing) = existing {
        return if existing == logical_operation {
            Ok(())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    connection
        .execute(
            "INSERT INTO logical_request_effect(effect_operation, logical_operation)
             VALUES (?1, ?2)",
            params![effect_operation.0.as_slice(), logical_operation.0.as_slice()],
        )
        .map_err(database_error)?;
    Ok(())
}

fn logical_operation_for_effect_on(
    connection: &rusqlite::Connection,
    effect_operation: Identity,
) -> Result<Option<Identity>, ProviderError> {
    connection
        .query_row(
            "SELECT logical_operation FROM logical_request_effect
             WHERE effect_operation = ?1",
            params![effect_operation.0.as_slice()],
            |row| crate::decode_identity(row.get(0)?),
        )
        .optional()
        .map_err(database_error)
}

fn validate_peer_provisioning(
    node: NodeIdentity,
    peer_identity: &[u8],
    endpoint: SocketAddr,
    credential_reference: Identity,
    credential_material: &[u8],
) -> Result<(), ProviderError> {
    if node.is_zero()
        || peer_identity.is_empty()
        || peer_identity.len() > MAX_PEER_IDENTITY_BYTES
        || peer_identity.contains(&0)
        || credential_reference.is_zero()
        || credential_material.is_empty()
        || credential_material.len() > MAX_CREDENTIAL_BYTES
        || !endpoint.ip().is_loopback()
    {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    Ok(())
}

fn validate_local_credential(
    credentials: &BTreeMap<(NodeIdentity, Identity), Vec<u8>>,
    node: NodeIdentity,
    reference: Identity,
    material: &[u8],
) -> Result<(), ProviderError> {
    if credentials.get(&(node, reference)).is_some_and(|existing| existing != material) {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    Ok(())
}

fn install_logical_resource_on(
    connection: &rusqlite::Connection,
    state: &LogicalRequestState,
) -> Result<(), ProviderError> {
    let existing = load_logical_resource_on(connection, state.claim.resource)?;
    if let Some(existing) = existing {
        return if existing.peer_identity == state.claim.peer_identity
            && existing.credential_reference == state.claim.credential_reference
        {
            Ok(())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    let identity_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM logical_request_resource WHERE resource_id = ?1)",
            params![state.claim.resource.identity.0.as_slice()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if identity_exists {
        return Err(error(ProviderErrorKind::StaleGeneration, false));
    }
    connection
        .execute(
            "INSERT INTO logical_request_resource(
                 resource_id, resource_generation, peer_identity, credential_reference
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                state.claim.resource.identity.0.as_slice(),
                generation(state.claim.resource.generation),
                &state.claim.peer_identity,
                state.claim.credential_reference.0.as_slice()
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

fn install_logical_peer_on(
    connection: &rusqlite::Connection,
    node: NodeIdentity,
    peer_identity: &[u8],
    endpoint: SocketAddr,
    credential_reference: Identity,
) -> Result<(), ProviderError> {
    let existing = load_peer_without_material_on(connection, node, peer_identity)?;
    if let Some(existing) = existing {
        return if existing.endpoint == endpoint
            && existing.credential_reference == credential_reference
        {
            Ok(())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    connection
        .execute(
            "INSERT INTO logical_request_peer(
                 node_id, peer_identity, credential_reference, endpoint
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                node.0.0.as_slice(),
                peer_identity,
                credential_reference.0.as_slice(),
                endpoint.to_string()
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

fn load_logical_resource_on(
    connection: &rusqlite::Connection,
    resource: EntityRef,
) -> Result<Option<LogicalResource>, ProviderError> {
    let stored = connection
        .query_row(
            "SELECT peer_identity, credential_reference
             FROM logical_request_resource
             WHERE resource_id = ?1 AND resource_generation = ?2",
            params![resource.identity.0.as_slice(), generation(resource.generation)],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(database_error)?;
    stored
        .map(|(peer_identity, credential_reference)| {
            Ok(LogicalResource {
                peer_identity,
                credential_reference: crate::decode_identity(credential_reference)
                    .map_err(database_error)?,
            })
        })
        .transpose()
}

fn require_logical_resource_on(
    connection: &rusqlite::Connection,
    resource: EntityRef,
) -> Result<LogicalResource, ProviderError> {
    if let Some(resource) = load_logical_resource_on(connection, resource)? {
        return Ok(resource);
    }
    let identity_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM logical_request_resource WHERE resource_id = ?1)",
            params![resource.identity.0.as_slice()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    Err(error(
        if identity_exists {
            ProviderErrorKind::StaleGeneration
        } else {
            ProviderErrorKind::NotFound
        },
        false,
    ))
}

fn validate_logical_resource_on(
    connection: &rusqlite::Connection,
    resource: EntityRef,
    state: &LogicalRequestState,
) -> Result<(), ProviderError> {
    let stored = require_logical_resource_on(connection, resource)?;
    if stored.peer_identity != state.claim.peer_identity
        || stored.credential_reference != state.claim.credential_reference
    {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    Ok(())
}

fn load_peer_without_material_on(
    connection: &rusqlite::Connection,
    node: NodeIdentity,
    peer_identity: &[u8],
) -> Result<Option<LogicalPeerConfig>, ProviderError> {
    let stored = connection
        .query_row(
            "SELECT credential_reference, endpoint FROM logical_request_peer
             WHERE node_id = ?1 AND peer_identity = ?2",
            params![node.0.0.as_slice(), peer_identity],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(database_error)?;
    stored
        .map(|(credential_reference, endpoint)| {
            let endpoint: SocketAddr =
                endpoint.parse().map_err(|_| error(ProviderErrorKind::Integrity, false))?;
            if !endpoint.ip().is_loopback() {
                return Err(error(ProviderErrorKind::Integrity, false));
            }
            Ok(LogicalPeerConfig {
                peer_identity: peer_identity.to_vec(),
                credential_reference: crate::decode_identity(credential_reference)
                    .map_err(database_error)?,
                endpoint,
                credential: Vec::new(),
            })
        })
        .transpose()
}

fn load_peer_on(
    connection: &rusqlite::Connection,
    node: NodeIdentity,
    peer_identity: &[u8],
) -> Result<LogicalPeerConfig, ProviderError> {
    load_peer_without_material_on(connection, node, peer_identity)?
        .ok_or_else(|| error(ProviderErrorKind::NotFound, false))
}

fn ledger_from_state(state: &LogicalRequestState, request: Option<Vec<u8>>) -> LogicalLedgerRecord {
    LogicalLedgerRecord {
        revision: 0,
        resource: state.claim.resource,
        operation_id: state.operation_id,
        peer_identity: state.claim.peer_identity.clone(),
        credential_reference: state.claim.credential_reference,
        request_size: state.request_size,
        request_digest: state.request_digest,
        request,
        phase: match state.phase {
            LogicalRequestPhase::Ready => LedgerPhase::Prepared,
            LogicalRequestPhase::Pending | LogicalRequestPhase::PartialResponse => {
                LedgerPhase::Pending
            }
            LogicalRequestPhase::UnknownCompletion
            | LogicalRequestPhase::Reconciling
            | LogicalRequestPhase::Replaying
            | LogicalRequestPhase::Cancelling => LedgerPhase::UnknownCompletion,
            LogicalRequestPhase::Completed => LedgerPhase::Completed,
            LogicalRequestPhase::TimedOut => LedgerPhase::TimedOut,
            LogicalRequestPhase::Cancelled => LedgerPhase::Cancelled,
            LogicalRequestPhase::Rejected => LedgerPhase::Rejected,
        },
        response: None,
        response_metadata: state.response,
        delivered_cursor: state.response_cursor,
        rejection: state.rejection,
        cleaned: false,
    }
}

fn validate_ledger(
    record: &LogicalLedgerRecord,
    state: &LogicalRequestState,
) -> Result<(), ProviderError> {
    if record.resource != state.claim.resource
        || record.operation_id != state.operation_id
        || record.peer_identity != state.claim.peer_identity
        || record.credential_reference != state.claim.credential_reference
        || record.request_size != state.request_size
        || record.request_digest != state.request_digest
        || record.delivered_cursor != state.response_cursor
    {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    if let Some(request) = &record.request
        && (request.len() as u32 != record.request_size
            || contract_core::canonical_digest(request.as_slice())
                .map_err(|_| error(ProviderErrorKind::Integrity, false))?
                != record.request_digest)
    {
        return Err(error(ProviderErrorKind::Integrity, false));
    }
    let observed_response = ledger_response_metadata(record)?;
    if let Some(expected) = state.response
        && observed_response != Some(expected)
    {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    if record.phase == LedgerPhase::Completed && observed_response.is_none() {
        return Err(error(ProviderErrorKind::Integrity, false));
    }
    Ok(())
}

fn load_ledger_on(
    connection: &rusqlite::Connection,
    operation_id: Identity,
) -> Result<Option<LogicalLedgerRecord>, ProviderError> {
    let bytes = connection
        .query_row(
            "SELECT record FROM logical_request_ledger WHERE operation_id = ?1",
            params![operation_id.0.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(database_error)?;
    bytes.map(|bytes| deserialize(&bytes)).transpose()
}

fn save_ledger_on(
    connection: &rusqlite::Connection,
    record: &LogicalLedgerRecord,
) -> Result<LogicalLedgerRecord, ProviderError> {
    validate_ledger_record(record)?;
    if let Some(existing) = load_ledger_on(connection, record.operation_id)? {
        validate_ledger_update(&existing, record)?;
    } else if record.revision != 0 {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    let mut next = record.clone();
    next.revision =
        record.revision.checked_add(1).ok_or_else(|| error(ProviderErrorKind::Storage, false))?;
    connection
        .execute(
            "INSERT INTO logical_request_ledger(operation_id, record) VALUES (?1, ?2)
             ON CONFLICT(operation_id) DO UPDATE SET record = excluded.record",
            params![record.operation_id.0.as_slice(), serialize(&next)?],
        )
        .map_err(database_error)?;
    Ok(next)
}

fn validate_ledger_record(record: &LogicalLedgerRecord) -> Result<(), ProviderError> {
    if let Some(request) = &record.request
        && (request.len() as u32 != record.request_size
            || contract_core::canonical_digest(request.as_slice())
                .map_err(|_| error(ProviderErrorKind::Integrity, false))?
                != record.request_digest)
    {
        return Err(error(ProviderErrorKind::Integrity, false));
    }
    let response = ledger_response_metadata(record)?;
    if (record.phase == LedgerPhase::Completed && response.is_none())
        || record.delivered_cursor > response.map_or(0, |metadata| metadata.size)
        || (record.phase == LedgerPhase::Rejected) != record.rejection.is_some()
    {
        return Err(error(ProviderErrorKind::Integrity, false));
    }
    Ok(())
}

fn validate_ledger_update(
    existing: &LogicalLedgerRecord,
    next: &LogicalLedgerRecord,
) -> Result<(), ProviderError> {
    let immutable_mismatch = existing.revision != next.revision
        || existing.resource != next.resource
        || existing.operation_id != next.operation_id
        || existing.peer_identity != next.peer_identity
        || existing.credential_reference != next.credential_reference
        || existing.request_size != next.request_size
        || existing.request_digest != next.request_digest;
    let request_regressed =
        existing.request.as_ref().is_some_and(|request| next.request.as_ref() != Some(request));
    let response_regressed =
        existing.response.as_ref().is_some_and(|response| next.response.as_ref() != Some(response));
    let metadata_regressed =
        existing.response_metadata.is_some_and(|metadata| next.response_metadata != Some(metadata));
    let rejection_changed = existing.rejection.is_some() && existing.rejection != next.rejection;
    let terminal_regressed =
        ledger_phase_is_terminal(&existing.phase) && existing.phase != next.phase;
    if immutable_mismatch
        || request_regressed
        || response_regressed
        || metadata_regressed
        || rejection_changed
        || terminal_regressed
        || next.delivered_cursor < existing.delivered_cursor
        || (existing.cleaned && !next.cleaned)
    {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    Ok(())
}

fn ledger_phase_is_terminal(phase: &LedgerPhase) -> bool {
    matches!(
        phase,
        LedgerPhase::Completed
            | LedgerPhase::TimedOut
            | LedgerPhase::Cancelled
            | LedgerPhase::Rejected
    )
}

fn ledger_observation(
    record: &LogicalLedgerRecord,
) -> Result<visa_profile::LogicalRequestObservation, ProviderError> {
    let response = ledger_response_metadata(record)?;
    Ok(visa_profile::LogicalRequestObservation {
        phase: match record.phase {
            LedgerPhase::Prepared | LedgerPhase::Pending => LogicalRequestPhase::Pending,
            LedgerPhase::UnknownCompletion => LogicalRequestPhase::UnknownCompletion,
            LedgerPhase::Completed => LogicalRequestPhase::Completed,
            LedgerPhase::TimedOut => LogicalRequestPhase::TimedOut,
            LedgerPhase::Cancelled => LogicalRequestPhase::Cancelled,
            LedgerPhase::Rejected => LogicalRequestPhase::Rejected,
        },
        response,
        rejection: record.rejection,
    })
}

fn ledger_response_metadata(
    record: &LogicalLedgerRecord,
) -> Result<Option<LogicalResponseMetadata>, ProviderError> {
    let material = record.response.as_deref().map(response_metadata).transpose()?;
    if let (Some(material), Some(stored)) = (material, record.response_metadata)
        && material != stored
    {
        return Err(error(ProviderErrorKind::Integrity, false));
    }
    Ok(material.or(record.response_metadata))
}

fn response_metadata(response: &[u8]) -> Result<LogicalResponseMetadata, ProviderError> {
    Ok(LogicalResponseMetadata {
        size: u32::try_from(response.len())
            .map_err(|_| error(ProviderErrorKind::Integrity, false))?,
        digest: contract_core::canonical_digest(response)
            .map_err(|_| error(ProviderErrorKind::Integrity, false))?,
    })
}

fn apply_wire_status(
    record: &mut LogicalLedgerRecord,
    status: WireStatus,
    max_response_size: u32,
) -> Result<(), ProviderError> {
    record.rejection = None;
    match status {
        WireStatus::Pending => record.phase = LedgerPhase::Pending,
        WireStatus::Completed { response } => {
            if response.len() > max_response_size as usize {
                record.phase = LedgerPhase::Rejected;
                record.rejection = Some(LogicalRequestRejection::PolicyDenied);
                record.response = None;
                record.response_metadata = None;
            } else {
                record.response_metadata = Some(response_metadata(&response)?);
                record.phase = LedgerPhase::Completed;
                record.response = Some(response);
            }
        }
        WireStatus::Cancelled => {
            record.phase = LedgerPhase::Cancelled;
            record.response = None;
            record.response_metadata = None;
        }
        WireStatus::NotFound => record.phase = LedgerPhase::UnknownCompletion,
        WireStatus::Rejected(rejection) => {
            record.phase = LedgerPhase::Rejected;
            record.rejection = Some(rejection);
            record.response = None;
            record.response_metadata = None;
        }
    }
    Ok(())
}

fn replay_after_unknown_is_safe(state: &LogicalRequestState) -> bool {
    matches!(
        (state.claim.delivery, state.claim.replay, state.claim.idempotency),
        (
            DeliveryPolicy::AtLeastOnce,
            LogicalRequestReplay::IfIdempotent,
            LogicalRequestIdempotency::Idempotent
        ) | (
            DeliveryPolicy::Deduplicated,
            LogicalRequestReplay::WithOperationId,
            LogicalRequestIdempotency::OperationIdDeduplicated
        )
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireRequest {
    Execute { operation_id: Identity, request: Vec<u8> },
    Lookup { operation_id: Identity, request_digest: contract_core::Digest },
    Cancel { operation_id: Identity, request_digest: contract_core::Digest },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireHello {
    nonce: [u8; AUTH_NONCE_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGreeting {
    peer_identity: Vec<u8>,
    proof: [u8; AUTH_TAG_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedWireRequest {
    request: WireRequest,
    proof: [u8; AUTH_TAG_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReply {
    status: WireStatus,
    proof: [u8; AUTH_TAG_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireStatus {
    Pending,
    Completed { response: Vec<u8> },
    Cancelled,
    NotFound,
    Rejected(LogicalRequestRejection),
}

enum ConnectFailure {
    TimedOut,
    Unavailable,
}

enum ExchangeFailure {
    BeforeSend(ProviderError),
    Unknown,
    Protocol,
}

enum PeerAuthentication {
    Authenticated([u8; AUTH_NONCE_BYTES]),
    Rejected(LogicalRequestRejection),
}

enum SendDisposition {
    Sent,
    Rejected(LogicalRequestRejection),
}

fn connect_peer(
    peer: &LogicalPeerConfig,
    timeout_millis: u64,
) -> Result<TcpStream, ConnectFailure> {
    let timeout = Duration::from_millis(timeout_millis);
    let stream = TcpStream::connect_timeout(&peer.endpoint, timeout).map_err(|source| {
        if source.kind() == std::io::ErrorKind::TimedOut {
            ConnectFailure::TimedOut
        } else {
            ConnectFailure::Unavailable
        }
    })?;
    stream.set_read_timeout(Some(timeout)).map_err(|_| ConnectFailure::Unavailable)?;
    stream.set_write_timeout(Some(timeout)).map_err(|_| ConnectFailure::Unavailable)?;
    Ok(stream)
}

fn exchange(
    provider: &mut SqliteProvider,
    peer: &LogicalPeerConfig,
    timeout_millis: u64,
    request: &WireRequest,
    fence: LogicalRequestFence<'_>,
) -> Result<WireStatus, ProviderError> {
    let mut stream = connect_peer(peer, timeout_millis)
        .map_err(|_| error(ProviderErrorKind::Unavailable, true))?;
    exchange_connected(provider, &mut stream, peer, request, fence).map_err(|failure| match failure
    {
        ExchangeFailure::BeforeSend(source) => source,
        ExchangeFailure::Unknown => error(ProviderErrorKind::OutcomeUnknown, true),
        ExchangeFailure::Protocol => error(ProviderErrorKind::Integrity, false),
    })
}

fn exchange_connected(
    provider: &mut SqliteProvider,
    stream: &mut TcpStream,
    peer: &LogicalPeerConfig,
    request: &WireRequest,
    fence: LogicalRequestFence<'_>,
) -> Result<WireStatus, ExchangeFailure> {
    let nonce = match authenticate_peer(stream, peer)? {
        PeerAuthentication::Authenticated(nonce) => nonce,
        PeerAuthentication::Rejected(rejection) => {
            return Ok(WireStatus::Rejected(rejection));
        }
    };
    let request_bytes =
        contract_core::canonical_bytes(request).map_err(|_| ExchangeFailure::Protocol)?;
    let proof = authentication_tag(
        &peer.credential,
        b"visa-logical-request-client-v1",
        &nonce,
        &request_bytes,
    )
    .ok_or(ExchangeFailure::Protocol)?;
    let envelope = AuthenticatedWireRequest { request: request.clone(), proof };
    send_authenticated_request(provider, stream, &envelope, fence).map_err(|source| {
        if source.kind == ProviderErrorKind::OutcomeUnknown {
            ExchangeFailure::Unknown
        } else {
            ExchangeFailure::BeforeSend(source)
        }
    })?;
    let reply = read_frame::<WireReply>(stream, MAX_WIRE_RESPONSE_BYTES)
        .map_err(|_| ExchangeFailure::Unknown)?;
    let status_bytes =
        contract_core::canonical_bytes(&reply.status).map_err(|_| ExchangeFailure::Unknown)?;
    if !authentication_tag_matches(
        &peer.credential,
        b"visa-logical-request-server-reply-v1",
        &nonce,
        &status_bytes,
        &reply.proof,
    ) {
        return Err(ExchangeFailure::Unknown);
    }
    Ok(reply.status)
}

fn send_wire_without_reply(
    provider: &mut SqliteProvider,
    stream: &mut TcpStream,
    peer: &LogicalPeerConfig,
    request: &WireRequest,
    fence: LogicalRequestFence<'_>,
) -> Result<SendDisposition, ProviderError> {
    let nonce = match authenticate_peer(stream, peer).map_err(|failure| match failure {
        ExchangeFailure::BeforeSend(source) => source,
        ExchangeFailure::Unknown => error(ProviderErrorKind::OutcomeUnknown, true),
        ExchangeFailure::Protocol => error(ProviderErrorKind::Integrity, false),
    })? {
        PeerAuthentication::Authenticated(nonce) => nonce,
        PeerAuthentication::Rejected(rejection) => {
            return Ok(SendDisposition::Rejected(rejection));
        }
    };
    let request_bytes = contract_core::canonical_bytes(request)
        .map_err(|_| error(ProviderErrorKind::InvalidRequest, false))?;
    let proof = authentication_tag(
        &peer.credential,
        b"visa-logical-request-client-v1",
        &nonce,
        &request_bytes,
    )
    .ok_or_else(|| error(ProviderErrorKind::Integrity, false))?;
    let envelope = AuthenticatedWireRequest { request: request.clone(), proof };
    send_authenticated_request(provider, stream, &envelope, fence)?;
    Ok(SendDisposition::Sent)
}

fn send_authenticated_request(
    provider: &mut SqliteProvider,
    stream: &mut TcpStream,
    envelope: &AuthenticatedWireRequest,
    fence: LogicalRequestFence<'_>,
) -> Result<(), ProviderError> {
    let transaction = provider.immediate_transaction()?;
    authorize_effect_on(&transaction, fence.effect, fence.required)?;
    check_lease_on(
        &transaction,
        fence.effect.resource,
        fence.effect.node,
        fence.effect.lease_epoch,
    )?;
    validate_logical_resource_on(&transaction, fence.effect.resource, fence.state)?;
    write_frame(stream, envelope, MAX_WIRE_REQUEST_BYTES)
        .map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))?;
    transaction.commit().map_err(|_| error(ProviderErrorKind::OutcomeUnknown, true))
}

fn authenticate_peer(
    stream: &mut TcpStream,
    peer: &LogicalPeerConfig,
) -> Result<PeerAuthentication, ExchangeFailure> {
    let mut nonce = [0_u8; AUTH_NONCE_BYTES];
    getrandom::fill(&mut nonce)
        .map_err(|_| ExchangeFailure::BeforeSend(error(ProviderErrorKind::Unavailable, true)))?;
    write_frame(stream, &WireHello { nonce }, MAX_WIRE_REQUEST_BYTES)
        .map_err(|_| ExchangeFailure::BeforeSend(error(ProviderErrorKind::Unavailable, true)))?;
    let greeting = read_frame::<WireGreeting>(stream, MAX_WIRE_RESPONSE_BYTES)
        .map_err(|_| ExchangeFailure::BeforeSend(error(ProviderErrorKind::Unavailable, true)))?;
    if greeting.peer_identity.is_empty() || greeting.peer_identity.len() > MAX_PEER_IDENTITY_BYTES {
        return Err(ExchangeFailure::Protocol);
    }
    if greeting.peer_identity != peer.peer_identity {
        return Ok(PeerAuthentication::Rejected(LogicalRequestRejection::PeerMismatch));
    }
    if !authentication_tag_matches(
        &peer.credential,
        b"visa-logical-request-server-greeting-v1",
        &nonce,
        &greeting.peer_identity,
        &greeting.proof,
    ) {
        return Ok(PeerAuthentication::Rejected(LogicalRequestRejection::CredentialDenied));
    }
    Ok(PeerAuthentication::Authenticated(nonce))
}

fn authentication_tag(
    credential: &[u8],
    domain: &[u8],
    nonce: &[u8; AUTH_NONCE_BYTES],
    payload: &[u8],
) -> Option<[u8; AUTH_TAG_BYTES]> {
    let mut mac = HmacSha256::new_from_slice(credential).ok()?;
    update_authentication_mac(&mut mac, domain, nonce, payload);
    Some(mac.finalize().into_bytes().into())
}

fn authentication_tag_matches(
    credential: &[u8],
    domain: &[u8],
    nonce: &[u8; AUTH_NONCE_BYTES],
    payload: &[u8],
    proof: &[u8; AUTH_TAG_BYTES],
) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(credential) else {
        return false;
    };
    update_authentication_mac(&mut mac, domain, nonce, payload);
    mac.verify_slice(proof).is_ok()
}

fn update_authentication_mac(
    mac: &mut HmacSha256,
    domain: &[u8],
    nonce: &[u8; AUTH_NONCE_BYTES],
    payload: &[u8],
) {
    mac.update(b"visa-logical-request-auth-v1");
    mac.update(&(domain.len() as u64).to_be_bytes());
    mac.update(domain);
    mac.update(nonce);
    mac.update(&(payload.len() as u64).to_be_bytes());
    mac.update(payload);
}

fn write_frame<T: Serialize>(
    stream: &mut TcpStream,
    value: &T,
    limit: usize,
) -> std::io::Result<()> {
    let bytes = contract_core::canonical_bytes(value)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "wire encode"))?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    stream.write_all(WIRE_MAGIC)?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)
}

fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut TcpStream,
    limit: usize,
) -> std::io::Result<T> {
    read_frame_with_payload(stream, limit).map(|(value, _)| value)
}

fn read_frame_with_payload<T: serde::de::DeserializeOwned>(
    stream: &mut TcpStream,
    limit: usize,
) -> std::io::Result<(T, Vec<u8>)> {
    let mut magic = [0_u8; 8];
    stream.read_exact(&mut magic)?;
    if &magic != WIRE_MAGIC {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "wire version"));
    }
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > limit {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes)?;
    let value = contract_core::canonical_from_bytes(&bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "wire decode"))?;
    Ok((value, bytes))
}

fn profile_payload_error(error_value: visa_profile::ProfilePayloadError) -> ProviderError {
    use visa_profile::ProfilePayloadError;

    match error_value {
        ProfilePayloadError::UnknownProfile
        | ProfilePayloadError::VersionMismatch
        | ProfilePayloadError::UnsupportedContinuity => {
            error(ProviderErrorKind::Unsupported, false)
        }
        ProfilePayloadError::AccessMismatch => error(ProviderErrorKind::Denied, false),
        ProfilePayloadError::ResourceMismatch | ProfilePayloadError::StateConflict => {
            error(ProviderErrorKind::Conflict, false)
        }
        ProfilePayloadError::MissingExtension
        | ProfilePayloadError::DuplicateExtension
        | ProfilePayloadError::InvalidPayload => error(ProviderErrorKind::InvalidRequest, false),
    }
}

pub(crate) fn validate_binding_on(
    connection: &rusqlite::Connection,
    resource: EntityRef,
    node: NodeIdentity,
) -> Result<(), ProviderError> {
    let resource = require_logical_resource_on(connection, resource)?;
    let peer = load_peer_on(connection, node, &resource.peer_identity)?;
    if peer.credential_reference != resource.credential_reference {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    Ok(())
}

#[cfg(any(test, feature = "test-control"))]
#[derive(Clone, Debug)]
pub enum LoopbackLogicalPeerBehavior {
    Echo,
    Static(Vec<u8>),
    Delayed { delay: Duration, response: Vec<u8> },
    DropGreetingOnce { response: Vec<u8> },
    PauseGreetingOnce { response: Vec<u8> },
}

#[cfg(any(test, feature = "test-control"))]
pub struct LoopbackLogicalPeer {
    address: SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ledger: std::sync::Arc<std::sync::Mutex<BTreeMap<Identity, PeerOperation>>>,
    wire_payloads: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    requests: std::sync::Arc<std::sync::atomic::AtomicU64>,
    executions: std::sync::Arc<std::sync::atomic::AtomicU64>,
    greeting_barrier: Option<std::sync::Arc<LoopbackGreetingBarrier>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(any(test, feature = "test-control"))]
struct LoopbackPeerServer {
    peer_identity: Vec<u8>,
    credential: Vec<u8>,
    behavior: LoopbackLogicalPeerBehavior,
    ledger: std::sync::Arc<std::sync::Mutex<BTreeMap<Identity, PeerOperation>>>,
    wire_payloads: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    drop_greeting_once: std::sync::Arc<std::sync::atomic::AtomicBool>,
    greeting_barrier: Option<std::sync::Arc<LoopbackGreetingBarrier>>,
    requests: std::sync::Arc<std::sync::atomic::AtomicU64>,
    executions: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

#[cfg(any(test, feature = "test-control"))]
#[derive(Default)]
struct LoopbackGreetingBarrier {
    state: std::sync::Mutex<LoopbackGreetingBarrierState>,
    changed: std::sync::Condvar,
}

#[cfg(any(test, feature = "test-control"))]
#[derive(Default)]
struct LoopbackGreetingBarrierState {
    claimed: bool,
    reached: bool,
    released: bool,
}

#[cfg(any(test, feature = "test-control"))]
impl LoopbackGreetingBarrier {
    fn block_once(&self) {
        let mut state = self.state.lock().expect("loopback greeting barrier");
        if state.claimed {
            return;
        }
        state.claimed = true;
        state.reached = true;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).expect("loopback greeting barrier");
        }
    }

    fn wait_until_reached(&self, timeout: Duration) -> bool {
        let state = self.state.lock().expect("loopback greeting barrier");
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| !state.reached)
            .expect("loopback greeting barrier");
        state.reached
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("loopback greeting barrier");
        state.released = true;
        self.changed.notify_all();
    }
}

#[cfg(any(test, feature = "test-control"))]
impl LoopbackLogicalPeer {
    pub fn spawn(
        peer_identity: Vec<u8>,
        credential: Vec<u8>,
        behavior: LoopbackLogicalPeerBehavior,
    ) -> std::io::Result<Self> {
        use std::{
            net::TcpListener,
            sync::{
                Arc, Mutex,
                atomic::{AtomicBool, AtomicU64},
            },
        };

        if peer_identity.is_empty()
            || peer_identity.len() > MAX_PEER_IDENTITY_BYTES
            || credential.is_empty()
            || credential.len() > MAX_CREDENTIAL_BYTES
        {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "peer config"));
        }
        let response_len = match &behavior {
            LoopbackLogicalPeerBehavior::Echo => 0,
            LoopbackLogicalPeerBehavior::Static(response)
            | LoopbackLogicalPeerBehavior::Delayed { response, .. }
            | LoopbackLogicalPeerBehavior::DropGreetingOnce { response }
            | LoopbackLogicalPeerBehavior::PauseGreetingOnce { response } => response.len(),
        };
        if response_len > MAX_LOGICAL_RESPONSE_BYTES as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "response too large",
            ));
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicU64::new(0));
        let executions = Arc::new(AtomicU64::new(0));
        let ledger = Arc::new(Mutex::new(BTreeMap::<Identity, PeerOperation>::new()));
        let wire_payloads = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let drop_greeting_once = Arc::new(AtomicBool::new(matches!(
            &behavior,
            LoopbackLogicalPeerBehavior::DropGreetingOnce { .. }
        )));
        let greeting_barrier =
            matches!(&behavior, LoopbackLogicalPeerBehavior::PauseGreetingOnce { .. })
                .then(|| Arc::new(LoopbackGreetingBarrier::default()));
        let server = Arc::new(LoopbackPeerServer {
            peer_identity,
            credential,
            behavior,
            ledger: ledger.clone(),
            wire_payloads: wire_payloads.clone(),
            drop_greeting_once,
            greeting_barrier: greeting_barrier.clone(),
            requests: requests.clone(),
            executions: executions.clone(),
        });
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(std::sync::atomic::Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let server = server.clone();
                        std::thread::spawn(move || {
                            let _ = serve_peer_connection(stream, &server);
                        });
                    }
                    Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            stop,
            ledger,
            wire_payloads,
            requests,
            executions,
            greeting_barrier,
            thread: Some(thread),
        })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn execution_count(&self) -> u64 {
        self.executions.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Count application request frames accepted after peer authentication.
    /// A rejected greeting/credential exchange does not increment this value.
    pub fn request_count(&self) -> u64 {
        self.requests.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn received_frame_count(&self) -> usize {
        self.wire_payloads.lock().expect("loopback wire capture").len()
    }

    pub fn received_wire_contains(&self, needle: &[u8]) -> bool {
        !needle.is_empty()
            && self
                .wire_payloads
                .lock()
                .expect("loopback wire capture")
                .iter()
                .any(|frame| frame.windows(needle.len()).any(|window| window == needle))
    }

    /// Test-control fault: model a peer restart that loses its operation
    /// ledger while the provider retains a terminal local observation.
    pub fn clear_operation_ledger(&self) {
        self.ledger.lock().expect("loopback peer ledger").clear();
    }

    pub fn wait_for_greeting_barrier(&self, timeout: Duration) -> bool {
        self.greeting_barrier.as_ref().is_some_and(|barrier| barrier.wait_until_reached(timeout))
    }

    pub fn release_greeting_barrier(&self) {
        if let Some(barrier) = &self.greeting_barrier {
            barrier.release();
        }
    }
}

#[cfg(any(test, feature = "test-control"))]
impl Drop for LoopbackLogicalPeer {
    fn drop(&mut self) {
        self.release_greeting_barrier();
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(any(test, feature = "test-control"))]
#[derive(Clone)]
enum PeerOperation {
    Pending { request_digest: contract_core::Digest },
    Completed { request_digest: contract_core::Digest, response: Vec<u8> },
    Cancelled { request_digest: contract_core::Digest },
}

#[cfg(any(test, feature = "test-control"))]
fn serve_peer_connection(
    mut stream: TcpStream,
    server: &LoopbackPeerServer,
) -> std::io::Result<()> {
    let (hello, hello_payload) =
        read_frame_with_payload::<WireHello>(&mut stream, MAX_WIRE_REQUEST_BYTES)?;
    server.wire_payloads.lock().expect("loopback wire capture").push(hello_payload);
    if server.drop_greeting_once.swap(false, std::sync::atomic::Ordering::AcqRel) {
        return Ok(());
    }
    if let Some(barrier) = &server.greeting_barrier {
        barrier.block_once();
    }
    let greeting_proof = authentication_tag(
        &server.credential,
        b"visa-logical-request-server-greeting-v1",
        &hello.nonce,
        &server.peer_identity,
    )
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "credential"))?;
    write_frame(
        &mut stream,
        &WireGreeting { peer_identity: server.peer_identity.clone(), proof: greeting_proof },
        MAX_WIRE_RESPONSE_BYTES,
    )?;
    let (envelope, envelope_payload) =
        read_frame_with_payload::<AuthenticatedWireRequest>(&mut stream, MAX_WIRE_REQUEST_BYTES)?;
    server.wire_payloads.lock().expect("loopback wire capture").push(envelope_payload);
    let request_bytes = contract_core::canonical_bytes(&envelope.request)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "request encode"))?;
    if !authentication_tag_matches(
        &server.credential,
        b"visa-logical-request-client-v1",
        &hello.nonce,
        &request_bytes,
        &envelope.proof,
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "request authentication",
        ));
    }
    server.requests.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let status = match envelope.request {
        WireRequest::Execute { operation_id, request } => peer_execute(
            operation_id,
            request,
            &server.behavior,
            &server.ledger,
            &server.executions,
        ),
        WireRequest::Lookup { operation_id, request_digest } => {
            peer_lookup(operation_id, request_digest, &server.ledger)
        }
        WireRequest::Cancel { operation_id, request_digest } => {
            peer_cancel(operation_id, request_digest, &server.ledger)
        }
    };
    let status_bytes = contract_core::canonical_bytes(&status)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "reply encode"))?;
    let reply_proof = authentication_tag(
        &server.credential,
        b"visa-logical-request-server-reply-v1",
        &hello.nonce,
        &status_bytes,
    )
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "credential"))?;
    write_frame(&mut stream, &WireReply { status, proof: reply_proof }, MAX_WIRE_RESPONSE_BYTES)
}

#[cfg(any(test, feature = "test-control"))]
fn peer_execute(
    operation_id: Identity,
    request: Vec<u8>,
    behavior: &LoopbackLogicalPeerBehavior,
    ledger: &std::sync::Arc<std::sync::Mutex<BTreeMap<Identity, PeerOperation>>>,
    executions: &std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> WireStatus {
    if request.len() > MAX_LOGICAL_REQUEST_BYTES as usize {
        return WireStatus::Rejected(LogicalRequestRejection::PolicyDenied);
    }
    let digest = match contract_core::canonical_digest(request.as_slice()) {
        Ok(digest) => digest,
        Err(_) => return WireStatus::Rejected(LogicalRequestRejection::PolicyDenied),
    };
    {
        let mut operations = ledger.lock().expect("loopback peer ledger");
        if let Some(existing) = operations.get(&operation_id) {
            return peer_operation_status(existing, digest);
        }
        operations.insert(operation_id, PeerOperation::Pending { request_digest: digest });
    }
    executions.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let response = match behavior {
        LoopbackLogicalPeerBehavior::Echo => request,
        LoopbackLogicalPeerBehavior::Static(response)
        | LoopbackLogicalPeerBehavior::DropGreetingOnce { response }
        | LoopbackLogicalPeerBehavior::PauseGreetingOnce { response } => response.clone(),
        LoopbackLogicalPeerBehavior::Delayed { delay, response } => {
            std::thread::sleep(*delay);
            response.clone()
        }
    };
    let mut operations = ledger.lock().expect("loopback peer ledger");
    if matches!(operations.get(&operation_id), Some(PeerOperation::Cancelled { .. })) {
        return WireStatus::Cancelled;
    }
    operations.insert(
        operation_id,
        PeerOperation::Completed { request_digest: digest, response: response.clone() },
    );
    WireStatus::Completed { response }
}

#[cfg(any(test, feature = "test-control"))]
fn peer_operation_status(operation: &PeerOperation, expected: contract_core::Digest) -> WireStatus {
    match operation {
        PeerOperation::Pending { request_digest } if *request_digest == expected => {
            WireStatus::Pending
        }
        PeerOperation::Completed { request_digest, response } if *request_digest == expected => {
            WireStatus::Completed { response: response.clone() }
        }
        PeerOperation::Cancelled { request_digest } if *request_digest == expected => {
            WireStatus::Cancelled
        }
        _ => WireStatus::Rejected(LogicalRequestRejection::PolicyDenied),
    }
}

#[cfg(any(test, feature = "test-control"))]
fn peer_lookup(
    operation_id: Identity,
    request_digest: contract_core::Digest,
    ledger: &std::sync::Arc<std::sync::Mutex<BTreeMap<Identity, PeerOperation>>>,
) -> WireStatus {
    match ledger.lock().expect("loopback peer ledger").get(&operation_id) {
        Some(operation) => peer_operation_status(operation, request_digest),
        None => WireStatus::NotFound,
    }
}

#[cfg(any(test, feature = "test-control"))]
fn peer_cancel(
    operation_id: Identity,
    request_digest: contract_core::Digest,
    ledger: &std::sync::Arc<std::sync::Mutex<BTreeMap<Identity, PeerOperation>>>,
) -> WireStatus {
    let mut operations = ledger.lock().expect("loopback peer ledger");
    match operations.get(&operation_id) {
        Some(PeerOperation::Completed { request_digest: stored, response })
            if *stored == request_digest =>
        {
            WireStatus::Completed { response: response.clone() }
        }
        Some(PeerOperation::Cancelled { request_digest: stored }) if *stored == request_digest => {
            WireStatus::Cancelled
        }
        Some(PeerOperation::Pending { request_digest: stored }) if *stored == request_digest => {
            operations.insert(operation_id, PeerOperation::Cancelled { request_digest });
            WireStatus::Cancelled
        }
        Some(_) => WireStatus::Rejected(LogicalRequestRejection::PolicyDenied),
        None => {
            operations.insert(operation_id, PeerOperation::Cancelled { request_digest });
            WireStatus::Cancelled
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use contract_core::{
        AuthorityGrant, CONTRACT_VERSION, DeliveryPolicy, Digest, EffectRequest, EntityRef, Event,
        EventKind, Generation, IdempotencyKey, JournalEntry, JournalPosition, LeaseEpoch,
        ProfileAccess, Rights,
    };
    use substrate_api::{
        AuthorityPort, BindingKind, BindingPort, BindingRequest, CommitBundle, JournalPort,
        JournalScope, LeasePort, LeaseRecord, ProfilePort, ReauthorizationRequest,
    };
    use visa_profile::{
        ContinuityDisposition, LogicalRequestClaim, LogicalRequestIdempotency,
        LogicalRequestTransport, encode_logical_request_operation,
    };

    use super::*;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    struct TestDb {
        root: PathBuf,
        path: PathBuf,
    }

    impl TestDb {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("visa-logical-request-{label}-{}-{sequence}", std::process::id()));
            std::fs::create_dir(&root).expect("test directory creates");
            Self { path: root.join("provider.sqlite3"), root }
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn id(value: u128) -> Identity {
        Identity::from_u128(value)
    }

    fn entity(value: u128) -> EntityRef {
        EntityRef::initial(id(value))
    }

    struct Fixture {
        provider: SqliteProvider,
        state: LogicalRequestState,
        node: NodeIdentity,
        subject: EntityRef,
        authority: EntityRef,
        next_position: u64,
    }

    fn fixture(
        db: &TestDb,
        endpoint: SocketAddr,
        peer_identity: &[u8],
        credential: &[u8],
    ) -> Fixture {
        let node = NodeIdentity::new(id(101));
        let subject = entity(102);
        let resource = entity(103);
        let authority = entity(104);
        let body = b"logical request";
        let rights = Rights::PROFILE_READ
            .union(Rights::PROFILE_WRITE)
            .union(Rights::PROFILE_CONTROL)
            .union(Rights::REBIND);
        let state = LogicalRequestState {
            claim: LogicalRequestClaim {
                resource,
                peer_identity: peer_identity.to_vec(),
                credential_reference: id(105),
                required_rights: rights,
                transport: LogicalRequestTransport::Reconnectable,
                delivery: DeliveryPolicy::Deduplicated,
                replay: LogicalRequestReplay::WithOperationId,
                idempotency: LogicalRequestIdempotency::OperationIdDeduplicated,
                timeout_millis: 1_000,
                max_request_size: 1024,
                max_response_size: 1024,
            },
            operation_id: id(106),
            request_size: body.len() as u32,
            request_digest: contract_core::canonical_digest(body.as_slice()).unwrap(),
            phase: LogicalRequestPhase::Ready,
            response_cursor: 0,
            response: None,
            rejection: None,
            disposition: ContinuityDisposition::Revalidate,
            last_operation: None,
        };
        let mut provider =
            SqliteProvider::open(&db.path, JournalScope { node, component: subject.identity })
                .expect("provider opens");
        provider
            .install_policy(substrate_api::AuthorityPolicy {
                subject,
                resource,
                allowed_rights: rights,
            })
            .unwrap();
        provider
            .install_grant(&AuthorityGrant::active_root(authority, subject, resource, rights))
            .unwrap();
        provider
            .initialize_lease(LeaseRecord { resource, owner: node, epoch: LeaseEpoch(1) })
            .unwrap();
        provider.provision_logical_request(&state, endpoint, credential).unwrap();
        Fixture { provider, state, node, subject, authority, next_position: 1 }
    }

    fn effect_request(
        fixture: &Fixture,
        effect_id: u128,
        operation: LogicalRequestOperation,
    ) -> EffectRequest {
        let access = match operation {
            LogicalRequestOperation::Start { .. } => ProfileAccess::Write,
            LogicalRequestOperation::Observe { .. } => ProfileAccess::Read,
            LogicalRequestOperation::Reconcile | LogicalRequestOperation::Cancel => {
                ProfileAccess::Control
            }
        };
        EffectRequest {
            operation: id(effect_id),
            idempotency_key: IdempotencyKey::from_u128(effect_id + 10_000),
            causal_parent: None,
            node: fixture.node,
            subject: fixture.subject,
            resource: fixture.state.claim.resource,
            authority: fixture.authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: Digest::ZERO,
            kind: EffectKind::Profile {
                profile: LOGICAL_REQUEST_EXTENSION_ID,
                access,
                payload: encode_logical_request_operation(&operation).unwrap(),
            },
        }
    }

    fn append_intent(fixture: &mut Fixture, request: &EffectRequest) {
        let position = fixture.next_position;
        fixture.next_position += 1;
        fixture
            .provider
            .append_entry(&JournalEntry {
                version: CONTRACT_VERSION,
                position: JournalPosition(position),
                input_state: Digest::from_bytes([(position - 1) as u8; 32]),
                output_state: Digest::from_bytes([position as u8; 32]),
                event: Event::new(
                    id(20_000 + position as u128),
                    EventKind::EffectPrepared { request: request.clone() },
                ),
            })
            .unwrap();
    }

    fn apply_outcome(
        state: &LogicalRequestState,
        request: &EffectRequest,
        outcome: &EffectOutcome,
    ) -> LogicalRequestState {
        let mut extension = logical_request_extension(state).unwrap();
        let EffectOutcome::Succeeded { result, .. } = outcome else { panic!("success expected") };
        visa_profile::apply_profile_result(
            std::slice::from_mut(&mut extension),
            &request.kind,
            result,
            request.operation,
        )
        .unwrap();
        logical_request_state(&extension).unwrap()
    }

    fn execute(
        fixture: &mut Fixture,
        request: &EffectRequest,
    ) -> Result<EffectOutcome, ProviderError> {
        let extension = logical_request_extension(&fixture.state).unwrap();
        fixture.provider.execute_profile(request, &extension)
    }

    #[test]
    fn start_is_remotely_deduplicated_and_observe_advances_bounded_cursor() {
        let db = TestDb::new("chunks");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-a".to_vec(),
            b"secret-a".to_vec(),
            LoopbackLogicalPeerBehavior::Static(b"abcdef".to_vec()),
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-a", b"secret-a");
        let start = effect_request(
            &fixture,
            201,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &start);
        fixture.provider.inject_failure_once(FaultPoint::AfterLogicalRequestCommit);
        assert_eq!(
            execute(&mut fixture, &start).unwrap_err().kind,
            ProviderErrorKind::OutcomeUnknown
        );
        let durable = fixture
            .provider
            .query_profile_operation(start.operation, start.idempotency_key)
            .unwrap()
            .unwrap();
        assert_eq!(execute(&mut fixture, &start).unwrap(), durable);
        let duplicate_start = effect_request(
            &fixture,
            204,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &duplicate_start);
        assert!(matches!(
            execute(&mut fixture, &duplicate_start).unwrap(),
            EffectOutcome::Succeeded { .. }
        ));
        assert_eq!(peer.execution_count(), 1);
        fixture.state = apply_outcome(&fixture.state, &start, &durable);
        assert_eq!(fixture.state.phase, LogicalRequestPhase::Completed);

        let first =
            effect_request(&fixture, 202, LogicalRequestOperation::Observe { max_bytes: 2 });
        append_intent(&mut fixture, &first);
        let first_outcome = execute(&mut fixture, &first).unwrap();
        let EffectOutcome::Succeeded { result: EffectResult::Profile { payload, .. }, .. } =
            &first_outcome
        else {
            panic!("profile result")
        };
        assert!(matches!(
            visa_profile::decode_logical_request_result(payload).unwrap(),
            LogicalRequestResult::Observed { bytes, response_cursor: 2, .. } if bytes == b"ab"
        ));
        fixture.state = apply_outcome(&fixture.state, &first, &first_outcome);

        let rest =
            effect_request(&fixture, 203, LogicalRequestOperation::Observe { max_bytes: 16 });
        append_intent(&mut fixture, &rest);
        let rest_outcome = execute(&mut fixture, &rest).unwrap();
        fixture.state = apply_outcome(&fixture.state, &rest, &rest_outcome);
        assert_eq!(fixture.state.response_cursor, 6);
        fixture.provider.cleanup_profile_operation(&rest).unwrap();
        fixture.provider.cleanup_profile_operation(&rest).unwrap();

        let persisted: Vec<u8> = fixture
            .provider
            .connection
            .query_row(
                "SELECT record FROM logical_request_ledger WHERE operation_id = ?1",
                params![fixture.state.operation_id.0.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!persisted.windows(b"secret-a".len()).any(|window| window == b"secret-a"));
    }

    #[test]
    fn transient_io_failure_leaves_the_same_start_attempt_retryable() {
        let db = TestDb::new("transient-start");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-transient".to_vec(),
            b"transient-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Static(b"recovered".to_vec()),
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-transient", b"transient-secret");
        let start = effect_request(
            &fixture,
            205,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &start);
        fixture.provider.inject_failure_once(FaultPoint::BeforeLogicalRequestIo);

        let failure = execute(&mut fixture, &start).unwrap_err();
        assert_eq!(failure.kind, ProviderErrorKind::Unavailable);
        assert!(failure.retryable);
        assert_eq!(
            fixture
                .provider
                .query_profile_operation(start.operation, start.idempotency_key)
                .unwrap(),
            None
        );

        let outcome = execute(&mut fixture, &start).unwrap();
        fixture.state = apply_outcome(&fixture.state, &start, &outcome);
        assert_eq!(fixture.state.phase, LogicalRequestPhase::Completed);
        assert_eq!(peer.execution_count(), 1);
    }

    #[test]
    fn greeting_drop_is_before_send_and_retries_the_same_prepared_attempt() {
        let db = TestDb::new("greeting-drop");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-greeting".to_vec(),
            b"greeting-secret".to_vec(),
            LoopbackLogicalPeerBehavior::DropGreetingOnce { response: b"recovered".to_vec() },
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-greeting", b"greeting-secret");
        let start = effect_request(
            &fixture,
            206,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &start);

        assert_eq!(
            execute(&mut fixture, &start).unwrap_err(),
            error(ProviderErrorKind::Unavailable, true)
        );
        let prepared = load_ledger_on(&fixture.provider.connection, fixture.state.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(prepared.phase, LedgerPhase::Prepared);
        assert_eq!(peer.request_count(), 0);
        assert_eq!(peer.received_frame_count(), 1);

        let outcome = execute(&mut fixture, &start).unwrap();
        fixture.state = apply_outcome(&fixture.state, &start, &outcome);
        assert_eq!(fixture.state.phase, LogicalRequestPhase::Completed);
        assert_eq!(peer.execution_count(), 1);
        assert_eq!(peer.request_count(), 1);
        assert_eq!(peer.received_frame_count(), 3);
    }

    #[test]
    fn committed_handoff_fences_a_source_paused_before_the_authenticated_frame() {
        let db = TestDb::new("send-fence");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-fence".to_vec(),
            b"fence-secret".to_vec(),
            LoopbackLogicalPeerBehavior::PauseGreetingOnce { response: b"forbidden".to_vec() },
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-fence", b"fence-secret");
        let start = effect_request(
            &fixture,
            207,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &start);

        let destination = NodeIdentity::new(id(261));
        let destination_subject = EntityRef::new(fixture.subject.identity, Generation(1));
        let destination_authority = entity(262);
        let handoff_resource = entity(263);
        let handoff_authority = entity(264);
        let handoff = id(265);
        let snapshot = id(266);
        fixture
            .provider
            .install_policy(substrate_api::AuthorityPolicy {
                subject: destination_subject,
                resource: fixture.state.claim.resource,
                allowed_rights: fixture.state.claim.required_rights,
            })
            .unwrap();
        fixture
            .provider
            .reauthorize(ReauthorizationRequest {
                handoff,
                snapshot,
                source_authority: fixture.authority,
                destination_authority,
                destination_subject,
                resource: fixture.state.claim.resource,
                required_rights: fixture.state.claim.required_rights,
            })
            .unwrap();
        fixture
            .provider
            .install_policy(substrate_api::AuthorityPolicy {
                subject: destination_subject,
                resource: handoff_resource,
                allowed_rights: Rights::HANDOFF,
            })
            .unwrap();
        fixture
            .provider
            .install_grant(&AuthorityGrant::active_root(
                handoff_authority,
                destination_subject,
                handoff_resource,
                Rights::HANDOFF,
            ))
            .unwrap();
        let lease_commit = EffectRequest {
            operation: id(267),
            idempotency_key: IdempotencyKey::from_u128(10_267),
            causal_parent: None,
            node: destination,
            subject: destination_subject,
            resource: handoff_resource,
            authority: handoff_authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: Digest::ZERO,
            kind: EffectKind::LeaseCommit {
                handoff,
                snapshot,
                destination,
                expected_epoch: LeaseEpoch(1),
                next_epoch: LeaseEpoch(2),
            },
        };
        append_intent(&mut fixture, &lease_commit);
        let prepared = fixture
            .provider
            .prepare_transitions(&lease_commit, &[fixture.state.claim.resource])
            .unwrap();
        let commit_entry = JournalEntry {
            version: CONTRACT_VERSION,
            position: JournalPosition(fixture.next_position),
            input_state: Digest::from_bytes([2; 32]),
            output_state: Digest::from_bytes([3; 32]),
            event: Event::new(
                id(20_003),
                EventKind::HandoffCommitted {
                    operation: lease_commit.operation,
                    handoff,
                    snapshot,
                    source: fixture.node,
                    destination,
                    previous_epoch: LeaseEpoch(1),
                    new_epoch: LeaseEpoch(2),
                    outcome: prepared.outcome.clone(),
                },
            ),
        };
        let bundle = CommitBundle {
            entry: commit_entry,
            lease_transitions: prepared.transitions,
            final_authorities: vec![destination_authority],
        };
        let scope = fixture.provider.scope;
        let mut commit_provider = SqliteProvider::open(&db.path, scope).unwrap();
        let extension = logical_request_extension(&fixture.state).unwrap();
        let mut source_provider = fixture.provider;
        let source =
            std::thread::spawn(move || source_provider.execute_profile(&start, &extension));

        assert!(
            peer.wait_for_greeting_barrier(Duration::from_secs(2)),
            "source reached the real TCP greeting boundary"
        );
        commit_provider.commit_bundle(&bundle).unwrap();
        assert_eq!(
            commit_provider.current_lease(fixture.state.claim.resource).unwrap(),
            Some(LeaseRecord {
                resource: fixture.state.claim.resource,
                owner: destination,
                epoch: LeaseEpoch(2),
            })
        );
        peer.release_greeting_barrier();

        let failure = source.join().unwrap().unwrap_err();
        assert_eq!(failure.kind, ProviderErrorKind::StaleEpoch);
        assert_eq!(peer.request_count(), 0);
        assert_eq!(peer.execution_count(), 0);
        assert_eq!(peer.received_frame_count(), 1);
        assert!(!peer.received_wire_contains(b"logical request"));
    }

    #[test]
    fn ledger_compare_and_save_rejects_stale_terminal_cursor_and_cleanup_regressions() {
        let db = TestDb::new("ledger-cas");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-ledger".to_vec(),
            b"ledger-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Echo,
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-ledger", b"ledger-secret");
        let mut initial = ledger_from_state(&fixture.state, Some(b"logical request".to_vec()));
        fixture.provider.persist_ledger(&mut initial).unwrap();
        let stale = initial.clone();

        let mut terminal = initial;
        terminal.phase = LedgerPhase::Completed;
        terminal.response = Some(b"done".to_vec());
        terminal.response_metadata = Some(response_metadata(b"done").unwrap());
        terminal.delivered_cursor = 3;
        terminal.cleaned = true;
        fixture.provider.persist_ledger(&mut terminal).unwrap();

        let mut stale_overwrite = stale;
        stale_overwrite.phase = LedgerPhase::Pending;
        assert_eq!(
            fixture.provider.persist_ledger(&mut stale_overwrite).unwrap_err().kind,
            ProviderErrorKind::Conflict
        );
        for mut regression in [
            {
                let mut record = terminal.clone();
                record.phase = LedgerPhase::UnknownCompletion;
                record
            },
            {
                let mut record = terminal.clone();
                record.delivered_cursor = 2;
                record
            },
            {
                let mut record = terminal.clone();
                record.cleaned = false;
                record
            },
        ] {
            assert_eq!(
                fixture.provider.persist_ledger(&mut regression).unwrap_err().kind,
                ProviderErrorKind::Conflict
            );
        }
        assert_eq!(
            load_ledger_on(&fixture.provider.connection, fixture.state.operation_id)
                .unwrap()
                .unwrap(),
            terminal
        );
    }

    #[test]
    fn lookup_and_cancel_bind_reused_operation_ids_to_the_request_digest() {
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-digest".to_vec(),
            b"digest-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Echo,
        )
        .unwrap();

        let completed_db = TestDb::new("digest-completed");
        let mut completed =
            fixture(&completed_db, peer.address(), b"peer-digest", b"digest-secret");
        let start = effect_request(
            &completed,
            270,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut completed, &start);
        let outcome = execute(&mut completed, &start).unwrap();
        completed.state = apply_outcome(&completed.state, &start, &outcome);
        assert_eq!(completed.state.phase, LogicalRequestPhase::Completed);
        assert_eq!(peer.execution_count(), 1);

        let lookup_db = TestDb::new("digest-lookup");
        let mut lookup = fixture(&lookup_db, peer.address(), b"peer-digest", b"digest-secret");
        lookup.state.request_size = b"different request".len() as u32;
        lookup.state.request_digest =
            contract_core::canonical_digest(b"different request".as_slice()).unwrap();
        lookup.state.phase = LogicalRequestPhase::UnknownCompletion;
        lookup.state.last_operation = Some(id(271));
        let reconcile = effect_request(&lookup, 272, LogicalRequestOperation::Reconcile);
        append_intent(&mut lookup, &reconcile);
        let outcome = execute(&mut lookup, &reconcile).unwrap();
        lookup.state = apply_outcome(&lookup.state, &reconcile, &outcome);
        assert_eq!(lookup.state.phase, LogicalRequestPhase::Rejected);
        assert_eq!(lookup.state.rejection, Some(LogicalRequestRejection::PolicyDenied));

        let cancel_db = TestDb::new("digest-cancel");
        let mut cancel = fixture(&cancel_db, peer.address(), b"peer-digest", b"digest-secret");
        cancel.state.operation_id = id(273);
        cancel.state.phase = LogicalRequestPhase::UnknownCompletion;
        cancel.state.last_operation = Some(id(274));
        let cancel_request = effect_request(&cancel, 275, LogicalRequestOperation::Cancel);
        append_intent(&mut cancel, &cancel_request);
        let outcome = execute(&mut cancel, &cancel_request).unwrap();
        cancel.state = apply_outcome(&cancel.state, &cancel_request, &outcome);
        assert_eq!(cancel.state.phase, LogicalRequestPhase::Cancelled);

        let cancelled_db = TestDb::new("digest-cancelled-execute");
        let mut cancelled_execute =
            fixture(&cancelled_db, peer.address(), b"peer-digest", b"digest-secret");
        cancelled_execute.state.operation_id = id(273);
        let cancelled_start = effect_request(
            &cancelled_execute,
            275_001,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut cancelled_execute, &cancelled_start);
        let outcome = execute(&mut cancelled_execute, &cancelled_start).unwrap();
        cancelled_execute.state =
            apply_outcome(&cancelled_execute.state, &cancelled_start, &outcome);
        assert_eq!(cancelled_execute.state.phase, LogicalRequestPhase::Cancelled);

        let execute_db = TestDb::new("digest-execute");
        let mut execute_mismatch =
            fixture(&execute_db, peer.address(), b"peer-digest", b"digest-secret");
        execute_mismatch.state.operation_id = id(273);
        execute_mismatch.state.request_size = b"different request".len() as u32;
        execute_mismatch.state.request_digest =
            contract_core::canonical_digest(b"different request".as_slice()).unwrap();
        let mismatched_start = effect_request(
            &execute_mismatch,
            276,
            LogicalRequestOperation::Start { request: b"different request".to_vec() },
        );
        append_intent(&mut execute_mismatch, &mismatched_start);
        let outcome = execute(&mut execute_mismatch, &mismatched_start).unwrap();
        execute_mismatch.state =
            apply_outcome(&execute_mismatch.state, &mismatched_start, &outcome);
        assert_eq!(execute_mismatch.state.phase, LogicalRequestPhase::Rejected);
        assert_eq!(execute_mismatch.state.rejection, Some(LogicalRequestRejection::PolicyDenied));
        assert_eq!(peer.execution_count(), 1, "mismatched operation ID never re-executes");
    }

    #[test]
    fn unknown_completion_reconciles_by_logical_operation_id_without_reexecution() {
        let db = TestDb::new("reconcile");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-b".to_vec(),
            b"secret-b".to_vec(),
            LoopbackLogicalPeerBehavior::Static(b"done".to_vec()),
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-b", b"secret-b");
        let start = effect_request(
            &fixture,
            211,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &start);
        fixture.provider.inject_failure_once(FaultPoint::AfterLogicalRequestSend);
        assert_eq!(
            execute(&mut fixture, &start).unwrap_err().kind,
            ProviderErrorKind::OutcomeUnknown
        );
        let unknown = fixture
            .provider
            .query_profile_operation(start.operation, start.idempotency_key)
            .unwrap()
            .unwrap();
        fixture.state = apply_outcome(&fixture.state, &start, &unknown);
        assert_eq!(fixture.state.phase, LogicalRequestPhase::UnknownCompletion);

        for attempt in 0..20_u128 {
            let reconcile =
                effect_request(&fixture, 212 + attempt, LogicalRequestOperation::Reconcile);
            append_intent(&mut fixture, &reconcile);
            let outcome = execute(&mut fixture, &reconcile).unwrap();
            fixture.state = apply_outcome(&fixture.state, &reconcile, &outcome);
            if fixture.state.phase == LogicalRequestPhase::Completed {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(fixture.state.phase, LogicalRequestPhase::Completed);
        assert_eq!(peer.execution_count(), 1);
    }

    #[test]
    fn before_send_policy_rejects_replay_after_completion_became_unknown() {
        let db = TestDb::new("before-send-unknown");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-before-send".to_vec(),
            b"before-send-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Static(b"must-not-execute".to_vec()),
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-before-send", b"before-send-secret");
        fixture.state.claim.delivery = DeliveryPolicy::AtMostOnce;
        fixture.state.claim.replay = LogicalRequestReplay::BeforeSend;
        fixture.state.claim.idempotency = LogicalRequestIdempotency::NonIdempotent;
        fixture.state.phase = LogicalRequestPhase::UnknownCompletion;
        fixture.state.disposition = ContinuityDisposition::Revalidate;
        fixture.state.last_operation = Some(id(215));

        let reconcile = effect_request(&fixture, 216, LogicalRequestOperation::Reconcile);
        append_intent(&mut fixture, &reconcile);
        let outcome = execute(&mut fixture, &reconcile).unwrap();
        fixture.state = apply_outcome(&fixture.state, &reconcile, &outcome);

        assert_eq!(fixture.state.phase, LogicalRequestPhase::Rejected);
        assert_eq!(fixture.state.rejection, Some(LogicalRequestRejection::UnsafeReplay));
        assert_eq!(peer.execution_count(), 0);
    }

    #[test]
    fn cancel_after_unknown_send_converges_to_cancelled_or_completed() {
        let db = TestDb::new("cancel-race");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-c".to_vec(),
            b"secret-c".to_vec(),
            LoopbackLogicalPeerBehavior::Delayed {
                delay: Duration::from_millis(100),
                response: b"late".to_vec(),
            },
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-c", b"secret-c");
        let start = effect_request(
            &fixture,
            221,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &start);
        fixture.provider.inject_failure_once(FaultPoint::AfterLogicalRequestSend);
        assert!(execute(&mut fixture, &start).is_err());
        let unknown = fixture
            .provider
            .query_profile_operation(start.operation, start.idempotency_key)
            .unwrap()
            .unwrap();
        fixture.state = apply_outcome(&fixture.state, &start, &unknown);

        let cancel = effect_request(&fixture, 222, LogicalRequestOperation::Cancel);
        append_intent(&mut fixture, &cancel);
        fixture.provider.inject_failure_once(FaultPoint::AfterLogicalCancelSend);
        assert!(execute(&mut fixture, &cancel).is_err());
        let cancel_unknown = fixture
            .provider
            .query_profile_operation(cancel.operation, cancel.idempotency_key)
            .unwrap()
            .unwrap();
        fixture.state = apply_outcome(&fixture.state, &cancel, &cancel_unknown);

        for attempt in 0..20_u128 {
            let reconcile =
                effect_request(&fixture, 223 + attempt, LogicalRequestOperation::Reconcile);
            append_intent(&mut fixture, &reconcile);
            let outcome = execute(&mut fixture, &reconcile).unwrap();
            fixture.state = apply_outcome(&fixture.state, &reconcile, &outcome);
            if matches!(
                fixture.state.phase,
                LogicalRequestPhase::Cancelled | LogicalRequestPhase::Completed
            ) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(
            fixture.state.phase,
            LogicalRequestPhase::Cancelled | LogicalRequestPhase::Completed
        ));
        assert!(peer.execution_count() <= 1);
    }

    #[test]
    fn peer_identity_and_credentials_are_verified_outside_canonical_state() {
        let db = TestDb::new("peer-mismatch");
        let peer = LoopbackLogicalPeer::spawn(
            b"actual-peer".to_vec(),
            b"server-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Echo,
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"expected-peer", b"server-secret");
        let start = effect_request(
            &fixture,
            231,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &start);
        let outcome = execute(&mut fixture, &start).unwrap();
        fixture.state = apply_outcome(&fixture.state, &start, &outcome);
        assert_eq!(fixture.state.phase, LogicalRequestPhase::Rejected);
        assert_eq!(fixture.state.rejection, Some(LogicalRequestRejection::PeerMismatch));
        assert_eq!(peer.request_count(), 0, "identity mismatch rejects before application data");
        assert_eq!(peer.execution_count(), 0);
        assert!(!peer.received_wire_contains(b"logical request"));
        assert!(!peer.received_wire_contains(b"server-secret"));

        let scope = fixture.provider.scope;
        drop(fixture.provider);
        let reopened = SqliteProvider::open(&db.path, scope).unwrap();
        assert!(reopened.logical_credentials.is_empty(), "credential bytes never reopen");
    }

    #[test]
    fn wrong_provider_local_credential_is_a_typed_rejection() {
        let db = TestDb::new("credential-denied");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-d".to_vec(),
            b"server-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Echo,
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-d", b"wrong-secret");
        let start = effect_request(
            &fixture,
            235,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &start);
        let outcome = execute(&mut fixture, &start).unwrap();
        fixture.state = apply_outcome(&fixture.state, &start, &outcome);
        assert_eq!(fixture.state.phase, LogicalRequestPhase::Rejected);
        assert_eq!(fixture.state.rejection, Some(LogicalRequestRejection::CredentialDenied));
        assert_eq!(peer.request_count(), 0, "credential mismatch rejects before application data");
        assert_eq!(peer.execution_count(), 0);
        assert!(!peer.received_wire_contains(b"logical request"));
        assert!(!peer.received_wire_contains(b"wrong-secret"));
        assert!(!peer.received_wire_contains(b"server-secret"));
    }

    #[test]
    fn completed_canonical_state_survives_missing_local_and_peer_ledgers() {
        let db = TestDb::new("completed-terminal");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-terminal".to_vec(),
            b"terminal-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Echo,
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-terminal", b"terminal-secret");
        let start = effect_request(
            &fixture,
            238,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &start);
        let outcome = execute(&mut fixture, &start).unwrap();
        fixture.state = apply_outcome(&fixture.state, &start, &outcome);
        assert_eq!(fixture.state.phase, LogicalRequestPhase::Completed);
        assert_eq!(peer.execution_count(), 1);
        let requests_before = peer.request_count();

        fixture.provider.forget_logical_request_operation(fixture.state.operation_id).unwrap();
        peer.clear_operation_ledger();
        let reconcile = effect_request(&fixture, 239, LogicalRequestOperation::Reconcile);
        append_intent(&mut fixture, &reconcile);
        let outcome = execute(&mut fixture, &reconcile).unwrap();
        fixture.state = apply_outcome(&fixture.state, &reconcile, &outcome);

        assert_eq!(fixture.state.phase, LogicalRequestPhase::Completed);
        assert_eq!(peer.execution_count(), 1);
        assert_eq!(
            peer.request_count(),
            requests_before,
            "terminal reconcile stays provider-local"
        );

        let observe =
            effect_request(&fixture, 241, LogicalRequestOperation::Observe { max_bytes: 1 });
        append_intent(&mut fixture, &observe);
        let failure = execute(&mut fixture, &observe).unwrap_err();
        assert_eq!(failure, error(ProviderErrorKind::Unavailable, true));
        let ledger = load_ledger_on(&fixture.provider.connection, fixture.state.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(ledger.phase, LedgerPhase::Completed);
        assert_eq!(ledger.response_metadata, fixture.state.response);
    }

    #[test]
    fn resolved_failure_without_a_logical_mapping_cleans_up_idempotently() {
        let db = TestDb::new("failed-cleanup");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-cleanup".to_vec(),
            b"cleanup-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Echo,
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-cleanup", b"cleanup-secret");
        let request = effect_request(
            &fixture,
            240,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &request);
        crate::write_outcome(
            &fixture.provider.connection,
            request.operation,
            &EffectOutcome::Failed(contract_core::EffectFailure {
                class: contract_core::FailureClass::Denied,
                retryable: false,
                evidence: None,
            }),
        )
        .unwrap();

        fixture.provider.cleanup_profile_operation(&request).unwrap();
        fixture.provider.cleanup_profile_operation(&request).unwrap();
    }

    #[test]
    fn indeterminate_operation_cleanup_does_not_mark_the_logical_ledger_cleaned() {
        let db = TestDb::new("indeterminate-cleanup");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-indeterminate-cleanup".to_vec(),
            b"indeterminate-cleanup-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Echo,
        )
        .unwrap();
        let mut fixture = fixture(
            &db,
            peer.address(),
            b"peer-indeterminate-cleanup",
            b"indeterminate-cleanup-secret",
        );
        let request = effect_request(
            &fixture,
            240_001,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &request);
        let record = ledger_from_state(&fixture.state, Some(b"logical request".to_vec()));
        let transaction = fixture.provider.immediate_transaction().unwrap();
        let record = save_ledger_on(&transaction, &record).unwrap();
        associate_effect_on(&transaction, request.operation, record.operation_id).unwrap();
        crate::write_outcome(
            &transaction,
            request.operation,
            &EffectOutcome::Indeterminate { evidence: None },
        )
        .unwrap();
        transaction.commit().unwrap();

        assert_eq!(
            fixture.provider.cleanup_profile_operation(&request).unwrap_err(),
            error(ProviderErrorKind::OutcomeUnknown, true)
        );
        assert!(
            !load_ledger_on(&fixture.provider.connection, record.operation_id)
                .unwrap()
                .unwrap()
                .cleaned
        );
    }

    #[test]
    fn read_timeout_is_unknown_until_lookup_finds_the_completed_operation() {
        let db = TestDb::new("timeout");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-timeout".to_vec(),
            b"timeout-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Delayed {
                delay: Duration::from_millis(300),
                response: b"eventual".to_vec(),
            },
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-timeout", b"timeout-secret");
        fixture.state.claim.timeout_millis = 100;
        let start = effect_request(
            &fixture,
            236,
            LogicalRequestOperation::Start { request: b"logical request".to_vec() },
        );
        append_intent(&mut fixture, &start);
        let outcome = execute(&mut fixture, &start).unwrap();
        fixture.state = apply_outcome(&fixture.state, &start, &outcome);
        assert_eq!(fixture.state.phase, LogicalRequestPhase::UnknownCompletion);

        std::thread::sleep(Duration::from_millis(350));
        let reconcile = effect_request(&fixture, 237, LogicalRequestOperation::Reconcile);
        append_intent(&mut fixture, &reconcile);
        let outcome = execute(&mut fixture, &reconcile).unwrap();
        fixture.state = apply_outcome(&fixture.state, &reconcile, &outcome);
        assert_eq!(fixture.state.phase, LogicalRequestPhase::Completed);
        assert_eq!(peer.execution_count(), 1);
    }

    #[test]
    fn logical_profile_binding_requires_target_peer_and_reacquired_credential() {
        let db = TestDb::new("binding");
        let peer = LoopbackLogicalPeer::spawn(
            b"peer-binding".to_vec(),
            b"binding-secret".to_vec(),
            LoopbackLogicalPeerBehavior::Echo,
        )
        .unwrap();
        let mut fixture = fixture(&db, peer.address(), b"peer-binding", b"binding-secret");
        let destination = NodeIdentity::new(id(250));
        let destination_subject = EntityRef::new(fixture.subject.identity, Generation(1));
        let destination_authority = entity(251);
        let handoff = id(252);
        let snapshot = id(253);
        let rights = fixture.state.claim.required_rights;
        fixture
            .provider
            .install_policy(substrate_api::AuthorityPolicy {
                subject: destination_subject,
                resource: fixture.state.claim.resource,
                allowed_rights: rights,
            })
            .unwrap();
        fixture
            .provider
            .reauthorize(ReauthorizationRequest {
                handoff,
                snapshot,
                source_authority: fixture.authority,
                destination_authority,
                destination_subject,
                resource: fixture.state.claim.resource,
                required_rights: rights,
            })
            .unwrap();
        let binding = BindingRequest {
            handoff,
            snapshot,
            claim: fixture.state.claim.resource,
            authority: destination_authority,
            exposed_rights: rights,
            expected_owner: fixture.node,
            expected_epoch: LeaseEpoch(1),
            candidate_owner: destination,
            candidate_epoch: LeaseEpoch(2),
            kind: BindingKind::Profile { profile: LOGICAL_REQUEST_EXTENSION_ID },
        };
        assert_eq!(
            fixture.provider.prepare_binding(binding).unwrap_err().kind,
            ProviderErrorKind::NotFound
        );
        fixture
            .provider
            .provision_logical_request_peer(
                destination,
                &fixture.state.claim.peer_identity,
                peer.address(),
                fixture.state.claim.credential_reference,
                b"binding-secret",
            )
            .unwrap();
        let receipt = fixture.provider.prepare_binding(binding).unwrap();
        assert_eq!(receipt.node, destination);

        let scope = fixture.provider.scope;
        drop(fixture.provider);
        let mut reopened = SqliteProvider::open(&db.path, scope).unwrap();
        assert_eq!(reopened.prepare_binding(binding).unwrap_err().kind, ProviderErrorKind::Denied);
        reopened
            .provision_logical_request_peer(
                destination,
                &fixture.state.claim.peer_identity,
                peer.address(),
                fixture.state.claim.credential_reference,
                b"binding-secret",
            )
            .unwrap();
        assert_eq!(reopened.prepare_binding(binding).unwrap(), receipt);
    }

    #[test]
    fn schema_four_migrates_to_five_without_rewriting_regular_file_tables() {
        let db = TestDb::new("v4-migration");
        let scope = JournalScope { node: NodeIdentity::new(id(240)), component: id(241) };
        let provider = SqliteProvider::open(&db.path, scope).unwrap();
        provider
            .connection
            .execute_batch(
                "DROP TABLE logical_request_effect;
                 DROP TABLE logical_request_ledger;
                 DROP TABLE logical_request_peer;
                 DROP TABLE logical_request_resource;
                 PRAGMA user_version = 4;",
            )
            .unwrap();
        drop(provider);
        let reopened = SqliteProvider::open(&db.path, scope).expect("v4 migrates");
        let version: i64 =
            reopened.connection.query_row("PRAGMA user_version", [], |row| row.get(0)).unwrap();
        assert_eq!(version, 5);
        let regular_tables: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table'
                 AND name IN ('regular_file_resource', 'regular_file_plan')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(regular_tables, 2);
    }
}
