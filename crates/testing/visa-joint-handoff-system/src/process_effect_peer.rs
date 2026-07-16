use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Mutex,
};

use contract_core::{Digest, Identity};
use joint_handoff_core::{
    ClassificationCounts, ClosureProgressReceipt, ClosureReceipt, EffectScopeVersion,
    FreezeDisposition, NexusFreezeReceipt, NexusThawReceipt, OwnershipAbortReceipt,
    OwnershipCommitReceipt, PrepareIntentReceipt, ReceiptHeader, ReceiptKind, ReceiptRef,
    TypedReceipt,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use visa_conformance::{
    JointEffectClassification, joint_classification_counts, joint_classification_root,
    joint_effect_cohort_digest,
};

use crate::{
    EffectCloseRequest, EffectCloseResult, EffectFreezeRequest, EffectFreezeResult,
    EffectFreezeToken, EffectPeer, EffectPeerConfig, EffectPeerError, EffectPeerQuery,
    EffectPublicationRequest, EffectPublicationResult, EffectThawRequest, ReferenceEffectRecord,
    nexus_effect_wire::{
        AUTHENTICATION_BOUNDARY, CommitEffect, CrashService, EffectSelector, NativeHandoffStatus,
        NativeOwnershipDecision, NativePrepareIntent, NativeReadiness, NativeReceipt,
        NativeReceiptKind, NativeReceiptPayload, PeerCommand, PeerConfig as NativePeerConfig,
        PeerRequest, PeerResponse, RECEIPT_SCHEMA, REQUEST_SCHEMA, RESPONSE_SCHEMA, RebindService,
        ReceiptDigestInput, RegisterEffect, ResponseStatus,
    },
};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEffectPeerLaunch {
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub nexus_revision: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEffectPeerIdentity {
    pub process_id: u32,
    pub executable_path: PathBuf,
    pub executable_sha256: String,
    pub nexus_revision: String,
    pub start_time_ticks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeJsonlExchange {
    pub request_id: u64,
    pub request_jsonl: String,
    pub response_jsonl: String,
    pub receipt_sequence: u64,
    pub receipt_kind: String,
    pub request_sha256: String,
    pub previous_receipt_sha256: Option<String>,
    pub receipt_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeResponseLossObservation {
    pub request_id: u64,
    pub request_jsonl: String,
    pub discarded_response_jsonl: String,
    pub replay_response_jsonl: String,
    pub byte_identical: bool,
    pub accepted_chain_length_before: usize,
    pub accepted_chain_length_after: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessServiceRebindObservation {
    pub previous_supervisor_id: u64,
    pub previous_supervisor_generation: u64,
    pub replacement_supervisor_id: u64,
    pub replacement_supervisor_generation: u64,
    pub previous_binding_epoch: u64,
    pub crashed_binding_epoch: u64,
    pub rebound_binding_epoch: u64,
    pub crashed_client_effects: Vec<u64>,
    pub adopted_client_effects: Vec<u64>,
    pub recovery_remaining: usize,
}

impl ProcessEffectPeerLaunch {
    pub fn new(
        executable: impl Into<PathBuf>,
        executable_sha256: impl Into<String>,
        nexus_revision: impl Into<String>,
    ) -> Self {
        Self {
            executable: executable.into(),
            executable_sha256: executable_sha256.into(),
            nexus_revision: nexus_revision.into(),
        }
    }
}

pub struct ProcessEffectPeer {
    inner: Mutex<ProcessEffectPeerState>,
}

struct ProcessEffectPeerState {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    launch: ProcessEffectPeerLaunch,
    identity: Option<ProcessEffectPeerIdentity>,
    config: EffectPeerConfig,
    native_binding_epoch: u64,
    native_supervisor_id: u64,
    native_supervisor_generation: u64,
    next_request_id: u64,
    last_native_sequence: u64,
    last_native_receipt_sha256: Option<String>,
    accepted: BTreeMap<u64, AcceptedResponse>,
    raw_responses: Vec<Vec<u8>>,
    lose_next_response: bool,
    pending_lost_response: Option<PendingLostResponse>,
    response_loss_observations: Vec<NativeResponseLossObservation>,
    effects: BTreeMap<Identity, ReferenceEffectRecord>,
    native_effects: BTreeMap<Identity, u64>,
    freeze: Option<ProcessFreeze>,
    thaw_request: Option<EffectThawRequest>,
    thaw: Option<NexusThawReceipt>,
    latest_close: Option<EffectCloseResult>,
    close_steps: BTreeMap<u64, (EffectCloseRequest, EffectCloseResult)>,
    closure_revision: u64,
    next_neutral_sequence: u64,
    neutral_previous: Option<ReceiptRef>,
    shutdown: bool,
}

#[derive(Clone)]
struct AcceptedResponse {
    request: Vec<u8>,
    raw: Vec<u8>,
    receipt: NativeReceipt,
}

#[derive(Clone)]
struct PendingLostResponse {
    request: PeerRequest,
    request_bytes: Vec<u8>,
    discarded_raw: Vec<u8>,
    accepted_chain_length_before: usize,
}

#[derive(Clone)]
struct ProcessFreeze {
    request: EffectFreezeRequest,
    result: EffectFreezeResult,
    intent_request_digest: u64,
}

impl ProcessEffectPeer {
    pub fn spawn(
        launch: ProcessEffectPeerLaunch,
        config: EffectPeerConfig,
    ) -> Result<Self, EffectPeerError> {
        validate_launch(&launch)?;
        let native_config = native_config(config)?;
        let mut child = Command::new(&launch.executable)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(transport)?;
        let stdin = child.stdin.take().ok_or_else(|| transport("child stdin was not piped"))?;
        let stdout = child.stdout.take().ok_or_else(|| transport("child stdout was not piped"))?;
        let mut state = ProcessEffectPeerState {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            launch,
            identity: None,
            config,
            native_binding_epoch: native_config.binding_epoch,
            native_supervisor_id: native_config.supervisor_id,
            native_supervisor_generation: native_config.supervisor_generation,
            next_request_id: 0,
            last_native_sequence: 0,
            last_native_receipt_sha256: None,
            accepted: BTreeMap::new(),
            raw_responses: Vec::new(),
            lose_next_response: false,
            pending_lost_response: None,
            response_loss_observations: Vec::new(),
            effects: BTreeMap::new(),
            native_effects: BTreeMap::new(),
            freeze: None,
            thaw_request: None,
            thaw: None,
            latest_close: None,
            close_steps: BTreeMap::new(),
            closure_revision: 0,
            next_neutral_sequence: 0,
            neutral_previous: None,
            shutdown: false,
        };
        state.identity = match observe_child_identity(state.child.id(), &state.launch) {
            Ok(identity) => Some(identity),
            Err(error) => {
                state.terminate();
                return Err(error);
            }
        };
        let receipt = match state.send(PeerCommand::Initialize(native_config)) {
            Ok(receipt) => receipt,
            Err(error) => {
                state.terminate();
                return Err(error);
            }
        };
        match receipt.payload {
            NativeReceiptPayload::Initialized(payload)
                if payload.config == native_config
                    && payload.process_id == state.child.id()
                    && payload.boot_incarnation != 0 => {}
            _ => {
                state.terminate();
                return Err(rejected("initialize receipt did not bind the child and config"));
            }
        }
        Ok(Self { inner: Mutex::new(state) })
    }

    pub fn executable_sha256(path: impl AsRef<Path>) -> Result<String, EffectPeerError> {
        let bytes = fs::read(path).map_err(transport)?;
        Ok(sha256_hex(&bytes))
    }

    pub fn launch(&self) -> Result<ProcessEffectPeerLaunch, EffectPeerError> {
        Ok(self.inner.lock().map_err(|_| EffectPeerError::Integrity)?.launch.clone())
    }

    pub fn process_identity(&self) -> Result<ProcessEffectPeerIdentity, EffectPeerError> {
        self.inner
            .lock()
            .map_err(|_| EffectPeerError::Integrity)?
            .identity
            .clone()
            .ok_or(EffectPeerError::Integrity)
    }

    pub fn native_transcript(&self) -> Result<Vec<NativeJsonlExchange>, EffectPeerError> {
        let state = self.inner.lock().map_err(|_| EffectPeerError::Integrity)?;
        state
            .accepted
            .iter()
            .map(|(request_id, accepted)| {
                let mut request_jsonl = String::from_utf8(accepted.request.clone())
                    .map_err(|_| rejected("cached native request was not UTF-8"))?;
                request_jsonl.push('\n');
                let response_jsonl = String::from_utf8(accepted.raw.clone())
                    .map_err(|_| rejected("cached native response was not UTF-8"))?;
                let receipt_kind = serde_json::to_value(accepted.receipt.kind)
                    .map_err(|_| EffectPeerError::Integrity)?
                    .as_str()
                    .ok_or(EffectPeerError::Integrity)?
                    .to_owned();
                Ok(NativeJsonlExchange {
                    request_id: *request_id,
                    request_jsonl,
                    response_jsonl,
                    receipt_sequence: accepted.receipt.sequence,
                    receipt_kind,
                    request_sha256: accepted.receipt.request_sha256.clone(),
                    previous_receipt_sha256: accepted.receipt.previous_receipt_sha256.clone(),
                    receipt_sha256: accepted.receipt.receipt_sha256.clone(),
                })
            })
            .collect()
    }

    pub fn shutdown(&self) -> Result<(), EffectPeerError> {
        let mut state = self.inner.lock().map_err(|_| EffectPeerError::Integrity)?;
        if state.shutdown {
            return Ok(());
        }
        let receipt = state.send(PeerCommand::Shutdown)?;
        if !matches!(receipt.payload, NativeReceiptPayload::Shutdown) {
            return Err(rejected("shutdown returned the wrong receipt kind"));
        }
        state.shutdown = true;
        let status = state.child.wait().map_err(transport)?;
        if !status.success() {
            return Err(transport(format!("effect peer exited with {status}")));
        }
        Ok(())
    }

    pub fn replay_last_native_request(&self) -> Result<Vec<u8>, EffectPeerError> {
        let mut state = self.inner.lock().map_err(|_| EffectPeerError::Integrity)?;
        let request_id = state.next_request_id;
        let accepted =
            state.accepted.get(&request_id).cloned().ok_or(EffectPeerError::Integrity)?;
        let request: PeerRequest = serde_json::from_slice(&accepted.request)
            .map_err(|_| rejected("cached request was not valid JSON"))?;
        let replay = state.send_request(request)?;
        if replay.receipt != accepted.receipt {
            return Err(rejected("native replay changed its receipt"));
        }
        Ok(replay.raw)
    }

    /// Arm a real response-loss fault for the next new native request. The
    /// request reaches the child and its first JSONL response is read and
    /// discarded without advancing the adapter's accepted receipt chain.
    pub fn arm_next_response_loss(&self) -> Result<(), EffectPeerError> {
        let mut state = self.inner.lock().map_err(|_| EffectPeerError::Integrity)?;
        if state.lose_next_response || state.pending_lost_response.is_some() {
            return Err(EffectPeerError::AcknowledgementRecoveryConflict {
                request_id: state.next_request_id,
            });
        }
        state.lose_next_response = true;
        Ok(())
    }

    pub fn response_loss_observations(
        &self,
    ) -> Result<Vec<NativeResponseLossObservation>, EffectPeerError> {
        self.inner
            .lock()
            .map(|state| state.response_loss_observations.clone())
            .map_err(|_| EffectPeerError::Integrity)
    }

    pub fn crash_and_rebind_service(
        &self,
        replacement_supervisor: Identity,
        replacement_supervisor_generation: u64,
    ) -> Result<ProcessServiceRebindObservation, EffectPeerError> {
        let mut state = self.inner.lock().map_err(|_| EffectPeerError::Integrity)?;
        state.crash_and_rebind_service(replacement_supervisor, replacement_supervisor_generation)
    }
}

impl EffectPeer for ProcessEffectPeer {
    fn publish(
        &self,
        request: EffectPublicationRequest,
    ) -> Result<EffectPublicationResult, EffectPeerError> {
        let mut state = self.inner.lock().map_err(|_| EffectPeerError::Integrity)?;
        state.publish(request)
    }

    fn freeze(&self, request: EffectFreezeRequest) -> Result<EffectFreezeResult, EffectPeerError> {
        let mut state = self.inner.lock().map_err(|_| EffectPeerError::Integrity)?;
        state.freeze(request)
    }

    fn thaw(&self, request: EffectThawRequest) -> Result<NexusThawReceipt, EffectPeerError> {
        let mut state = self.inner.lock().map_err(|_| EffectPeerError::Integrity)?;
        state.thaw(request)
    }

    fn close(&self, request: EffectCloseRequest) -> Result<EffectCloseResult, EffectPeerError> {
        let mut state = self.inner.lock().map_err(|_| EffectPeerError::Integrity)?;
        state.close(request)
    }

    fn query(&self) -> Result<EffectPeerQuery, EffectPeerError> {
        let mut state = self.inner.lock().map_err(|_| EffectPeerError::Integrity)?;
        state.query()
    }

    fn rebind(
        &self,
        _new_registry_instance: Identity,
    ) -> Result<EffectScopeVersion, EffectPeerError> {
        Err(EffectPeerError::Unsupported(
            "native service rebind preserves the Registry instance and cannot refine Registry replacement",
        ))
    }

    fn native_raw_responses(&self) -> Vec<Vec<u8>> {
        self.inner.lock().map_or_else(|_| Vec::new(), |state| state.raw_responses.clone())
    }
}

impl Drop for ProcessEffectPeer {
    fn drop(&mut self) {
        let Ok(state) = self.inner.get_mut() else {
            return;
        };
        if !state.shutdown {
            state.terminate();
        }
    }
}

impl ProcessEffectPeerState {
    fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.shutdown = true;
    }

    fn publish(
        &mut self,
        request: EffectPublicationRequest,
    ) -> Result<EffectPublicationResult, EffectPeerError> {
        validate_publication(self.config, &request)?;
        if let Some(existing) = self.effects.get(&request.record.effect) {
            if existing == &request.record {
                return Ok(EffectPublicationResult::Replay);
            }
            if !registered_to_committed(existing, &request.record, self.thaw.is_some()) {
                return Err(EffectPeerError::PublicationConflict);
            }
        }
        match request.record.classification {
            JointEffectClassification::Registered | JointEffectClassification::Committed => {}
            JointEffectClassification::Aborted => {
                return Err(EffectPeerError::Unsupported(
                    "native v1 cannot publish a synthetic aborted effect",
                ));
            }
            JointEffectClassification::ResolvedTombstone
            | JointEffectClassification::UnresolvedTombstone => {
                return Err(EffectPeerError::Unsupported(
                    "native v1 cannot manufacture production device tombstones",
                ));
            }
        }
        let client_effect = compact_identity(b"client-effect", request.record.effect);
        if self.native_effects.iter().any(|(identity, native)| {
            *identity != request.record.effect && *native == client_effect
        }) {
            return Err(rejected(
                "two portable effects collided in the native identity projection",
            ));
        }
        if let Some(existing) = self.native_effects.get(&request.record.effect) {
            if *existing != client_effect {
                return Err(EffectPeerError::Integrity);
            }
        } else {
            let register = RegisterEffect {
                client_effect,
                operation_class: compact_identity(b"operation-class", request.record.domain) as u32,
                syscall_number: compact_identity(b"operation", request.record.operation),
                syscall_arguments: [
                    request.record.binding_generation,
                    compact_identity(b"handoff", request.key.handoff),
                    compact_identity(b"source", request.key.source.0),
                    compact_identity(b"destination", request.key.destination.0),
                    0,
                    0,
                ],
                credit_units: 1,
                publication_required: true,
            };
            expect_payload(
                self.send(PeerCommand::Register(register))?,
                NativeReceiptKind::EffectRegistered,
            )?;
            self.native_effects.insert(request.record.effect, client_effect);
        }
        match request.record.classification {
            JointEffectClassification::Registered => {}
            JointEffectClassification::Committed => {
                expect_payload(
                    self.send(PeerCommand::Prepare(EffectSelector {
                        client_effect,
                        binding_epoch: self.native_binding_epoch,
                    }))?,
                    NativeReceiptKind::EffectPrepared,
                )?;
                let outcome =
                    request.record.outcome_digest.ok_or(EffectPeerError::InvalidRequest)?;
                expect_payload(
                    self.send(PeerCommand::Commit(CommitEffect {
                        client_effect,
                        binding_epoch: self.native_binding_epoch,
                        result: i64::from_be_bytes(outcome.0[..8].try_into().unwrap()),
                        domain_revision: request.record.binding_generation,
                    }))?,
                    NativeReceiptKind::EffectCommitted,
                )?;
            }
            JointEffectClassification::Aborted
            | JointEffectClassification::ResolvedTombstone
            | JointEffectClassification::UnresolvedTombstone => unreachable!(),
        }
        self.effects.insert(request.record.effect, request.record);
        Ok(EffectPublicationResult::Published)
    }

    fn freeze(
        &mut self,
        request: EffectFreezeRequest,
    ) -> Result<EffectFreezeResult, EffectPeerError> {
        validate_freeze(self.config, &request)?;
        if let Some(existing) = &self.freeze {
            return if existing.request == request {
                Ok(existing.result.clone())
            } else {
                Err(EffectPeerError::StepConflict)
            };
        }
        let intent = request.intent.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)?;
        validate_intent(self.config, &request.intent)?;
        let intent_request_digest =
            compact_digest(b"intent-request", request.intent.request_digest);
        let native = NativePrepareIntent {
            handoff_id: compact_identity(b"handoff", request.key.handoff),
            log_identity: compact_identity(b"ownership-log", request.intent.header.log_id),
            intent_position: request.intent.intent_revision,
            service_incarnation: compact_identity(
                b"ownership-incarnation",
                request.intent.header.issuer_incarnation,
            ),
            key_identity: compact_identity(b"ownership-key", request.intent.header.key_id),
            request_digest: intent_request_digest,
        };
        let receipt = self.send(PeerCommand::Freeze(native))?;
        let NativeReceiptPayload::AdmissionFrozen(payload) = receipt.payload else {
            return Err(rejected("freeze returned the wrong native payload"));
        };
        verify_freeze_payload(
            self.config,
            &request,
            &payload,
            &self.effects,
            self.native_binding_epoch,
        )?;
        let records = self.effects.values().cloned().collect::<Vec<_>>();
        let neutral_blocked = records.iter().any(|record| {
            matches!(
                record.classification,
                JointEffectClassification::Registered
                    | JointEffectClassification::UnresolvedTombstone
            )
        });
        let key = conformance_key(request.key)?;
        let effect_cohort_digest = joint_effect_cohort_digest(key, records.clone())
            .map_err(|_| EffectPeerError::Integrity)?;
        let classification_root = joint_classification_root(key, records.clone())
            .map_err(|_| EffectPeerError::Integrity)?;
        let native_counts = joint_classification_counts(records);
        let counts = ClassificationCounts {
            registered: native_counts.registered,
            committed: native_counts.committed,
            aborted: native_counts.aborted,
            unresolved: native_counts.unresolved,
            tombstones: native_counts.tombstones,
        };
        let disposition = match payload.readiness {
            NativeReadiness::ReadyToCommit if !neutral_blocked => FreezeDisposition::ReadyToCommit,
            NativeReadiness::NeedsAbort
            | NativeReadiness::PublicationPending
            | NativeReadiness::BlockedRetained => {
                FreezeDisposition::Blocked { blocker_digest: classification_root }
            }
            NativeReadiness::ReadyToCommit => {
                return Err(rejected("native readiness omitted a neutral freeze blocker"));
            }
        };
        let header = self.next_neutral_header(ReceiptKind::NexusFreeze, None)?;
        let mapped = NexusFreezeReceipt {
            header,
            key: request.key,
            intent,
            registry_instance: request.registry_instance,
            scope_id: request.scope_id,
            scope_generation: request.scope_generation,
            authority_epoch: request.authority_epoch,
            freeze_generation: request.freeze_generation,
            domain_bindings_digest: self.config.domain_bindings_digest,
            effect_cohort_digest,
            classification_root,
            counts,
            disposition,
        };
        let freeze_ref = mapped.receipt_ref().map_err(|_| EffectPeerError::Integrity)?;
        self.neutral_previous = Some(freeze_ref);
        let result = EffectFreezeResult {
            token: EffectFreezeToken {
                key: request.key,
                reservation: request.intent.reservation,
                registry_instance: request.registry_instance,
                scope_id: request.scope_id,
                scope_generation: request.scope_generation,
                authority_epoch: request.authority_epoch,
                freeze_generation: request.freeze_generation,
                freeze: freeze_ref,
            },
            receipt: mapped,
        };
        self.freeze =
            Some(ProcessFreeze { request, result: result.clone(), intent_request_digest });
        Ok(result)
    }

    fn thaw(&mut self, request: EffectThawRequest) -> Result<NexusThawReceipt, EffectPeerError> {
        if let Some(existing) = &self.thaw {
            return if self.thaw_request.as_ref() == Some(&request) {
                Ok(existing.clone())
            } else {
                Err(EffectPeerError::StepConflict)
            };
        }
        let freeze = self.freeze.clone().ok_or(EffectPeerError::NotFrozen)?;
        if request.token != freeze.result.token {
            return Err(EffectPeerError::TokenMismatch);
        }
        validate_abort(self.config, &freeze, &request.abort)?;
        let decision = native_decision(self.config, &freeze, &request.abort.header);
        let receipt = self.send(PeerCommand::Thaw(decision))?;
        let NativeReceiptPayload::AdmissionThawed(payload) = receipt.payload else {
            return Err(rejected("thaw returned the wrong native payload"));
        };
        if payload.handoff_id != decision.handoff_id
            || payload.freeze_generation != decision.freeze_generation
            || payload.decision_position != decision.decision_position
        {
            return Err(rejected("thaw payload did not bind the decision"));
        }
        let previous = freeze.result.token.freeze;
        let header = self.next_neutral_header(ReceiptKind::NexusThaw, Some(previous.digest))?;
        let mapped = NexusThawReceipt {
            header,
            key: self.config.key,
            abort: request.abort.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)?,
            nexus_freeze: previous,
            thaw_generation: request
                .token
                .freeze_generation
                .checked_add(1)
                .ok_or(EffectPeerError::InvalidRequest)?,
        };
        self.neutral_previous = Some(mapped.receipt_ref().map_err(|_| EffectPeerError::Integrity)?);
        self.thaw_request = Some(request);
        self.thaw = Some(mapped.clone());
        Ok(mapped)
    }

    fn close(&mut self, request: EffectCloseRequest) -> Result<EffectCloseResult, EffectPeerError> {
        if let Some((existing_request, existing_result)) =
            self.close_steps.get(&request.expected_closure_revision)
        {
            return if existing_request == &request {
                Ok(existing_result.clone())
            } else {
                Err(EffectPeerError::StepConflict)
            };
        }
        let freeze = self.freeze.clone().ok_or(EffectPeerError::NotFrozen)?;
        if request.token != freeze.result.token {
            return Err(EffectPeerError::TokenMismatch);
        }
        if self.thaw.is_some() {
            return Err(EffectPeerError::ExistingAbort(Box::new(self.thaw.clone().unwrap())));
        }
        if request.expected_closure_revision != self.closure_revision {
            return Err(EffectPeerError::StaleRevision {
                expected: request.expected_closure_revision,
                actual: self.closure_revision,
            });
        }
        if freeze.result.receipt.disposition != FreezeDisposition::ReadyToCommit {
            return Err(EffectPeerError::FreezeBlocked);
        }
        validate_commit(self.config, &freeze, &request.commit)?;
        let decision = native_decision(self.config, &freeze, &request.commit.header);
        let receipt = self.send(PeerCommand::CloseStep(decision))?;
        let NativeReceiptPayload::ClosureProgress(payload) = receipt.payload else {
            return Err(rejected("close returned the wrong native payload"));
        };
        if payload.publication_pending {
            let client_effect = payload
                .native_effect
                .and_then(|native| {
                    self.native_effects.values().find(|value| **value == native).copied()
                })
                .ok_or_else(|| rejected("close publication did not name a known effect"))?;
            expect_payload(
                self.send(PeerCommand::AcknowledgePublication(EffectSelector {
                    client_effect,
                    binding_epoch: self.native_binding_epoch,
                }))?,
                NativeReceiptKind::PublicationAcknowledged,
            )?;
        }
        let next_revision =
            self.closure_revision.checked_add(1).ok_or(EffectPeerError::InvalidRequest)?;
        let previous = self.neutral_previous.ok_or(EffectPeerError::Integrity)?;
        let commit = request.commit.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)?;
        let mapped = match payload.status {
            NativeHandoffStatus::Closing => EffectCloseResult::Progress(ClosureProgressReceipt {
                header: self
                    .next_neutral_header(ReceiptKind::ClosureProgress, Some(previous.digest))?,
                key: self.config.key,
                commit,
                nexus_freeze: freeze.result.token.freeze,
                closure_revision: next_revision,
                remaining_effects: u64::try_from(payload.live_effects)
                    .map_err(|_| EffectPeerError::Integrity)?,
                retained_tombstones: 0,
                progress_root: mapped_native_digest(b"closure-progress", &payload),
            }),
            NativeHandoffStatus::Closed => {
                let terminal = payload
                    .terminal_manifest_digest
                    .ok_or_else(|| rejected("closed payload omitted terminal manifest"))?;
                EffectCloseResult::Closed(ClosureReceipt {
                    header: self
                        .next_neutral_header(ReceiptKind::Closure, Some(previous.digest))?,
                    key: self.config.key,
                    commit,
                    nexus_freeze: freeze.result.token.freeze,
                    closure_revision: next_revision,
                    effect_manifest_digest: mapped_u64_digest(b"terminal-manifest", terminal),
                    closed_authority_epoch: payload.authority_epoch,
                })
            }
            NativeHandoffStatus::Retained => {
                return Err(EffectPeerError::Unsupported(
                    "native retained status lacks the typed tombstone manifest required by v1",
                ));
            }
            NativeHandoffStatus::Frozen => return Err(EffectPeerError::FreezeBlocked),
            NativeHandoffStatus::Aborted => {
                return Err(EffectPeerError::Unsupported(
                    "native query reported an abort without a mapped thaw receipt",
                ));
            }
        };
        self.closure_revision = next_revision;
        self.neutral_previous = Some(mapped.receipt_ref()?);
        self.close_steps.insert(request.expected_closure_revision, (request, mapped.clone()));
        self.latest_close = Some(mapped.clone());
        Ok(mapped)
    }

    fn query(&mut self) -> Result<EffectPeerQuery, EffectPeerError> {
        if self.freeze.is_some() && !self.shutdown {
            let receipt = self.send(PeerCommand::Query)?;
            if !matches!(receipt.payload, NativeReceiptPayload::HandoffQuery(_)) {
                return Err(rejected("query returned the wrong native payload"));
            }
        }
        Ok(EffectPeerQuery {
            scope: EffectScopeVersion {
                registry_instance: self.config.registry_instance,
                scope_id: self.config.scope_id,
                scope_generation: self.config.scope_generation,
                authority_epoch: self.config.authority_epoch,
                freeze_generation: self.config.freeze_generation,
            },
            gate_open: self.freeze.is_none() || self.thaw.is_some(),
            effect_count: self.effects.len(),
            freeze: self.freeze.as_ref().map(|freeze| freeze.result.clone()),
            thaw: self.thaw.clone(),
            latest_close: self.latest_close.clone(),
        })
    }

    fn crash_and_rebind_service(
        &mut self,
        replacement_supervisor: Identity,
        replacement_supervisor_generation: u64,
    ) -> Result<ProcessServiceRebindObservation, EffectPeerError> {
        if replacement_supervisor.is_zero() || replacement_supervisor_generation == 0 {
            return Err(EffectPeerError::InvalidRequest);
        }
        let previous_supervisor_id = self.native_supervisor_id;
        let previous_supervisor_generation = self.native_supervisor_generation;
        let previous_binding_epoch = self.native_binding_epoch;
        let crash = CrashService {
            supervisor_id: previous_supervisor_id,
            supervisor_generation: previous_supervisor_generation,
            binding_epoch: previous_binding_epoch,
        };
        let receipt = self.send(PeerCommand::CrashService(crash))?;
        let NativeReceiptPayload::ServiceCrashed(crashed) = receipt.payload else {
            return Err(rejected("service crash returned the wrong native payload"));
        };
        let mut expected_clients = self.native_effects.values().copied().collect::<Vec<_>>();
        expected_clients.sort_unstable();
        let mut crashed_client_effects =
            crashed.cohort.iter().map(|effect| effect.client_effect).collect::<Vec<_>>();
        crashed_client_effects.sort_unstable();
        if crashed.scope_id != compact_identity(b"scope", self.config.scope_id)
            || crashed.scope_generation != self.config.scope_generation
            || crashed.supervisor_id != previous_supervisor_id
            || crashed.supervisor_generation != previous_supervisor_generation
            || crashed.previous_binding_epoch != previous_binding_epoch
            || crashed.crashed_binding_epoch <= previous_binding_epoch
            || crashed_client_effects != expected_clients
            || crashed.cohort.iter().any(|effect| {
                effect.native_effect_id == 0
                    || effect.native_effect_generation == 0
                    || effect.binding_epoch != previous_binding_epoch
            })
        {
            return Err(rejected("service crash payload did not bind the active native cohort"));
        }

        let replacement_supervisor_id = compact_identity(b"supervisor", replacement_supervisor);
        let rebind = RebindService {
            crashed_binding_epoch: crashed.crashed_binding_epoch,
            replacement_supervisor_id,
            replacement_supervisor_generation,
        };
        let receipt = self.send(PeerCommand::RebindService(rebind))?;
        let NativeReceiptPayload::ServiceRebound(rebound) = receipt.payload else {
            return Err(rejected("service rebind returned the wrong native payload"));
        };
        let mut adopted_client_effects =
            rebound.adopted.iter().map(|effect| effect.client_effect).collect::<Vec<_>>();
        adopted_client_effects.sort_unstable();
        if rebound.scope_id != compact_identity(b"scope", self.config.scope_id)
            || rebound.scope_generation != self.config.scope_generation
            || rebound.supervisor_id != replacement_supervisor_id
            || rebound.supervisor_generation != replacement_supervisor_generation
            || rebound.binding_epoch != crashed.crashed_binding_epoch
            || rebound.recovery_remaining != 0
            || adopted_client_effects != crashed_client_effects
            || rebound.adopted.iter().any(|effect| {
                effect.native_effect_id == 0
                    || effect.native_effect_generation == 0
                    || effect.previous_binding_epoch != previous_binding_epoch
                    || effect.binding_epoch != rebound.binding_epoch
            })
        {
            return Err(rejected("service rebind payload did not bind complete native adoption"));
        }
        self.native_binding_epoch = rebound.binding_epoch;
        self.native_supervisor_id = replacement_supervisor_id;
        self.native_supervisor_generation = replacement_supervisor_generation;
        Ok(ProcessServiceRebindObservation {
            previous_supervisor_id,
            previous_supervisor_generation,
            replacement_supervisor_id,
            replacement_supervisor_generation,
            previous_binding_epoch,
            crashed_binding_epoch: crashed.crashed_binding_epoch,
            rebound_binding_epoch: rebound.binding_epoch,
            crashed_client_effects,
            adopted_client_effects,
            recovery_remaining: rebound.recovery_remaining,
        })
    }

    fn send(&mut self, command: PeerCommand) -> Result<NativeReceipt, EffectPeerError> {
        if let Some(pending) = self.pending_lost_response.clone() {
            let request = PeerRequest {
                schema: REQUEST_SCHEMA.to_owned(),
                request_id: pending.request.request_id,
                command,
            };
            let request_bytes =
                serde_json::to_vec(&request).map_err(|_| EffectPeerError::Integrity)?;
            if request_bytes != pending.request_bytes {
                return Err(EffectPeerError::AcknowledgementRecoveryConflict {
                    request_id: pending.request.request_id,
                });
            }
            return Ok(self.recover_lost_response(pending)?.receipt);
        }
        self.next_request_id =
            self.next_request_id.checked_add(1).ok_or(EffectPeerError::InvalidRequest)?;
        let request = PeerRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: self.next_request_id,
            command,
        };
        Ok(self.send_request(request)?.receipt)
    }

    fn send_request(&mut self, request: PeerRequest) -> Result<AcceptedResponse, EffectPeerError> {
        let request_bytes = serde_json::to_vec(&request).map_err(|_| EffectPeerError::Integrity)?;
        self.stdin.write_all(&request_bytes).map_err(transport)?;
        self.stdin.write_all(b"\n").map_err(transport)?;
        self.stdin.flush().map_err(transport)?;
        let raw = read_response_line(&mut self.stdout)?;
        if self.lose_next_response {
            self.lose_next_response = false;
            let request_id = request.request_id;
            self.pending_lost_response = Some(PendingLostResponse {
                request,
                request_bytes,
                discarded_raw: raw,
                accepted_chain_length_before: self.accepted.len(),
            });
            return Err(EffectPeerError::AcknowledgementLost { request_id });
        }
        self.verify_response(&request_bytes, &raw, request.request_id)
    }

    fn recover_lost_response(
        &mut self,
        pending: PendingLostResponse,
    ) -> Result<AcceptedResponse, EffectPeerError> {
        self.stdin.write_all(&pending.request_bytes).map_err(transport)?;
        self.stdin.write_all(b"\n").map_err(transport)?;
        self.stdin.flush().map_err(transport)?;
        let replay_raw = read_response_line(&mut self.stdout)?;
        if replay_raw != pending.discarded_raw {
            return Err(rejected("lost native response did not replay byte-identically"));
        }
        let accepted =
            self.verify_response(&pending.request_bytes, &replay_raw, pending.request.request_id)?;
        let mut request_jsonl = pending.request_bytes.clone();
        request_jsonl.push(b'\n');
        let request_jsonl =
            String::from_utf8(request_jsonl).map_err(|_| EffectPeerError::Integrity)?;
        let discarded_response_jsonl =
            String::from_utf8(pending.discarded_raw).map_err(|_| EffectPeerError::Integrity)?;
        let replay_response_jsonl =
            String::from_utf8(replay_raw).map_err(|_| EffectPeerError::Integrity)?;
        self.response_loss_observations.push(NativeResponseLossObservation {
            request_id: pending.request.request_id,
            request_jsonl,
            byte_identical: discarded_response_jsonl == replay_response_jsonl,
            discarded_response_jsonl,
            replay_response_jsonl,
            accepted_chain_length_before: pending.accepted_chain_length_before,
            accepted_chain_length_after: self.accepted.len(),
        });
        self.pending_lost_response = None;
        Ok(accepted)
    }

    fn verify_response(
        &mut self,
        request_bytes: &[u8],
        raw: &[u8],
        request_id: u64,
    ) -> Result<AcceptedResponse, EffectPeerError> {
        let json = raw
            .strip_suffix(b"\n")
            .ok_or_else(|| rejected("native response was not LF terminated"))?;
        if json.ends_with(b"\r") {
            return Err(rejected("native response used CRLF"));
        }
        let response: PeerResponse = serde_json::from_slice(json)
            .map_err(|_| rejected("native response did not match its strict schema"))?;
        if serde_json::to_vec(&response).map_err(|_| EffectPeerError::Integrity)? != json {
            return Err(rejected("native response was not canonical JSON"));
        }
        if response.schema != RESPONSE_SCHEMA || response.request_id != request_id {
            return Err(rejected("native response schema or request ID mismatched"));
        }
        if let Some(existing) = self.accepted.get(&request_id) {
            if existing.request != request_bytes || existing.raw != raw {
                return Err(rejected("native request replay was not byte-identical"));
            }
            return Ok(existing.clone());
        }
        match response.status {
            ResponseStatus::Error => {
                if response.receipt.is_some() {
                    return Err(rejected("native error response contained a receipt"));
                }
                let error = response.error.ok_or_else(|| rejected("native error was empty"))?;
                return Err(EffectPeerError::NativePeer { code: error.code, detail: error.detail });
            }
            ResponseStatus::Ok if response.error.is_some() => {
                return Err(rejected("native success response contained an error"));
            }
            ResponseStatus::Ok => {}
        }
        let receipt = response.receipt.ok_or_else(|| rejected("native success omitted receipt"))?;
        verify_native_receipt(
            &receipt,
            request_bytes,
            self.last_native_sequence,
            self.last_native_receipt_sha256.as_deref(),
        )?;
        self.last_native_sequence = receipt.sequence;
        self.last_native_receipt_sha256 = Some(receipt.receipt_sha256.clone());
        let accepted =
            AcceptedResponse { request: request_bytes.to_vec(), raw: raw.to_vec(), receipt };
        self.raw_responses.push(raw.to_vec());
        self.accepted.insert(request_id, accepted.clone());
        Ok(accepted)
    }

    fn next_neutral_header(
        &mut self,
        kind: ReceiptKind,
        previous_digest: Option<Digest>,
    ) -> Result<ReceiptHeader, EffectPeerError> {
        self.next_neutral_sequence =
            self.next_neutral_sequence.checked_add(1).ok_or(EffectPeerError::InvalidRequest)?;
        Ok(ReceiptHeader {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            kind,
            issuer: self.config.issuer.issuer,
            issuer_incarnation: self.config.issuer.issuer_incarnation,
            key_id: self.config.issuer.key_id,
            log_id: self.config.issuer.log_id,
            sequence: self.next_neutral_sequence,
            previous_digest,
        })
    }
}

pub(crate) fn verify_native_receipt(
    receipt: &NativeReceipt,
    request_bytes: &[u8],
    last_sequence: u64,
    previous_receipt: Option<&str>,
) -> Result<(), EffectPeerError> {
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.authentication_boundary != AUTHENTICATION_BOUNDARY
        || receipt.kind != receipt.payload.receipt_kind()
        || receipt.sequence != last_sequence.checked_add(1).ok_or(EffectPeerError::Integrity)?
        || receipt.previous_receipt_sha256.as_deref() != previous_receipt
    {
        return Err(rejected("native receipt header or chain mismatched"));
    }
    let request_sha256 = sha256_hex(request_bytes);
    if receipt.request_sha256 != request_sha256 {
        return Err(rejected("native receipt issuance-binding digest mismatched"));
    }
    let payload_bytes =
        serde_json::to_vec(&receipt.payload).map_err(|_| EffectPeerError::Integrity)?;
    if receipt.payload_sha256 != sha256_hex(&payload_bytes) {
        return Err(rejected("native receipt payload digest mismatched"));
    }
    let input = ReceiptDigestInput {
        schema: RECEIPT_SCHEMA,
        sequence: receipt.sequence,
        kind: receipt.kind,
        request_sha256: &receipt.request_sha256,
        previous_receipt_sha256: receipt.previous_receipt_sha256.as_deref(),
        payload_sha256: &receipt.payload_sha256,
        authentication_boundary: AUTHENTICATION_BOUNDARY,
        payload: &receipt.payload,
    };
    let bytes = serde_json::to_vec(&input).map_err(|_| EffectPeerError::Integrity)?;
    if receipt.receipt_sha256 != sha256_hex(&bytes) {
        return Err(rejected("native receipt digest mismatched"));
    }
    Ok(())
}

pub(crate) fn validate_native_jsonl_chain(
    chain: &[NativeJsonlExchange],
) -> Result<(), EffectPeerError> {
    if chain.is_empty() {
        return Err(rejected("native JSONL chain was empty"));
    }
    let mut previous = None;
    let mut previous_sequence = 0;
    for (index, exchange) in chain.iter().enumerate() {
        let expected = u64::try_from(index).map_err(|_| EffectPeerError::Integrity)? + 1;
        if exchange.request_id != expected || exchange.receipt_sequence != expected {
            return Err(rejected("native request/receipt sequence was not contiguous"));
        }
        if !exchange.request_jsonl.ends_with('\n')
            || !exchange.response_jsonl.ends_with('\n')
            || exchange.request_jsonl.ends_with("\r\n")
            || exchange.response_jsonl.ends_with("\r\n")
        {
            return Err(rejected(
                "native transcript did not preserve canonical LF-delimited JSONL",
            ));
        }
        if exchange.previous_receipt_sha256 != previous {
            return Err(rejected("native transcript parent digest was not contiguous"));
        }
        let request_json = exchange
            .request_jsonl
            .strip_suffix('\n')
            .ok_or_else(|| rejected("native request was not LF terminated"))?;
        let request: PeerRequest = serde_json::from_str(request_json)
            .map_err(|_| rejected("native request transcript was not valid JSON"))?;
        if request.schema != REQUEST_SCHEMA
            || request.request_id != exchange.request_id
            || serde_json::to_vec(&request).map_err(|_| EffectPeerError::Integrity)?
                != request_json.as_bytes()
        {
            return Err(rejected(
                "native request transcript schema, canonical form, or identity mismatched",
            ));
        }
        let response_json = exchange
            .response_jsonl
            .strip_suffix('\n')
            .ok_or_else(|| rejected("native response was not LF terminated"))?;
        let response: PeerResponse = serde_json::from_str(response_json)
            .map_err(|_| rejected("native response transcript was not valid JSON"))?;
        if serde_json::to_vec(&response).map_err(|_| EffectPeerError::Integrity)?
            != response_json.as_bytes()
        {
            return Err(rejected("native response transcript was not canonical JSON"));
        }
        if response.schema != RESPONSE_SCHEMA
            || response.request_id != exchange.request_id
            || !matches!(response.status, ResponseStatus::Ok)
            || response.error.is_some()
        {
            return Err(rejected(
                "native response transcript was not an accepted success response",
            ));
        }
        let expected_kind = expected_native_receipt_kind(&request.command);
        let receipt =
            response.receipt.ok_or_else(|| rejected("native transcript omitted receipt"))?;
        if receipt.kind != expected_kind || receipt.payload.receipt_kind() != expected_kind {
            return Err(rejected("native command and receipt payload kind did not correspond"));
        }
        let receipt_kind = serde_json::to_value(receipt.kind)
            .map_err(|_| EffectPeerError::Integrity)?
            .as_str()
            .ok_or(EffectPeerError::Integrity)?
            .to_owned();
        if receipt.sequence != exchange.receipt_sequence
            || receipt_kind != exchange.receipt_kind
            || receipt.request_sha256 != exchange.request_sha256
            || receipt.previous_receipt_sha256 != exchange.previous_receipt_sha256
            || receipt.receipt_sha256 != exchange.receipt_sha256
        {
            return Err(rejected(
                "native transcript metadata did not match its raw JSONL response",
            ));
        }
        verify_native_receipt(
            &receipt,
            request_json.as_bytes(),
            previous_sequence,
            previous.as_deref(),
        )?;
        previous_sequence = receipt.sequence;
        previous = Some(exchange.receipt_sha256.clone());
    }
    Ok(())
}

const fn expected_native_receipt_kind(command: &PeerCommand) -> NativeReceiptKind {
    match command {
        PeerCommand::Initialize(_) => NativeReceiptKind::Initialized,
        PeerCommand::Register(_) => NativeReceiptKind::EffectRegistered,
        PeerCommand::Prepare(_) => NativeReceiptKind::EffectPrepared,
        PeerCommand::Commit(_) => NativeReceiptKind::EffectCommitted,
        PeerCommand::Complete(_) => NativeReceiptKind::EffectCompleted,
        PeerCommand::AcknowledgePublication(_) => NativeReceiptKind::PublicationAcknowledged,
        PeerCommand::CrashService(_) => NativeReceiptKind::ServiceCrashed,
        PeerCommand::RebindService(_) => NativeReceiptKind::ServiceRebound,
        PeerCommand::Freeze(_) => NativeReceiptKind::AdmissionFrozen,
        PeerCommand::AbortUncommitted => NativeReceiptKind::UncommittedAborted,
        PeerCommand::Thaw(_) => NativeReceiptKind::AdmissionThawed,
        PeerCommand::CloseStep(_) => NativeReceiptKind::ClosureProgress,
        PeerCommand::Query => NativeReceiptKind::HandoffQuery,
        PeerCommand::Shutdown => NativeReceiptKind::Shutdown,
    }
}

fn validate_launch(launch: &ProcessEffectPeerLaunch) -> Result<(), EffectPeerError> {
    if launch.executable_sha256.len() != 64
        || !launch.executable_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        || launch.nexus_revision.len() != 40
        || !launch
            .nexus_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EffectPeerError::InvalidRequest);
    }
    let actual = ProcessEffectPeer::executable_sha256(&launch.executable)?;
    if actual != launch.executable_sha256 {
        return Err(rejected("nexus-effect-peer executable digest mismatched"));
    }
    Ok(())
}

fn observe_child_identity(
    pid: u32,
    launch: &ProcessEffectPeerLaunch,
) -> Result<ProcessEffectPeerIdentity, EffectPeerError> {
    let proc_executable = PathBuf::from(format!("/proc/{pid}/exe"));
    let actual = ProcessEffectPeer::executable_sha256(&proc_executable)?;
    if actual != launch.executable_sha256 {
        return Err(rejected("spawned child executable digest mismatched"));
    }
    let executable_path = fs::read_link(&proc_executable).map_err(transport)?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(transport)?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| rejected("spawned child stat record was malformed"))?;
    let start_time_ticks = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| rejected("spawned child stat omitted start time"))?
        .parse::<u64>()
        .map_err(transport)?;
    Ok(ProcessEffectPeerIdentity {
        process_id: pid,
        executable_path,
        executable_sha256: actual,
        nexus_revision: launch.nexus_revision.clone(),
        start_time_ticks,
    })
}

fn validate_publication(
    config: EffectPeerConfig,
    request: &EffectPublicationRequest,
) -> Result<(), EffectPeerError> {
    if request.key != config.key {
        return Err(EffectPeerError::HandoffMismatch);
    }
    if request.registry_instance != config.registry_instance {
        return Err(EffectPeerError::StaleRegistry);
    }
    if request.scope_id != config.scope_id || request.scope_generation != config.scope_generation {
        return Err(EffectPeerError::StaleScope);
    }
    if request.source_epoch != config.key.expected_epoch
        || request.record.binding_generation != config.scope_generation
        || request.record.effect.is_zero()
        || request.record.operation.is_zero()
        || request.record.domain.is_zero()
    {
        return Err(EffectPeerError::StaleEpoch);
    }
    Ok(())
}

fn validate_freeze(
    config: EffectPeerConfig,
    request: &EffectFreezeRequest,
) -> Result<(), EffectPeerError> {
    if request.key != config.key {
        return Err(EffectPeerError::HandoffMismatch);
    }
    if request.registry_instance != config.registry_instance {
        return Err(EffectPeerError::StaleRegistry);
    }
    if request.scope_id != config.scope_id || request.scope_generation != config.scope_generation {
        return Err(EffectPeerError::StaleScope);
    }
    if request.authority_epoch != config.authority_epoch {
        return Err(EffectPeerError::StaleEpoch);
    }
    if request.freeze_generation != config.freeze_generation {
        return Err(EffectPeerError::StaleFreezeGeneration);
    }
    Ok(())
}

fn validate_intent(
    config: EffectPeerConfig,
    intent: &PrepareIntentReceipt,
) -> Result<(), EffectPeerError> {
    if intent.key != config.key
        || intent.header.kind != ReceiptKind::PrepareIntent
        || intent.header.issuer != config.ownership_issuer.issuer
        || intent.header.issuer_incarnation != config.ownership_issuer.issuer_incarnation
        || intent.header.key_id != config.ownership_issuer.key_id
        || intent.header.log_id != config.ownership_issuer.log_id
        || intent.intent_revision != intent.header.sequence
        || intent.request_digest == Digest::ZERO
    {
        return Err(EffectPeerError::InvalidRequest);
    }
    Ok(())
}

fn validate_abort(
    config: EffectPeerConfig,
    freeze: &ProcessFreeze,
    abort: &OwnershipAbortReceipt,
) -> Result<(), EffectPeerError> {
    let reference = abort.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)?;
    if abort.key != config.key
        || abort.reservation != freeze.result.token.reservation
        || abort.header.kind != ReceiptKind::OwnershipAbort
        || reference.issuer != config.ownership_issuer.issuer
        || reference.issuer_incarnation != config.ownership_issuer.issuer_incarnation
        || reference.key_id != config.ownership_issuer.key_id
        || reference.log_id != config.ownership_issuer.log_id
        || abort.header.sequence != abort.decision_sequence
        || abort.decision_sequence <= abort.basis_revision
    {
        return Err(EffectPeerError::InvalidRequest);
    }
    Ok(())
}

fn validate_commit(
    config: EffectPeerConfig,
    freeze: &ProcessFreeze,
    commit: &OwnershipCommitReceipt,
) -> Result<(), EffectPeerError> {
    let reference = commit.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)?;
    if commit.key != config.key
        || commit.reservation != freeze.result.token.reservation
        || commit.header.kind != ReceiptKind::OwnershipCommit
        || reference.issuer != config.ownership_issuer.issuer
        || reference.issuer_incarnation != config.ownership_issuer.issuer_incarnation
        || reference.key_id != config.ownership_issuer.key_id
        || reference.log_id != config.ownership_issuer.log_id
        || commit.header.sequence != commit.decision_sequence
        || commit.decision_sequence <= commit.prepared_revision
    {
        return Err(EffectPeerError::InvalidRequest);
    }
    Ok(())
}

fn verify_freeze_payload(
    config: EffectPeerConfig,
    request: &EffectFreezeRequest,
    payload: &crate::nexus_effect_wire::FreezePayload,
    effects: &BTreeMap<Identity, ReferenceEffectRecord>,
    native_binding_epoch: u64,
) -> Result<(), EffectPeerError> {
    let committed = effects
        .values()
        .filter(|effect| effect.classification == JointEffectClassification::Committed)
        .count();
    if payload.handoff_id != compact_identity(b"handoff", request.key.handoff)
        || payload.scope_id != compact_identity(b"scope", config.scope_id)
        || payload.scope_generation != config.scope_generation
        || payload.authority_epoch != config.authority_epoch
        || payload.binding_epoch != native_binding_epoch
        || payload.freeze_generation != config.freeze_generation
        || payload.cohort_size != effects.len()
        || payload.committed_at_freeze != committed
        || payload.registry_instance == 0
        || payload.boot_incarnation == 0
        || payload.frozen_scope_revision == 0
        || payload.cohort_digest == 0
        || payload.classification_digest == 0
    {
        return Err(rejected("native freeze payload did not bind the configured cohort"));
    }
    Ok(())
}

fn native_decision(
    config: EffectPeerConfig,
    freeze: &ProcessFreeze,
    header: &ReceiptHeader,
) -> NativeOwnershipDecision {
    NativeOwnershipDecision {
        handoff_id: compact_identity(b"handoff", config.key.handoff),
        freeze_generation: config.freeze_generation,
        log_identity: compact_identity(b"ownership-log", header.log_id),
        decision_position: header.sequence,
        service_incarnation: compact_identity(b"ownership-incarnation", header.issuer_incarnation),
        key_identity: compact_identity(b"ownership-key", header.key_id),
        request_digest: freeze.intent_request_digest,
    }
}

fn native_config(config: EffectPeerConfig) -> Result<NativePeerConfig, EffectPeerError> {
    Ok(NativePeerConfig {
        scope_id: compact_identity(b"scope", config.scope_id),
        scope_generation: config.scope_generation,
        authority_epoch: config.authority_epoch,
        binding_epoch: config.scope_generation,
        supervisor_id: compact_identity(b"supervisor", config.key.source.0),
        supervisor_generation: config.scope_generation,
        task_id: compact_identity(b"task", config.key.continuity_unit.identity),
        task_generation: config
            .key
            .continuity_unit
            .generation
            .0
            .checked_add(1)
            .ok_or(EffectPeerError::InvalidRequest)?,
        credit_class: 1,
        credit_limit: 1_000_000,
    })
}

fn registered_to_committed(
    existing: &ReferenceEffectRecord,
    proposed: &ReferenceEffectRecord,
    thawed: bool,
) -> bool {
    thawed
        && existing.classification == JointEffectClassification::Registered
        && proposed.classification == JointEffectClassification::Committed
        && existing.effect == proposed.effect
        && existing.operation == proposed.operation
        && existing.domain == proposed.domain
        && existing.binding_generation == proposed.binding_generation
}

fn expect_payload(
    receipt: NativeReceipt,
    kind: NativeReceiptKind,
) -> Result<NativeReceipt, EffectPeerError> {
    if receipt.kind == kind {
        Ok(receipt)
    } else {
        Err(rejected("native operation returned the wrong receipt kind"))
    }
}

fn conformance_key(
    key: joint_handoff_core::JointHandoffKey,
) -> Result<visa_conformance::JointHandoffKey, EffectPeerError> {
    let value = serde_json::to_value(key).map_err(|_| EffectPeerError::Integrity)?;
    serde_json::from_value(value).map_err(|_| EffectPeerError::Integrity)
}

fn read_response_line(reader: &mut BufReader<ChildStdout>) -> Result<Vec<u8>, EffectPeerError> {
    let mut raw = Vec::new();
    let read = reader.read_until(b'\n', &mut raw).map_err(transport)?;
    if read == 0 {
        return Err(transport("nexus-effect-peer closed stdout"));
    }
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(rejected("native response exceeded the bounded line size"));
    }
    Ok(raw)
}

pub(crate) fn compact_identity(domain: &[u8], identity: Identity) -> u64 {
    let mut digest = Sha256::new();
    digest.update(b"vISA nexus effect peer identity v1");
    digest.update(domain);
    digest.update(identity.0);
    nonzero_u64(digest.finalize().as_slice())
}

pub(crate) fn compact_digest(domain: &[u8], value: Digest) -> u64 {
    let mut digest = Sha256::new();
    digest.update(b"vISA nexus effect peer digest v1");
    digest.update(domain);
    digest.update(value.0);
    nonzero_u64(digest.finalize().as_slice())
}

fn nonzero_u64(bytes: &[u8]) -> u64 {
    let value = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    if value == 0 { 1 } else { value }
}

pub(crate) fn mapped_u64_digest(domain: &[u8], value: u64) -> Digest {
    let mut digest = Sha256::new();
    digest.update(b"vISA mapped Nexus native u64 v1");
    digest.update(domain);
    digest.update(value.to_be_bytes());
    Digest::from_bytes(digest.finalize().into())
}

pub(crate) fn mapped_native_digest(domain: &[u8], value: &impl Serialize) -> Digest {
    let mut digest = Sha256::new();
    digest.update(b"vISA mapped Nexus native payload v1");
    digest.update(domain);
    digest.update(serde_json::to_vec(value).unwrap_or_default());
    Digest::from_bytes(digest.finalize().into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn rejected(detail: &'static str) -> EffectPeerError {
    EffectPeerError::NativeReceiptRejected(detail)
}

fn transport(error: impl std::fmt::Display) -> EffectPeerError {
    EffectPeerError::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    use contract_core::{EntityRef, Generation, LeaseEpoch, NodeIdentity};
    use joint_handoff_core::{JointHandoffKey, ReceiptIssuerIdentity};
    use visa_conformance::{JointEffectClassification, JointEffectRecord};

    use super::*;
    use crate::{
        OwnershipAbortRequest, OwnershipReserveRequest, ReferenceOwnershipLog,
        effect_receipt_issuer, ownership_receipt_issuer,
    };

    fn receipt(sequence: u64, request: &[u8], previous: Option<&str>) -> NativeReceipt {
        let payload = NativeReceiptPayload::Shutdown;
        let request_sha256 = sha256_hex(request);
        let payload_sha256 = sha256_hex(&serde_json::to_vec(&payload).unwrap());
        let input = ReceiptDigestInput {
            schema: RECEIPT_SCHEMA,
            sequence,
            kind: NativeReceiptKind::Shutdown,
            request_sha256: &request_sha256,
            previous_receipt_sha256: previous,
            payload_sha256: &payload_sha256,
            authentication_boundary: AUTHENTICATION_BOUNDARY,
            payload: &payload,
        };
        let receipt_sha256 = sha256_hex(&serde_json::to_vec(&input).unwrap());
        NativeReceipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            sequence,
            kind: NativeReceiptKind::Shutdown,
            request_sha256,
            previous_receipt_sha256: previous.map(str::to_owned),
            payload_sha256,
            authentication_boundary: AUTHENTICATION_BOUNDARY.to_owned(),
            payload,
            receipt_sha256,
        }
    }

    fn rejected_result(result: Result<(), EffectPeerError>) {
        assert!(matches!(result, Err(EffectPeerError::NativeReceiptRejected(_))));
    }

    fn exchange_with_shutdown_receipt(request: PeerRequest) -> NativeJsonlExchange {
        let request_bytes = serde_json::to_vec(&request).unwrap();
        let receipt = receipt(1, &request_bytes, None);
        let response = PeerResponse {
            schema: RESPONSE_SCHEMA.to_owned(),
            request_id: request.request_id,
            status: ResponseStatus::Ok,
            receipt: Some(receipt.clone()),
            error: None,
        };
        NativeJsonlExchange {
            request_id: request.request_id,
            request_jsonl: format!("{}\n", String::from_utf8(request_bytes).unwrap()),
            response_jsonl: format!("{}\n", serde_json::to_string(&response).unwrap()),
            receipt_sequence: 1,
            receipt_kind: "shutdown".to_owned(),
            request_sha256: receipt.request_sha256.clone(),
            previous_receipt_sha256: None,
            receipt_sha256: receipt.receipt_sha256.clone(),
        }
    }

    fn shutdown_exchange() -> NativeJsonlExchange {
        exchange_with_shutdown_receipt(PeerRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: 1,
            command: PeerCommand::Shutdown,
        })
    }

    fn mutate_response(
        exchange: &mut NativeJsonlExchange,
        mutation: impl FnOnce(&mut PeerResponse),
    ) {
        let mut response: PeerResponse =
            serde_json::from_str(exchange.response_jsonl.strip_suffix('\n').unwrap()).unwrap();
        mutation(&mut response);
        exchange.response_jsonl = format!("{}\n", serde_json::to_string(&response).unwrap());
    }

    #[test]
    fn native_verifier_rejects_every_digest_chain_mutation() {
        let request = br#"{"schema":"request","request_id":1}"#;
        let valid = receipt(1, request, None);
        assert_eq!(verify_native_receipt(&valid, request, 0, None), Ok(()));

        let mut changed = valid.clone();
        changed.schema.push_str("-substituted");
        rejected_result(verify_native_receipt(&changed, request, 0, None));

        let mut changed = valid.clone();
        changed.sequence = 2;
        rejected_result(verify_native_receipt(&changed, request, 0, None));

        let mut changed = valid.clone();
        changed.kind = NativeReceiptKind::Initialized;
        rejected_result(verify_native_receipt(&changed, request, 0, None));

        let mut changed = valid.clone();
        changed.request_sha256 = "1".repeat(64);
        rejected_result(verify_native_receipt(&changed, request, 0, None));

        let mut changed = valid.clone();
        changed.previous_receipt_sha256 = Some("2".repeat(64));
        rejected_result(verify_native_receipt(&changed, request, 0, None));

        let mut changed = valid.clone();
        changed.payload_sha256 = "3".repeat(64);
        rejected_result(verify_native_receipt(&changed, request, 0, None));

        let mut changed = valid.clone();
        changed.authentication_boundary = "signature-claimed-without-proof".to_owned();
        rejected_result(verify_native_receipt(&changed, request, 0, None));

        let mut changed = valid;
        changed.receipt_sha256 = "4".repeat(64);
        rejected_result(verify_native_receipt(&changed, request, 0, None));
    }

    #[test]
    fn native_verifier_accepts_only_the_exact_next_parent() {
        let first_request = br#"{"request_id":1}"#;
        let first = receipt(1, first_request, None);
        assert_eq!(verify_native_receipt(&first, first_request, 0, None), Ok(()));

        let second_request = br#"{"request_id":2}"#;
        let second = receipt(2, second_request, Some(&first.receipt_sha256));
        assert_eq!(
            verify_native_receipt(
                &second,
                second_request,
                first.sequence,
                Some(&first.receipt_sha256),
            ),
            Ok(())
        );
        rejected_result(verify_native_receipt(
            &second,
            second_request,
            first.sequence,
            Some(&"5".repeat(64)),
        ));
        rejected_result(verify_native_receipt(
            &second,
            first_request,
            first.sequence,
            Some(&first.receipt_sha256),
        ));
    }

    #[test]
    fn native_jsonl_chain_binds_raw_bytes_and_every_metadata_field() {
        let valid = shutdown_exchange();
        assert_eq!(validate_native_jsonl_chain(std::slice::from_ref(&valid)), Ok(()));

        let mut changed = valid.clone();
        changed.receipt_kind = "initialized".to_owned();
        rejected_result(validate_native_jsonl_chain(&[changed]));

        let mut changed = valid.clone();
        changed.response_jsonl.push('\n');
        rejected_result(validate_native_jsonl_chain(&[changed]));

        let mut changed = valid;
        changed.receipt_sequence = 2;
        rejected_result(validate_native_jsonl_chain(&[changed]));
    }

    #[test]
    fn native_jsonl_chain_rejects_live_adapter_response_invariant_mutations() {
        let wrong_request_schema = exchange_with_shutdown_receipt(PeerRequest {
            schema: "substituted-request-schema".to_owned(),
            request_id: 1,
            command: PeerCommand::Shutdown,
        });
        rejected_result(validate_native_jsonl_chain(&[wrong_request_schema]));

        let mut wrong_response_schema = shutdown_exchange();
        mutate_response(&mut wrong_response_schema, |response| {
            response.schema = "substituted-response-schema".to_owned();
        });
        rejected_result(validate_native_jsonl_chain(&[wrong_response_schema]));

        let mut error_with_receipt = shutdown_exchange();
        mutate_response(&mut error_with_receipt, |response| {
            response.status = ResponseStatus::Error;
        });
        rejected_result(validate_native_jsonl_chain(&[error_with_receipt]));

        let mut success_with_error = shutdown_exchange();
        mutate_response(&mut success_with_error, |response| {
            response.error = Some(crate::nexus_effect_wire::NativeError {
                code: "impossible-success-error".to_owned(),
                detail: "success responses cannot retain native errors".to_owned(),
            });
        });
        rejected_result(validate_native_jsonl_chain(&[success_with_error]));

        let mut success_without_receipt = shutdown_exchange();
        mutate_response(&mut success_without_receipt, |response| {
            response.receipt = None;
        });
        rejected_result(validate_native_jsonl_chain(&[success_without_receipt]));
    }

    #[test]
    fn native_jsonl_chain_rejects_command_receipt_kind_mismatch() {
        let query_with_shutdown_receipt = exchange_with_shutdown_receipt(PeerRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: 1,
            command: PeerCommand::Query,
        });
        rejected_result(validate_native_jsonl_chain(&[query_with_shutdown_receipt]));
    }

    #[test]
    fn native_identity_and_digest_projections_are_domain_separated() {
        let identity = Identity::from_u128(9);
        assert_ne!(compact_identity(b"scope", identity), 0);
        assert_ne!(compact_identity(b"scope", identity), compact_identity(b"handoff", identity));
        assert_ne!(mapped_u64_digest(b"terminal", 7), mapped_u64_digest(b"cohort", 7));
    }

    #[test]
    #[ignore = "requires a separately built nexus-effect-peer binary"]
    fn real_nexus_process_replays_byte_identical_response_and_keeps_raw_chain() {
        let executable = std::env::var_os("NEXUS_EFFECT_PEER_BIN")
            .map(PathBuf::from)
            .expect("NEXUS_EFFECT_PEER_BIN must name the built Nexus peer");
        let executable_sha256 = std::env::var("NEXUS_EFFECT_PEER_SHA256")
            .expect("NEXUS_EFFECT_PEER_SHA256 must pin the exact executable");
        let nexus_revision = std::env::var("NEXUS_EFFECT_PEER_REVISION")
            .expect("NEXUS_EFFECT_PEER_REVISION must pin the Nexus source revision");
        let key = JointHandoffKey {
            continuity_unit: EntityRef {
                identity: Identity::from_u128(1),
                generation: Generation(1),
            },
            handoff: Identity::from_u128(2),
            source: NodeIdentity::new(Identity::from_u128(3)),
            destination: NodeIdentity::new(Identity::from_u128(4)),
            expected_epoch: LeaseEpoch(7),
            next_epoch: LeaseEpoch(8),
        };
        let issuer = |seed| ReceiptIssuerIdentity {
            issuer: Identity::from_u128(seed),
            issuer_incarnation: Identity::from_u128(seed + 1),
            key_id: Identity::from_u128(seed + 2),
            log_id: Identity::from_u128(seed + 3),
        };
        let config = EffectPeerConfig {
            key,
            issuer: issuer(10),
            ownership_issuer: issuer(20),
            registry_instance: Identity::from_u128(30),
            scope_id: Identity::from_u128(31),
            scope_generation: 1,
            authority_epoch: 1,
            freeze_generation: 1,
            domain_bindings_digest: Digest::from_bytes([1; 32]),
        };
        let peer = ProcessEffectPeer::spawn(
            ProcessEffectPeerLaunch::new(executable, executable_sha256, nexus_revision),
            config,
        )
        .unwrap();
        let raw = peer.native_raw_responses();
        assert_eq!(raw.len(), 1);
        assert!(raw[0].ends_with(b"\n"));
        assert_eq!(peer.replay_last_native_request().unwrap(), raw[0]);
        assert_eq!(peer.native_raw_responses(), raw);

        peer.shutdown().unwrap();
        let raw = peer.native_raw_responses();
        assert_eq!(raw.len(), 2);
        assert!(raw.iter().all(|line| line.ends_with(b"\n")));
    }

    #[test]
    #[ignore = "requires a separately built nexus-effect-peer binary"]
    fn real_nexus_process_preserves_registered_effect_across_abort() {
        let executable = std::env::var_os("NEXUS_EFFECT_PEER_BIN")
            .map(PathBuf::from)
            .expect("NEXUS_EFFECT_PEER_BIN must name the built Nexus peer");
        let launch = ProcessEffectPeerLaunch::new(
            executable,
            std::env::var("NEXUS_EFFECT_PEER_SHA256")
                .expect("NEXUS_EFFECT_PEER_SHA256 must pin the exact executable"),
            std::env::var("NEXUS_EFFECT_PEER_REVISION")
                .expect("NEXUS_EFFECT_PEER_REVISION must pin the Nexus source revision"),
        );
        let key = JointHandoffKey {
            continuity_unit: EntityRef {
                identity: Identity::from_u128(101),
                generation: Generation(1),
            },
            handoff: Identity::from_u128(102),
            source: NodeIdentity::new(Identity::from_u128(103)),
            destination: NodeIdentity::new(Identity::from_u128(104)),
            expected_epoch: LeaseEpoch(7),
            next_epoch: LeaseEpoch(8),
        };
        let issuer = |seed| ReceiptIssuerIdentity {
            issuer: Identity::from_u128(seed),
            issuer_incarnation: Identity::from_u128(seed + 1),
            key_id: Identity::from_u128(seed + 2),
            log_id: Identity::from_u128(seed + 3),
        };
        let ownership_namespace = issuer(200);
        let config = EffectPeerConfig {
            key,
            issuer: effect_receipt_issuer(issuer(300), key).unwrap(),
            ownership_issuer: ownership_receipt_issuer(ownership_namespace, key).unwrap(),
            registry_instance: Identity::from_u128(310),
            scope_id: Identity::from_u128(311),
            scope_generation: 1,
            authority_epoch: 5,
            freeze_generation: 1,
            domain_bindings_digest: Digest::from_bytes([4; 32]),
        };
        let peer = ProcessEffectPeer::spawn(launch, config).unwrap();
        let registered = JointEffectRecord {
            effect: Identity::from_u128(320),
            operation: Identity::from_u128(321),
            domain: Identity::from_u128(322),
            binding_generation: 1,
            classification: JointEffectClassification::Registered,
            outcome_digest: None,
            tombstone_digest: None,
        };
        let publication = |record| EffectPublicationRequest {
            key,
            registry_instance: config.registry_instance,
            scope_id: config.scope_id,
            scope_generation: config.scope_generation,
            source_epoch: key.expected_epoch,
            record,
        };
        assert_eq!(
            peer.publish(publication(registered.clone())).unwrap(),
            EffectPublicationResult::Published
        );

        let mut ownership = ReferenceOwnershipLog::open(":memory:", ownership_namespace).unwrap();
        ownership.initialize_unit(key.continuity_unit, key.source, key.expected_epoch).unwrap();
        let intent =
            ownership.reserve(OwnershipReserveRequest { key, expected_state_sequence: 0 }).unwrap();
        let frozen = peer
            .freeze(EffectFreezeRequest {
                key,
                intent: intent.clone(),
                registry_instance: config.registry_instance,
                scope_id: config.scope_id,
                scope_generation: config.scope_generation,
                authority_epoch: config.authority_epoch,
                freeze_generation: config.freeze_generation,
            })
            .unwrap();
        assert!(matches!(frozen.receipt.disposition, FreezeDisposition::Blocked { .. }));
        let abort = ownership
            .abort(OwnershipAbortRequest {
                key,
                reservation: intent.reservation,
                basis: intent.receipt_ref().unwrap(),
                expected_state_sequence: 1,
            })
            .unwrap();
        let thaw_request = EffectThawRequest { token: frozen.token, abort };
        let thaw = peer.thaw(thaw_request.clone()).unwrap();
        let raw_after_thaw = peer.native_raw_responses();
        assert_eq!(peer.thaw(thaw_request).unwrap(), thaw);
        assert_eq!(peer.native_raw_responses(), raw_after_thaw);

        let committed = JointEffectRecord {
            classification: JointEffectClassification::Committed,
            outcome_digest: Some(Digest::from_bytes([9; 32])),
            ..registered
        };
        assert_eq!(
            peer.publish(publication(committed.clone())).unwrap(),
            EffectPublicationResult::Published
        );
        let raw_after_commit = peer.native_raw_responses();
        assert_eq!(peer.publish(publication(committed)).unwrap(), EffectPublicationResult::Replay);
        assert_eq!(peer.native_raw_responses(), raw_after_commit);
        assert!(peer.query().unwrap().gate_open);
        peer.shutdown().unwrap();
    }
}
