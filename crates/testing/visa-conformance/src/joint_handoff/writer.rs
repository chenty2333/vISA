use std::collections::BTreeMap;

use contract_core::{
    Digest, EntityRef, IdempotencyKey, Identity, JournalPosition, LeaseEpoch, NodeIdentity,
};
use sha2::{Digest as _, Sha256};

use super::*;

const CASE_NAMESPACE_DOMAIN: &[u8] = b"vISA/joint-handoff/reference-case/v1\0";

#[derive(Clone)]
struct TraceBuilder {
    trace: JointRawTrace,
    current_issuers: JointIssuerSet,
    current_scope: EffectScopeVersion,
    domain_bindings_digest: Digest,
    sequences: BTreeMap<(Identity, Identity, Identity), u64>,
    effects: BTreeMap<Identity, JointEffectRecord>,
    intent: Option<ReceiptRef>,
    visa_freeze: Option<ReceiptRef>,
    nexus_freeze: Option<ReceiptRef>,
    destination_prepared: Option<ReceiptRef>,
    prepared: Option<ReceiptRef>,
    decision: Option<ReceiptRef>,
    thaw: Option<ReceiptRef>,
    closure: Option<ReceiptRef>,
    source_fence: Option<ReceiptRef>,
    reservation: Identity,
}

impl TraceBuilder {
    fn new(case_id: &str) -> Self {
        let key = JointHandoffKey {
            continuity_unit: EntityRef::initial(case_identity(case_id, b"continuity-unit")),
            handoff: case_identity(case_id, b"handoff"),
            source: NodeIdentity::new(case_identity(case_id, b"source")),
            destination: NodeIdentity::new(case_identity(case_id, b"destination")),
            expected_epoch: LeaseEpoch(1),
            next_epoch: LeaseEpoch(2),
        };
        let issuers = JointIssuerSet {
            ownership: case_issuer(case_id, b"ownership"),
            visa_source: case_issuer(case_id, b"visa-source"),
            visa_destination: case_issuer(case_id, b"visa-destination"),
            effect_closure: case_issuer(case_id, b"effect-closure"),
        };
        let scope = EffectScopeVersion {
            registry_instance: identity(60),
            scope_id: identity(61),
            scope_generation: 1,
            authority_epoch: 1,
            freeze_generation: 1,
        };
        let domain_bindings_digest = digest(62);
        let mapping = JointMappingManifest {
            version: JointProtocolVersion::V1,
            key,
            visa_operation_cohort_digest: digest(63),
            effect_scope: scope,
            effect_cohort_digest: digest(64),
            domain_bindings_manifest_digest: domain_bindings_digest,
            ownership_service: OwnershipVersion {
                service_id: issuers.ownership.issuer,
                service_incarnation: issuers.ownership.issuer_incarnation,
                log_sequence: 1,
            },
            protocol_revision: 1,
        };
        let prepared_input = JointPreparedInput {
            snapshot: SnapshotBinding {
                snapshot: identity(70),
                integrity: digest(71),
                body_digest: digest(72),
                source_journal_position: JournalPosition(1),
                component_digest: digest(73),
                profile_digest: digest(74),
            },
            destination_journal_position: JournalPosition(3),
            destination_state_digest: digest(75),
            prepared_destination_digest: digest(76),
            prepared_authorities_digest: digest(77),
            prepared_bindings_digest: digest(78),
            lease_commit_operation: identity(79),
            lease_commit_idempotency: IdempotencyKey::from_u128(80),
            lease_commit_request_digest: digest(81),
        };
        Self {
            trace: JointRawTrace {
                schema_version: JOINT_HANDOFF_RAW_TRACE_SCHEMA_VERSION.to_owned(),
                case_id: case_id.to_owned(),
                protocol_version: JointProtocolVersion::V1,
                key,
                issuers,
                initial_scope: scope,
                mapping,
                prepared_input,
                events: Vec::new(),
            },
            current_issuers: issuers,
            current_scope: scope,
            domain_bindings_digest,
            sequences: BTreeMap::new(),
            effects: BTreeMap::new(),
            intent: None,
            visa_freeze: None,
            nexus_freeze: None,
            destination_prepared: None,
            prepared: None,
            decision: None,
            thaw: None,
            closure: None,
            source_fence: None,
            reservation: case_identity(case_id, b"ownership-reservation"),
        }
    }

    fn push(&mut self, event: JointRawEventKind) {
        let index = u64::try_from(self.trace.events.len()).unwrap();
        self.trace.events.push(JointRawEvent { index, event });
    }

    fn issuer(&self, role: ReceiptIssuerRole) -> ReceiptIssuerIdentity {
        match role {
            ReceiptIssuerRole::Ownership => self.current_issuers.ownership,
            ReceiptIssuerRole::VisaSource => self.current_issuers.visa_source,
            ReceiptIssuerRole::VisaDestination => self.current_issuers.visa_destination,
            ReceiptIssuerRole::EffectClosure => self.current_issuers.effect_closure,
        }
    }

    fn next_header(
        &mut self,
        role: ReceiptIssuerRole,
        kind: ReceiptKind,
        previous_digest: Option<Digest>,
    ) -> ReceiptHeader {
        let issuer = self.issuer(role);
        let key = (issuer.issuer, issuer.issuer_incarnation, issuer.log_id);
        let sequence = self.sequences.entry(key).or_default();
        *sequence += 1;
        ReceiptHeader {
            version: JointProtocolVersion::V1,
            kind,
            issuer: issuer.issuer,
            issuer_incarnation: issuer.issuer_incarnation,
            key_id: issuer.key_id,
            log_id: issuer.log_id,
            sequence: *sequence,
            previous_digest,
        }
    }

    fn peek_header(
        &self,
        role: ReceiptIssuerRole,
        kind: ReceiptKind,
        previous_digest: Option<Digest>,
    ) -> ReceiptHeader {
        let issuer = self.issuer(role);
        let sequence = self
            .sequences
            .get(&(issuer.issuer, issuer.issuer_incarnation, issuer.log_id))
            .copied()
            .unwrap_or(0)
            + 1;
        ReceiptHeader {
            version: JointProtocolVersion::V1,
            kind,
            issuer: issuer.issuer,
            issuer_incarnation: issuer.issuer_incarnation,
            key_id: issuer.key_id,
            log_id: issuer.log_id,
            sequence,
            previous_digest,
        }
    }

    fn accept(&mut self, receipt: JointReceipt) -> ReceiptRef {
        let reference = joint_receipt_ref(&receipt).unwrap();
        let request = self.request_for(&receipt);
        let envelope = joint_receipt_envelope(&receipt, &request).unwrap();
        self.push(JointRawEventKind::ReceiptAccepted { request, envelope, receipt });
        reference
    }

    fn reject(&mut self, receipt: JointReceipt, rejection: OracleRejection) {
        let request = self.request_for(&receipt);
        let envelope = joint_receipt_envelope(&receipt, &request).unwrap();
        self.push(JointRawEventKind::ReceiptRejected {
            request,
            envelope,
            receipt,
            rejection,
            state_before_sha256: String::new(),
            state_after_sha256: String::new(),
        });
    }

    fn request_for(&self, receipt: &JointReceipt) -> ReceiptRequest {
        joint_receipt_request(
            receipt,
            request_operation_identity(&self.trace.case_id, receipt.header()),
        )
    }

    fn prepare_intent(&mut self) -> JointReceipt {
        let ownership = self.current_issuers.ownership;
        let receipt = JointReceipt::PrepareIntent(PrepareIntentReceipt {
            header: self.next_header(
                ReceiptIssuerRole::Ownership,
                ReceiptKind::PrepareIntent,
                None,
            ),
            key: self.trace.key,
            ownership_service: ownership.issuer,
            service_incarnation: ownership.issuer_incarnation,
            reservation: self.reservation,
            intent_revision: 1,
            request_digest: digest(90),
        });
        self.intent = Some(self.accept(receipt.clone()));
        receipt
    }

    fn visa_freeze(&mut self) -> JointReceipt {
        let intent = self.intent.unwrap();
        let receipt = JointReceipt::VisaFreeze(VisaFreezeReceipt {
            header: self.next_header(ReceiptIssuerRole::VisaSource, ReceiptKind::VisaFreeze, None),
            key: self.trace.key,
            intent,
            journal_position: JournalPosition(1),
            state_digest: digest(91),
            portable_state_digest: digest(92),
        });
        self.visa_freeze = Some(self.accept(receipt.clone()));
        receipt
    }

    fn effect(
        &mut self,
        record: JointEffectRecord,
        accepted: bool,
        rejection: Option<OracleRejection>,
    ) {
        self.push(JointRawEventKind::EffectPublication {
            source_epoch: self.trace.key.expected_epoch,
            scope_generation: self.current_scope.scope_generation,
            record: record.clone(),
            accepted,
            rejection,
        });
        if accepted {
            self.effects.insert(record.effect, record);
        }
    }

    fn nexus_freeze(&mut self, blocked: bool) -> JointReceipt {
        let intent = self.intent.unwrap();
        let effects: Vec<_> = self.effects.values().cloned().collect();
        let cohort = joint_effect_cohort_digest(self.trace.key, effects.clone()).unwrap();
        let classification = joint_classification_root(self.trace.key, effects.clone()).unwrap();
        let disposition = if blocked {
            FreezeDisposition::Blocked { blocker_digest: classification }
        } else {
            FreezeDisposition::ReadyToCommit
        };
        let receipt = JointReceipt::EffectFreeze(EffectFreezeReceipt {
            header: self.next_header(
                ReceiptIssuerRole::EffectClosure,
                ReceiptKind::NexusFreeze,
                None,
            ),
            key: self.trace.key,
            intent,
            registry_instance: self.current_scope.registry_instance,
            scope_id: self.current_scope.scope_id,
            scope_generation: self.current_scope.scope_generation,
            authority_epoch: self.current_scope.authority_epoch,
            freeze_generation: self.current_scope.freeze_generation,
            domain_bindings_digest: self.domain_bindings_digest,
            effect_cohort_digest: cohort,
            classification_root: classification,
            counts: joint_classification_counts(effects),
            disposition,
        });
        self.nexus_freeze = Some(self.accept(receipt.clone()));
        self.refresh_mapping();
        receipt
    }

    fn destination_prepared_candidate(&self) -> JointReceipt {
        let input = &self.trace.prepared_input;
        let nexus = self.nexus_freeze.unwrap();
        JointReceipt::DestinationPrepared(Box::new(DestinationPreparedReceipt {
            header: self.peek_header(
                ReceiptIssuerRole::VisaDestination,
                ReceiptKind::DestinationPrepared,
                None,
            ),
            key: self.trace.key,
            intent: self.intent.unwrap(),
            visa_freeze: self.visa_freeze.unwrap(),
            nexus_freeze: nexus,
            snapshot: input.snapshot,
            journal_position: input.destination_journal_position,
            state_digest: input.destination_state_digest,
            prepared_destination_digest: input.prepared_destination_digest,
            authorities_digest: input.prepared_authorities_digest,
            bindings_digest: input.prepared_bindings_digest,
            joint_mapping_manifest_digest: joint_mapping_digest(&self.trace.mapping).unwrap(),
            lease_commit_operation: input.lease_commit_operation,
            lease_commit_idempotency: input.lease_commit_idempotency,
            lease_commit_request_digest: input.lease_commit_request_digest,
        }))
    }

    fn destination_prepared(&mut self) -> JointReceipt {
        let mut receipt = self.destination_prepared_candidate();
        receipt_header_mut(&mut receipt).sequence =
            self.consume_peeked_sequence(ReceiptIssuerRole::VisaDestination);
        self.destination_prepared = Some(self.accept(receipt.clone()));
        receipt
    }

    fn consume_peeked_sequence(&mut self, role: ReceiptIssuerRole) -> u64 {
        let issuer = self.issuer(role);
        let entry = self
            .sequences
            .entry((issuer.issuer, issuer.issuer_incarnation, issuer.log_id))
            .or_default();
        *entry += 1;
        *entry
    }

    fn ownership_prepared_candidate(&self) -> JointReceipt {
        JointReceipt::OwnershipPrepared(Box::new(OwnershipPreparedReceipt {
            header: self.peek_header(
                ReceiptIssuerRole::Ownership,
                ReceiptKind::OwnershipPrepared,
                Some(self.intent.unwrap().digest),
            ),
            key: self.trace.key,
            reservation: self.reservation,
            intent: self.intent.unwrap(),
            visa_freeze: self.visa_freeze.unwrap(),
            nexus_freeze: self.nexus_freeze.unwrap(),
            destination_prepared: self.destination_prepared.unwrap(),
            bindings: self.prepared_bindings(),
            prepared_revision: 2,
        }))
    }

    fn prepared_bindings(&self) -> PreparedBindings {
        let input = &self.trace.prepared_input;
        PreparedBindings {
            prepare_intent_receipt_digest: self.intent.unwrap().digest,
            visa_freeze_receipt_digest: self.visa_freeze.unwrap().digest,
            effect_freeze_receipt_digest: self.nexus_freeze.unwrap().digest,
            snapshot: input.snapshot.snapshot,
            snapshot_integrity_digest: input.snapshot.integrity,
            source_journal_position: JournalPosition(1),
            source_state_digest: digest(91),
            component_digest: input.snapshot.component_digest,
            profile_digest: input.snapshot.profile_digest,
            destination_prepared_receipt_digest: self.destination_prepared.unwrap().digest,
            destination_state_digest: input.destination_state_digest,
            prepared_authorities_digest: input.prepared_authorities_digest,
            prepared_bindings_digest: input.prepared_bindings_digest,
            effect_cohort_manifest_digest: joint_effect_cohort_digest(
                self.trace.key,
                self.effects.values().cloned(),
            )
            .unwrap(),
            joint_mapping_manifest_digest: joint_mapping_digest(&self.trace.mapping).unwrap(),
        }
    }

    fn ownership_prepared(&mut self) -> JointReceipt {
        self.refresh_mapping();
        let mut receipt = self.ownership_prepared_candidate();
        receipt_header_mut(&mut receipt).sequence =
            self.consume_peeked_sequence(ReceiptIssuerRole::Ownership);
        self.prepared = Some(self.accept(receipt.clone()));
        receipt
    }

    fn commit_candidate(&self) -> JointReceipt {
        let header = self.peek_header(
            ReceiptIssuerRole::Ownership,
            ReceiptKind::OwnershipCommit,
            Some(self.prepared.unwrap().digest),
        );
        JointReceipt::OwnershipCommit(OwnershipCommitReceipt {
            header,
            key: self.trace.key,
            reservation: self.reservation,
            prepared: self.prepared.unwrap(),
            prepared_revision: 2,
            decision_sequence: header.sequence,
            non_equivocation_root: digest(93),
        })
    }

    fn commit(&mut self) -> JointReceipt {
        let mut receipt = self.commit_candidate();
        let sequence = self.consume_peeked_sequence(ReceiptIssuerRole::Ownership);
        set_decision_sequence(&mut receipt, sequence);
        self.decision = Some(self.accept(receipt.clone()));
        receipt
    }

    fn durable_commit_loses_ack(&mut self) -> OwnershipCommitObservation {
        let JointReceipt::OwnershipCommit(receipt) = self.commit_candidate() else {
            unreachable!()
        };
        let typed = JointReceipt::OwnershipCommit(receipt.clone());
        let request = self.request_for(&typed);
        let observation = OwnershipCommitObservation {
            envelope: joint_receipt_envelope(&typed, &request).unwrap(),
            request,
            receipt,
        };
        self.fault(JointExternalFault::CommitAcknowledgementLost {
            durable_commit: Box::new(observation.clone()),
        });
        observation
    }

    fn recover_durable_commit(&mut self, observation: OwnershipCommitObservation) {
        self.push(JointRawEventKind::OwnershipQuery {
            result: OwnershipQueryResult::CommitDecided { observation: observation.clone() },
        });
        let sequence = self.consume_peeked_sequence(ReceiptIssuerRole::Ownership);
        assert_eq!(sequence, observation.receipt.header.sequence);
        let receipt = JointReceipt::OwnershipCommit(observation.receipt);
        self.decision = Some(self.accept(receipt));
    }

    fn abort_via_query(&mut self) -> JointReceipt {
        let JointReceipt::OwnershipAbort(receipt) = self.abort_candidate() else { unreachable!() };
        let typed = JointReceipt::OwnershipAbort(receipt.clone());
        let request = self.request_for(&typed);
        let observation = OwnershipAbortObservation {
            envelope: joint_receipt_envelope(&typed, &request).unwrap(),
            request,
            receipt,
        };
        self.push(JointRawEventKind::OwnershipQuery {
            result: OwnershipQueryResult::AbortDecided { observation: observation.clone() },
        });
        let sequence = self.consume_peeked_sequence(ReceiptIssuerRole::Ownership);
        assert_eq!(sequence, observation.receipt.header.sequence);
        let receipt = JointReceipt::OwnershipAbort(observation.receipt);
        self.decision = Some(self.accept(receipt.clone()));
        receipt
    }

    fn abort_candidate(&self) -> JointReceipt {
        let (basis, revision) = self.prepared.map_or((self.intent.unwrap(), 1), |value| (value, 2));
        let header = self.peek_header(
            ReceiptIssuerRole::Ownership,
            ReceiptKind::OwnershipAbort,
            Some(basis.digest),
        );
        JointReceipt::OwnershipAbort(OwnershipAbortReceipt {
            header,
            key: self.trace.key,
            reservation: self.reservation,
            basis,
            basis_revision: revision,
            decision_sequence: header.sequence,
            non_equivocation_root: digest(94),
        })
    }

    fn abort(&mut self) -> JointReceipt {
        let mut receipt = self.abort_candidate();
        let sequence = self.consume_peeked_sequence(ReceiptIssuerRole::Ownership);
        set_decision_sequence(&mut receipt, sequence);
        self.decision = Some(self.accept(receipt.clone()));
        receipt
    }

    fn thaw(&mut self) -> JointReceipt {
        let abort = self.decision.unwrap();
        let receipt = JointReceipt::EffectThaw(EffectThawReceipt {
            header: self.next_header(
                ReceiptIssuerRole::EffectClosure,
                ReceiptKind::NexusThaw,
                Some(self.nexus_freeze.unwrap().digest),
            ),
            key: self.trace.key,
            abort,
            nexus_freeze: self.nexus_freeze.unwrap(),
            thaw_generation: self.current_scope.freeze_generation + 1,
        });
        self.thaw = Some(self.accept(receipt.clone()));
        receipt
    }

    fn source_resume(&mut self) -> JointReceipt {
        let thaw = self.thaw.unwrap();
        let receipt = JointReceipt::VisaSourceResume(VisaSourceResumeReceipt {
            header: self.next_header(
                ReceiptIssuerRole::VisaSource,
                ReceiptKind::VisaSourceResume,
                Some(self.visa_freeze.unwrap().digest),
            ),
            key: self.trace.key,
            abort: self.decision.unwrap(),
            thaw: Some(thaw),
            journal_position: JournalPosition(4),
            state_digest: digest(95),
        });
        self.accept(receipt.clone());
        receipt
    }

    fn closure(&mut self) -> JointReceipt {
        let commit = self.decision.unwrap();
        let cohort =
            joint_effect_cohort_digest(self.trace.key, self.effects.values().cloned()).unwrap();
        let receipt = JointReceipt::Closure(ClosureReceipt {
            header: self.next_header(
                ReceiptIssuerRole::EffectClosure,
                ReceiptKind::Closure,
                Some(self.nexus_freeze.unwrap().digest),
            ),
            key: self.trace.key,
            commit,
            nexus_freeze: self.nexus_freeze.unwrap(),
            closure_revision: 1,
            effect_manifest_digest: cohort,
            closed_authority_epoch: self.current_scope.authority_epoch,
        });
        self.closure = Some(self.accept(receipt.clone()));
        receipt
    }

    fn source_fence(&mut self) -> JointReceipt {
        let closure = self.closure.unwrap();
        let receipt = JointReceipt::VisaSourceFence(VisaSourceFenceReceipt {
            header: self.next_header(
                ReceiptIssuerRole::VisaSource,
                ReceiptKind::VisaSourceFence,
                Some(self.visa_freeze.unwrap().digest),
            ),
            key: self.trace.key,
            commit: self.decision.unwrap(),
            closure,
            journal_position: JournalPosition(5),
            state_digest: digest(96),
        });
        self.source_fence = Some(self.accept(receipt.clone()));
        receipt
    }

    fn activate(&mut self) -> JointReceipt {
        let commit = self.decision.unwrap();
        let closure = self.closure.unwrap();
        let source_fence = self.source_fence.unwrap();
        let activation_command =
            case_identity(&self.trace.case_id, b"destination-activation-command");
        let resume_command = case_identity(&self.trace.case_id, b"destination-resume-command");
        self.push(JointRawEventKind::DestinationActivationStarted {
            commit,
            closure,
            activation_command,
        });
        let receipt = JointReceipt::VisaDestinationActivation(VisaDestinationActivationReceipt {
            header: self.next_header(
                ReceiptIssuerRole::VisaDestination,
                ReceiptKind::VisaDestinationActivation,
                Some(self.destination_prepared.unwrap().digest),
            ),
            key: self.trace.key,
            commit,
            closure,
            source_fence,
            activation_command,
            resume_command,
            activation_attempt_record_digest: digest(98),
            journal_position: JournalPosition(6),
            state_digest: digest(97),
        });
        self.accept(receipt.clone());
        receipt
    }

    fn full_commit_prefix(&mut self, effect: Option<JointEffectRecord>) {
        self.prepare_intent();
        if let Some(effect) = effect {
            self.effect(effect, true, None);
        }
        self.visa_freeze();
        self.nexus_freeze(false);
        self.destination_prepared();
        self.ownership_prepared();
    }

    fn finish_commit(&mut self) {
        self.commit();
        self.closure();
        self.source_fence();
        self.activate();
    }

    fn finish_abort(&mut self) {
        self.abort();
        self.thaw();
        self.source_resume();
    }

    fn fault(&mut self, fault: JointExternalFault) {
        self.push(JointRawEventKind::ExternalFault {
            fault,
            state_before_sha256: String::new(),
            state_after_sha256: String::new(),
        });
    }

    fn crash(&mut self, actor: JointActor) {
        self.push(JointRawEventKind::ActorCrashed { actor });
    }

    fn restart(&mut self, actor: JointActor) {
        self.push(JointRawEventKind::ActorRestarted { actor });
    }

    fn rebind_nexus(&mut self) -> (ReceiptIssuerIdentity, EffectScopeVersion) {
        let previous = self.current_issuers.effect_closure;
        let previous_scope = self.current_scope;
        // A service binding may be recreated inside one handoff, but the
        // pinned native signer and its log namespace do not change mid-flight.
        let current = previous;
        let current_scope = EffectScopeVersion {
            registry_instance: case_identity(&self.trace.case_id, b"effect-rebind-registry"),
            scope_id: previous_scope.scope_id,
            scope_generation: previous_scope.scope_generation + 1,
            authority_epoch: previous_scope.authority_epoch,
            freeze_generation: previous_scope.freeze_generation + 1,
        };
        self.domain_bindings_digest = digest(161);
        self.push(JointRawEventKind::NexusServiceRebound {
            previous,
            current,
            previous_scope,
            current_scope,
            domain_bindings_manifest_digest: self.domain_bindings_digest,
        });
        self.current_issuers.effect_closure = current;
        self.current_scope = current_scope;
        self.refresh_mapping();
        (previous, previous_scope)
    }

    fn refresh_mapping(&mut self) {
        self.trace.mapping.effect_scope = self.current_scope;
        self.trace.mapping.effect_cohort_digest =
            joint_effect_cohort_digest(self.trace.key, self.effects.values().cloned()).unwrap();
        self.trace.mapping.domain_bindings_manifest_digest = self.domain_bindings_digest;
    }

    fn finish(mut self) -> JointRawTrace {
        self.refresh_mapping();
        annotate_joint_trace_observations(&mut self.trace)
            .expect("reference trace observations are derived by the independent oracle");
        self.trace
    }
}

fn receipt_header_mut(receipt: &mut JointReceipt) -> &mut ReceiptHeader {
    match receipt {
        JointReceipt::PrepareIntent(value) => &mut value.header,
        JointReceipt::VisaFreeze(value) => &mut value.header,
        JointReceipt::EffectFreeze(value) => &mut value.header,
        JointReceipt::DestinationPrepared(value) => &mut value.header,
        JointReceipt::OwnershipPrepared(value) => &mut value.header,
        JointReceipt::OwnershipAbort(value) => &mut value.header,
        JointReceipt::OwnershipCommit(value) => &mut value.header,
        JointReceipt::EffectThaw(value) => &mut value.header,
        JointReceipt::ClosureProgress(value) => &mut value.header,
        JointReceipt::Closure(value) => &mut value.header,
        JointReceipt::RetainedTombstone(value) => &mut value.header,
        JointReceipt::VisaSourceFence(value) => &mut value.header,
        JointReceipt::VisaSourceResume(value) => &mut value.header,
        JointReceipt::VisaDestinationActivation(value) => &mut value.header,
    }
}

fn set_decision_sequence(receipt: &mut JointReceipt, sequence: u64) {
    let header = receipt_header_mut(receipt);
    header.sequence = sequence;
    match receipt {
        JointReceipt::OwnershipAbort(value) => value.decision_sequence = sequence,
        JointReceipt::OwnershipCommit(value) => value.decision_sequence = sequence,
        _ => unreachable!(),
    }
}

fn identity(value: u128) -> Identity {
    Identity::from_u128(value)
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}

fn case_issuer(case_id: &str, role: &[u8]) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: case_identity_with_suffix(case_id, role, b"issuer"),
        issuer_incarnation: case_identity_with_suffix(case_id, role, b"incarnation"),
        key_id: case_identity_with_suffix(case_id, role, b"key"),
        log_id: case_identity_with_suffix(case_id, role, b"log"),
    }
}

fn case_identity(case_id: &str, label: &[u8]) -> Identity {
    case_identity_with_suffix(case_id, label, b"identity")
}

fn request_operation_identity(case_id: &str, header: &ReceiptHeader) -> Identity {
    let mut suffix = Vec::with_capacity(16 + 16 + 8 + 1);
    suffix.extend_from_slice(&header.issuer.0);
    suffix.extend_from_slice(&header.log_id.0);
    suffix.extend_from_slice(&header.sequence.to_be_bytes());
    suffix.push(header.kind as u8);
    case_identity_with_suffix(case_id, b"receipt-request-operation", &suffix)
}

fn case_identity_with_suffix(case_id: &str, label: &[u8], suffix: &[u8]) -> Identity {
    let mut hasher = Sha256::new();
    hasher.update(CASE_NAMESPACE_DOMAIN);
    hasher.update((case_id.len() as u64).to_be_bytes());
    hasher.update(case_id.as_bytes());
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update((suffix.len() as u64).to_be_bytes());
    hasher.update(suffix);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    if bytes == [0; 16] {
        bytes[15] = 1;
    }
    Identity::from_bytes(bytes)
}

fn committed_effect(value: u128, binding_generation: u64) -> JointEffectRecord {
    JointEffectRecord {
        effect: identity(value),
        operation: identity(value + 1),
        domain: identity(value + 2),
        binding_generation,
        classification: JointEffectClassification::Committed,
        outcome_digest: Some(digest(u8::try_from(value).unwrap_or(200))),
        tombstone_digest: None,
    }
}

fn registered_effect(value: u128, binding_generation: u64) -> JointEffectRecord {
    JointEffectRecord {
        effect: identity(value),
        operation: identity(value + 1),
        domain: identity(value + 2),
        binding_generation,
        classification: JointEffectClassification::Registered,
        outcome_digest: None,
        tombstone_digest: None,
    }
}

fn unresolved_effect(value: u128, binding_generation: u64) -> JointEffectRecord {
    JointEffectRecord {
        effect: identity(value),
        operation: identity(value + 1),
        domain: identity(value + 2),
        binding_generation,
        classification: JointEffectClassification::UnresolvedTombstone,
        outcome_digest: None,
        tombstone_digest: Some(digest(201)),
    }
}

fn trace_for(case_id: &str) -> JointRawTrace {
    let mut builder = TraceBuilder::new(case_id);
    match case_id {
        "freeze-wins-effect-commit" => {
            builder.prepare_intent();
            builder.visa_freeze();
            builder.nexus_freeze(false);
            let effect = committed_effect(100, builder.current_scope.scope_generation);
            builder.effect(effect, false, Some(OracleRejection::EffectGateClosed));
            builder.destination_prepared();
            builder.ownership_prepared();
            builder.finish_commit();
        }
        "effect-commit-wins-freeze" => {
            let generation = builder.current_scope.scope_generation;
            builder.full_commit_prefix(Some(committed_effect(100, generation)));
            builder.finish_commit();
        }
        "destination-prepare-fails-abort-thaw" => {
            builder.prepare_intent();
            builder.visa_freeze();
            builder.nexus_freeze(false);
            builder.fault(JointExternalFault::DestinationPreparationFailed);
            builder.finish_abort();
        }
        "commit-ack-lost-query-close" => {
            builder.full_commit_prefix(None);
            let durable_commit = builder.durable_commit_loses_ack();
            builder.push(JointRawEventKind::OwnershipQuery {
                result: OwnershipQueryResult::Unavailable,
            });
            builder.recover_durable_commit(durable_commit);
            builder.closure();
            builder.source_fence();
            builder.activate();
        }
        "frozen-service-crash-rebind" => {
            builder.prepare_intent();
            builder.visa_freeze();
            let old_issuer = builder.current_issuers.effect_closure;
            let old_scope = builder.current_scope;
            builder.crash(JointActor::NexusService);
            builder.rebind_nexus();
            let mut stale = builder.nexus_freeze_candidate(old_issuer, old_scope, false);
            receipt_header_mut(&mut stale).sequence = 1;
            builder.reject(stale, OracleRejection::StaleScope);
            builder.nexus_freeze(false);
            builder.destination_prepared();
            builder.ownership_prepared();
            builder.finish_commit();
        }
        "unresolved-tombstone-blocks-seal" => {
            builder.prepare_intent();
            let effect = unresolved_effect(110, builder.current_scope.scope_generation);
            builder.effect(effect, true, None);
            builder.visa_freeze();
            builder.nexus_freeze(true);
            let candidate = builder.blocked_prepared_candidate();
            builder.reject(candidate, OracleRejection::ClosureBlocked);
        }
        "stale-token-scope-epoch-probes" => {
            builder.prepare_intent();
            builder.visa_freeze();
            let mut stale_generation = builder.nexus_freeze_candidate(
                builder.current_issuers.effect_closure,
                builder.current_scope,
                false,
            );
            if let JointReceipt::EffectFreeze(value) = &mut stale_generation {
                value.freeze_generation += 1;
            }
            builder.reject(stale_generation, OracleRejection::StaleFreezeGeneration);

            let mut stale_scope = builder.nexus_freeze_candidate(
                builder.current_issuers.effect_closure,
                builder.current_scope,
                false,
            );
            if let JointReceipt::EffectFreeze(value) = &mut stale_scope {
                value.scope_id = identity(220);
            }
            builder.reject(stale_scope, OracleRejection::StaleScope);

            let mut stale_epoch = builder.nexus_freeze_candidate(
                builder.current_issuers.effect_closure,
                builder.current_scope,
                false,
            );
            if let JointReceipt::EffectFreeze(value) = &mut stale_epoch {
                value.key.expected_epoch = LeaseEpoch(2);
                value.key.next_epoch = LeaseEpoch(3);
            }
            builder.reject(stale_epoch, OracleRejection::StaleEpoch);

            let mut stale_registry = builder.nexus_freeze_candidate(
                builder.current_issuers.effect_closure,
                builder.current_scope,
                false,
            );
            if let JointReceipt::EffectFreeze(value) = &mut stale_registry {
                value.registry_instance = identity(221);
            }
            builder.reject(stale_registry, OracleRejection::StaleScope);

            let mut wrong_handoff = builder.nexus_freeze_candidate(
                builder.current_issuers.effect_closure,
                builder.current_scope,
                false,
            );
            if let JointReceipt::EffectFreeze(value) = &mut wrong_handoff {
                value.key.handoff = identity(222);
            }
            builder.reject(wrong_handoff, OracleRejection::HandoffMismatch);
            builder.nexus_freeze(false);
            builder.finish_abort();
        }
        "abort-commit-race-abort-wins" => {
            builder.full_commit_prefix(None);
            builder.abort();
            let commit = builder.commit_candidate();
            builder.reject(commit, OracleRejection::DecisionConflict);
            builder.thaw();
            builder.source_resume();
        }
        "abort-commit-race-commit-wins" => {
            builder.full_commit_prefix(None);
            builder.commit();
            let abort = builder.abort_candidate();
            builder.reject(abort, OracleRejection::DecisionConflict);
            builder.closure();
            builder.source_fence();
            builder.activate();
        }
        "source-crash-after-commit-before-close" => {
            builder.full_commit_prefix(None);
            builder.commit();
            builder.crash(JointActor::Source);
            builder.restart(JointActor::Source);
            builder.closure();
            builder.source_fence();
            builder.activate();
        }
        "destination-crash-before-activation" => {
            builder.full_commit_prefix(None);
            builder.commit();
            builder.closure();
            builder.source_fence();
            builder.crash(JointActor::Destination);
            builder.restart(JointActor::Destination);
            builder.activate();
        }
        "concurrent-two-destinations" => {
            builder.prepare_intent();
            builder.visa_freeze();
            builder.nexus_freeze(false);
            let mut competing = builder.destination_prepared_candidate();
            if let JointReceipt::DestinationPrepared(value) = &mut competing {
                value.key.destination = NodeIdentity::new(identity(230));
            }
            builder.reject(competing, OracleRejection::CompetingDestination);
            builder.destination_prepared();
            builder.ownership_prepared();
            builder.finish_commit();
        }
        "crash-after-freeze-before-seal" => {
            builder.prepare_intent();
            builder.visa_freeze();
            builder.nexus_freeze(false);
            builder.crash(JointActor::Coordinator);
            builder.restart(JointActor::Coordinator);
            builder.finish_abort();
        }
        "stale-destination-prepared-receipt" => {
            builder.prepare_intent();
            builder.visa_freeze();
            builder.nexus_freeze(false);
            let mut stale = builder.destination_prepared_candidate();
            if let JointReceipt::DestinationPrepared(value) = &mut stale {
                value.snapshot.integrity = digest(231);
            }
            builder.reject(stale, OracleRejection::ReceiptMismatch);
            builder.finish_abort();
        }
        "duplicate-reordered-receipts" => {
            let reordered = builder.reordered_visa_freeze_candidate();
            builder.reject(reordered, OracleRejection::InvalidPhase);
            let intent = builder.prepare_intent();
            let request = builder.request_for(&intent);
            let envelope = joint_receipt_envelope(&intent, &request).unwrap();
            builder.push(JointRawEventKind::ReceiptAccepted { request, envelope, receipt: intent });
            builder.visa_freeze();
            builder.nexus_freeze(false);
            builder.destination_prepared();
            builder.ownership_prepared();
            let commit = builder.commit();
            let request = builder.request_for(&commit);
            let envelope = joint_receipt_envelope(&commit, &request).unwrap();
            builder.push(JointRawEventKind::ReceiptAccepted { request, envelope, receipt: commit });
            builder.closure();
            builder.source_fence();
            builder.activate();
        }
        "precommit-abort-preserves-uncommitted-effect" => {
            let generation = builder.current_scope.scope_generation;
            let registered = registered_effect(120, generation);
            builder.effect(registered, true, None);
            builder.prepare_intent();
            builder.visa_freeze();
            builder.nexus_freeze(true);
            builder.fault(JointExternalFault::DestinationPreparationFailed);
            builder.abort_via_query();
            builder.thaw();
            builder.source_resume();
            builder.effect(committed_effect(120, generation), true, None);
        }
        _ => panic!("unknown test case: {case_id}"),
    }
    builder.finish()
}

impl TraceBuilder {
    fn nexus_freeze_candidate(
        &self,
        issuer: ReceiptIssuerIdentity,
        scope: EffectScopeVersion,
        blocked: bool,
    ) -> JointReceipt {
        let effects: Vec<_> = self.effects.values().cloned().collect();
        let cohort = joint_effect_cohort_digest(self.trace.key, effects.clone()).unwrap();
        let classification = joint_classification_root(self.trace.key, effects.clone()).unwrap();
        JointReceipt::EffectFreeze(EffectFreezeReceipt {
            header: ReceiptHeader {
                version: JointProtocolVersion::V1,
                kind: ReceiptKind::NexusFreeze,
                issuer: issuer.issuer,
                issuer_incarnation: issuer.issuer_incarnation,
                key_id: issuer.key_id,
                log_id: issuer.log_id,
                sequence: self
                    .sequences
                    .get(&(issuer.issuer, issuer.issuer_incarnation, issuer.log_id))
                    .copied()
                    .unwrap_or(0)
                    + 1,
                previous_digest: None,
            },
            key: self.trace.key,
            intent: self.intent.unwrap(),
            registry_instance: scope.registry_instance,
            scope_id: scope.scope_id,
            scope_generation: scope.scope_generation,
            authority_epoch: scope.authority_epoch,
            freeze_generation: scope.freeze_generation,
            domain_bindings_digest: self.domain_bindings_digest,
            effect_cohort_digest: cohort,
            classification_root: classification,
            counts: joint_classification_counts(effects),
            disposition: if blocked {
                FreezeDisposition::Blocked { blocker_digest: classification }
            } else {
                FreezeDisposition::ReadyToCommit
            },
        })
    }

    fn blocked_prepared_candidate(&self) -> JointReceipt {
        let fake_destination = ReceiptRef {
            version: JointProtocolVersion::V1,
            kind: ReceiptKind::DestinationPrepared,
            handoff: self.trace.key.handoff,
            issuer: self.current_issuers.visa_destination.issuer,
            issuer_incarnation: self.current_issuers.visa_destination.issuer_incarnation,
            key_id: self.current_issuers.visa_destination.key_id,
            log_id: self.current_issuers.visa_destination.log_id,
            sequence: 1,
            digest: digest(240),
        };
        JointReceipt::OwnershipPrepared(Box::new(OwnershipPreparedReceipt {
            header: self.peek_header(
                ReceiptIssuerRole::Ownership,
                ReceiptKind::OwnershipPrepared,
                Some(self.intent.unwrap().digest),
            ),
            key: self.trace.key,
            reservation: self.reservation,
            intent: self.intent.unwrap(),
            visa_freeze: self.visa_freeze.unwrap(),
            nexus_freeze: self.nexus_freeze.unwrap(),
            destination_prepared: fake_destination,
            bindings: self.blocked_prepared_bindings(fake_destination),
            prepared_revision: 2,
        }))
    }

    fn blocked_prepared_bindings(&self, destination: ReceiptRef) -> PreparedBindings {
        let input = &self.trace.prepared_input;
        PreparedBindings {
            prepare_intent_receipt_digest: self.intent.unwrap().digest,
            visa_freeze_receipt_digest: self.visa_freeze.unwrap().digest,
            effect_freeze_receipt_digest: self.nexus_freeze.unwrap().digest,
            snapshot: input.snapshot.snapshot,
            snapshot_integrity_digest: input.snapshot.integrity,
            source_journal_position: JournalPosition(1),
            source_state_digest: digest(91),
            component_digest: input.snapshot.component_digest,
            profile_digest: input.snapshot.profile_digest,
            destination_prepared_receipt_digest: destination.digest,
            destination_state_digest: input.destination_state_digest,
            prepared_authorities_digest: input.prepared_authorities_digest,
            prepared_bindings_digest: input.prepared_bindings_digest,
            effect_cohort_manifest_digest: joint_effect_cohort_digest(
                self.trace.key,
                self.effects.values().cloned(),
            )
            .unwrap(),
            joint_mapping_manifest_digest: joint_mapping_digest(&self.trace.mapping).unwrap(),
        }
    }

    fn reordered_visa_freeze_candidate(&self) -> JointReceipt {
        let fake_intent = ReceiptRef {
            version: JointProtocolVersion::V1,
            kind: ReceiptKind::PrepareIntent,
            handoff: self.trace.key.handoff,
            issuer: self.current_issuers.ownership.issuer,
            issuer_incarnation: self.current_issuers.ownership.issuer_incarnation,
            key_id: self.current_issuers.ownership.key_id,
            log_id: self.current_issuers.ownership.log_id,
            sequence: 1,
            digest: digest(241),
        };
        JointReceipt::VisaFreeze(VisaFreezeReceipt {
            header: self.peek_header(ReceiptIssuerRole::VisaSource, ReceiptKind::VisaFreeze, None),
            key: self.trace.key,
            intent: fake_intent,
            journal_position: JournalPosition(1),
            state_digest: digest(242),
            portable_state_digest: digest(243),
        })
    }
}

pub fn build_reference_joint_evidence_bundle(
    expectations: &JointEvidenceExpectations,
) -> Result<JointEvidenceBundle, String> {
    let cases = JOINT_HANDOFF_CASE_DEFINITIONS
        .iter()
        .map(|definition| -> Result<JointCaseEvidence, String> {
            let trace = trace_for(definition.id);
            Ok(JointCaseEvidence {
                case_id: definition.id.to_owned(),
                trace_sha256: joint_raw_trace_sha256(&trace)?,
                claimed_terminal: definition.terminal,
                claimed_assertions: definition.required_assertions.to_vec(),
                trace,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(JointEvidenceBundle {
        schema_version: JOINT_HANDOFF_EVIDENCE_SCHEMA_VERSION.to_owned(),
        claim_id: JOINT_HANDOFF_CLAIM_ID.to_owned(),
        bundle_id: JOINT_UNPUBLISHED_BUNDLE_ID.to_owned(),
        source_lock_sha256: expectations.source_lock_sha256.clone(),
        neutral_tree: expectations.neutral_tree.clone(),
        neutral_bundle_sha256: expectations.neutral_bundle_sha256.clone(),
        registry_sha256: joint_handoff_registry_sha256(),
        protocol_schema_sha256: expectations.protocol_schema_sha256.clone(),
        machine_contract_sha256: expectations.machine_contract_sha256.clone(),
        refinement_map_sha256: expectations.refinement_map_sha256.clone(),
        abstract_registry_sha256: expectations.abstract_registry_sha256.clone(),
        visa: JointSourceRevision {
            repository: JOINT_VISA_REPOSITORY.to_owned(),
            git_sha: expectations.visa_git_sha.clone(),
            role: JointSourceRole::ExecutedCheckout,
            checkout_clean: Some(true),
        },
        nexus: JointSourceRevision {
            repository: JOINT_NEXUS_REPOSITORY.to_owned(),
            git_sha: expectations.nexus_git_sha.clone(),
            role: JointSourceRole::SourceLockOnly,
            checkout_clean: None,
        },
        neutral: JointSourceRevision {
            repository: JOINT_NEUTRAL_REPOSITORY.to_owned(),
            git_sha: expectations.neutral_git_sha.clone(),
            role: JointSourceRole::SourceLockOnly,
            checkout_clean: None,
        },
        tcb: JointTcbDeclaration {
            ownership_log_non_equivocating: true,
            ownership_log_not_rolled_back: true,
            native_receipt_verifiers_pinned: true,
            exclusive_trusted_coordinator_api: true,
            crash_stable_freeze_marker: true,
            fail_closed_recovery: true,
            same_boot_only: true,
            hostile_storage_rollback_covered: false,
            host_reboot_covered: false,
            confidential_transport_covered: false,
        },
        production_replay_sha256: None,
        cases,
    })
}
