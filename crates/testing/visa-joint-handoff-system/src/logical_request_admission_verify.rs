use contract_core::{
    ActivationRole, ActivationStatus, AuthorityGrant, AuthorityStatus, BindingReceipt,
    CONTRACT_VERSION, CanonicalState, Command, CommandKind, Decision, DeliveryPolicy, Digest,
    EffectKind, EffectOutcome, EffectRequest, EffectResult, EntityRef, Event, EventKind,
    EvidenceKind, EvidenceRef, ExtensionSupport, Generation, HandoffPhase, IdempotencyKey,
    Identity, JournalPosition, KeyValueClaim, LeaseEpoch, NodeIdentity, PreparedDestination,
    ProfileAccess, ResourceClaims, Rights, SchemaVersion, SnapshotEnvelope, SnapshotRecord,
    TimerClaim, TimerClock, TimerDisposition, canonical_digest, snapshot_integrity, state_digest,
};
use joint_handoff_core::{
    ClosureProgressReceipt, FreezeDisposition, ReceiptKind, ReceiptRequest, TypedReceipt,
    canonical_bytes as joint_bytes, canonical_from_bytes as joint_from_bytes,
};
use sha2::{Digest as _, Sha256};
use visa_component_adapter::{
    LogicalRequestComponentState, LogicalRequestWorkloadLifecycle, ProfileBinding, identity_string,
    prepare_profile_effect,
};
use visa_conformance::{
    JointEffectClassification, JointEffectRecord, joint_classification_root,
    joint_effect_cohort_digest,
};
use visa_joint_handoff::{
    DurableJointSession, JointProjectionAppendError, JointProjectionAppendOutcome,
    JointProjectionLog, JointProjectionLogHead, JointProjectionRecord, JointProjectionRecordKind,
    NativeReceiptRecord,
};
use visa_profile::{
    ContinuityDisposition, CooperativeHandoffProfile, LOGICAL_REQUEST_EXTENSION_ID,
    LOGICAL_REQUEST_EXTENSION_VERSION, LogicalRequestClaim, LogicalRequestIdempotency,
    LogicalRequestObservation, LogicalRequestOperation, LogicalRequestPhase, LogicalRequestReplay,
    LogicalRequestResult, LogicalRequestState, LogicalRequestTransport, LogicalResponseMetadata,
    decode_logical_request_result, encode_logical_request_operation, encode_logical_request_result,
    logical_request_extension, logical_request_state,
};
use visa_runtime::{SnapshotExpectations, validate_snapshot};
use visa_wasmtime::PortableLogicalRequestState;

use crate::{
    ADMISSION_LIMITATIONS, AdmissionDatabaseEvidence, AdmissionJointProjectionEvidence,
    AdmissionReceiptMaterial, AdmissionStagedAdvanceEvidence, EffectCloseRequest,
    EffectFreezeRequest, EffectFreezeToken, LOGICAL_REQUEST_ADMISSION_SCHEMA,
    LogicalRequestAdmissionClaims, LogicalRequestAdmissionExpectations,
    LogicalRequestAdmissionReport, NativeJsonlExchange, OwnershipReserveRequest,
    OwnershipSealRequest, ProcessLiveEffectPhase, admission_digest, admission_identity,
    compact_digest, compact_identity, expected_admission_authenticator, mapped_native_digest,
    mapped_u64_digest,
    nexus_effect_wire::{
        EffectSelector, NativeHandoffStatus, NativeOwnershipDecision, NativePrepareIntent,
        NativeReadiness, NativeReceiptPayload, PeerCommand, PeerRequest, PeerResponse,
    },
    process_effect_peer::validate_native_jsonl_chain,
};

const EXPECTED_SEQUENCE: [&str; 19] = [
    "preview",
    "nexus-register",
    "nexus-prepare",
    "nexus-commit-ack-lost",
    "nexus-commit-recovered",
    "source-start",
    "nexus-outcome-recorded",
    "ownership-reserved",
    "visa-frozen",
    "destination-locally-prepared",
    "nexus-frozen",
    "ownership-sealed",
    "ownership-commit-ack-lost",
    "ownership-commit-recovered",
    "nexus-closed",
    "source-fenced",
    "destination-guest-restored",
    "destination-activated",
    "destination-reconciled",
];

const EXPECTED_SOURCE_START_POSITION: JournalPosition = JournalPosition(3);
const EXPECTED_SNAPSHOT_POSITION: JournalPosition = JournalPosition(6);
const EXPECTED_SOURCE_FENCE_POSITION: JournalPosition = JournalPosition(7);
const PROVIDER_GENERATED_ID_PREFIX: u128 = 0x7669_7361_2d68_6f73_0000_0000_0000_0000;
const EXPECTED_SESSION_ID: &str = "logical-request-admission:source-session";
const EXPECTED_LOGICAL_PEER_IDENTITY: &[u8] = b"visa-admission-logical-peer-v1";
const EXPECTED_LOGICAL_REQUEST: &[u8] = b"visa-admission-ordered-request-v1";
const EXPECTED_LOGICAL_RESPONSE: &[u8] = b"visa-admission-ordered-response-v1";

struct ExpectedAdmissionSemantics {
    component_digest: Digest,
    start_request: EffectRequest,
    start_outcome: EffectOutcome,
    source_start_state: CanonicalState,
    exported_source_state: CanonicalState,
    snapshot: SnapshotEnvelope,
    destination_prepared_state: CanonicalState,
    lease_request: EffectRequest,
    lease_outcome: EffectOutcome,
    lease_committed_state: CanonicalState,
}

pub fn validate_logical_request_admission_report(
    report: &LogicalRequestAdmissionReport,
    expected: &LogicalRequestAdmissionExpectations,
) -> Result<(), String> {
    require(report.schema == LOGICAL_REQUEST_ADMISSION_SCHEMA, "unexpected report schema")?;
    require(report.all_passed, "report is not terminally accepted")?;
    require(!report.run_identity.is_zero(), "report run identity is zero")?;
    require(
        report.run_identity == expected.run_identity
            && report.nexus.process == expected.nexus_process,
        "report run or Nexus process identity did not match external expectations",
    )?;
    require(
        report.claims == LogicalRequestAdmissionClaims::bounded(),
        "report widened or narrowed the fixed claim boundary",
    )?;
    require(
        report.sequence.steps.iter().map(String::as_str).eq(EXPECTED_SEQUENCE),
        "report did not preserve the admission-ordered execution sequence",
    )?;
    require(
        report.limitations.iter().map(String::as_str).eq(ADMISSION_LIMITATIONS),
        "report limitations changed the fixed bounded claim",
    )?;
    require(
        report.sequence.external_requests_before_nexus_commit == 0
            && report.sequence.external_executions_before_nexus_commit == 0
            && report.sequence.external_executions_after_source_start == 1
            && report.sequence.external_executions_after_destination_reconcile == 1,
        "external counters do not prove admission before one execution",
    )?;

    let component_digest = report.runtime.snapshot.body.component_digest;
    require(component_digest != Digest::ZERO, "report component digest is zero")?;
    let semantics = ExpectedAdmissionSemantics::for_run(report.run_identity, component_digest)?;
    validate_effect_identity(report, &semantics)?;
    validate_staged_admission(report)?;
    validate_native_chain(report)?;
    validate_run_and_process_identity(report)?;
    validate_snapshot_and_receipts(report, &semantics)?;
    validate_terminal_states(report, &semantics)?;
    validate_projection(report)?;
    validate_database_evidence(report)?;
    Ok(())
}

impl ExpectedAdmissionSemantics {
    fn for_run(run: Identity, component_digest: Digest) -> Result<Self, String> {
        let source_node = NodeIdentity::new(admission_identity(run, b"source-node")?);
        let destination_node = NodeIdentity::new(admission_identity(run, b"destination-node")?);
        let component = admission_identity(run, b"component")?;
        let source_component = EntityRef::initial(component);
        let destination_component = EntityRef::new(component, Generation(1));
        let timer = fixture_entity(run, b"timer")?;
        let key_value = fixture_entity(run, b"key-value")?;
        let request_resource = fixture_entity(run, b"logical-request")?;
        let logical_operation = admission_identity(run, b"logical-operation")?;
        let source_handoff_authority = fixture_entity(run, b"source-handoff-authority")?;
        let source_timer_authority = fixture_entity(run, b"source-timer-authority")?;
        let source_key_value_authority = fixture_entity(run, b"source-key-value-authority")?;
        let source_request_authority = fixture_entity(run, b"source-request-authority")?;
        let request_rights = expected_profile_rights();
        let logical_request = LogicalRequestState {
            claim: LogicalRequestClaim {
                resource: request_resource,
                peer_identity: EXPECTED_LOGICAL_PEER_IDENTITY.to_vec(),
                credential_reference: admission_identity(run, b"credential-reference")?,
                required_rights: request_rights,
                transport: LogicalRequestTransport::Reconnectable,
                delivery: DeliveryPolicy::Deduplicated,
                replay: LogicalRequestReplay::WithOperationId,
                idempotency: LogicalRequestIdempotency::OperationIdDeduplicated,
                timeout_millis: 1_000,
                max_request_size: visa_profile::MAX_LOGICAL_REQUEST_BYTES,
                max_response_size: visa_profile::MAX_LOGICAL_RESPONSE_BYTES,
            },
            operation_id: logical_operation,
            request_size: u32::try_from(EXPECTED_LOGICAL_REQUEST.len())
                .map_err(|_| "expected logical request is too large")?,
            request_digest: canonical_digest(EXPECTED_LOGICAL_REQUEST).map_err(debug)?,
            phase: LogicalRequestPhase::Ready,
            response_cursor: 0,
            response: None,
            rejection: None,
            disposition: ContinuityDisposition::Revalidate,
            last_operation: None,
        };
        let logical_extension = logical_request_extension(&logical_request).map_err(debug)?;
        let profile = CooperativeHandoffProfile::v1(vec![ExtensionSupport {
            id: LOGICAL_REQUEST_EXTENSION_ID,
            version: LOGICAL_REQUEST_EXTENSION_VERSION,
        }]);
        let profile_digest = canonical_digest(&profile).map_err(debug)?;
        let claims = ResourceClaims {
            timer: TimerClaim {
                resource: timer,
                clock: TimerClock::PausedMonotonicDuration,
                required_rights: expected_timer_rights(),
            },
            key_value: KeyValueClaim {
                resource: key_value,
                namespace: admission_identity(run, b"key-value-namespace")?,
                required_rights: expected_key_value_rights(),
                delivery: DeliveryPolicy::Deduplicated,
            },
        };
        let source_authorities = vec![
            AuthorityGrant::active_root(
                source_handoff_authority,
                source_component,
                source_component,
                Rights::HANDOFF,
            ),
            AuthorityGrant::active_root(
                source_timer_authority,
                source_component,
                timer,
                expected_timer_rights(),
            ),
            AuthorityGrant::active_root(
                source_key_value_authority,
                source_component,
                key_value,
                expected_key_value_rights(),
            ),
            AuthorityGrant::active_root(
                source_request_authority,
                source_component,
                request_resource,
                request_rights,
            ),
        ];
        let initial = CanonicalState::dormant_with_extensions(
            source_component,
            source_node,
            component_digest,
            profile_digest,
            SchemaVersion::new(profile.version.major, profile.version.minor),
            claims,
            source_authorities,
            vec![logical_extension],
        );
        let activate = Command::new(
            admission_identity(run, b"source-activate")?,
            CommandKind::Activate {
                authority: source_handoff_authority,
                lease_epoch: LeaseEpoch(1),
            },
        );
        let active_source = applied_state(&initial, &committed_event(&initial, &activate)?)?;

        let binding = ProfileBinding::for_state(&active_source, LOGICAL_REQUEST_EXTENSION_ID)
            .map_err(debug)?;
        let start_payload = encode_logical_request_operation(&LogicalRequestOperation::Start {
            request: EXPECTED_LOGICAL_REQUEST.to_vec(),
        })
        .map_err(debug)?;
        let start_request = prepare_profile_effect(
            &active_source,
            &binding,
            ProfileAccess::Write,
            identity_string(logical_operation).as_bytes(),
            start_payload,
        )
        .map_err(debug)?;
        let start_result = EffectResult::Profile {
            profile: LOGICAL_REQUEST_EXTENSION_ID,
            payload: encode_logical_request_result(&LogicalRequestResult::Started {
                observation: LogicalRequestObservation {
                    phase: LogicalRequestPhase::UnknownCompletion,
                    response: None,
                    rejection: None,
                },
            })
            .map_err(debug)?,
        };
        let start_outcome = expected_provider_outcome(1, &start_request, start_result)?;
        let start_command = Command::new(
            runtime_component_command(start_request.operation),
            CommandKind::RequestEffect(start_request.clone()),
        );
        let start_intent = execution_intent(&active_source, &start_command)?;
        let start_intent_state = applied_state(&active_source, &start_intent)?;
        let start_resolve = Command::new(
            runtime_derived_identity(start_request.operation, b"resolve")?,
            CommandKind::ResolveEffect {
                operation: start_request.operation,
                outcome: start_outcome.clone(),
            },
        );
        let source_start_state = applied_state(
            &start_intent_state,
            &committed_event(&start_intent_state, &start_resolve)?,
        )?;

        let begin_quiesce = Command::new(
            admission_identity(run, b"source-begin-quiesce")?,
            CommandKind::BeginHandoff { authority: source_handoff_authority },
        );
        let quiescing = applied_state(
            &source_start_state,
            &committed_event(&source_start_state, &begin_quiesce)?,
        )?;
        let logical_at_freeze = canonical_logical_state(&quiescing)?;
        let component_state = LogicalRequestComponentState::from_canonical(
            EXPECTED_SESSION_ID.to_owned(),
            &logical_at_freeze,
            LogicalRequestWorkloadLifecycle::Frozen,
        )
        .map_err(debug)?;
        let portable =
            PortableLogicalRequestState::encode(&component_state).map_err(debug)?.into_bytes();
        let freeze = Command::new(
            admission_identity(run, b"source-commit-safe-point")?,
            CommandKind::Freeze { portable_state: portable, timer: TimerDisposition::Idle },
        );
        let frozen = applied_state(&quiescing, &committed_event(&quiescing, &freeze)?)?;
        let snapshot_record = SnapshotRecord {
            handoff: admission_identity(run, b"handoff")?,
            snapshot: admission_identity(run, b"snapshot")?,
            journal_position: EXPECTED_SNAPSHOT_POSITION,
            evidence: EvidenceRef {
                identity: admission_identity(run, b"snapshot-integrity-evidence")?,
                kind: EvidenceKind::SnapshotIntegrity,
                digest: state_digest(&frozen).map_err(debug)?,
            },
        };
        let export = Command::new(
            admission_identity(run, b"source-export-snapshot")?,
            CommandKind::ExportSnapshot { snapshot: snapshot_record },
        );
        let exported_source_state = applied_state(&frozen, &committed_event(&frozen, &export)?)?;
        let body = exported_source_state
            .snapshot_body()
            .ok_or("expected exported source state omitted snapshot body")?;
        let snapshot = SnapshotEnvelope {
            version: CONTRACT_VERSION,
            integrity: snapshot_integrity(&body).map_err(debug)?,
            body,
        };
        let supported_extensions = [ExtensionSupport {
            id: LOGICAL_REQUEST_EXTENSION_ID,
            version: LOGICAL_REQUEST_EXTENSION_VERSION,
        }];
        let restored = semantic_core::restore(
            &snapshot,
            snapshot.integrity,
            component_digest,
            profile_digest,
            SchemaVersion::new(1, 0),
            &supported_extensions,
            destination_node,
        )
        .map_err(debug)?;
        let prepared = expected_prepared_destination(
            run,
            destination_node,
            destination_component,
            timer,
            key_value,
            request_resource,
            source_handoff_authority,
            source_timer_authority,
            source_key_value_authority,
            source_request_authority,
        )?;
        let prepare = Command::new(
            admission_identity(run, b"destination-local-prepare")?,
            CommandKind::PrepareDestination(prepared),
        );
        let destination_prepared_state =
            applied_state(&restored, &committed_event(&restored, &prepare)?)?;
        let lease_request = expected_destination_commit_request(run, &destination_prepared_state)?;
        let source_fence = EvidenceRef {
            identity: provider_generated_identity(7),
            kind: EvidenceKind::SourceFence,
            digest: expected_source_fence_digest(&lease_request)?,
        };
        let lease_result = EffectResult::LeaseAdvanced {
            owner: destination_node,
            epoch: LeaseEpoch(2),
            source_fence,
        };
        let lease_outcome = expected_provider_outcome(8, &lease_request, lease_result)?;
        let lease_command = Command::new(
            admission_identity(run, b"destination-lease-commit-command")?,
            CommandKind::RequestEffect(lease_request.clone()),
        );
        let lease_intent = execution_intent(&destination_prepared_state, &lease_command)?;
        let lease_intent_state = applied_state(&destination_prepared_state, &lease_intent)?;
        let lease_resolve = Command::new(
            runtime_derived_identity(lease_request.operation, b"resolve")?,
            CommandKind::ResolveEffect {
                operation: lease_request.operation,
                outcome: lease_outcome.clone(),
            },
        );
        let lease_committed_state = applied_state(
            &lease_intent_state,
            &committed_event(&lease_intent_state, &lease_resolve)?,
        )?;

        Ok(Self {
            component_digest,
            start_request,
            start_outcome,
            source_start_state,
            exported_source_state,
            snapshot,
            destination_prepared_state,
            lease_request,
            lease_outcome,
            lease_committed_state,
        })
    }
}

fn fixture_entity(run: Identity, label: &[u8]) -> Result<EntityRef, String> {
    Ok(EntityRef::initial(admission_identity(run, label)?))
}

const fn expected_timer_rights() -> Rights {
    Rights::TIMER_ARM.union(Rights::TIMER_CANCEL).union(Rights::REBIND)
}

const fn expected_key_value_rights() -> Rights {
    Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND)
}

const fn expected_profile_rights() -> Rights {
    Rights::PROFILE_READ
        .union(Rights::PROFILE_WRITE)
        .union(Rights::PROFILE_CONTROL)
        .union(Rights::REBIND)
}

fn provider_generated_identity(sequence: u64) -> Identity {
    Identity::from_u128(PROVIDER_GENERATED_ID_PREFIX | u128::from(sequence))
}

fn expected_provider_outcome(
    evidence_sequence: u64,
    request: &EffectRequest,
    result: EffectResult,
) -> Result<EffectOutcome, String> {
    let mut digest = Sha256::new();
    digest.update(serde_json::to_vec(request).map_err(debug)?);
    digest.update(serde_json::to_vec(&result).map_err(debug)?);
    Ok(EffectOutcome::Succeeded {
        result,
        evidence: EvidenceRef {
            identity: provider_generated_identity(evidence_sequence),
            kind: EvidenceKind::EffectOutcome,
            digest: Digest::from_bytes(digest.finalize().into()),
        },
    })
}

fn expected_source_fence_digest(request: &EffectRequest) -> Result<Digest, String> {
    let mut digest = Sha256::new();
    digest.update(b"vISA source fence");
    digest.update(serde_json::to_vec(request).map_err(debug)?);
    Ok(Digest::from_bytes(digest.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn expected_prepared_destination(
    run: Identity,
    destination: NodeIdentity,
    destination_component: EntityRef,
    timer: EntityRef,
    key_value: EntityRef,
    request_resource: EntityRef,
    source_handoff_authority: EntityRef,
    source_timer_authority: EntityRef,
    source_key_value_authority: EntityRef,
    source_request_authority: EntityRef,
) -> Result<PreparedDestination, String> {
    let handoff = admission_identity(run, b"handoff")?;
    let snapshot = admission_identity(run, b"snapshot")?;
    let handoff_grant = expected_reauthorized_grant(
        fixture_entity(run, b"destination-handoff-authority")?,
        source_handoff_authority,
        destination_component,
        destination_component,
        Rights::HANDOFF,
    );
    let timer_grant = expected_reauthorized_grant(
        fixture_entity(run, b"destination-timer-authority")?,
        source_timer_authority,
        destination_component,
        timer,
        expected_timer_rights(),
    );
    let key_value_grant = expected_reauthorized_grant(
        fixture_entity(run, b"destination-key-value-authority")?,
        source_key_value_authority,
        destination_component,
        key_value,
        expected_key_value_rights(),
    );
    let request_grant = expected_reauthorized_grant(
        fixture_entity(run, b"destination-request-authority")?,
        source_request_authority,
        destination_component,
        request_resource,
        expected_profile_rights(),
    );
    let timer_binding = expected_binding(
        handoff,
        snapshot,
        timer,
        1,
        timer_grant.authority,
        expected_timer_rights(),
        destination,
        2,
        None,
    )?;
    let key_value_binding = expected_binding(
        handoff,
        snapshot,
        key_value,
        3,
        key_value_grant.authority,
        expected_key_value_rights(),
        destination,
        4,
        None,
    )?;
    let request_binding = expected_binding(
        handoff,
        snapshot,
        request_resource,
        5,
        request_grant.authority,
        expected_profile_rights(),
        destination,
        6,
        Some(LOGICAL_REQUEST_EXTENSION_ID),
    )?;
    Ok(PreparedDestination {
        handoff,
        snapshot,
        destination,
        component_generation: destination_component.generation,
        expected_epoch: LeaseEpoch(1),
        next_epoch: LeaseEpoch(2),
        authorities: vec![handoff_grant, timer_grant, key_value_grant, request_grant],
        bindings: vec![timer_binding, key_value_binding, request_binding],
    })
}

fn expected_reauthorized_grant(
    authority: EntityRef,
    parent: EntityRef,
    subject: EntityRef,
    resource: EntityRef,
    rights: Rights,
) -> AuthorityGrant {
    AuthorityGrant {
        authority,
        parent: Some(parent),
        subject,
        resource,
        rights,
        status: AuthorityStatus::Active,
    }
}

#[allow(clippy::too_many_arguments)]
fn expected_binding(
    handoff: Identity,
    snapshot: Identity,
    claim: EntityRef,
    binding_sequence: u64,
    authority: EntityRef,
    exposed_rights: Rights,
    node: NodeIdentity,
    evidence_sequence: u64,
    profile: Option<Identity>,
) -> Result<BindingReceipt, String> {
    let binding = EntityRef::initial(provider_generated_identity(binding_sequence));
    let mut digest = Sha256::new();
    digest.update(handoff.0);
    digest.update(snapshot.0);
    digest.update(claim.identity.0);
    digest.update(claim.generation.0.to_be_bytes());
    digest.update(binding.identity.0);
    digest.update(authority.identity.0);
    digest.update(authority.generation.0.to_be_bytes());
    digest.update(exposed_rights.bits().to_be_bytes());
    digest.update(node.0.0);
    digest.update(LeaseEpoch(2).0.to_be_bytes());
    if let Some(profile) = profile {
        digest.update(b"profile-binding-v1");
        digest.update(profile.0);
    }
    Ok(BindingReceipt {
        handoff,
        snapshot,
        claim,
        binding,
        authority,
        exposed_rights,
        node,
        lease_epoch: LeaseEpoch(2),
        evidence: EvidenceRef {
            identity: provider_generated_identity(evidence_sequence),
            kind: EvidenceKind::Binding,
            digest: Digest::from_bytes(digest.finalize().into()),
        },
    })
}

fn validate_run_and_process_identity(report: &LogicalRequestAdmissionReport) -> Result<(), String> {
    let key = report.nexus.freeze.key;
    let run = report.run_identity;
    let component = admission_identity(run, b"component")?;
    let expected_key = joint_handoff_core::JointHandoffKey {
        continuity_unit: EntityRef::initial(component),
        handoff: admission_identity(run, b"handoff")?,
        source: NodeIdentity::new(admission_identity(run, b"source-node")?),
        destination: NodeIdentity::new(admission_identity(run, b"destination-node")?),
        expected_epoch: LeaseEpoch(1),
        next_epoch: LeaseEpoch(2),
    };
    let expected = expected_admission_authenticator(report.run_identity, key)?;
    require(
        key == expected_key
            && report.nexus.registration.registry_instance
                == admission_identity(run, b"registry-instance")?
            && report.nexus.registration.scope_id == admission_identity(run, b"scope")?
            && report.nexus.freeze.scope_generation == 1
            && report.nexus.freeze.authority_epoch == 1
            && report.nexus.freeze.freeze_generation == 1
            && report.nexus.freeze.domain_bindings_digest
                == admission_digest(run, b"domain-bindings")?
            && report.source.logical_operation == admission_identity(run, b"logical-operation")?
            && report.source.preview.node == expected_key.source
            && report.source.preview.subject == expected_key.continuity_unit
            && report.source.preview.resource
                == EntityRef::initial(admission_identity(run, b"logical-request")?)
            && report.source.preview.authority
                == EntityRef::initial(admission_identity(run, b"source-request-authority")?)
            && report.source.preview.lease_epoch == expected_key.expected_epoch
            && report.runtime.issuer_set == expected.issuers
            && report.runtime.authentication_secret == expected.secret,
        "report identities or authenticator are not derived from run identity",
    )?;

    let process = &report.nexus.process;
    require(
        process.process_id != 0
            && process.start_time_ticks != 0
            && !process.executable_path.as_os_str().is_empty()
            && is_sha256(&process.executable_sha256)
            && is_lower_hex(&process.nexus_revision, 40),
        "Nexus process identity is incomplete or malformed",
    )?;
    let initialize = unique_exchange(&report.nexus.native_chain, |command| {
        matches!(command, PeerCommand::Initialize(_))
    })?;
    let (request, response) = decode_exchange(initialize)?;
    let PeerCommand::Initialize(initialize_config) = request.command else {
        return Err("Initialize exchange carried the wrong command".to_owned());
    };
    let receipt = response.receipt.ok_or("Initialize response omitted its native receipt")?;
    let NativeReceiptPayload::Initialized(initialized) = receipt.payload else {
        return Err("Initialize response carried the wrong native payload".to_owned());
    };
    require(
        initialized.process_id == process.process_id
            && initialized.boot_incarnation == 1
            && initialized.config == initialize_config
            && initialize_config.scope_id
                == compact_identity(b"scope", report.nexus.registration.scope_id)
            && initialize_config.scope_generation == report.nexus.freeze.scope_generation
            && initialize_config.authority_epoch == report.nexus.freeze.authority_epoch
            && initialize_config.binding_epoch == report.nexus.freeze.scope_generation
            && initialize_config.supervisor_id
                == compact_identity(b"supervisor", expected_key.source.0)
            && initialize_config.supervisor_generation == report.nexus.freeze.scope_generation
            && initialize_config.task_id
                == compact_identity(b"task", expected_key.continuity_unit.identity)
            && initialize_config.task_generation == expected_key.continuity_unit.generation.0 + 1
            && initialize_config.credit_class == 1
            && initialize_config.credit_limit == 1_000_000,
        "reported Nexus process ID did not match the raw Initialize receipt",
    )
}

fn validate_effect_identity(
    report: &LogicalRequestAdmissionReport,
    semantics: &ExpectedAdmissionSemantics,
) -> Result<(), String> {
    let registration = &report.nexus.registration;
    let final_publication = &report.nexus.final_publication;
    let preview = &report.source.preview;
    require(
        report.source.preview == semantics.start_request
            && report.source.source_start_effect == semantics.start_request.operation
            && report.source.source_start_outcome == semantics.start_outcome
            && report.source.source_start_state == semantics.source_start_state
            && report.source.source_journal_position == EXPECTED_SOURCE_START_POSITION
            && report.source.source_state_digest
                == state_digest(&semantics.source_start_state).map_err(debug)?,
        "source Start was not the exact independently rebuilt fixture transition",
    )?;
    let outcome_digest = canonical_digest(&semantics.start_outcome)
        .map_err(|error| format!("cannot digest source outcome: {error:?}"))?;
    require(
        registration.key == report.nexus.freeze.key
            && registration.registry_instance == report.nexus.freeze.registry_instance
            && registration.scope_id == report.nexus.freeze.scope_id
            && registration.scope_generation == report.nexus.freeze.scope_generation
            && registration.source_epoch == registration.key.expected_epoch,
        "Nexus registration did not bind the frozen production scope",
    )?;
    require(
        registration.record.effect == report.source.logical_operation
            && registration.record.operation == preview.operation
            && registration.record.domain == LOGICAL_REQUEST_EXTENSION_ID
            && registration.record.binding_generation == registration.scope_generation
            && registration.record.classification == JointEffectClassification::Registered
            && registration.record.outcome_digest.is_none()
            && registration.record.tombstone_digest.is_none()
            && report.source.source_start_effect == preview.operation,
        "logical request did not map exactly to the registered Nexus effect",
    )?;
    let expected_final = JointEffectRecord {
        classification: JointEffectClassification::Committed,
        outcome_digest: Some(outcome_digest),
        ..registration.record.clone()
    };
    require(
        final_publication.key == registration.key
            && final_publication.registry_instance == registration.registry_instance
            && final_publication.scope_id == registration.scope_id
            && final_publication.scope_generation == registration.scope_generation
            && final_publication.source_epoch == registration.source_epoch
            && final_publication.record == expected_final,
        "final Nexus publication changed identity or provider outcome",
    )?;
    validate_unknown_completion(&semantics.start_outcome)?;
    let source_start = &report.source.source_start_state;
    let source_logical = canonical_logical_state(source_start)?;
    require(
        report.source.source_start_phase == "unknown_completion"
            && state_digest(source_start).map_err(debug)? == report.source.source_state_digest
            && report.source.source_journal_position == EXPECTED_SOURCE_START_POSITION
            && source_start.phase == HandoffPhase::Running
            && source_start.component == registration.key.continuity_unit
            && source_start.component_digest == report.runtime.snapshot.body.component_digest
            && source_start.profile_digest == report.runtime.snapshot.body.profile_digest
            && source_start.activation.node == registration.key.source
            && source_start.activation.role == ActivationRole::Source
            && source_start.activation.status == ActivationStatus::Active
            && source_start.ownership.owner == Some(registration.key.source)
            && source_start.ownership.epoch == registration.key.expected_epoch
            && source_logical.operation_id == report.source.logical_operation
            && source_logical.phase == LogicalRequestPhase::UnknownCompletion
            && source_logical.last_operation == Some(report.source.source_start_effect)
            && report.source.source_ledger_revision == 3
            && report.source.source_ledger_retained_request
            && report.source.source_start_provider_row_present
            && report.source.source_start_effect_mapping_present,
        "source SQLite truth does not retain exact UnknownCompletion",
    )
}

fn validate_unknown_completion(outcome: &EffectOutcome) -> Result<(), String> {
    let EffectOutcome::Succeeded { result: EffectResult::Profile { profile, payload }, .. } =
        outcome
    else {
        return Err("source outcome is not a successful profile result".to_owned());
    };
    require(*profile == LOGICAL_REQUEST_EXTENSION_ID, "source outcome used the wrong profile")?;
    let result = decode_logical_request_result(payload)
        .map_err(|error| format!("cannot decode source logical outcome: {error:?}"))?;
    let LogicalRequestResult::Started { observation } = result else {
        return Err("source outcome used the wrong logical result variant".to_owned());
    };
    require(
        observation.phase == LogicalRequestPhase::UnknownCompletion
            && observation.response.is_none()
            && observation.rejection.is_none(),
        "source outcome did not honestly encode UnknownCompletion",
    )
}

fn validate_staged_admission(report: &LogicalRequestAdmissionReport) -> Result<(), String> {
    validate_advance(&report.nexus.register, ProcessLiveEffectPhase::Registered, 1, true)?;
    validate_advance(&report.nexus.prepare, ProcessLiveEffectPhase::Prepared, 2, true)?;
    validate_advance(
        &report.nexus.commit,
        ProcessLiveEffectPhase::CommittedAwaitingOutcome,
        3,
        true,
    )?;
    validate_advance(&report.nexus.outcome, ProcessLiveEffectPhase::OutcomeRecorded, 4, false)?;
    let ids = [
        (report.nexus.register.native_effect_id, report.nexus.register.native_effect_generation),
        (report.nexus.prepare.native_effect_id, report.nexus.prepare.native_effect_generation),
        (report.nexus.commit.native_effect_id, report.nexus.commit.native_effect_generation),
        (report.nexus.outcome.native_effect_id, report.nexus.outcome.native_effect_generation),
    ];
    require(
        ids[0] == (1, 1) && ids.iter().all(|identity| *identity == ids[0]),
        "staged native identity changed or was not the first fresh Registry effect",
    )?;
    let verified = &report.nexus.verified_commit;
    require(
        verified.native_effect_id == ids[0].0
            && verified.native_effect_generation == ids[0].1
            && verified.binding_epoch == 1
            && verified.commit_sequence == 1
            && verified.result == 0
            && verified.domain_revision == report.nexus.registration.scope_generation
            && !verified.registry_replay
            && report.nexus.commit_metadata_result == verified.result
            && report.nexus.commit_domain_revision == verified.domain_revision
            && report.nexus.commit_metadata_meaning == "logical-request-send-admitted",
        "verified Nexus Commit metadata is not the exact first production commit",
    )?;
    let sequences = [
        report.nexus.register.native_sequence.ok_or("Register native sequence is absent")?,
        report.nexus.prepare.native_sequence.ok_or("Prepare native sequence is absent")?,
        report.nexus.commit.native_sequence.ok_or("Commit native sequence is absent")?,
    ];
    require(
        sequences[0] < sequences[1] && sequences[1] < sequences[2],
        "native staged receipt sequence is not strictly ordered",
    )?;
    let loss = &report.nexus.commit_ack_loss;
    let lost_request: PeerRequest =
        serde_json::from_str(loss.request_jsonl.trim()).map_err(debug)?;
    require(
        matches!(lost_request.command, PeerCommand::Commit(_))
            && loss.byte_identical
            && loss.discarded_response_jsonl == loss.replay_response_jsonl
            && loss.accepted_chain_length_before.checked_add(1)
                == Some(loss.accepted_chain_length_after),
        "Nexus Commit ACK-loss recovery was not byte-exact",
    )
}

fn validate_advance(
    advance: &AdmissionStagedAdvanceEvidence,
    phase: ProcessLiveEffectPhase,
    sequence: u64,
    native: bool,
) -> Result<(), String> {
    let native_shape = if native {
        advance.native_sequence.is_some()
            && advance.native_request_sha256.as_ref().is_some_and(|value| is_sha256(value))
            && advance.native_receipt_sha256.as_ref().is_some_and(|value| is_sha256(value))
    } else {
        advance.native_sequence.is_none()
            && advance.native_request_sha256.is_none()
            && advance.native_receipt_sha256.is_none()
    };
    require(
        advance.phase == process_phase_name(phase)
            && advance.advance == sequence
            && !advance.replay
            && advance.native_effect_id != 0
            && advance.native_effect_generation != 0
            && native_shape,
        "staged admission evidence did not bind its exact phase",
    )
}

fn validate_native_chain(report: &LogicalRequestAdmissionReport) -> Result<(), String> {
    validate_native_jsonl_chain(&report.nexus.native_chain).map_err(debug)?;
    require(report.nexus.native_complete_count == 0, "native Complete must remain absent")?;
    validate_staged_native_exchanges(report)?;
    let commands = decode_commands(&report.nexus.native_chain)?;
    require(
        matches!(
            commands.as_slice(),
            [
                PeerCommand::Initialize(_),
                PeerCommand::Register(_),
                PeerCommand::Prepare(_),
                PeerCommand::Commit(_),
                PeerCommand::Freeze(_),
                PeerCommand::CloseStep(_),
                PeerCommand::AcknowledgePublication(_),
                PeerCommand::CloseStep(_),
                PeerCommand::Query,
                PeerCommand::Shutdown,
            ]
        ),
        "native chain changed the exact bounded command sequence",
    )?;
    let register =
        unique_position(&commands, |command| matches!(command, PeerCommand::Register(_)))?;
    let prepare = unique_position(&commands, |command| matches!(command, PeerCommand::Prepare(_)))?;
    let commit = unique_position(&commands, |command| matches!(command, PeerCommand::Commit(_)))?;
    let freeze = unique_position(&commands, |command| matches!(command, PeerCommand::Freeze(_)))?;
    let publication_ack = unique_position(&commands, |command| {
        matches!(command, PeerCommand::AcknowledgePublication(_))
    })?;
    let query = unique_position(&commands, |command| matches!(command, PeerCommand::Query))?;
    let shutdown = unique_position(&commands, |command| matches!(command, PeerCommand::Shutdown))?;
    let close_positions = commands
        .iter()
        .enumerate()
        .filter_map(|(index, command)| {
            matches!(command, PeerCommand::CloseStep(_)).then_some(index)
        })
        .collect::<Vec<_>>();
    require(
        close_positions.len() >= 2
            && register < prepare
            && prepare < commit
            && commit < freeze
            && freeze < close_positions[0]
            && close_positions[0] < publication_ack
            && publication_ack < *close_positions.last().ok_or("CloseStep is absent")?
            && *close_positions.last().ok_or("CloseStep is absent")? < query
            && query < shutdown
            && commands.iter().all(|command| !matches!(command, PeerCommand::Complete(_))),
        "native chain did not preserve CloseStep -> Publication ACK -> CloseStep",
    )?;
    validate_native_handoff_suffix(report)
}

fn validate_native_handoff_suffix(report: &LogicalRequestAdmissionReport) -> Result<(), String> {
    let key = report.nexus.freeze.key;
    let intent = &report.ownership.intent;
    let initialize_exchange = unique_exchange(&report.nexus.native_chain, |command| {
        matches!(command, PeerCommand::Initialize(_))
    })?;
    let (_, initialize_response) = decode_exchange(initialize_exchange)?;
    let initialize_receipt =
        initialize_response.receipt.ok_or("Initialize response omitted its receipt")?;
    let NativeReceiptPayload::Initialized(initialized) = initialize_receipt.payload else {
        return Err("Initialize response carried the wrong payload".to_owned());
    };
    let register_exchange = exchange_for_advance(report, &report.nexus.register)?;
    let (register_request, register_response) = decode_exchange(register_exchange)?;
    let PeerCommand::Register(_) = register_request.command else {
        return Err("staged Register exchange carried the wrong command".to_owned());
    };
    let register_receipt =
        register_response.receipt.ok_or("staged Register response omitted its receipt")?;
    let NativeReceiptPayload::EffectRegistered(register_payload) = register_receipt.payload else {
        return Err("staged Register response carried the wrong payload".to_owned());
    };
    let (expected_native_cohort_digest, expected_native_classification_digest) =
        native_handoff_digests(
            register_payload.native_effect_id,
            register_payload.native_effect_generation,
            report.nexus.verified_commit.commit_sequence,
        );
    let expected_native_terminal_manifest_digest = native_terminal_manifest_digest(
        register_payload.native_effect_id,
        register_payload.native_effect_generation,
    );
    let expected_freeze = NativePrepareIntent {
        handoff_id: compact_identity(b"handoff", key.handoff),
        log_identity: compact_identity(b"ownership-log", intent.header.log_id),
        intent_position: intent.intent_revision,
        service_incarnation: compact_identity(
            b"ownership-incarnation",
            intent.header.issuer_incarnation,
        ),
        key_identity: compact_identity(b"ownership-key", intent.header.key_id),
        request_digest: compact_digest(b"intent-request", intent.request_digest),
    };
    let freeze_exchange = unique_exchange(&report.nexus.native_chain, |command| {
        matches!(command, PeerCommand::Freeze(_))
    })?;
    let (freeze_request, freeze_response) = decode_exchange(freeze_exchange)?;
    let PeerCommand::Freeze(freeze_command) = freeze_request.command else {
        return Err("native Freeze exchange carried the wrong command".to_owned());
    };
    let freeze_receipt =
        freeze_response.receipt.ok_or("native Freeze response omitted its receipt")?;
    let NativeReceiptPayload::AdmissionFrozen(freeze_payload) = freeze_receipt.payload else {
        return Err("native Freeze response carried the wrong payload".to_owned());
    };
    if freeze_payload.boot_incarnation != initialized.boot_incarnation
        || freeze_payload.frozen_scope_revision != 3
        || freeze_payload.cohort_digest != expected_native_cohort_digest
        || freeze_payload.classification_digest != expected_native_classification_digest
    {
        return Err(format!(
            "native Freeze exact projection mismatch: boot={}/{} revision={}/3 cohort={:#x}/{:#x} classification={:#x}/{:#x}",
            freeze_payload.boot_incarnation,
            initialized.boot_incarnation,
            freeze_payload.frozen_scope_revision,
            freeze_payload.cohort_digest,
            expected_native_cohort_digest,
            freeze_payload.classification_digest,
            expected_native_classification_digest,
        ));
    }
    require(
        freeze_command == expected_freeze
            && freeze_payload.handoff_id == expected_freeze.handoff_id
            && freeze_payload.registry_instance == 1
            && freeze_payload.boot_incarnation == 1
            && freeze_payload.boot_incarnation == initialized.boot_incarnation
            && freeze_payload.scope_id == compact_identity(b"scope", report.nexus.freeze.scope_id)
            && freeze_payload.scope_generation == report.nexus.freeze.scope_generation
            && freeze_payload.authority_epoch == report.nexus.freeze.authority_epoch
            && freeze_payload.binding_epoch == report.nexus.verified_commit.binding_epoch
            && freeze_payload.freeze_generation == report.nexus.freeze.freeze_generation
            && freeze_payload.frozen_scope_revision == 3
            && freeze_payload.cohort_digest == expected_native_cohort_digest
            && freeze_payload.classification_digest == expected_native_classification_digest
            && freeze_payload.cohort_size == 1
            && freeze_payload.committed_at_freeze == 1
            && freeze_payload.readiness == NativeReadiness::ReadyToCommit,
        "native Freeze did not bind the exact admitted production cohort",
    )?;

    let conformance_key: visa_conformance::JointHandoffKey =
        serde_json::from_value(serde_json::to_value(key).map_err(debug)?).map_err(debug)?;
    let terminal_records = vec![report.nexus.final_publication.record.clone()];
    require(
        report.nexus.freeze.effect_cohort_digest
            == joint_effect_cohort_digest(conformance_key, terminal_records.clone())
                .map_err(debug)?
            && report.nexus.freeze.classification_root
                == joint_classification_root(conformance_key, terminal_records).map_err(debug)?,
        "neutral NexusFreeze cohort digests did not match the final publication",
    )?;

    let commit = &report.ownership.commit;
    let expected_decision = NativeOwnershipDecision {
        handoff_id: expected_freeze.handoff_id,
        freeze_generation: report.nexus.freeze.freeze_generation,
        log_identity: compact_identity(b"ownership-log", commit.header.log_id),
        decision_position: commit.header.sequence,
        service_incarnation: compact_identity(
            b"ownership-incarnation",
            commit.header.issuer_incarnation,
        ),
        key_identity: compact_identity(b"ownership-key", commit.header.key_id),
        request_digest: expected_freeze.request_digest,
    };
    let close_material = report
        .runtime
        .receipt_material
        .iter()
        .filter(|material| material.kind == "closure-progress" || material.kind == "closure")
        .collect::<Vec<_>>();
    let close_exchanges = report
        .nexus
        .native_chain
        .iter()
        .filter_map(|exchange| {
            decode_exchange(exchange).ok().and_then(|(request, response)| {
                matches!(request.command, PeerCommand::CloseStep(_)).then_some((request, response))
            })
        })
        .collect::<Vec<_>>();
    require(
        close_exchanges.len() == 2
            && close_material.len() == 2
            && close_material[0].kind == "closure-progress"
            && close_material[1].kind == "closure",
        "exact one-effect cell did not retain one progress step and one terminal close",
    )?;
    let expected_first_close_revision = freeze_payload
        .frozen_scope_revision
        .checked_add(2)
        .ok_or("first native close revision overflow")?;
    let expected_terminal_close_revision = expected_first_close_revision
        .checked_add(2)
        .ok_or("terminal native close revision overflow")?;
    let mut first_close_payload = None;
    for (index, ((request, response), material)) in
        close_exchanges.iter().zip(close_material).enumerate()
    {
        let PeerCommand::CloseStep(decision) = request.command else {
            unreachable!();
        };
        require(decision == expected_decision, "native CloseStep changed ownership decision")?;
        let receipt = response.receipt.as_ref().ok_or("CloseStep response omitted its receipt")?;
        let NativeReceiptPayload::ClosureProgress(payload) = &receipt.payload else {
            return Err("CloseStep response carried the wrong payload".to_owned());
        };
        let expected_closed_authority_epoch = report
            .nexus
            .freeze
            .authority_epoch
            .checked_add(1)
            .ok_or("closed authority epoch overflow")?;
        if payload.freeze_generation != report.nexus.freeze.freeze_generation
            || payload.authority_epoch != expected_closed_authority_epoch
            || payload.binding_epoch != report.nexus.verified_commit.binding_epoch
        {
            return Err(format!(
                "native CloseStep payload changed the frozen authority identity: freeze={}/{} authority={}/{} binding={}/{}",
                payload.freeze_generation,
                report.nexus.freeze.freeze_generation,
                payload.authority_epoch,
                expected_closed_authority_epoch,
                payload.binding_epoch,
                report.nexus.verified_commit.binding_epoch,
            ));
        }
        if index == 0 {
            let progress: ClosureProgressReceipt =
                joint_from_bytes(&material.payload).map_err(debug)?;
            let expected_progress_root = mapped_native_digest(b"closure-progress", payload);
            if payload.status != NativeHandoffStatus::Closing
                || payload.readiness.is_some()
                || payload.scope_revision != expected_first_close_revision
                || payload.live_effects != 0
                || payload.pending_publications != 1
                || payload.native_effect != Some(report.nexus.verified_commit.client_effect)
                || !payload.publication_pending
                || payload.terminal_manifest_digest.is_some()
                || progress.remaining_effects != payload.live_effects as u64
                || progress.retained_tombstones != 0
                || progress.progress_root != expected_progress_root
            {
                return Err(format!(
                    "ClosureProgress exact projection mismatch: payload={payload:?} expected_revision={expected_first_close_revision} expected_effect={} progress_remaining={} progress_retained={} progress_root={:?}/{:?}",
                    report.nexus.verified_commit.client_effect,
                    progress.remaining_effects,
                    progress.retained_tombstones,
                    progress.progress_root,
                    expected_progress_root,
                ));
            }
            first_close_payload = Some(*payload);
        } else {
            let terminal = payload
                .terminal_manifest_digest
                .ok_or("closed native payload omitted terminal manifest")?;
            require(
                payload.status == NativeHandoffStatus::Closed
                    && payload.readiness.is_none()
                    && payload.scope_revision == expected_terminal_close_revision
                    && payload.live_effects == 0
                    && payload.pending_publications == 0
                    && payload.native_effect.is_none()
                    && !payload.publication_pending
                    && terminal == expected_native_terminal_manifest_digest
                    && report.nexus.closure.effect_manifest_digest
                        == mapped_u64_digest(b"terminal-manifest", terminal)
                    && report.nexus.closure.closed_authority_epoch == payload.authority_epoch,
                "Closure did not refine the matching terminal native CloseStep payload",
            )?;
        }
    }

    let publication_ack = unique_exchange(&report.nexus.native_chain, |command| {
        matches!(command, PeerCommand::AcknowledgePublication(_))
    })?;
    let (ack_request, ack_response) = decode_exchange(publication_ack)?;
    let PeerCommand::AcknowledgePublication(selector) = ack_request.command else {
        unreachable!();
    };
    let ack_receipt = ack_response.receipt.ok_or("Publication ACK response omitted its receipt")?;
    let NativeReceiptPayload::PublicationAcknowledged(acknowledged) = ack_receipt.payload else {
        return Err("Publication ACK response carried the wrong payload".to_owned());
    };
    let expected_selector = EffectSelector {
        client_effect: report.nexus.verified_commit.client_effect,
        binding_epoch: report.nexus.verified_commit.binding_epoch,
    };
    let first_close_payload = first_close_payload.ok_or("first native close payload is absent")?;
    require(
        first_close_payload.publication_pending
            && first_close_payload.native_effect == Some(expected_selector.client_effect)
            && selector == expected_selector
            && acknowledged == expected_selector,
        "Publication ACK did not bind the admitted effect and binding epoch",
    )?;

    let query_exchange = unique_exchange(&report.nexus.native_chain, |command| {
        matches!(command, PeerCommand::Query)
    })?;
    let (query_request, query_response) = decode_exchange(query_exchange)?;
    require(matches!(query_request.command, PeerCommand::Query), "raw Query command changed")?;
    let query_receipt = query_response.receipt.ok_or("Query response omitted its receipt")?;
    let NativeReceiptPayload::HandoffQuery(query) = query_receipt.payload else {
        return Err("Query response carried the wrong payload".to_owned());
    };
    let query_manifest =
        query.terminal_manifest_digest.ok_or("terminal Query omitted the closure manifest")?;
    require(
        query.status == NativeHandoffStatus::Closed
            && query.readiness.is_none()
            && query.freeze_generation == report.nexus.freeze.freeze_generation
            && query.scope_revision == expected_terminal_close_revision
            && query.authority_epoch == report.nexus.closure.closed_authority_epoch
            && query.binding_epoch == report.nexus.verified_commit.binding_epoch
            && query.live_effects == 0
            && query.pending_publications == 0
            && !query.publication_pending
            && query.native_effect.is_none()
            && query_manifest == expected_native_terminal_manifest_digest
            && report.nexus.closure.effect_manifest_digest
                == mapped_u64_digest(b"terminal-manifest", query_manifest),
        "terminal native Query did not retain the exact closed cohort",
    )
}

fn validate_staged_native_exchanges(report: &LogicalRequestAdmissionReport) -> Result<(), String> {
    let register_exchange = exchange_for_advance(report, &report.nexus.register)?;
    let prepare_exchange = exchange_for_advance(report, &report.nexus.prepare)?;
    let commit_exchange = exchange_for_advance(report, &report.nexus.commit)?;
    let (register_request, register_response) = decode_exchange(register_exchange)?;
    let (prepare_request, prepare_response) = decode_exchange(prepare_exchange)?;
    let (commit_request, commit_response) = decode_exchange(commit_exchange)?;

    let PeerCommand::Register(register_command) = register_request.command else {
        return Err("Register advance did not name the raw Register command".to_owned());
    };
    let register_receipt =
        register_response.receipt.ok_or("Register response omitted its native receipt")?;
    let NativeReceiptPayload::EffectRegistered(register_payload) = register_receipt.payload else {
        return Err("Register response carried the wrong native payload".to_owned());
    };
    let PeerCommand::Prepare(prepare_command) = prepare_request.command else {
        return Err("Prepare advance did not name the raw Prepare command".to_owned());
    };
    let prepare_receipt =
        prepare_response.receipt.ok_or("Prepare response omitted its native receipt")?;
    let NativeReceiptPayload::EffectPrepared(prepare_payload) = prepare_receipt.payload else {
        return Err("Prepare response carried the wrong native payload".to_owned());
    };
    let PeerCommand::Commit(commit_command) = commit_request.command else {
        return Err("Commit advance did not name the raw Commit command".to_owned());
    };
    let commit_receipt =
        commit_response.receipt.ok_or("Commit response omitted its native receipt")?;
    let NativeReceiptPayload::EffectCommitted(commit_payload) = commit_receipt.payload else {
        return Err("Commit response carried the wrong native payload".to_owned());
    };

    let verified = &report.nexus.verified_commit;
    let registration = &report.nexus.registration;
    let expected_register = crate::nexus_effect_wire::RegisterEffect {
        client_effect: compact_identity(b"client-effect", registration.record.effect),
        operation_class: compact_identity(b"operation-class", registration.record.domain) as u32,
        syscall_number: compact_identity(b"operation", registration.record.operation),
        syscall_arguments: [
            registration.record.binding_generation,
            compact_identity(b"handoff", registration.key.handoff),
            compact_identity(b"source", registration.key.source.0),
            compact_identity(b"destination", registration.key.destination.0),
            0,
            0,
        ],
        credit_units: 1,
        publication_required: true,
    };
    require(
        register_command == expected_register
            && register_command.client_effect == verified.client_effect
            && register_payload.client_effect == verified.client_effect
            && register_payload.native_effect_id == verified.native_effect_id
            && register_payload.native_effect_generation == verified.native_effect_generation
            && register_payload.authority_epoch == report.nexus.freeze.authority_epoch
            && register_payload.binding_epoch == verified.binding_epoch
            && prepare_command.client_effect == verified.client_effect
            && prepare_command.binding_epoch == verified.binding_epoch
            && prepare_payload == prepare_command
            && commit_command.client_effect == verified.client_effect
            && commit_command.binding_epoch == verified.binding_epoch
            && commit_command.result == verified.result
            && commit_command.domain_revision == verified.domain_revision
            && commit_payload.client_effect == verified.client_effect
            && commit_payload.native_effect_id == verified.native_effect_id
            && commit_payload.binding_epoch == verified.binding_epoch
            && commit_payload.commit_sequence == verified.commit_sequence
            && commit_payload.result == verified.result
            && commit_payload.domain_revision == verified.domain_revision
            && commit_payload.registry_replay == verified.registry_replay,
        "staged advances did not bind the exact Register, Prepare, and Commit exchange",
    )?;

    let loss = &report.nexus.commit_ack_loss;
    let accepted_after = u64::try_from(loss.accepted_chain_length_after)
        .map_err(|_| "Commit ACK-loss chain length does not fit u64")?;
    require(
        loss.request_id == commit_exchange.request_id
            && loss.request_jsonl == commit_exchange.request_jsonl
            && loss.discarded_response_jsonl == commit_exchange.response_jsonl
            && loss.replay_response_jsonl == commit_exchange.response_jsonl
            && accepted_after == commit_exchange.receipt_sequence,
        "Commit ACK-loss observation did not bind the same raw Commit exchange",
    )
}

fn exchange_for_advance<'a>(
    report: &'a LogicalRequestAdmissionReport,
    advance: &AdmissionStagedAdvanceEvidence,
) -> Result<&'a NativeJsonlExchange, String> {
    let sequence = advance.native_sequence.ok_or("staged native sequence is absent")?;
    let exchange = report
        .nexus
        .native_chain
        .iter()
        .find(|exchange| exchange.receipt_sequence == sequence)
        .ok_or("staged native receipt is absent from the raw chain")?;
    require(
        advance.native_request_sha256.as_deref() == Some(exchange.request_sha256.as_str())
            && advance.native_receipt_sha256.as_deref() == Some(exchange.receipt_sha256.as_str()),
        "staged hashes do not match the raw native chain",
    )?;
    Ok(exchange)
}

fn validate_snapshot_and_receipts(
    report: &LogicalRequestAdmissionReport,
    semantics: &ExpectedAdmissionSemantics,
) -> Result<(), String> {
    let key = report.nexus.freeze.key;
    let snapshot = &report.runtime.snapshot;
    let body = &snapshot.body;
    let expected_profile_version = SchemaVersion::new(1, 0);
    let expected_profile_digest =
        canonical_digest(&CooperativeHandoffProfile::v1(vec![ExtensionSupport {
            id: LOGICAL_REQUEST_EXTENSION_ID,
            version: LOGICAL_REQUEST_EXTENSION_VERSION,
        }]))
        .map_err(debug)?;
    require(
        *snapshot == semantics.snapshot,
        "portable snapshot was not the exact independently rebuilt source export",
    )?;
    validate_snapshot(
        snapshot,
        &SnapshotExpectations {
            component_digest: semantics.component_digest,
            profile_digest: expected_profile_digest,
            profile_version: expected_profile_version,
            supported_extensions: vec![ExtensionSupport {
                id: LOGICAL_REQUEST_EXTENSION_ID,
                version: LOGICAL_REQUEST_EXTENSION_VERSION,
            }],
            destination: key.destination,
        },
    )
    .map_err(debug)?;
    let destination_prepared_state = &semantics.destination_prepared_state;
    let prepared_destination = destination_prepared_state
        .prepared_destination
        .as_ref()
        .ok_or("destination prepared state omitted prepared bindings")?;
    require(
        report.runtime.destination_prepared_state == *destination_prepared_state
            && state_digest(destination_prepared_state).map_err(debug)?
                == report.runtime.destination_prepared.state_digest,
        "destination prepared state was not the exact semantic projection of the snapshot",
    )?;
    require(
        semantics.lease_request.request_digest
            == report.runtime.destination_prepared.lease_commit_request_digest,
        "DestinationPrepared lease-commit request digest was not independently derived",
    )?;
    let intent_ref = report.ownership.intent.receipt_ref().map_err(debug)?;
    let visa_freeze_ref = report.runtime.visa_freeze.receipt_ref().map_err(debug)?;
    let freeze_ref = report.nexus.freeze.receipt_ref().map_err(debug)?;
    let destination_ref = report.runtime.destination_prepared.receipt_ref().map_err(debug)?;
    let prepared_ref = report.ownership.prepared.receipt_ref().map_err(debug)?;
    let commit_ref = report.ownership.commit.receipt_ref().map_err(debug)?;
    let closure_ref = report.nexus.closure.receipt_ref().map_err(debug)?;
    let source_fence_ref = report.runtime.source_fence.receipt_ref().map_err(debug)?;
    let reserve_request = OwnershipReserveRequest { key, expected_state_sequence: 0 };
    let reserve_request_digest =
        joint_handoff_core::canonical_digest(&reserve_request).map_err(debug)?;
    let reservation_digest = joint_handoff_core::canonical_digest(&(
        b"ownership-reservation".as_slice(),
        &reserve_request,
    ))
    .map_err(debug)?;
    let mut reservation_bytes = [0_u8; 16];
    reservation_bytes.copy_from_slice(&reservation_digest.0[..16]);
    let expected_reservation = Identity::from_bytes(reservation_bytes);
    let expected_commit_root = joint_handoff_core::canonical_digest(&(
        b"vISA reference ownership decision v1".as_slice(),
        key,
        expected_reservation,
        b"commit".as_slice(),
        3_u64,
    ))
    .map_err(debug)?;
    let expected_mapping = joint_handoff_core::JointMappingManifest {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        key,
        visa_operation_cohort_digest: canonical_digest(&body.operations).map_err(debug)?,
        effect_scope: joint_handoff_core::EffectScopeVersion {
            registry_instance: report.nexus.freeze.registry_instance,
            scope_id: report.nexus.freeze.scope_id,
            scope_generation: report.nexus.freeze.scope_generation,
            authority_epoch: report.nexus.freeze.authority_epoch,
            freeze_generation: report.nexus.freeze.freeze_generation,
        },
        effect_cohort_digest: report.nexus.freeze.effect_cohort_digest,
        domain_bindings_manifest_digest: report.nexus.freeze.domain_bindings_digest,
        ownership_service: joint_handoff_core::OwnershipVersion {
            service_id: report.runtime.issuer_set.ownership.issuer,
            service_incarnation: report.runtime.issuer_set.ownership.issuer_incarnation,
            log_sequence: report.ownership.intent.header.sequence,
        },
        protocol_revision: 1,
    };
    let expected_mapping_digest =
        joint_handoff_core::canonical_digest(&expected_mapping).map_err(debug)?;
    let expected_bindings = joint_handoff_core::PreparedBindings {
        prepare_intent_receipt_digest: intent_ref.digest,
        visa_freeze_receipt_digest: visa_freeze_ref.digest,
        effect_freeze_receipt_digest: freeze_ref.digest,
        snapshot: report.runtime.destination_prepared.snapshot.snapshot,
        snapshot_integrity_digest: report.runtime.destination_prepared.snapshot.integrity,
        source_journal_position: report
            .runtime
            .destination_prepared
            .snapshot
            .source_journal_position,
        source_state_digest: report.runtime.visa_freeze.state_digest,
        component_digest: report.runtime.destination_prepared.snapshot.component_digest,
        profile_digest: report.runtime.destination_prepared.snapshot.profile_digest,
        destination_prepared_receipt_digest: destination_ref.digest,
        destination_state_digest: report.runtime.destination_prepared.state_digest,
        prepared_authorities_digest: report.runtime.destination_prepared.authorities_digest,
        prepared_bindings_digest: report.runtime.destination_prepared.bindings_digest,
        effect_cohort_manifest_digest: report.nexus.freeze.effect_cohort_digest,
        joint_mapping_manifest_digest: expected_mapping_digest,
    };
    require(
        snapshot.version == CONTRACT_VERSION
            && body.version == CONTRACT_VERSION
            && body.profile_version == expected_profile_version
            && body.snapshot.handoff == key.handoff
            && body.source_node == key.source
            && body.component == key.continuity_unit
            && body.source_lease_epoch == key.expected_epoch
            && body.component_digest == semantics.component_digest
            && body.profile_digest == expected_profile_digest
            && body.operations == semantics.source_start_state.operations
            && body.extensions == semantics.source_start_state.extensions
            && report.source.source_journal_position == EXPECTED_SOURCE_START_POSITION
            && body.snapshot.journal_position == EXPECTED_SNAPSHOT_POSITION
            && snapshot.integrity == snapshot_integrity(body).map_err(debug)?
            && report.ownership.intent.key == key
            && report.ownership.intent.reservation == expected_reservation
            && report.ownership.intent.intent_revision == 1
            && report.ownership.intent.request_digest == reserve_request_digest
            && report.runtime.visa_freeze.key == key
            && report.runtime.visa_freeze.intent == intent_ref
            && report.runtime.visa_freeze.journal_position == body.snapshot.journal_position
            && report.runtime.visa_freeze.state_digest
                == state_digest(&semantics.exported_source_state).map_err(debug)?
            && report.runtime.visa_freeze.portable_state_digest
                == canonical_digest(&body.portable_state).map_err(debug)?,
        "VisaFreeze does not bind the exact portable snapshot",
    )?;
    require(
        report.runtime.destination_prepared.key == key
            && report.runtime.destination_prepared.intent == intent_ref
            && report.runtime.destination_prepared.visa_freeze == visa_freeze_ref
            && report.runtime.destination_prepared.nexus_freeze == freeze_ref
            && report.runtime.destination_prepared.snapshot.snapshot == body.snapshot.snapshot
            && report.runtime.destination_prepared.snapshot.integrity == snapshot.integrity
            && report.runtime.destination_prepared.snapshot.body_digest
                == canonical_digest(body).map_err(debug)?
            && report.runtime.destination_prepared.snapshot.source_journal_position
                == body.snapshot.journal_position
            && report.runtime.destination_prepared.snapshot.component_digest
                == body.component_digest
            && report.runtime.destination_prepared.snapshot.profile_digest == body.profile_digest,
        "DestinationPrepared does not bind the exact source snapshot and freezes",
    )?;
    require(
        report.ownership.prepared.key == key
            && report.ownership.prepared.reservation == report.ownership.intent.reservation
            && report.ownership.prepared.intent == intent_ref
            && report.ownership.prepared.visa_freeze == visa_freeze_ref
            && report.ownership.prepared.nexus_freeze == freeze_ref
            && report.ownership.prepared.destination_prepared == destination_ref
            && report.ownership.prepared.bindings == expected_bindings
            && report.ownership.prepared.prepared_revision == 2
            && report.ownership.commit_request.key == key
            && report.ownership.commit_request.reservation == report.ownership.intent.reservation
            && report.ownership.commit_request.prepared == prepared_ref
            && report.ownership.commit_request.expected_state_sequence == 2
            && report.ownership.commit == report.ownership.queried_commit
            && report.ownership.commit == report.ownership.retried_commit
            && report.ownership.commit.key == key
            && report.ownership.commit.reservation == report.ownership.intent.reservation
            && report.ownership.commit.prepared == prepared_ref
            && report.ownership.commit.prepared_revision == 2
            && report.ownership.commit.decision_sequence == 3
            && report.ownership.commit.non_equivocation_root == expected_commit_root
            && report.ownership.journal_mode.eq_ignore_ascii_case("wal")
            && report.ownership.synchronous == 2
            && report.ownership.acknowledgement_error == "acknowledgement_lost"
            && report.ownership.commit_ack_lost_after_durable_write
            && report.ownership.reopened_query_exact
            && report.ownership.exact_retry,
        "ownership ACK-loss recovery or exact receipt lineage is inconsistent",
    )?;
    require(
        report.runtime.destination_prepared.prepared_destination_digest
            == canonical_digest(prepared_destination).map_err(debug)?
            && report.runtime.destination_prepared.authorities_digest
                == canonical_digest(&prepared_destination.authorities).map_err(debug)?
            && report.runtime.destination_prepared.bindings_digest
                == canonical_digest(&prepared_destination.bindings).map_err(debug)?
            && report.runtime.destination_prepared.joint_mapping_manifest_digest
                == expected_mapping_digest,
        "DestinationPrepared digests did not bind the restored prepared state and mapping",
    )?;
    require(
        report.nexus.closure.key == key
            && report.nexus.closure.commit == commit_ref
            && report.nexus.closure.nexus_freeze == freeze_ref
            && report.runtime.source_fence.key == key
            && report.runtime.source_fence.commit == commit_ref
            && report.runtime.source_fence.closure == closure_ref
            && report.runtime.destination_activation.key == key
            && report.runtime.destination_activation.commit == commit_ref
            && report.runtime.destination_activation.closure == closure_ref
            && report.runtime.destination_activation.source_fence == source_fence_ref,
        "closure, source fence, or destination activation changed causal refs",
    )?;
    require(
        report.nexus.freeze.disposition == FreezeDisposition::ReadyToCommit
            && report.nexus.freeze.counts == report.nexus.frozen_counts
            && report.nexus.freeze.counts.registered == 1
            && report.nexus.freeze.counts.committed == 1
            && report.nexus.freeze.counts.aborted == 0
            && report.nexus.freeze.counts.unresolved == 0
            && report.nexus.freeze.counts.tombstones == 0,
        "Nexus frozen cohort facts are inconsistent",
    )
}

fn validate_projection(report: &LogicalRequestAdmissionReport) -> Result<(), String> {
    let records = decode_projection(&report.runtime.joint_projection)?;
    let native_records = records
        .iter()
        .filter_map(|record| {
            let JointProjectionRecordKind::NativeReceipt(native) = &record.kind else {
                return None;
            };
            Some(native)
        })
        .collect::<Vec<_>>();
    require(
        native_records.len() == report.runtime.receipt_material.len(),
        "joint transcript and receipt materials have different lengths",
    )?;
    for (native, material) in native_records.iter().zip(&report.runtime.receipt_material) {
        require(
            native.request.as_slice() == material.issuance_request
                && native.envelope.as_slice() == material.envelope
                && native.payload.as_slice() == material.payload
                && receipt_kind_name(native.kind) == material.kind,
            "receipt material does not match the durable joint record",
        )?;
        let peer_expected = matches!(
            native.kind,
            ReceiptKind::PrepareIntent
                | ReceiptKind::NexusFreeze
                | ReceiptKind::OwnershipPrepared
                | ReceiptKind::OwnershipCommit
                | ReceiptKind::ClosureProgress
                | ReceiptKind::Closure
        );
        require(
            material.peer_invocation.is_some() == peer_expected,
            "receipt material mischaracterized its real peer invocation",
        )?;
    }
    validate_receipt_material_bindings(report, &native_records)?;
    validate_local_projection_bindings(report, &records)?;
    let log = ReportProjectionLog { head: report.runtime.joint_projection.head, records };
    let authenticator =
        expected_admission_authenticator(report.run_identity, report.nexus.freeze.key)?;
    let session = DurableJointSession::recover(
        log,
        authenticator.clone(),
        report.nexus.freeze.key,
        authenticator.issuers,
    )
    .map_err(debug)?;
    require(
        session.head() == Some(report.runtime.joint_projection.head)
            && session.state().state().phase == joint_handoff_core::JointPhase::DestinationActive
            && session.replay_source_fence_attempt().is_none()
            && session.replay_destination_activation_attempt().is_none(),
        "durable joint transcript did not replay to completed activation",
    )
}

fn validate_receipt_material_bindings(
    report: &LogicalRequestAdmissionReport,
    native_records: &[&NativeReceiptRecord],
) -> Result<(), String> {
    let key = report.nexus.freeze.key;
    let intent_ref = report.ownership.intent.receipt_ref().map_err(debug)?;
    let visa_freeze_ref = report.runtime.visa_freeze.receipt_ref().map_err(debug)?;
    let freeze_ref = report.nexus.freeze.receipt_ref().map_err(debug)?;
    let destination_ref = report.runtime.destination_prepared.receipt_ref().map_err(debug)?;
    let commit_ref = report.ownership.commit.receipt_ref().map_err(debug)?;
    let freeze_request = EffectFreezeRequest {
        key,
        intent: report.ownership.intent.clone(),
        registry_instance: report.nexus.freeze.registry_instance,
        scope_id: report.nexus.freeze.scope_id,
        scope_generation: report.nexus.freeze.scope_generation,
        authority_epoch: report.nexus.freeze.authority_epoch,
        freeze_generation: report.nexus.freeze.freeze_generation,
    };
    let freeze_request_bytes = joint_bytes(&freeze_request).map_err(debug)?;
    let seal_request = OwnershipSealRequest {
        key,
        reservation: report.ownership.intent.reservation,
        intent: intent_ref,
        visa_freeze: visa_freeze_ref,
        effect_freeze: freeze_ref,
        destination_prepared: destination_ref,
        bindings: report.ownership.prepared.bindings,
        expected_state_sequence: 1,
    };
    let reserve_request = OwnershipReserveRequest { key, expected_state_sequence: 0 };
    let reserve_request_bytes = joint_bytes(&reserve_request).map_err(debug)?;
    let seal_request_bytes = joint_bytes(&seal_request).map_err(debug)?;
    let commit_request_bytes = joint_bytes(&report.ownership.commit_request).map_err(debug)?;
    let freeze_token = EffectFreezeToken {
        key,
        reservation: report.ownership.intent.reservation,
        registry_instance: report.nexus.freeze.registry_instance,
        scope_id: report.nexus.freeze.scope_id,
        scope_generation: report.nexus.freeze.scope_generation,
        authority_epoch: report.nexus.freeze.authority_epoch,
        freeze_generation: report.nexus.freeze.freeze_generation,
        freeze: freeze_ref,
    };

    let mut seen = Vec::new();
    let mut close_step = 0_u64;
    let mut close_revision = 0_u64;
    let mut closed = false;
    for (native, material) in native_records.iter().zip(&report.runtime.receipt_material) {
        let (command, peer_invocation) = match native.kind {
            ReceiptKind::PrepareIntent => (
                admission_identity(report.run_identity, b"record-prepare-intent")?,
                Some(reserve_request_bytes.as_slice()),
            ),
            ReceiptKind::VisaFreeze => {
                (admission_identity(report.run_identity, b"record-visa-freeze")?, None)
            }
            ReceiptKind::NexusFreeze => (
                admission_identity(report.run_identity, b"record-nexus-freeze")?,
                Some(freeze_request_bytes.as_slice()),
            ),
            ReceiptKind::DestinationPrepared => {
                (admission_identity(report.run_identity, b"record-destination-prepared")?, None)
            }
            ReceiptKind::OwnershipPrepared => (
                admission_identity(report.run_identity, b"record-ownership-prepared")?,
                Some(seal_request_bytes.as_slice()),
            ),
            ReceiptKind::OwnershipCommit => (
                admission_identity(report.run_identity, b"record-ownership-commit")?,
                Some(commit_request_bytes.as_slice()),
            ),
            ReceiptKind::ClosureProgress | ReceiptKind::Closure => {
                require(!closed, "joint transcript appended closure material after Closure")?;
                close_step = close_step.checked_add(1).ok_or("closure step overflow")?;
                let label = format!("record-nexus-close-{close_step}");
                let command = admission_identity(report.run_identity, label.as_bytes())?;
                let request = EffectCloseRequest {
                    token: freeze_token,
                    commit: report.ownership.commit.clone(),
                    expected_closure_revision: close_revision,
                };
                let invocation = joint_bytes(&request).map_err(debug)?;
                let next_revision =
                    close_revision.checked_add(1).ok_or("closure revision overflow")?;
                if native.kind == ReceiptKind::ClosureProgress {
                    let progress: ClosureProgressReceipt =
                        joint_from_bytes(native.payload.as_slice()).map_err(debug)?;
                    require(
                        progress.key == key
                            && progress.commit == commit_ref
                            && progress.nexus_freeze == freeze_ref
                            && progress.closure_revision == next_revision,
                        "ClosureProgress did not bind the exact revisioned close request",
                    )?;
                    validate_typed_material(
                        native,
                        material,
                        &progress,
                        command,
                        Some(invocation.as_slice()),
                    )?;
                } else {
                    require(
                        report.nexus.closure.closure_revision == next_revision,
                        "Closure did not advance the exact close revision",
                    )?;
                    validate_typed_material(
                        native,
                        material,
                        &report.nexus.closure,
                        command,
                        Some(invocation.as_slice()),
                    )?;
                    closed = true;
                }
                close_revision = next_revision;
                seen.push(native.kind);
                continue;
            }
            ReceiptKind::VisaSourceFence => {
                (admission_identity(report.run_identity, b"record-visa-source-fence")?, None)
            }
            ReceiptKind::VisaDestinationActivation => (
                admission_identity(report.run_identity, b"record-visa-destination-activation")?,
                None,
            ),
            ReceiptKind::OwnershipAbort
            | ReceiptKind::NexusThaw
            | ReceiptKind::RetainedTombstone
            | ReceiptKind::VisaSourceResume => {
                return Err(
                    "bounded Commit transcript contained an abort or tombstone receipt".to_owned()
                );
            }
        };
        match native.kind {
            ReceiptKind::PrepareIntent => validate_typed_material(
                native,
                material,
                &report.ownership.intent,
                command,
                peer_invocation,
            )?,
            ReceiptKind::VisaFreeze => validate_typed_material(
                native,
                material,
                &report.runtime.visa_freeze,
                command,
                peer_invocation,
            )?,
            ReceiptKind::NexusFreeze => validate_typed_material(
                native,
                material,
                &report.nexus.freeze,
                command,
                peer_invocation,
            )?,
            ReceiptKind::DestinationPrepared => validate_typed_material(
                native,
                material,
                &report.runtime.destination_prepared,
                command,
                peer_invocation,
            )?,
            ReceiptKind::OwnershipPrepared => validate_typed_material(
                native,
                material,
                &report.ownership.prepared,
                command,
                peer_invocation,
            )?,
            ReceiptKind::OwnershipCommit => validate_typed_material(
                native,
                material,
                &report.ownership.commit,
                command,
                peer_invocation,
            )?,
            ReceiptKind::VisaSourceFence => validate_typed_material(
                native,
                material,
                &report.runtime.source_fence,
                command,
                peer_invocation,
            )?,
            ReceiptKind::VisaDestinationActivation => validate_typed_material(
                native,
                material,
                &report.runtime.destination_activation,
                command,
                peer_invocation,
            )?,
            ReceiptKind::ClosureProgress
            | ReceiptKind::Closure
            | ReceiptKind::OwnershipAbort
            | ReceiptKind::NexusThaw
            | ReceiptKind::RetainedTombstone
            | ReceiptKind::VisaSourceResume => unreachable!(),
        }
        seen.push(native.kind);
    }
    let required = [
        ReceiptKind::PrepareIntent,
        ReceiptKind::VisaFreeze,
        ReceiptKind::NexusFreeze,
        ReceiptKind::DestinationPrepared,
        ReceiptKind::OwnershipPrepared,
        ReceiptKind::OwnershipCommit,
        ReceiptKind::Closure,
        ReceiptKind::VisaSourceFence,
        ReceiptKind::VisaDestinationActivation,
    ];
    require(
        closed
            && close_revision == report.nexus.closure.closure_revision
            && required.iter().all(|kind| seen.iter().filter(|seen| *seen == kind).count() == 1),
        "joint transcript omitted or duplicated a required top-level receipt",
    )
}

fn validate_typed_material<T>(
    native: &NativeReceiptRecord,
    material: &AdmissionReceiptMaterial,
    receipt: &T,
    command: Identity,
    peer_invocation: Option<&[u8]>,
) -> Result<(), String>
where
    T: TypedReceipt + serde::Serialize,
{
    let payload = joint_bytes(receipt).map_err(debug)?;
    let request = joint_bytes(&ReceiptRequest::for_receipt(command, receipt)).map_err(debug)?;
    require(
        native.kind == T::KIND
            && native.command_identity == command
            && native.payload.as_slice() == payload
            && material.payload == payload
            && native.request.as_slice() == request
            && material.issuance_request == request
            && material.peer_invocation.as_deref() == peer_invocation,
        "typed receipt material changed payload, command, issuance request, or peer invocation",
    )
}

fn validate_local_projection_bindings(
    report: &LogicalRequestAdmissionReport,
    records: &[JointProjectionRecord],
) -> Result<(), String> {
    let key = report.nexus.freeze.key;
    let commit_ref = report.ownership.commit.receipt_ref().map_err(debug)?;
    let closure_ref = report.nexus.closure.receipt_ref().map_err(debug)?;
    let source_fence_ref = report.runtime.source_fence.receipt_ref().map_err(debug)?;
    let freeze_request = EffectFreezeRequest {
        key,
        intent: report.ownership.intent.clone(),
        registry_instance: report.nexus.freeze.registry_instance,
        scope_id: report.nexus.freeze.scope_id,
        scope_generation: report.nexus.freeze.scope_generation,
        authority_epoch: report.nexus.freeze.authority_epoch,
        freeze_generation: report.nexus.freeze.freeze_generation,
    };
    let freeze_request_bytes = joint_bytes(&freeze_request).map_err(debug)?;
    let source_completion_command =
        admission_identity(report.run_identity, b"record-visa-source-fence")?;
    let source_fence_template = joint_handoff_core::VisaSourceFenceReceipt {
        header: report.runtime.source_fence.header,
        key,
        commit: commit_ref,
        closure: closure_ref,
        journal_position: JournalPosition::ORIGIN,
        state_digest: Digest::ZERO,
    };
    let source_completion_digest =
        ReceiptRequest::for_receipt(source_completion_command, &source_fence_template)
            .digest()
            .map_err(debug)?;
    let expected_destination_idempotency = IdempotencyKey::from_bytes(
        admission_identity(report.run_identity, b"destination-lease-commit-idempotency")?.0,
    );

    let mut effect_freeze_count = 0_usize;
    let mut source_attempt = None;
    let mut source_observed = None;
    let mut destination_attempt = None;
    let mut destination_observed = None;
    for record in records {
        match &record.kind {
            JointProjectionRecordKind::NativeReceipt(_) => {}
            JointProjectionRecordKind::EffectFreezeAttempt(attempt) => {
                effect_freeze_count += 1;
                require(
                    attempt.attempt
                        == admission_identity(report.run_identity, b"attempt-nexus-freeze")?
                        && attempt.invocation.as_slice() == freeze_request_bytes,
                    "EffectFreezeAttempt did not bind the exact run identity and invocation",
                )?;
            }
            JointProjectionRecordKind::SourceFenceAttempt(attempt) => {
                require(source_attempt.is_none(), "SourceFenceAttempt was duplicated")?;
                require(
                    attempt.ownership_commit == commit_ref
                        && attempt.closure == closure_ref
                        && attempt.fence_command
                            == admission_identity(report.run_identity, b"source-fence-command")?
                        && attempt.fence_operation
                            == admission_identity(report.run_identity, b"source-fence-operation")?
                        && attempt.expected_pre_state_digest
                            == report.runtime.visa_freeze.state_digest
                        && attempt.expected_pre_journal_position
                            == report.runtime.visa_freeze.journal_position
                        && attempt.completion_request_digest == source_completion_digest,
                    "SourceFenceAttempt did not bind the exact source projection",
                )?;
                source_attempt = Some(record.canonical_digest().map_err(debug)?);
            }
            JointProjectionRecordKind::SourceFenceObserved(observed) => {
                require(source_observed.is_none(), "SourceFenceObserved was duplicated")?;
                source_observed = Some(*observed);
            }
            JointProjectionRecordKind::DestinationActivationAttempt(attempt) => {
                require(
                    destination_attempt.is_none(),
                    "DestinationActivationAttempt was duplicated",
                )?;
                require(
                    attempt.ownership_commit == commit_ref
                        && attempt.closure == closure_ref
                        && attempt.source_fence == source_fence_ref
                        && attempt.joint_command
                            == admission_identity(
                                report.run_identity,
                                b"destination-activation-command",
                            )?
                        && attempt.commit_command
                            == admission_identity(
                                report.run_identity,
                                b"destination-lease-commit-command",
                            )?
                        && attempt.commit_operation
                            == admission_identity(
                                report.run_identity,
                                b"destination-lease-commit-operation",
                            )?
                        && attempt.commit_idempotency == expected_destination_idempotency
                        && attempt.commit_request_digest
                            == report.runtime.destination_prepared.lease_commit_request_digest
                        && attempt.resume_command
                            == admission_identity(
                                report.run_identity,
                                b"destination-resume-after-activation",
                            )?
                        && attempt.expected_pre_state_digest
                            == report.runtime.destination_prepared.state_digest
                        && attempt.expected_pre_journal_position
                            == report.runtime.destination_prepared.journal_position,
                    "DestinationActivationAttempt did not bind the exact guarded projection",
                )?;
                destination_attempt = Some(record.canonical_digest().map_err(debug)?);
            }
            JointProjectionRecordKind::DestinationActivationPreviewObserved(observed) => {
                require(
                    destination_observed.is_none(),
                    "DestinationActivationPreviewObserved was duplicated",
                )?;
                destination_observed = Some(*observed);
            }
            JointProjectionRecordKind::BeginDestinationActivation { .. }
            | JointProjectionRecordKind::SourceAbortAttempt(_)
            | JointProjectionRecordKind::SourceAbortObserved(_) => {
                return Err(
                    "Commit transcript contained a legacy or abort local projection".to_owned()
                );
            }
        }
    }
    let source_attempt_digest = source_attempt.ok_or("SourceFenceAttempt is absent")?;
    let source_observed = source_observed.ok_or("SourceFenceObserved is absent")?;
    let destination_attempt_digest =
        destination_attempt.ok_or("DestinationActivationAttempt is absent")?;
    let destination_observed =
        destination_observed.ok_or("DestinationActivationPreviewObserved is absent")?;
    require(
        effect_freeze_count == 1
            && source_observed.attempt_record_digest == source_attempt_digest
            && source_observed.journal_position == report.runtime.source_fence.journal_position
            && source_observed.state_digest == report.runtime.source_fence.state_digest
            && destination_observed.attempt_record_digest == destination_attempt_digest
            && destination_observed.journal_position
                == report.runtime.destination_activation.journal_position
            && destination_observed.state_digest
                == report.runtime.destination_activation.state_digest
            && report.runtime.destination_activation.activation_attempt_record_digest
                == destination_attempt_digest
            && report.runtime.destination_activation.activation_command
                == admission_identity(report.run_identity, b"destination-activation-command")?
            && report.runtime.destination_activation.resume_command
                == admission_identity(report.run_identity, b"destination-resume-after-activation")?,
        "local projection observations or activation receipt changed attempt identity",
    )
}

fn expected_destination_commit_request(
    run: Identity,
    state: &CanonicalState,
) -> Result<EffectRequest, String> {
    let prepared = state
        .prepared_destination
        .as_ref()
        .ok_or("destination prepared state omitted PreparedDestination")?;
    let operation = admission_identity(run, b"destination-lease-commit-operation")?;
    let idempotency_key = IdempotencyKey::from_bytes(
        admission_identity(run, b"destination-lease-commit-idempotency")?.0,
    );
    let resume_guard = admission_identity(run, b"destination-resume-after-activation")?;
    let subject = EntityRef::new(state.component.identity, prepared.component_generation);
    let mut authorities = prepared.authorities.iter().filter(|grant| {
        grant.subject == subject
            && grant.resource == subject
            && grant.status == AuthorityStatus::Active
            && grant.rights.contains(Rights::HANDOFF)
    });
    let authority = authorities
        .next()
        .ok_or("destination prepared state omitted its handoff authority")?
        .authority;
    require(authorities.next().is_none(), "destination handoff authority is ambiguous")?;
    let kind = EffectKind::LeaseCommit {
        handoff: prepared.handoff,
        snapshot: prepared.snapshot,
        destination: prepared.destination,
        expected_epoch: prepared.expected_epoch,
        next_epoch: prepared.next_epoch,
    };
    let causal_parent = Some(resume_guard);
    let request_digest = canonical_digest(&(
        operation,
        idempotency_key,
        causal_parent,
        prepared.destination,
        subject,
        authority,
        kind.clone(),
    ))
    .map_err(debug)?;
    Ok(EffectRequest {
        operation,
        idempotency_key,
        causal_parent,
        node: prepared.destination,
        subject,
        resource: subject,
        authority,
        lease_epoch: prepared.expected_epoch,
        request_digest,
        kind,
    })
}

fn expected_destination_activation_state(
    report: &LogicalRequestAdmissionReport,
    semantics: &ExpectedAdmissionSemantics,
) -> Result<CanonicalState, String> {
    let prepared_state = &semantics.destination_prepared_state;
    let request = &semantics.lease_request;
    let activation = &report.runtime.destination_activation_state;
    require(
        activation.operations.len() == prepared_state.operations.len() + 1
            && activation.operations.starts_with(&prepared_state.operations),
        "destination activation did not append exactly one lease-commit operation",
    )?;
    let lease_record = activation
        .operations
        .last()
        .ok_or("destination activation omitted lease-commit operation")?;
    require(
        lease_record.request == *request
            && lease_record.outcome.as_ref() == Some(&semantics.lease_outcome),
        "destination activation lease-commit request or outcome did not match the independently rebuilt canonical values",
    )?;
    let resumed = Event::new(
        admission_identity(report.run_identity, b"destination-resume-after-activation")?,
        EventKind::JointDestinationResumed {
            activation_record_digest: report
                .runtime
                .destination_activation
                .activation_attempt_record_digest,
        },
    );
    applied_state(&semantics.lease_committed_state, &resumed)
}

fn expected_source_terminal_state(
    report: &LogicalRequestAdmissionReport,
    semantics: &ExpectedAdmissionSemantics,
) -> Result<CanonicalState, String> {
    let key = report.nexus.freeze.key;
    let decision = expected_receipt_evidence(
        report.ownership.commit.receipt_ref().map_err(debug)?,
        EvidenceKind::AuthorityDecision,
    )?;
    let closure = expected_receipt_evidence(
        report.nexus.closure.receipt_ref().map_err(debug)?,
        EvidenceKind::SourceFence,
    )?;
    let outcome = EffectOutcome::Succeeded {
        result: EffectResult::LeaseAdvanced {
            owner: key.destination,
            epoch: key.next_epoch,
            source_fence: closure,
        },
        evidence: decision,
    };
    let event = Event::new(
        admission_identity(report.run_identity, b"source-fence-command")?,
        EventKind::HandoffCommitted {
            operation: admission_identity(report.run_identity, b"source-fence-operation")?,
            handoff: key.handoff,
            snapshot: semantics.snapshot.body.snapshot.snapshot,
            source: key.source,
            destination: key.destination,
            previous_epoch: key.expected_epoch,
            new_epoch: key.next_epoch,
            outcome,
        },
    );
    applied_state(&semantics.exported_source_state, &event)
}

fn expected_receipt_evidence(
    receipt: joint_handoff_core::ReceiptRef,
    kind: EvidenceKind,
) -> Result<EvidenceRef, String> {
    require(
        receipt.digest != Digest::ZERO && !receipt.handoff.is_zero(),
        "receipt evidence source was empty",
    )?;
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&receipt.digest.0[..16]);
    let identity = Identity::from_bytes(identity);
    require(!identity.is_zero(), "receipt evidence identity was zero")?;
    Ok(EvidenceRef { identity, kind, digest: receipt.digest })
}

fn expected_reconcile_outcome(request: &EffectRequest) -> Result<EffectOutcome, String> {
    let response = LogicalResponseMetadata {
        size: u32::try_from(EXPECTED_LOGICAL_RESPONSE.len())
            .map_err(|_| "expected logical response is too large")?,
        digest: canonical_digest(EXPECTED_LOGICAL_RESPONSE).map_err(debug)?,
    };
    let result = EffectResult::Profile {
        profile: LOGICAL_REQUEST_EXTENSION_ID,
        payload: encode_logical_request_result(&LogicalRequestResult::Reconciled {
            observation: LogicalRequestObservation {
                phase: LogicalRequestPhase::Completed,
                response: Some(response),
                rejection: None,
            },
        })
        .map_err(debug)?,
    };
    expected_provider_outcome(9, request, result)
}

fn validate_terminal_states(
    report: &LogicalRequestAdmissionReport,
    semantics: &ExpectedAdmissionSemantics,
) -> Result<(), String> {
    let key = report.nexus.freeze.key;
    let source = &report.runtime.source_terminal_state;
    let activation = &report.runtime.destination_activation_state;
    let destination = &report.runtime.destination_terminal_state;
    let expected_source = expected_source_terminal_state(report, semantics)?;
    let expected_activation = expected_destination_activation_state(report, semantics)?;
    require(
        *source == expected_source
            && report.runtime.source_fence.journal_position == EXPECTED_SOURCE_FENCE_POSITION
            && source.phase == HandoffPhase::Committed
            && source.component == key.continuity_unit
            && source.activation.node == key.source
            && source.activation.role == ActivationRole::Source
            && source.activation.status == ActivationStatus::Fenced
            && source.ownership.owner == Some(key.destination)
            && source.ownership.epoch == key.next_epoch
            && state_digest(source).map_err(debug)? == report.runtime.source_fence.state_digest,
        "source terminal state is not exact Committed/Source/Fenced",
    )?;
    require(
        activation.phase == HandoffPhase::Running
            && activation.component.identity == key.continuity_unit.identity
            && activation.component.generation.0 == key.continuity_unit.generation.0 + 1
            && activation.component_digest == report.runtime.snapshot.body.component_digest
            && activation.profile_digest == report.runtime.snapshot.body.profile_digest
            && activation.activation.node == key.destination
            && activation.activation.role == ActivationRole::Destination
            && activation.activation.status == ActivationStatus::Active
            && activation.ownership.owner == Some(key.destination)
            && activation.ownership.epoch == key.next_epoch
            && state_digest(activation).map_err(debug)?
                == report.runtime.destination_activation.state_digest
            && destination.phase == HandoffPhase::Running
            && destination.activation.role == ActivationRole::Destination
            && destination.activation.status == ActivationStatus::Active
            && destination.ownership.owner == Some(key.destination)
            && destination.ownership.epoch == key.next_epoch,
        "destination terminal state is not exact Running/Destination/Active",
    )?;
    require(
        expected_activation == *activation,
        "destination activation was not the exact prepare -> lease commit -> guarded resume projection",
    )?;
    require(
        report.runtime.destination_guest_restored_before_activation_receipt
            && report.runtime.destination_release_blocked_before_completion
            && report.destination.source_start_absent_before_reconcile
            && report.destination.logical_ledger_absent_before_reconcile
            && report.destination.portable_source_operation_present_before_reconcile
            && report.destination.reconcile_effect != report.source.source_start_effect
            && report.destination.reconcile_effect_differs_from_source_start
            && report.destination.reconcile_provider_row_present
            && report.destination.destination_ledger_revision == 2
            && !report.destination.destination_ledger_retained_request
            && report.destination.terminal_phase == "completed"
            && report.destination.remote_request_count == 2
            && report.destination.remote_execution_count == 1,
        "destination restore, no-copy boundary, or reconcile truth is inconsistent",
    )?;
    let activation_logical = canonical_logical_state(activation)?;
    let terminal_logical = canonical_logical_state(destination)?;
    let reconcile_operation =
        destination.operations.last().ok_or("destination terminal state omitted Reconcile")?;
    let mut control_idempotency = b"logical-request-reconcile-v1".to_vec();
    control_idempotency.extend_from_slice(&activation_logical.operation_id.0);
    control_idempotency
        .extend_from_slice(&activation_logical.last_operation.unwrap_or(Identity::ZERO).0);
    let binding =
        ProfileBinding::for_state(activation, LOGICAL_REQUEST_EXTENSION_ID).map_err(debug)?;
    let operation_payload =
        encode_logical_request_operation(&LogicalRequestOperation::Reconcile).map_err(debug)?;
    let expected_reconcile_request = prepare_profile_effect(
        activation,
        &binding,
        ProfileAccess::Control,
        &control_idempotency,
        operation_payload,
    )
    .map_err(debug)?;
    let expected_reconcile_outcome = expected_reconcile_outcome(&expected_reconcile_request)?;
    require(
        reconcile_operation.outcome.as_ref() == Some(&expected_reconcile_outcome),
        "destination Reconcile outcome was not the exact independently rebuilt provider result",
    )?;
    let EffectOutcome::Succeeded { result: EffectResult::Profile { profile, payload }, .. } =
        &expected_reconcile_outcome
    else {
        return Err("destination Reconcile outcome was not a successful profile result".to_owned());
    };
    let LogicalRequestResult::Reconciled { observation } =
        decode_logical_request_result(payload).map_err(debug)?
    else {
        return Err("destination Reconcile outcome used the wrong logical result".to_owned());
    };
    let request_command = Command::new(
        runtime_component_command(expected_reconcile_request.operation),
        CommandKind::RequestEffect(expected_reconcile_request.clone()),
    );
    let intent = execution_intent(activation, &request_command)?;
    let intent_state = applied_state(activation, &intent)?;
    let resolve_command = Command::new(
        runtime_derived_identity(expected_reconcile_request.operation, b"resolve")?,
        CommandKind::ResolveEffect {
            operation: expected_reconcile_request.operation,
            outcome: expected_reconcile_outcome.clone(),
        },
    );
    let resolved = committed_event(&intent_state, &resolve_command)?;
    let expected_terminal_state = applied_state(&intent_state, &resolved)?;
    require(
        expected_terminal_state == *destination
            && destination.operations.len() == activation.operations.len() + 1
            && reconcile_operation.request == expected_reconcile_request
            && reconcile_operation.request.operation == report.destination.reconcile_effect
            && *profile == LOGICAL_REQUEST_EXTENSION_ID
            && observation.phase == LogicalRequestPhase::Completed
            && activation.operations.iter().any(|record| {
                record.request == report.source.preview
                    && record.outcome.as_ref() == Some(&semantics.start_outcome)
            })
            && activation_logical.operation_id == report.source.logical_operation
            && activation_logical.phase == LogicalRequestPhase::UnknownCompletion
            && activation_logical.last_operation == Some(report.source.source_start_effect)
            && terminal_logical.operation_id == report.source.logical_operation
            && terminal_logical.phase == LogicalRequestPhase::Completed
            && terminal_logical.last_operation == Some(report.destination.reconcile_effect),
        "destination activation-to-Reconcile transition changed unrelated canonical state",
    )
}

fn canonical_logical_state(
    state: &CanonicalState,
) -> Result<visa_profile::LogicalRequestState, String> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == LOGICAL_REQUEST_EXTENSION_ID);
    let extension = matching.next().ok_or("logical-request extension is absent")?;
    require(matching.next().is_none(), "logical-request extension is duplicated")?;
    logical_request_state(extension).map_err(debug)
}

fn execution_intent(state: &CanonicalState, command: &Command) -> Result<Event, String> {
    match semantic_core::preflight(state, command) {
        Decision::Execute { intent, request } if matches!(&intent.kind, EventKind::EffectPrepared { request: actual } if actual == &request) => {
            Ok(intent)
        }
        decision => Err(format!("semantic request projection did not execute: {decision:?}")),
    }
}

fn committed_event(state: &CanonicalState, command: &Command) -> Result<Event, String> {
    match semantic_core::preflight(state, command) {
        Decision::Commit(event) => Ok(event),
        decision => Err(format!("semantic projection did not commit: {decision:?}")),
    }
}

fn applied_state(state: &CanonicalState, event: &Event) -> Result<CanonicalState, String> {
    match semantic_core::apply(state, event).map_err(debug)? {
        semantic_core::ApplyResult::Applied(next) => Ok(next),
        semantic_core::ApplyResult::Replay(_) => {
            Err("semantic projection unexpectedly replayed".to_owned())
        }
    }
}

fn runtime_derived_identity(operation: Identity, domain: &[u8]) -> Result<Identity, String> {
    let digest = canonical_digest(&(operation, domain)).map_err(debug)?;
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&digest.0[..16]);
    let identity = Identity::from_bytes(identity);
    require(!identity.is_zero(), "runtime-derived identity is zero")?;
    Ok(identity)
}

fn runtime_component_command(operation: Identity) -> Identity {
    length_prefixed_identity(&[b"visa-command-v1", &operation.0])
}

fn length_prefixed_identity(parts: &[&[u8]]) -> Identity {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    let bytes: [u8; 32] = digest.finalize().into();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&bytes[..16]);
    Identity::from_bytes(identity)
}

fn validate_database_evidence(report: &LogicalRequestAdmissionReport) -> Result<(), String> {
    let expected = [
        (&report.databases.source, "source.sqlite3", 5_u32),
        (&report.databases.destination, "destination.sqlite3", 5_u32),
        (&report.databases.ownership, "ownership.sqlite3", 2_u32),
        (&report.databases.joint_projection, "joint-projection.sqlite3", 0_u32),
    ];
    for (database, path, version) in expected {
        validate_database(database, path, version)?;
    }
    let databases = [
        &report.databases.source,
        &report.databases.destination,
        &report.databases.ownership,
        &report.databases.joint_projection,
    ];
    let distinct = databases.iter().enumerate().all(|(index, left)| {
        databases
            .iter()
            .skip(index + 1)
            .all(|right| (left.device, left.inode) != (right.device, right.inode))
    });
    require(
        distinct
            && report.databases.all_device_inode_pairs_distinct
            && report.databases.source_destination_paths_distinct,
        "SQLite evidence does not prove four independent stores",
    )
}

fn validate_database(
    database: &AdmissionDatabaseEvidence,
    path: &str,
    version: u32,
) -> Result<(), String> {
    require(
        database.path == path
            && database.user_version == version
            && database.device != 0
            && database.inode != 0
            && database.hard_link_count == 1
            && database.regular_file
            && !database.symlink
            && database.integrity_check == "ok"
            && database.foreign_key_violations == 0
            && database.runtime_journal_mode == "wal"
            && database.wal_checkpoint_busy == 0
            && database.wal_log_frames == database.wal_checkpointed_frames
            && database.archive_journal_mode == "delete"
            && database.sidecars_absent,
        "SQLite report evidence is not exact",
    )
}

fn decode_projection(
    transcript: &AdmissionJointProjectionEvidence,
) -> Result<Vec<JointProjectionRecord>, String> {
    require(
        transcript.head.sequence as usize == transcript.canonical_record_bytes.len(),
        "joint projection head length is inconsistent",
    )?;
    transcript
        .canonical_record_bytes
        .iter()
        .map(|bytes| JointProjectionRecord::from_canonical_bytes(bytes).map_err(debug))
        .collect()
}

fn decode_commands(chain: &[NativeJsonlExchange]) -> Result<Vec<PeerCommand>, String> {
    chain
        .iter()
        .map(|exchange| {
            serde_json::from_str::<PeerRequest>(exchange.request_jsonl.trim())
                .map(|request| request.command)
                .map_err(debug)
        })
        .collect()
}

fn decode_exchange(exchange: &NativeJsonlExchange) -> Result<(PeerRequest, PeerResponse), String> {
    let request_json =
        exchange.request_jsonl.strip_suffix('\n').ok_or("native request was not LF terminated")?;
    let response_json = exchange
        .response_jsonl
        .strip_suffix('\n')
        .ok_or("native response was not LF terminated")?;
    let request: PeerRequest = serde_json::from_str(request_json).map_err(debug)?;
    let response: PeerResponse = serde_json::from_str(response_json).map_err(debug)?;
    require(
        request.request_id == exchange.request_id && response.request_id == exchange.request_id,
        "native exchange request IDs changed",
    )?;
    Ok((request, response))
}

fn unique_exchange(
    chain: &[NativeJsonlExchange],
    predicate: impl Fn(&PeerCommand) -> bool,
) -> Result<&NativeJsonlExchange, String> {
    let mut found = None;
    for exchange in chain {
        let (request, _) = decode_exchange(exchange)?;
        if predicate(&request.command) {
            require(found.is_none(), "native command exchange was not unique")?;
            found = Some(exchange);
        }
    }
    found.ok_or("native command exchange is absent".to_owned())
}

fn unique_position(
    commands: &[PeerCommand],
    predicate: impl Fn(&PeerCommand) -> bool,
) -> Result<usize, String> {
    let positions = commands
        .iter()
        .enumerate()
        .filter_map(|(index, command)| predicate(command).then_some(index))
        .collect::<Vec<_>>();
    if let [position] = positions.as_slice() {
        Ok(*position)
    } else {
        Err("native command was not unique".to_owned())
    }
}

const fn process_phase_name(phase: ProcessLiveEffectPhase) -> &'static str {
    match phase {
        ProcessLiveEffectPhase::Registered => "registered",
        ProcessLiveEffectPhase::Prepared => "prepared",
        ProcessLiveEffectPhase::CommittedAwaitingOutcome => "committed_awaiting_outcome",
        ProcessLiveEffectPhase::OutcomeRecorded => "outcome_recorded",
    }
}

const fn receipt_kind_name(kind: ReceiptKind) -> &'static str {
    match kind {
        ReceiptKind::PrepareIntent => "prepare-intent",
        ReceiptKind::VisaFreeze => "visa-freeze",
        ReceiptKind::NexusFreeze => "nexus-freeze",
        ReceiptKind::DestinationPrepared => "destination-prepared",
        ReceiptKind::OwnershipPrepared => "ownership-prepared",
        ReceiptKind::OwnershipAbort => "ownership-abort",
        ReceiptKind::OwnershipCommit => "ownership-commit",
        ReceiptKind::NexusThaw => "nexus-thaw",
        ReceiptKind::ClosureProgress => "closure-progress",
        ReceiptKind::Closure => "closure",
        ReceiptKind::RetainedTombstone => "retained-tombstone",
        ReceiptKind::VisaSourceFence => "visa-source-fence",
        ReceiptKind::VisaSourceResume => "visa-source-resume",
        ReceiptKind::VisaDestinationActivation => "visa-destination-activation",
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn native_handoff_digests(
    effect_id: u64,
    effect_generation: u64,
    commit_sequence: u64,
) -> (u64, u64) {
    let cohort = native_nonzero_digest(native_digest_word(
        native_digest_word(0xcbf2_9ce4_8422_2325, effect_id),
        effect_generation,
    ));
    let mut classification = 0x8422_2325_cbf2_9ce4;
    for value in [
        effect_id,
        effect_generation,
        0, // ProductionEffectPeer uses the legacy registration domain.
        3, // EffectPhase::Committed
        2, // CreditState::Committed
        commit_sequence,
        0, // no publication ticket exists until the first CloseStep
    ] {
        classification = native_digest_word(classification, value);
    }
    (cohort, native_nonzero_digest(classification))
}

fn native_terminal_manifest_digest(effect_id: u64, effect_generation: u64) -> u64 {
    let mut digest = 0x9e37_79b9_7f4a_7c15;
    for value in [
        effect_id,
        effect_generation,
        1, // first fresh Registry terminal sequence
        1, // TerminalOutcome::Completed
        1, // one required publication was acknowledged
    ] {
        digest = native_digest_word(digest, value);
    }
    native_nonzero_digest(digest)
}

const fn native_digest_word(state: u64, value: u64) -> u64 {
    (state ^ value).wrapping_mul(0x0000_0100_0000_01b3)
}

const fn native_nonzero_digest(value: u64) -> u64 {
    if value == 0 { 1 } else { value }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReportProjectionLogError;

struct ReportProjectionLog {
    head: JointProjectionLogHead,
    records: Vec<JointProjectionRecord>,
}

impl JointProjectionLog for ReportProjectionLog {
    type Error = ReportProjectionLogError;

    fn head(&self) -> Result<Option<JointProjectionLogHead>, Self::Error> {
        Ok(Some(self.head))
    }

    fn read(&self, sequence: u64) -> Result<Option<JointProjectionRecord>, Self::Error> {
        let Some(index) = sequence.checked_sub(1).and_then(|value| usize::try_from(value).ok())
        else {
            return Ok(None);
        };
        Ok(self.records.get(index).cloned())
    }

    fn append(
        &mut self,
        _expected_head: Option<JointProjectionLogHead>,
        _record: &JointProjectionRecord,
    ) -> Result<JointProjectionAppendOutcome, JointProjectionAppendError<Self::Error>> {
        Err(JointProjectionAppendError::Backend(ReportProjectionLogError))
    }
}

fn require(condition: bool, detail: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(detail.to_owned()) }
}

fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_rebuild_uses_the_run_bound_component_digest() {
        let component_digest = Digest::from_bytes([0xa5; 32]);
        let semantics =
            ExpectedAdmissionSemantics::for_run(Identity::from_u128(91_200), component_digest)
                .unwrap();

        assert_eq!(semantics.component_digest, component_digest);
        assert_eq!(semantics.source_start_state.component_digest, component_digest);
        assert_eq!(semantics.exported_source_state.component_digest, component_digest);
        assert_eq!(semantics.snapshot.body.component_digest, component_digest);
        assert_eq!(semantics.destination_prepared_state.component_digest, component_digest);
        assert_eq!(semantics.lease_committed_state.component_digest, component_digest);
    }

    #[test]
    #[ignore = "requires VISA_ADMISSION_REPORT from a separately built exact-SHA artifact"]
    fn separately_built_admission_report_is_semantically_portable() {
        let path = std::env::var_os("VISA_ADMISSION_REPORT")
            .map(std::path::PathBuf::from)
            .expect("VISA_ADMISSION_REPORT must name the downloaded report");
        let raw = std::fs::read(path).unwrap();
        let report: LogicalRequestAdmissionReport = serde_json::from_slice(&raw).unwrap();
        let expectations = LogicalRequestAdmissionExpectations {
            run_identity: report.run_identity,
            nexus_process: report.nexus.process.clone(),
        };

        validate_logical_request_admission_report(&report, &expectations).unwrap();
    }
}
