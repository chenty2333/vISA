use std::path::PathBuf;

use contract_core::{Digest, EntityRef, Identity, LeaseEpoch, NodeIdentity};
use joint_handoff_core::{
    FreezeDisposition, JointHandoffKey, PrepareIntentReceipt, PreparedBindings,
    ReceiptIssuerIdentity, ReceiptKind, ReceiptRef, TypedReceipt,
};
use serde::{Deserialize, Serialize};
use visa_conformance::{JointEffectClassification, JointEffectRecord};

use crate::{
    EffectCloseRequest, EffectCloseResult, EffectFreezeRequest, EffectPeer, EffectPeerConfig,
    EffectPeerError, EffectPublicationRequest, EffectPublicationResult, EffectThawRequest,
    NativeJsonlExchange, OwnershipAbortRequest, OwnershipCommitRequest, OwnershipReserveRequest,
    OwnershipSealRequest, ProcessEffectPeer, ProcessEffectPeerIdentity, ProcessEffectPeerLaunch,
    ProcessServiceRebindObservation, ReferenceOwnershipLog, effect_receipt_issuer,
    ownership_receipt_issuer, process_effect_peer::validate_native_jsonl_chain,
};

pub const NEXUS_PROCESS_QUALIFICATION_SCHEMA: &str = "visa.nexus-process-qualification-cell.v1";
pub const NEXUS_PROCESS_AUTHENTICATION_BOUNDARY: &str =
    "same-boot-executable-sha256-and-native-chain-integrity-only";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusProcessQualificationInputs {
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub nexus_revision: String,
}

impl NexusProcessQualificationInputs {
    pub fn launch(&self) -> ProcessEffectPeerLaunch {
        ProcessEffectPeerLaunch::new(
            self.executable.clone(),
            self.executable_sha256.clone(),
            self.nexus_revision.clone(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusProcessQualificationReport {
    pub schema: String,
    pub all_passed: bool,
    pub process_backed: bool,
    pub authentication_boundary: String,
    pub launch: NexusProcessQualificationInputs,
    pub scenarios: Vec<NexusProcessScenarioReport>,
    pub capabilities: NexusProcessCapabilityReport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusProcessScenarioReport {
    pub case_id: String,
    pub process: ProcessEffectPeerIdentity,
    pub operations: Vec<NexusProcessOperation>,
    pub exact_replays: Vec<NexusExactReplayObservation>,
    pub terminal: String,
    pub final_gate_open: bool,
    pub final_effect_count: usize,
    pub native_chain: Vec<NativeJsonlExchange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusProcessOperation {
    pub step: String,
    pub outcome: String,
    pub neutral_receipt_kind: Option<String>,
    pub neutral_receipt: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusExactReplayObservation {
    pub request_id: u64,
    pub original_response_jsonl: String,
    pub replay_response_jsonl: String,
    pub byte_identical: bool,
    pub accepted_chain_length_before: usize,
    pub accepted_chain_length_after: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusProcessCapabilityReport {
    pub service_crash_rebind: NexusNativeCapability,
    pub service_crash_rebind_observation: Option<ProcessServiceRebindObservation>,
    pub registry_replacement: NexusNativeCapability,
    pub retained_tombstone: NexusNativeCapability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NexusNativeCapability {
    Supported { detail: String },
    Unsupported { detail: String },
}

pub fn run_nexus_process_qualification_cell(
    inputs: NexusProcessQualificationInputs,
) -> Result<NexusProcessQualificationReport, String> {
    validate_inputs(&inputs)?;
    let close = run_committed_close(&inputs)?;
    let (case_16, capabilities) = run_registered_abort_commit(&inputs)?;
    let report = NexusProcessQualificationReport {
        schema: NEXUS_PROCESS_QUALIFICATION_SCHEMA.to_owned(),
        all_passed: true,
        process_backed: true,
        authentication_boundary: NEXUS_PROCESS_AUTHENTICATION_BOUNDARY.to_owned(),
        launch: inputs,
        scenarios: vec![close, case_16],
        capabilities,
    };
    validate_nexus_process_qualification_report(&report)?;
    let bytes = serde_json::to_vec(&report).map_err(debug)?;
    let decoded: NexusProcessQualificationReport = serde_json::from_slice(&bytes).map_err(debug)?;
    require(decoded == report, "qualification report did not round-trip exactly")?;
    Ok(report)
}

fn run_committed_close(
    inputs: &NexusProcessQualificationInputs,
) -> Result<NexusProcessScenarioReport, String> {
    let fixture = Fixture::new(1_000)?;
    let peer = ProcessEffectPeer::spawn(inputs.launch(), fixture.config).map_err(debug)?;
    let process = peer.process_identity().map_err(debug)?;
    let mut operations = Vec::new();

    let record = fixture.committed_effect(1_100);
    expect_published(peer.publish(fixture.publication(record)).map_err(debug)?)?;
    outcome(&mut operations, "publish-committed-effect", "published");

    let mut ownership = fixture.ownership_log()?;
    let intent = fixture.reserve(&mut ownership)?;
    receipt(&mut operations, "ownership-reserve", ReceiptKind::PrepareIntent, &intent)?;
    let frozen = peer.freeze(fixture.freeze(intent.clone())).map_err(debug)?;
    require(
        frozen.receipt.disposition == FreezeDisposition::ReadyToCommit,
        "committed cohort was not ready to close",
    )?;
    receipt(&mut operations, "nexus-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;

    let query = peer.query().map_err(debug)?;
    require(!query.gate_open, "freeze query reported an open admission gate")?;
    outcome(&mut operations, "query-frozen", "frozen-ready-to-commit");
    let exact_replays = vec![exact_replay(&peer)?];

    let commit = fixture.seal_commit(&mut ownership, &intent, &frozen.receipt)?;
    receipt(&mut operations, "ownership-commit", ReceiptKind::OwnershipCommit, &commit)?;
    let mut revision = 0;
    let mut closed = false;
    for _ in 0..16 {
        let result = peer
            .close(EffectCloseRequest {
                token: frozen.token,
                commit: commit.clone(),
                expected_closure_revision: revision,
            })
            .map_err(debug)?;
        revision = result.closure_revision();
        match result {
            EffectCloseResult::Progress(value) => receipt(
                &mut operations,
                "nexus-close-progress",
                ReceiptKind::ClosureProgress,
                &value,
            )?,
            EffectCloseResult::Closed(value) => {
                receipt(&mut operations, "nexus-close", ReceiptKind::Closure, &value)?;
                closed = true;
                break;
            }
            EffectCloseResult::RetainedTombstone(value) => {
                receipt(
                    &mut operations,
                    "nexus-retained-tombstone",
                    ReceiptKind::RetainedTombstone,
                    &value,
                )?;
                return Err(
                    "ordinary committed-effect close unexpectedly retained a tombstone".to_owned()
                );
            }
        }
    }
    require(closed, "Nexus close did not terminalize within the bounded cell")?;
    let query = peer.query().map_err(debug)?;
    require(
        matches!(query.latest_close, Some(EffectCloseResult::Closed(_))),
        "post-close query did not return the terminal closure",
    )?;
    outcome(&mut operations, "query-closed", "source-closed");

    peer.shutdown().map_err(debug)?;
    outcome(&mut operations, "shutdown", "clean-exit");
    let native_chain = peer.native_transcript().map_err(debug)?;
    validate_native_jsonl_chain(&native_chain).map_err(debug)?;
    Ok(NexusProcessScenarioReport {
        case_id: "nexus-process-committed-effect-close".to_owned(),
        process,
        operations,
        exact_replays,
        terminal: "source-closed".to_owned(),
        final_gate_open: query.gate_open,
        final_effect_count: query.effect_count,
        native_chain,
    })
}

fn run_registered_abort_commit(
    inputs: &NexusProcessQualificationInputs,
) -> Result<(NexusProcessScenarioReport, NexusProcessCapabilityReport), String> {
    let fixture = Fixture::new(2_000)?;
    let peer = ProcessEffectPeer::spawn(inputs.launch(), fixture.config).map_err(debug)?;
    let process = peer.process_identity().map_err(debug)?;
    let mut operations = Vec::new();

    let registered = fixture.registered_effect(2_100);
    expect_published(peer.publish(fixture.publication(registered.clone())).map_err(debug)?)?;
    outcome(&mut operations, "publish-registered-effect", "published");

    let mut ownership = fixture.ownership_log()?;
    let intent = fixture.reserve(&mut ownership)?;
    receipt(&mut operations, "ownership-reserve", ReceiptKind::PrepareIntent, &intent)?;
    let frozen = peer.freeze(fixture.freeze(intent.clone())).map_err(debug)?;
    require(
        matches!(frozen.receipt.disposition, FreezeDisposition::Blocked { .. }),
        "registered effect did not block ownership commit",
    )?;
    receipt(&mut operations, "nexus-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
    let frozen_query = peer.query().map_err(debug)?;
    require(
        !frozen_query.gate_open && frozen_query.effect_count == 1,
        "frozen registered cohort query was inconsistent",
    )?;
    outcome(&mut operations, "query-frozen", "blocked-registered-effect");

    let abort = ownership
        .abort(OwnershipAbortRequest {
            key: fixture.key,
            reservation: intent.reservation,
            basis: intent.receipt_ref().map_err(debug)?,
            expected_state_sequence: 1,
        })
        .map_err(debug)?;
    receipt(&mut operations, "ownership-abort", ReceiptKind::OwnershipAbort, &abort)?;
    let thaw = peer.thaw(EffectThawRequest { token: frozen.token, abort }).map_err(debug)?;
    receipt(&mut operations, "nexus-thaw", ReceiptKind::NexusThaw, &thaw)?;
    let exact_replays = vec![exact_replay(&peer)?];

    let thawed_query = peer.query().map_err(debug)?;
    require(
        thawed_query.gate_open && thawed_query.effect_count == 1,
        "abort/thaw did not preserve one registered effect behind an open gate",
    )?;
    outcome(&mut operations, "query-thawed", "registered-effect-preserved");

    let committed = JointEffectRecord {
        classification: JointEffectClassification::Committed,
        outcome_digest: Some(digest(91)),
        ..registered.clone()
    };
    expect_published(peer.publish(fixture.publication(committed.clone())).map_err(debug)?)?;
    outcome(&mut operations, "same-effect-prepare-commit-after-thaw", "committed");
    require(
        peer.publish(fixture.publication(committed)).map_err(debug)?
            == EffectPublicationResult::Replay,
        "same committed effect did not replay at the portable boundary",
    )?;
    outcome(&mut operations, "same-effect-portable-replay", "exact-replay");

    let final_query = peer.query().map_err(debug)?;
    require(
        final_query.gate_open && final_query.effect_count == 1,
        "case 16 terminal query lost the preserved effect or gate state",
    )?;
    outcome(&mut operations, "query-after-same-effect-commit", "gate-open-one-effect");

    let retained_tombstone = probe_tombstone(&peer, &fixture)?;
    let service_crash_rebind_observation =
        peer.crash_and_rebind_service(id(fixture.seed + 400), 2).map_err(debug)?;
    outcome(
        &mut operations,
        "native-service-crash-rebind",
        "same-registry-same-scope-binding-recovered",
    );
    let service_crash_rebind = NexusNativeCapability::Supported {
        detail: "production service supervisor and binding recovered within the same Registry and ScopeKey"
            .to_owned(),
    };
    let registry_replacement = probe_registry_replacement(&peer, &fixture)?;
    let post_rebind_query = peer.query().map_err(debug)?;
    require(
        post_rebind_query.gate_open && post_rebind_query.effect_count == 1,
        "native service rebind did not preserve the thawed effect scope",
    )?;
    outcome(&mut operations, "query-after-service-rebind", "gate-open-one-adopted-effect");
    peer.shutdown().map_err(debug)?;
    outcome(&mut operations, "shutdown", "clean-exit");
    let native_chain = peer.native_transcript().map_err(debug)?;
    validate_native_jsonl_chain(&native_chain).map_err(debug)?;
    let scenario = NexusProcessScenarioReport {
        case_id: "nexus-process-case-16-registered-abort-thaw-same-effect-commit".to_owned(),
        process,
        operations,
        exact_replays,
        terminal: "source-resumed-same-effect-committed".to_owned(),
        final_gate_open: post_rebind_query.gate_open,
        final_effect_count: post_rebind_query.effect_count,
        native_chain,
    };
    Ok((
        scenario,
        NexusProcessCapabilityReport {
            service_crash_rebind,
            service_crash_rebind_observation: Some(service_crash_rebind_observation),
            registry_replacement,
            retained_tombstone,
        },
    ))
}

fn probe_tombstone(
    peer: &ProcessEffectPeer,
    fixture: &Fixture,
) -> Result<NexusNativeCapability, String> {
    let record = JointEffectRecord {
        effect: id(fixture.seed + 300),
        operation: id(fixture.seed + 301),
        domain: id(fixture.seed + 302),
        binding_generation: fixture.config.scope_generation,
        classification: JointEffectClassification::ResolvedTombstone,
        outcome_digest: Some(digest(92)),
        tombstone_digest: Some(digest(93)),
    };
    match peer.publish(fixture.publication(record)) {
        Ok(value) => Ok(NexusNativeCapability::Supported {
            detail: format!("native tombstone publication completed as {value:?}"),
        }),
        Err(EffectPeerError::Unsupported(detail)) => {
            Ok(NexusNativeCapability::Unsupported { detail: detail.to_owned() })
        }
        Err(error) => Err(format!("retained-tombstone capability probe was ambiguous: {error:?}")),
    }
}

fn probe_registry_replacement(
    peer: &ProcessEffectPeer,
    fixture: &Fixture,
) -> Result<NexusNativeCapability, String> {
    match peer.rebind(id(fixture.seed + 400)) {
        Ok(scope) => Ok(NexusNativeCapability::Supported {
            detail: format!(
                "replacement registry={} scope_generation={} authority_epoch={} freeze_generation={}",
                hex_identity(scope.registry_instance),
                scope.scope_generation,
                scope.authority_epoch,
                scope.freeze_generation,
            ),
        }),
        Err(EffectPeerError::Unsupported(detail)) => {
            Ok(NexusNativeCapability::Unsupported { detail: detail.to_owned() })
        }
        Err(error) => {
            Err(format!("Registry-replacement capability probe was ambiguous: {error:?}"))
        }
    }
}

fn exact_replay(peer: &ProcessEffectPeer) -> Result<NexusExactReplayObservation, String> {
    let before = peer.native_transcript().map_err(debug)?;
    let original =
        before.last().ok_or_else(|| "native chain was empty before replay".to_owned())?;
    let replay = peer.replay_last_native_request().map_err(debug)?;
    let replay_response_jsonl = String::from_utf8(replay).map_err(debug)?;
    let after = peer.native_transcript().map_err(debug)?;
    let observation = NexusExactReplayObservation {
        request_id: original.request_id,
        original_response_jsonl: original.response_jsonl.clone(),
        byte_identical: replay_response_jsonl == original.response_jsonl,
        replay_response_jsonl,
        accepted_chain_length_before: before.len(),
        accepted_chain_length_after: after.len(),
    };
    require(observation.byte_identical, "native replay response changed bytes")?;
    require(
        before == after,
        "exact native replay incorrectly extended or rewrote the accepted chain",
    )?;
    Ok(observation)
}

fn validate_inputs(inputs: &NexusProcessQualificationInputs) -> Result<(), String> {
    require(
        inputs.executable_sha256.len() == 64
            && inputs
                .executable_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Nexus executable identity must be exact lowercase SHA-256",
    )?;
    require(
        inputs.nexus_revision.len() == 40
            && inputs
                .nexus_revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Nexus revision must be an exact lowercase 40-hex Git SHA",
    )
}

pub fn validate_nexus_process_qualification_report(
    report: &NexusProcessQualificationReport,
) -> Result<(), String> {
    validate_inputs(&report.launch)?;
    require(report.schema == NEXUS_PROCESS_QUALIFICATION_SCHEMA, "wrong report schema")?;
    require(report.all_passed && report.process_backed, "cell did not pass as process-backed")?;
    require(
        report.authentication_boundary == NEXUS_PROCESS_AUTHENTICATION_BOUNDARY,
        "cell changed its same-boot authentication boundary",
    )?;
    require(report.scenarios.len() == 2, "cell did not retain both process scenarios")?;
    require(
        matches!(report.capabilities.service_crash_rebind, NexusNativeCapability::Supported { .. })
            && report.capabilities.service_crash_rebind_observation.is_some(),
        "cell did not retain production service crash/rebind evidence",
    )?;
    require(
        matches!(
            report.capabilities.registry_replacement,
            NexusNativeCapability::Unsupported { .. }
        ),
        "same-Registry service recovery was incorrectly reported as Registry replacement",
    )?;
    require(
        matches!(report.capabilities.retained_tombstone, NexusNativeCapability::Unsupported { .. }),
        "native retained-tombstone mapping was incorrectly reported as supported",
    )?;
    for capability in [
        &report.capabilities.service_crash_rebind,
        &report.capabilities.registry_replacement,
        &report.capabilities.retained_tombstone,
    ] {
        let detail = match capability {
            NexusNativeCapability::Supported { detail }
            | NexusNativeCapability::Unsupported { detail } => detail,
        };
        require(!detail.is_empty(), "native capability detail was empty")?;
    }
    let observation = report
        .capabilities
        .service_crash_rebind_observation
        .as_ref()
        .ok_or_else(|| "cell omitted service crash/rebind observation".to_owned())?;
    require(
        observation.previous_supervisor_id != 0
            && observation.replacement_supervisor_id != 0
            && observation.previous_supervisor_id != observation.replacement_supervisor_id
            && observation.previous_supervisor_generation != 0
            && observation.replacement_supervisor_generation
                > observation.previous_supervisor_generation
            && observation.previous_binding_epoch != 0
            && observation.crashed_binding_epoch > observation.previous_binding_epoch
            && observation.rebound_binding_epoch == observation.crashed_binding_epoch
            && observation.recovery_remaining == 0
            && !observation.crashed_client_effects.is_empty()
            && observation.crashed_client_effects == observation.adopted_client_effects
            && observation.crashed_client_effects.windows(2).all(|pair| pair[0] < pair[1]),
        "service crash/rebind observation was incomplete or internally inconsistent",
    )?;

    let expected = [
        // The adapter deliberately retains the terminalized portable record;
        // `effect_count` is the known-record population, not the native live
        // cohort size carried by the closure receipt.
        ("nexus-process-committed-effect-close", "source-closed", false, 1),
        (
            "nexus-process-case-16-registered-abort-thaw-same-effect-commit",
            "source-resumed-same-effect-committed",
            true,
            1,
        ),
    ];
    let mut observed_processes = Vec::new();
    for (scenario, (case_id, terminal, gate_open, effect_count)) in
        report.scenarios.iter().zip(expected)
    {
        require(scenario.case_id == case_id, "process scenario identity or order drifted")?;
        require(
            scenario.terminal == terminal
                && scenario.final_gate_open == gate_open
                && scenario.final_effect_count == effect_count,
            "process scenario terminal state drifted",
        )?;
        require(
            scenario.process.executable_sha256 == report.launch.executable_sha256
                && scenario.process.nexus_revision == report.launch.nexus_revision,
            "observed child identity did not bind the explicit launch inputs",
        )?;
        require(scenario.process.process_id != 0, "report retained a zero child PID")?;
        require(scenario.process.start_time_ticks != 0, "report retained a zero child start time")?;
        require(
            !scenario.process.executable_path.as_os_str().is_empty(),
            "report retained an empty observed child executable path",
        )?;
        observed_processes.push((scenario.process.process_id, scenario.process.start_time_ticks));
        require(!scenario.operations.is_empty(), "scenario omitted operation evidence")?;
        for operation in &scenario.operations {
            require(
                !operation.step.is_empty() && !operation.outcome.is_empty(),
                "scenario retained an empty operation step or outcome",
            )?;
            require(
                operation.neutral_receipt_kind.is_some() == operation.neutral_receipt.is_some(),
                "operation split its neutral receipt kind from its receipt bytes",
            )?;
            if let Some(receipt) = &operation.neutral_receipt {
                require(receipt.is_object(), "operation receipt was not a JSON object")?;
            }
        }
        require(!scenario.exact_replays.is_empty(), "scenario omitted exact replay evidence")?;
        validate_native_jsonl_chain(&scenario.native_chain).map_err(debug)?;
        for replay in &scenario.exact_replays {
            require(
                replay.request_id != 0
                    && replay.byte_identical
                    && replay.original_response_jsonl == replay.replay_response_jsonl
                    && replay.original_response_jsonl.ends_with('\n')
                    && !replay.original_response_jsonl.ends_with("\r\n")
                    && replay.accepted_chain_length_before
                        == usize::try_from(replay.request_id).map_err(debug)?
                    && replay.accepted_chain_length_after == replay.accepted_chain_length_before,
                "exact native replay evidence was inconsistent",
            )?;
            let exchange = scenario
                .native_chain
                .iter()
                .find(|exchange| exchange.request_id == replay.request_id)
                .ok_or_else(|| "exact replay did not name an accepted native request".to_owned())?;
            require(
                exchange.response_jsonl == replay.original_response_jsonl,
                "exact replay bytes differed from the accepted native chain",
            )?;
        }
        require(
            scenario.operations.last().is_some_and(|operation| {
                operation.step == "shutdown" && operation.outcome == "clean-exit"
            }),
            "process scenario did not end in a clean child shutdown",
        )?;
    }
    require(
        observed_processes[0] != observed_processes[1],
        "two process scenarios aliased one child process incarnation",
    )?;
    require(
        report.scenarios[1].operations.iter().any(|operation| {
            operation.step == "native-service-crash-rebind"
                && operation.outcome == "same-registry-same-scope-binding-recovered"
        }),
        "case 16 omitted its production service crash/rebind operation",
    )?;
    Ok(())
}

struct Fixture {
    seed: u128,
    key: JointHandoffKey,
    ownership_namespace: ReceiptIssuerIdentity,
    config: EffectPeerConfig,
}

impl Fixture {
    fn new(seed: u128) -> Result<Self, String> {
        let key = JointHandoffKey {
            continuity_unit: EntityRef::initial(id(seed + 1)),
            handoff: id(seed + 2),
            source: NodeIdentity::new(id(seed + 3)),
            destination: NodeIdentity::new(id(seed + 4)),
            expected_epoch: LeaseEpoch(7),
            next_epoch: LeaseEpoch(8),
        };
        let ownership_namespace = issuer(seed + 10);
        let config = EffectPeerConfig {
            key,
            issuer: effect_receipt_issuer(issuer(seed + 20), key).map_err(debug)?,
            ownership_issuer: ownership_receipt_issuer(ownership_namespace, key).map_err(debug)?,
            registry_instance: id(seed + 30),
            scope_id: id(seed + 31),
            scope_generation: 1,
            authority_epoch: 5,
            freeze_generation: 1,
            domain_bindings_digest: digest(4),
        };
        Ok(Self { seed, key, ownership_namespace, config })
    }

    fn ownership_log(&self) -> Result<ReferenceOwnershipLog, String> {
        let mut log =
            ReferenceOwnershipLog::open(":memory:", self.ownership_namespace).map_err(debug)?;
        log.initialize_unit(self.key.continuity_unit, self.key.source, self.key.expected_epoch)
            .map_err(debug)?;
        Ok(log)
    }

    fn reserve(&self, log: &mut ReferenceOwnershipLog) -> Result<PrepareIntentReceipt, String> {
        log.reserve(OwnershipReserveRequest { key: self.key, expected_state_sequence: 0 })
            .map_err(debug)
    }

    fn freeze(&self, intent: PrepareIntentReceipt) -> EffectFreezeRequest {
        EffectFreezeRequest {
            key: self.key,
            intent,
            registry_instance: self.config.registry_instance,
            scope_id: self.config.scope_id,
            scope_generation: self.config.scope_generation,
            authority_epoch: self.config.authority_epoch,
            freeze_generation: self.config.freeze_generation,
        }
    }

    fn publication(&self, record: JointEffectRecord) -> EffectPublicationRequest {
        EffectPublicationRequest {
            key: self.key,
            registry_instance: self.config.registry_instance,
            scope_id: self.config.scope_id,
            scope_generation: self.config.scope_generation,
            source_epoch: self.key.expected_epoch,
            record,
        }
    }

    fn committed_effect(&self, value: u128) -> JointEffectRecord {
        JointEffectRecord {
            effect: id(value),
            operation: id(value + 1),
            domain: id(value + 2),
            binding_generation: self.config.scope_generation,
            classification: JointEffectClassification::Committed,
            outcome_digest: Some(digest(90)),
            tombstone_digest: None,
        }
    }

    fn registered_effect(&self, value: u128) -> JointEffectRecord {
        JointEffectRecord {
            effect: id(value),
            operation: id(value + 1),
            domain: id(value + 2),
            binding_generation: self.config.scope_generation,
            classification: JointEffectClassification::Registered,
            outcome_digest: None,
            tombstone_digest: None,
        }
    }

    fn seal_commit(
        &self,
        log: &mut ReferenceOwnershipLog,
        intent: &PrepareIntentReceipt,
        freeze: &joint_handoff_core::NexusFreezeReceipt,
    ) -> Result<joint_handoff_core::OwnershipCommitReceipt, String> {
        let intent_ref = intent.receipt_ref().map_err(debug)?;
        let effect_ref = freeze.receipt_ref().map_err(debug)?;
        let visa = external_ref(self.key, ReceiptKind::VisaFreeze, self.seed + 100);
        let destination = external_ref(self.key, ReceiptKind::DestinationPrepared, self.seed + 110);
        let prepared = log
            .seal(OwnershipSealRequest {
                key: self.key,
                reservation: intent.reservation,
                intent: intent_ref,
                visa_freeze: visa,
                effect_freeze: effect_ref,
                destination_prepared: destination,
                bindings: bindings(
                    intent_ref,
                    visa,
                    effect_ref,
                    destination,
                    freeze.effect_cohort_digest,
                ),
                expected_state_sequence: 1,
            })
            .map_err(debug)?;
        log.commit(OwnershipCommitRequest {
            key: self.key,
            reservation: intent.reservation,
            prepared: prepared.receipt_ref().map_err(debug)?,
            expected_state_sequence: 2,
        })
        .map_err(debug)
    }
}

fn receipt<T: Serialize>(
    operations: &mut Vec<NexusProcessOperation>,
    step: &str,
    kind: ReceiptKind,
    value: &T,
) -> Result<(), String> {
    let kind = serde_json::to_value(kind).map_err(debug)?;
    let kind = kind.as_str().ok_or_else(|| "receipt kind did not serialize as text".to_owned())?;
    operations.push(NexusProcessOperation {
        step: step.to_owned(),
        outcome: "accepted".to_owned(),
        neutral_receipt_kind: Some(kind.to_owned()),
        neutral_receipt: Some(serde_json::to_value(value).map_err(debug)?),
    });
    Ok(())
}

fn outcome(operations: &mut Vec<NexusProcessOperation>, step: &str, value: &str) {
    operations.push(NexusProcessOperation {
        step: step.to_owned(),
        outcome: value.to_owned(),
        neutral_receipt_kind: None,
        neutral_receipt: None,
    });
}

fn expect_published(value: EffectPublicationResult) -> Result<(), String> {
    require(value == EffectPublicationResult::Published, "first publication was a replay")
}

fn bindings(
    intent: ReceiptRef,
    visa: ReceiptRef,
    effect: ReceiptRef,
    destination: ReceiptRef,
    cohort: Digest,
) -> PreparedBindings {
    PreparedBindings {
        prepare_intent_receipt_digest: intent.digest,
        visa_freeze_receipt_digest: visa.digest,
        effect_freeze_receipt_digest: effect.digest,
        snapshot: id(9_001),
        snapshot_integrity_digest: digest(41),
        source_journal_position: contract_core::JournalPosition(42),
        source_state_digest: digest(43),
        component_digest: digest(44),
        profile_digest: digest(45),
        destination_prepared_receipt_digest: destination.digest,
        destination_state_digest: digest(46),
        prepared_authorities_digest: digest(47),
        prepared_bindings_digest: digest(48),
        effect_cohort_manifest_digest: cohort,
        joint_mapping_manifest_digest: digest(50),
    }
}

fn external_ref(key: JointHandoffKey, kind: ReceiptKind, base: u128) -> ReceiptRef {
    ReceiptRef {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        handoff: key.handoff,
        issuer: id(base),
        issuer_incarnation: id(base + 1),
        key_id: id(base + 2),
        log_id: id(base + 3),
        sequence: 1,
        digest: digest(base as u8),
    }
}

fn issuer(base: u128) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: id(base),
        issuer_incarnation: id(base + 1),
        key_id: id(base + 2),
        log_id: id(base + 3),
    }
}

fn id(value: u128) -> Identity {
    Identity::from_u128(value)
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}

fn hex_identity(identity: Identity) -> String {
    let mut value = String::with_capacity(32);
    for byte in identity.0 {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}

fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualification_inputs_reject_moving_or_noncanonical_identities() {
        let mut inputs = NexusProcessQualificationInputs {
            executable: PathBuf::from("nexus-effect-peer"),
            executable_sha256: "a".repeat(64),
            nexus_revision: "b".repeat(40),
        };
        assert_eq!(validate_inputs(&inputs), Ok(()));
        inputs.nexus_revision = "main".to_owned();
        assert!(validate_inputs(&inputs).is_err());
        inputs.nexus_revision = "b".repeat(40);
        inputs.executable_sha256 = "A".repeat(64);
        assert!(validate_inputs(&inputs).is_err());
    }

    #[test]
    #[ignore = "requires an explicitly identified, separately built nexus-effect-peer binary"]
    fn real_nexus_process_qualification_cell_is_strictly_serializable() {
        let inputs = NexusProcessQualificationInputs {
            executable: std::env::var_os("NEXUS_EFFECT_PEER_BIN")
                .map(PathBuf::from)
                .expect("NEXUS_EFFECT_PEER_BIN must name the built Nexus peer"),
            executable_sha256: std::env::var("NEXUS_EFFECT_PEER_SHA256")
                .expect("NEXUS_EFFECT_PEER_SHA256 must pin the exact executable"),
            nexus_revision: std::env::var("NEXUS_EFFECT_PEER_REVISION")
                .expect("NEXUS_EFFECT_PEER_REVISION must pin the Nexus source revision"),
        };
        let report = run_nexus_process_qualification_cell(inputs).unwrap();
        assert!(report.all_passed && report.process_backed);
        assert_eq!(report.scenarios.len(), 2);
        assert!(report.scenarios.iter().all(|scenario| {
            !scenario.native_chain.is_empty()
                && scenario.exact_replays.iter().all(|replay| replay.byte_identical)
                && scenario.native_chain.iter().all(|exchange| {
                    exchange.request_jsonl.ends_with('\n')
                        && exchange.response_jsonl.ends_with('\n')
                })
        }));
        let bytes = serde_json::to_vec(&report).unwrap();
        assert_eq!(
            serde_json::from_slice::<NexusProcessQualificationReport>(&bytes).unwrap(),
            report
        );
    }
}
