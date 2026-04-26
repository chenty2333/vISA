use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

mod runtime;

use artifact_manifest::{
    ActivationCleanupManifest, ActivationCleanupStepManifest, ActivationContextManifest,
    ActivationRecordManifest, ActivationResumeManifest, ActivationWaitManifest,
    ArtifactBundleManifest, AuthorityObjectRefManifest, BoundaryValidationReportManifest,
    BoundaryValidationViolationManifest, CapabilityHandleArgManifest, CapabilityRecordManifest,
    CleanupEffectManifest, CleanupStepManifest, CleanupTransactionManifest, CodeObjectManifest,
    CommandEffectManifest, CommandResultManifest, ContractObjectRefManifest,
    ContractViolationManifest, GuestStateManifest, HartEventAttributionManifest,
    HartRecordManifest, HostcallSpecManifest, HostcallTraceManifest, InterfaceEventManifest,
    IpiEventManifest, MemoryClassPolicyManifest, MigrationCapabilityManifest,
    MigrationHostManifest, MigrationObjectManifest, MigrationPackageManifest,
    MigrationTargetManifest, PreemptionLatencySampleManifest, PreemptionManifest,
    RemotePreemptManifest, RequiredArtifactProfileManifest, RunnableQueueEntryManifest,
    RunnableQueueManifest, RuntimeActivationRecordManifest, SavedContextManifest,
    SchedulerDecisionManifest, SemanticRootSetManifest, SemanticSnapshotManifest,
    StoreRecordManifest, SubstrateBoundaryManifest, SubstrateEventManifest,
    TargetAddressMapEntryManifest, TargetArtifactImageManifest, TargetCapabilitySpecManifest,
    TargetMemoryPlanManifest, TargetTrapMetadataManifest, TaskRecordManifest,
    TimerInterruptManifest, TombstoneManifest, TrapRecordManifest, WaitRecordManifest,
};
use contract_core::{
    ValidatedArtifactEntry, ValidatedArtifactPlan, build_validated_artifact_plan,
    validate_migration_against_manifest, validate_replay_quiescent,
};
use runtime::{HostValidationSmokeTrace, RuntimeOnlyExecutor};
use semantic_core::{
    ActivationEntry, ArtifactRegistry, ArtifactVerificationState, AuthorityObjectRef, BoundaryKind,
    BoundaryStatus, BoundaryValidationReport, BoundaryValidationViolation, CapabilityClass,
    CapabilityHandleArg, CapabilityLedger, CapabilityRecord, CodeObject, CodePublishState,
    CodePublisher, CommandEnvelope, CommandResult, CommandStatus, ContractGraphSnapshot,
    ContractObjectKind, ContractObjectRef, ContractViolation, EntrypointState, EventKind,
    EventRecord, ExpectedTargetArtifact, ExternalObjectDeclaration, FrontendKind, HartState,
    HostcallCategory, HostcallFrame, HostcallLinkState, HostcallSpec, HostcallTraceRecord,
    IpiEventKind, ManagedStoreRecord, MemoryClassPolicy, MemoryLayoutState, MigrationObjectRecord,
    PackageReplayValidator, ReplayPackageValidationState, RestartPolicy, RuntimeMode,
    SavedContextReason, SemanticCommand, SemanticGraph, SemanticWaitKind, SnapshotBarrierValidator,
    StoreRecord, StoreState, TargetAddressMapEntry, TargetArtifactImage, TargetCapabilitySpec,
    TargetExecutor, TargetMemoryPlan, TargetStoreManager, TargetTrapClass, TargetTrapMetadata,
    TaskState, TombstoneRecord, TrapSurfaceState, VerifiedArtifact, memory_class_policies,
    validate_contract_graph,
};
use substrate_api::{SubstrateEvent, SubstrateRequester};
use target_abi::{
    OBJECT_KIND_CODE_OBJECT_V1, ObjectRefRaw, RV64_ENTRY_TRAP_EBREAK_OFFSET, TrapKindV1,
    TrapMapEntryV1,
};

const DEFAULT_ARTIFACT_ROOT: &str = "target/aotc/wasmtime/host-validation/debug";

#[derive(Clone, Debug, Default)]
struct TargetExecutorV1Report {
    target_artifacts: Vec<TargetArtifactImageManifest>,
    code_objects: Vec<CodeObjectManifest>,
    store_records: Vec<StoreRecordManifest>,
    capability_records: Vec<CapabilityRecordManifest>,
    wait_records: Vec<WaitRecordManifest>,
    activation_records: Vec<ActivationRecordManifest>,
    trap_records: Vec<TrapRecordManifest>,
    hostcall_trace: Vec<HostcallTraceManifest>,
    migration_objects: Vec<MigrationObjectManifest>,
    tombstones: Vec<TombstoneManifest>,
    contract_violations: Vec<ContractViolationManifest>,
    cleanup_transactions: Vec<CleanupTransactionManifest>,
    memory_policies: Vec<MemoryClassPolicyManifest>,
    snapshot_validation: BoundaryValidationReportManifest,
    replay_validation: BoundaryValidationReportManifest,
    target_event_tail: Vec<String>,
    substrate_events: Vec<SubstrateEventManifest>,
    command_results: Vec<CommandResultManifest>,
    interface_events: Vec<InterfaceEventManifest>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("target_executor error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let workspace_root = workspace_root()?;
    let artifact_root = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join(DEFAULT_ARTIFACT_ROOT));
    let migration_path = env::args().nth(2).map(PathBuf::from);
    let manifest = read_manifest(&artifact_root)?;
    let plan = validate_bundle_manifest(&manifest)?;
    let executor =
        RuntimeOnlyExecutor::host_validation(workspace_root.clone(), &plan.artifact_profile)?;
    let mut semantic = SemanticGraph::with_runtime_mode(runtime_mode_from_plan(&plan));
    let mut stores = Vec::with_capacity(plan.module_count());

    semantic.ensure_task(1, FrontendKind::Supervisor, "target-executor-bootstrap");
    semantic.set_task_state(1, TaskState::Running);
    record_preemptive_runtime_context_evidence(&mut semantic)?;
    publish_host_boundary_status(&mut semantic, &manifest);

    for entry in &plan.modules {
        match executor.load_store(entry) {
            Ok(store) => {
                register_store_semantics(&mut semantic, entry);
                stores.push(store);
            }
            Err(error) => {
                let reason = format!("host-validation-error:{error}");
                semantic.record_artifact_verification(
                    &entry.package,
                    &entry.artifact_name,
                    &entry.manifest_binding_hash,
                    &entry.target_artifact_sha256,
                    &entry.abi_fingerprint,
                    &entry.signature_scheme,
                    &entry.signer,
                    ArtifactVerificationState::Rejected,
                    Some(&reason),
                );
                let package_path = prepare_migration_package(
                    &artifact_root,
                    migration_path.clone(),
                    &manifest,
                    &semantic,
                    &TargetExecutorV1Report::default(),
                )?;
                return Err(format!(
                    "{} host-side validation failed before activation; wrote rejection evidence to {}",
                    entry.package,
                    package_path.display()
                )
                .into());
            }
        }
    }
    record_substrate_conformance_evidence(&mut semantic);
    record_command_surface_evidence(&mut semantic);
    record_interface_boundary_evidence(&mut semantic);
    let target_v1 = build_target_executor_v1(&plan, &semantic, &stores)?;

    println!(
        "target executor loaded {} runtime-only stores with {} capability grants across {} fault domains in {} mode",
        stores.len(),
        semantic.capability_count(),
        semantic.fault_domain_count(),
        semantic.runtime_mode().as_str()
    );
    println!(
        "semantic store graph contains {} stores",
        semantic.store_count()
    );
    println!(
        "semantic event log contains {} events",
        semantic.event_count()
    );
    for store in stores {
        println!(
            "store {} role={} fault_policy={} abi={} binding={}",
            store.package,
            store.role,
            store.fault_policy,
            short_hash(&store.abi_fingerprint),
            short_hash(&store.manifest_binding_hash)
        );
    }
    let network_store_count = plan
        .modules
        .iter()
        .filter(|entry| {
            matches!(
                entry.package.as_str(),
                "driver_virtio_net" | "net_core" | "linux_socket_service"
            )
        })
        .count();
    println!("network runtime stores loaded: {network_store_count}");
    let migration_path = prepare_migration_package(
        &artifact_root,
        migration_path,
        &manifest,
        &semantic,
        &target_v1,
    )?;
    let migration = read_migration_package(&migration_path)?;
    validate_migration_package(&migration, &manifest)?;
    restore_migration_package(&migration, &semantic, &plan)?;

    Ok(())
}

fn runtime_mode_from_plan(plan: &ValidatedArtifactPlan) -> RuntimeMode {
    match plan.runtime_mode.as_str() {
        "production" => RuntimeMode::Production,
        "replay" => RuntimeMode::Replay,
        _ => RuntimeMode::Research,
    }
}

fn register_store_semantics(semantic: &mut SemanticGraph, entry: &ValidatedArtifactEntry) {
    let store = semantic.register_store(
        &entry.package,
        &entry.artifact_name,
        &entry.role,
        &entry.fault_policy,
    );
    semantic.set_store_state(store, StoreState::Instantiating);
    semantic.set_store_state(store, StoreState::Running);
    semantic.record_store_executor_transition(
        store,
        "planned",
        "artifact-verified",
        Some("host-side-runtime-validation"),
        "host-side-wasmtime-validation",
        "host-side-trap-validation",
    );
    semantic.record_artifact_verification(
        &entry.package,
        &entry.artifact_name,
        &entry.manifest_binding_hash,
        &entry.target_artifact_sha256,
        &entry.abi_fingerprint,
        &entry.signature_scheme,
        &entry.signer,
        ArtifactVerificationState::HostValidated,
        Some("target-runtime-only-loader"),
    );
    semantic.record_store_activation(
        store,
        &entry.package,
        &entry.manifest_binding_hash,
        &entry.cwasm_sha256,
        CodePublishState::NotPublished,
        MemoryLayoutState::Verified,
        HostcallLinkState::NotLinked,
        TrapSurfaceState::ContractDeclared,
        EntrypointState::NotRunnable,
        Some("target-runtime-only-loader"),
    );
    for capability in &entry.capabilities {
        let rights = capability
            .rights
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        semantic.grant_manifest_capability(
            &entry.package,
            &capability.name,
            &rights,
            &capability.lifetime,
        );
    }
}

fn publish_host_boundary_status(semantic: &mut SemanticGraph, manifest: &ArtifactBundleManifest) {
    semantic.publish_boundary(
        "artifact-loader",
        BoundaryKind::ArtifactLoader,
        BoundaryStatus::ManifestBacked,
        &manifest.artifact_profile,
        None,
    );
    semantic.publish_boundary(
        "target-cwasm",
        BoundaryKind::RuntimeExecutor,
        BoundaryStatus::HostSide,
        &manifest.compiler.runtime_executor_abi,
        Some("bare-metal-cwasm-loader"),
    );
    semantic.publish_boundary(
        "hostcall-table",
        BoundaryKind::HostcallTable,
        BoundaryStatus::HostSide,
        &manifest.compiler.runtime_executor_abi,
        Some("target-hostcall-trampoline"),
    );
    semantic.publish_boundary(
        "target-executor",
        BoundaryKind::TargetExecutor,
        BoundaryStatus::HostSide,
        "wasmtime-host-validator",
        Some("target-runtime-only-executor"),
    );
    semantic.publish_boundary(
        "store-lifecycle",
        BoundaryKind::StoreLifecycle,
        BoundaryStatus::LifecycleObject,
        "target_executor-host-validation",
        Some("target-store-memory-stack-code-object"),
    );
    semantic.publish_boundary(
        "snapshot-replay",
        BoundaryKind::SnapshotReplay,
        BoundaryStatus::PackageOnly,
        "semantic-package-v1",
        Some("target-replay-runner"),
    );
}

fn record_substrate_conformance_evidence(semantic: &mut SemanticGraph) {
    record_substrate_event(
        semantic,
        SubstrateEvent::unsupported(
            "DmaAuthority",
            "dma_alloc",
            Some(SubstrateRequester::new("target-executor-substrate-probe")),
        ),
    );
}

fn record_command_surface_evidence(semantic: &mut SemanticGraph) {
    let command = CommandEnvelope::new(
        1,
        "target-executor-command-probe",
        SemanticCommand::CreateWait {
            wait: 9000,
            owner_task: None,
            owner_store: None,
            owner_store_generation: None,
            kind: SemanticWaitKind::Timer,
            generation: 1,
            blockers: Vec::new(),
            deadline: None,
            restart_policy: RestartPolicy::Never,
            saved_context: None,
        },
    );
    let _ = semantic.apply_envelope(command);
}

fn record_preemptive_runtime_context_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    semantic.ensure_task(9001, FrontendKind::LinuxElf, "p0-preemptive-demo-task");
    semantic.ensure_task(9002, FrontendKind::LinuxElf, "p2-timer-demo-task");
    semantic.ensure_task(9003, FrontendKind::LinuxElf, "p8-cleanup-demo-task");
    semantic.ensure_task(9004, FrontendKind::LinuxElf, "s6-remote-preempt-task");
    let cleanup_store = semantic.register_store(
        "p8.cleanup.driver",
        "p8-cleanup-driver.fake-aot",
        "driver",
        "restartable",
    );
    semantic.set_store_state(cleanup_store, StoreState::Running);
    let cleanup_store_generation = semantic
        .store_handle(cleanup_store)
        .map(|handle| handle.generation)
        .ok_or("p8 cleanup store handle is missing")?;
    let commands = [
        CommandEnvelope::new(
            1,
            "target-executor-s0",
            SemanticCommand::RegisterHart {
                hart: 1,
                hardware_id: 0,
                label: "boot-hart0".to_owned(),
                boot: true,
                note: "s0-hart-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            2,
            "target-executor-s0",
            SemanticCommand::SetHartState {
                hart: 1,
                hart_generation: 1,
                state: HartState::Idle,
                reason: "scheduler-ready".to_owned(),
                note: "s0-hart-state-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            3,
            "target-executor-s4",
            SemanticCommand::RegisterHart {
                hart: 2,
                hardware_id: 1,
                label: "secondary-hart1".to_owned(),
                boot: false,
                note: "s4-secondary-hart-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            4,
            "target-executor-s4",
            SemanticCommand::SetHartState {
                hart: 2,
                hart_generation: 1,
                state: HartState::Idle,
                reason: "secondary-scheduler-ready".to_owned(),
                note: "s4-secondary-hart-idle-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            5,
            "target-executor-s5",
            SemanticCommand::RecordIpiEvent {
                ipi: 9001,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 2,
                kind: IpiEventKind::SchedulerKick,
                reason: "s5-scheduler-kick".to_owned(),
                note: "s5-ipi-event-model-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            6,
            "target-executor-s6",
            SemanticCommand::CreateRunnableQueue {
                queue: 9004,
                label: "remote-preempt-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            7,
            "target-executor-s6",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9004,
                queue_generation: 1,
                hart: 2,
                hart_generation: 2,
                note: "s6-target-queue-owned-by-secondary-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            8,
            "target-executor-s6",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9004,
                owner_task: 9004,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            9,
            "target-executor-s6",
            SemanticCommand::EnqueueRunnable {
                queue: 9004,
                activation: 9004,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            9_001,
            "target-executor-s6",
            SemanticCommand::DequeueRunnable {
                queue: 9004,
                activation: 9004,
            },
        ),
        CommandEnvelope::new(
            9_002,
            "target-executor-s6",
            SemanticCommand::BindHartCurrentActivation {
                hart: 2,
                hart_generation: 2,
                activation: 9004,
                activation_generation: 3,
                note: "s6-dispatch-target-on-secondary-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_003,
            "target-executor-s6",
            SemanticCommand::RecordIpiEvent {
                ipi: 9002,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 3,
                kind: IpiEventKind::SchedulerKick,
                reason: "s6-remote-preempt-ipi".to_owned(),
                note: "s6-remote-preempt-ipi-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_004,
            "target-executor-s6",
            SemanticCommand::RemotePreemptActivation {
                remote_preempt: 9001,
                ipi: 9002,
                ipi_generation: 1,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 3,
                activation: 9004,
                activation_generation: 3,
                queue: 9004,
                note: "s6-remote-preempt-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            10,
            "target-executor-p0",
            SemanticCommand::CreateRunnableQueue {
                queue: 9001,
                label: "bootstrap-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            10_001,
            "target-executor-s3",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9001,
                queue_generation: 1,
                hart: 1,
                hart_generation: 2,
                note: "s3-bootstrap-queue-owned-by-boot-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            11,
            "target-executor-p0",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9001,
                owner_task: 9001,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            12,
            "target-executor-p0",
            SemanticCommand::EnqueueRunnable {
                queue: 9001,
                activation: 9001,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            13,
            "target-executor-p1",
            SemanticCommand::CreateActivationContext {
                context: 9001,
                activation: 9001,
                activation_generation: 2,
            },
        ),
        CommandEnvelope::new(
            14,
            "target-executor-p1",
            SemanticCommand::CaptureSavedContext {
                saved_context: 9001,
                context: 9001,
                context_generation: 1,
                reason: SavedContextReason::Initial,
                pc: 0x1000,
                sp: 0x8000,
                flags: 0,
                note: "p1-initial-context-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            20,
            "target-executor-p2",
            SemanticCommand::CreateRunnableQueue {
                queue: 9002,
                label: "timer-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            20_001,
            "target-executor-s3",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9002,
                queue_generation: 1,
                hart: 1,
                hart_generation: 2,
                note: "s3-timer-queue-owned-by-boot-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            21,
            "target-executor-p2",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9002,
                owner_task: 9002,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            22,
            "target-executor-p2",
            SemanticCommand::EnqueueRunnable {
                queue: 9002,
                activation: 9002,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            23,
            "target-executor-p2",
            SemanticCommand::DequeueRunnable {
                queue: 9002,
                activation: 9002,
            },
        ),
        CommandEnvelope::new(
            24,
            "target-executor-s1",
            SemanticCommand::BindHartCurrentActivation {
                hart: 1,
                hart_generation: 2,
                activation: 9002,
                activation_generation: 3,
                note: "s1-hart-current-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            25,
            "target-executor-p2",
            SemanticCommand::RecordTimerInterrupt {
                interrupt: 9001,
                timer_epoch: 1,
                hart: 1,
                hart_generation: 3,
                target_activation: Some(9002),
                target_activation_generation: Some(3),
                note: "p2-timer-interrupt-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            29,
            "target-executor-s1",
            SemanticCommand::ClearHartCurrentActivation {
                hart: 1,
                hart_generation: 3,
                activation: 9002,
                activation_generation: 3,
                reason: "timer-preempt".to_owned(),
                note: "s1-clear-current-before-preempt".to_owned(),
            },
        ),
        CommandEnvelope::new(
            30,
            "target-executor-p3",
            SemanticCommand::PreemptActivation {
                preemption: 9001,
                activation: 9002,
                activation_generation: 3,
                timer_interrupt: 9001,
                timer_interrupt_generation: 1,
                queue: 9002,
                note: "p3-preempt-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            40,
            "target-executor-p4",
            SemanticCommand::SavePreemptedContext {
                context: 9002,
                saved_context: 9002,
                preemption: 9001,
                preemption_generation: 1,
                pc: 0x2000,
                sp: 0x9000,
                flags: 0,
                note: "p4-save-preempted-context-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            50,
            "target-executor-p5",
            SemanticCommand::RecordSchedulerDecision {
                decision: 9001,
                queue: 9002,
                queue_generation: 2,
                selected_activation: 9002,
                selected_activation_generation: 4,
                reason: "runnable-available".to_owned(),
                note: "p5-scheduler-decision-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            60,
            "target-executor-p6",
            SemanticCommand::ResumeActivation {
                resume: 9001,
                scheduler_decision: 9001,
                scheduler_decision_generation: 1,
                activation: 9002,
                activation_generation: 4,
                note: "p6-resume-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            61,
            "target-executor-p9",
            SemanticCommand::RecordPreemptionLatencySample {
                sample: 9001,
                timer_interrupt: 9001,
                timer_interrupt_generation: 1,
                preemption: 9001,
                preemption_generation: 1,
                scheduler_decision: 9001,
                scheduler_decision_generation: 1,
                activation_resume: 9001,
                activation_resume_generation: 1,
                measured_nanos: 8_500,
                budget_nanos: 50_000,
                note: "p9-host-validation-preemption-latency-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70,
            "target-executor-p7",
            SemanticCommand::BlockActivationOnWait {
                activation_wait: 9001,
                activation: 9002,
                activation_generation: 5,
                wait: 9003,
                kind: SemanticWaitKind::Timer,
                blockers: {
                    let mut blockers = Vec::new();
                    blockers.push(ContractObjectRef::new(
                        ContractObjectKind::TimerInterrupt,
                        9001,
                        1,
                    ));
                    blockers
                },
                deadline: Some(200),
                restart_policy: RestartPolicy::RestartIfAllowed,
                note: "p7-block-on-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            71,
            "target-executor-p7",
            SemanticCommand::CancelActivationWait {
                activation_wait: 9001,
                activation_wait_generation: 1,
                wait_generation: 1,
                errno: 110,
                reason: semantic_core::WaitCancelReason::Timeout,
                note: "p7-cancel-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            80,
            "target-executor-p8",
            SemanticCommand::CreateRunnableQueue {
                queue: 9003,
                label: "cleanup-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            80_001,
            "target-executor-s3",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9003,
                queue_generation: 1,
                hart: 1,
                hart_generation: 4,
                note: "s3-cleanup-queue-owned-by-boot-hart-after-preempt".to_owned(),
            },
        ),
        CommandEnvelope::new(
            81,
            "target-executor-p8",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9003,
                owner_task: 9003,
                owner_task_generation: 1,
                owner_store: Some(cleanup_store),
                owner_store_generation: Some(cleanup_store_generation),
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            82,
            "target-executor-p8",
            SemanticCommand::EnqueueRunnable {
                queue: 9003,
                activation: 9003,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            83,
            "target-executor-p8",
            SemanticCommand::DequeueRunnable {
                queue: 9003,
                activation: 9003,
            },
        ),
        CommandEnvelope::new(
            84,
            "target-executor-p8",
            SemanticCommand::BlockActivationOnWait {
                activation_wait: 9002,
                activation: 9003,
                activation_generation: 3,
                wait: 9004,
                kind: SemanticWaitKind::DeviceIrq,
                blockers: {
                    let mut blockers = Vec::new();
                    blockers.push(ContractObjectRef::new(
                        ContractObjectKind::Store,
                        cleanup_store,
                        cleanup_store_generation,
                    ));
                    blockers
                },
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                note: "p8-block-driver-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            85,
            "target-executor-p8",
            SemanticCommand::CleanupActivationForStoreFault {
                cleanup: 9001,
                store: cleanup_store,
                store_generation: cleanup_store_generation,
                activation: 9003,
                activation_generation: 4,
                wait: Some(9004),
                wait_generation: Some(1),
                reason: "driver-store-fault".to_owned(),
                note: "p8-cleanup-dead-store-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

fn record_interface_boundary_evidence(semantic: &mut SemanticGraph) {
    semantic.record_interface_unsupported(
        "standard-wasi",
        "wasi:clocks/monotonic-clock",
        "subscribe",
        Some("target-executor-interface-probe".to_owned()),
        None,
        None,
    );
}

fn record_substrate_event(semantic: &mut SemanticGraph, event: SubstrateEvent) {
    match event {
        SubstrateEvent::Unsupported {
            authority,
            operation,
            requester,
        } => {
            let (requester, artifact, store) = substrate_requester_parts(requester);
            semantic.record_substrate_unsupported(authority, operation, requester, artifact, store);
        }
        SubstrateEvent::CapabilityDenied {
            authority,
            operation,
            requester,
            capability,
        } => {
            let (requester, artifact, store) = substrate_requester_parts(requester);
            semantic.record_substrate_capability_denied(
                authority,
                operation,
                requester,
                artifact,
                store,
                capability.map(|capability| capability.id),
                capability.map(|capability| capability.generation),
            );
        }
    }
}

fn substrate_requester_parts(
    requester: Option<SubstrateRequester>,
) -> (Option<String>, Option<u64>, Option<u64>) {
    let Some(requester) = requester else {
        return (None, None, None);
    };
    (
        Some(requester.subject),
        requester.artifact.map(|artifact| artifact.id),
        requester.store.map(|store| store.id),
    )
}

fn build_target_executor_v1(
    plan: &ValidatedArtifactPlan,
    semantic: &SemanticGraph,
    runtime_stores: &[runtime::LoadedRuntimeStore],
) -> Result<TargetExecutorV1Report, Box<dyn Error>> {
    let mut registry = ArtifactRegistry::with_expected(expected_target_artifacts(plan));
    let mut publisher = CodePublisher::new();
    let mut store_manager = TargetStoreManager::new();
    let mut executor = TargetExecutor::new();
    let mut ledger = CapabilityLedger::new();
    let mut report = TargetExecutorV1Report::default();
    let mut verified_artifacts = Vec::new();

    for (index, entry) in plan.modules.iter().enumerate() {
        let image = target_artifact_image((index + 1) as u64, entry, plan);
        report
            .target_artifacts
            .push(target_artifact_manifest(&image));
        let verified = registry.verify(image).map_err(|error| error.message())?;
        verified_artifacts.push(verified.clone());
        let store_id = semantic_store_id(semantic, &entry.package)?;
        let store_id = store_manager.register_verified_artifact_with_id(
            store_id,
            &verified,
            &entry.fault_policy,
            "rebuild-from-verified-artifact",
        );
        store_manager
            .set_running(store_id)
            .map_err(|error| error.message())?;

        let code_id = publisher
            .allocate(&verified)
            .map_err(|error| error.message())?;
        publisher.fill(code_id).map_err(|error| error.message())?;
        publisher.seal(code_id).map_err(|error| error.message())?;
        publisher
            .publish_rx(code_id)
            .map_err(|error| error.message())?;
        let store = store_manager
            .record(store_id)
            .ok_or("store manager lost store after register")?;
        grant_verified_capabilities(&mut ledger, &verified, store_id, store.store.generation)?;
        publisher
            .bind_to_store(code_id, &store.store)
            .map_err(|error| error.message())?;
        if let Some(runtime_store) = runtime_stores
            .iter()
            .find(|store| store.package == entry.package)
        {
            let code_object = publisher
                .object_mut(code_id)
                .map_err(|error| error.message())?;
            append_cwasm_smoke_hostcalls(code_object, index, &runtime_store.smoke_trace);
        }
        let code = publisher
            .object(code_id)
            .ok_or("publisher lost code object after bind")?
            .clone();

        run_activation_harness(index, &mut executor, store, &code, &ledger)?;
        if let Some(runtime_store) = runtime_stores
            .iter()
            .find(|store| store.package == entry.package)
        {
            run_cwasm_smoke_evidence(
                index,
                &mut executor,
                store,
                &code,
                &ledger,
                &runtime_store.smoke_trace,
            )?;
        }
    }

    if let Some(cleanup_artifact) = verified_artifacts.first() {
        let cleanup_store_id = store_manager.register_verified_artifact(
            cleanup_artifact,
            "restartable",
            "cleanup-harness-rebuild",
        );
        store_manager
            .set_running(cleanup_store_id)
            .map_err(|error| error.message())?;
        let cleanup_store_snapshot = store_manager
            .record(cleanup_store_id)
            .ok_or("cleanup store missing after registration")?
            .store
            .clone();
        ledger
            .grant_with_authority_ref(
                &cleanup_artifact.package,
                "store-control.cleanup-harness",
                AuthorityObjectRef::internal(
                    CapabilityClass::StoreControl,
                    ContractObjectRef::new(
                        ContractObjectKind::Store,
                        cleanup_store_snapshot.id,
                        cleanup_store_snapshot.generation,
                    ),
                ),
                &["kill"],
                "store",
                Some(cleanup_store_id),
                Some(cleanup_store_snapshot.generation),
                None,
                "cleanup-harness",
                true,
            )
            .map_err(|error| error.message())?;
        let cleanup_code_id = publisher
            .allocate(cleanup_artifact)
            .map_err(|error| error.message())?;
        publisher
            .fill(cleanup_code_id)
            .map_err(|error| error.message())?;
        publisher
            .seal(cleanup_code_id)
            .map_err(|error| error.message())?;
        publisher
            .publish_rx(cleanup_code_id)
            .map_err(|error| error.message())?;
        publisher
            .bind_to_store(cleanup_code_id, &cleanup_store_snapshot)
            .map_err(|error| error.message())?;
        let cleanup_code_snapshot = publisher
            .object(cleanup_code_id)
            .ok_or("cleanup code object missing after bind")?
            .clone();
        let cleanup_activation = executor
            .start_activation(
                &cleanup_store_snapshot,
                &cleanup_code_snapshot,
                ActivationEntry::Symbol("cleanup_harness".to_owned()),
            )
            .map_err(|error| error.message())?;
        executor
            .acquire_dmw_lease(cleanup_activation, "dmw.cleanup.harness")
            .map_err(|error| error.message())?;
        {
            let cleanup_store = &mut store_manager
                .record_mut(cleanup_store_id)
                .map_err(|error| error.message())?
                .store;
            let cleanup_code = publisher
                .object_mut(cleanup_code_id)
                .map_err(|error| error.message())?;
            executor
                .run_fault_cleanup(
                    cleanup_store,
                    Some(cleanup_activation),
                    Some(cleanup_code),
                    &mut ledger,
                    "cleanup-harness",
                )
                .map_err(|error| error.message())?;
        }
        store_manager
            .record_current_tombstone(cleanup_store_id, "cleanup-store-dead")
            .map_err(|error| error.message())?;
        publisher
            .record_current_tombstone(cleanup_code_id, "cleanup-code-retired")
            .map_err(|error| error.message())?;
    }

    let snapshot_validation =
        SnapshotBarrierValidator::validate(&executor.snapshot_barrier_validation_state());
    report.snapshot_validation = boundary_validation_report_manifest(&snapshot_validation);
    executor
        .snapshot_barrier()
        .map_err(|error| error.message())?;
    let replay_record_modes = executor
        .hostcall_trace()
        .iter()
        .map(|trace| trace.record_mode)
        .collect::<Vec<_>>();
    let replay_state = ReplayPackageValidationState::clean(replay_record_modes);
    let replay_validation = PackageReplayValidator::validate(&replay_state);
    report.replay_validation = boundary_validation_report_manifest(&replay_validation);
    for policy in memory_class_policies() {
        report.memory_policies.push(memory_policy_manifest(policy));
    }
    for code in publisher.objects() {
        report.code_objects.push(code_object_manifest(code));
    }
    for store in store_manager.records() {
        report
            .store_records
            .push(store_record_manifest(&store.store));
    }
    for capability in ledger.records() {
        report
            .capability_records
            .push(capability_record_manifest(capability));
    }
    for activation in executor.activations() {
        report
            .activation_records
            .push(activation_record_manifest(activation));
    }
    for trap in executor.traps() {
        report.trap_records.push(trap_record_manifest(trap));
    }
    for trace in executor.hostcall_trace() {
        report.hostcall_trace.push(hostcall_trace_manifest(trace));
    }
    for object in executor.classify_migration_objects(publisher.objects()) {
        report
            .migration_objects
            .push(migration_object_manifest(&object));
    }
    for cleanup in executor.cleanup_transactions() {
        report
            .cleanup_transactions
            .push(cleanup_transaction_manifest(cleanup));
    }
    for tombstone in publisher
        .tombstones()
        .iter()
        .chain(store_manager.tombstones().iter())
        .chain(executor.tombstones().iter())
    {
        report.tombstones.push(tombstone_manifest(tombstone));
    }
    let external_objects = declared_authority_objects(ledger.records());
    let contract_snapshot = ContractGraphSnapshot {
        artifacts: verified_artifacts,
        code_objects: publisher.objects().to_vec(),
        stores: store_manager
            .records()
            .iter()
            .map(|record| record.store.clone())
            .collect(),
        activations: executor.activations().to_vec(),
        traps: executor.traps().to_vec(),
        hostcalls: executor.hostcall_trace().to_vec(),
        capabilities: ledger.records().to_vec(),
        waits: Vec::new(),
        cleanup_transactions: executor.cleanup_transactions().to_vec(),
        tombstones: publisher
            .tombstones()
            .iter()
            .chain(store_manager.tombstones().iter())
            .chain(executor.tombstones().iter())
            .cloned()
            .collect(),
        external_objects,
        explicit_edges: Vec::new(),
    };
    report.contract_violations = validate_contract_graph(&contract_snapshot)
        .iter()
        .map(contract_violation_manifest)
        .collect();
    report.target_event_tail = executor.event_log().to_vec();
    report.substrate_events = substrate_event_manifests(semantic.event_log().tail(usize::MAX));
    report.command_results = semantic
        .command_results()
        .iter()
        .map(command_result_manifest)
        .collect();
    report.interface_events = interface_event_manifests(semantic.event_log().tail(usize::MAX));
    Ok(report)
}

fn declared_authority_objects(capabilities: &[CapabilityRecord]) -> Vec<ExternalObjectDeclaration> {
    let mut declarations = Vec::new();
    for capability in capabilities {
        let Some(object_ref) = capability.object_ref else {
            continue;
        };
        let object = object_ref.object();
        if declarations
            .iter()
            .any(|declaration: &ExternalObjectDeclaration| declaration.object == object)
        {
            continue;
        }
        declarations.push(ExternalObjectDeclaration::new(
            object,
            "target-executor-authority",
            object_ref.class().as_str(),
            &capability.debug_object_label,
        ));
    }
    declarations
}

fn append_cwasm_smoke_hostcalls(
    code: &mut CodeObject,
    module_index: usize,
    smoke_trace: &[HostValidationSmokeTrace],
) {
    for (index, trace) in smoke_trace.iter().enumerate() {
        let number = cwasm_smoke_hostcall_number(module_index, index);
        let name = format!("cwasm.host-validation.{}", trace.export);
        let object = format!("host-validation.{}", code.package);
        code.hostcalls.push(HostcallSpec::new(
            number,
            &name,
            HostcallCategory::Service,
            &object,
            &trace.export,
            false,
        ));
    }
}

fn run_cwasm_smoke_evidence(
    module_index: usize,
    executor: &mut TargetExecutor,
    store: &ManagedStoreRecord,
    code: &CodeObject,
    ledger: &CapabilityLedger,
    smoke_trace: &[HostValidationSmokeTrace],
) -> Result<(), Box<dyn Error>> {
    for (index, trace) in smoke_trace.iter().enumerate() {
        let activation = executor
            .start_activation(
                &store.store,
                code,
                ActivationEntry::Symbol(format!("cwasm-smoke:{}", trace.export)),
            )
            .map_err(|error| error.message())?;
        if trace.trap.is_some() {
            executor.synthetic_trap(
                TargetTrapClass::CodeObjectTrap,
                store.store.id,
                Some(activation),
                Some(code),
                Some(&format!("cwasm.host-validation.{}", trace.export)),
                "UnknownCodeTrap: host-validation Wasmtime trap attribution unavailable",
            );
            continue;
        }
        let number = cwasm_smoke_hostcall_number(module_index, index);
        let object = format!("host-validation.{}", code.package);
        let frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            code,
            number,
            &object,
            &trace.export,
            1,
        )
        .to_wire_frame();
        executor
            .invoke_hostcall(code, frame, ledger)
            .map_err(|error| error.message())?;
        executor
            .return_exit(activation)
            .map_err(|error| error.message())?;
    }
    Ok(())
}

fn cwasm_smoke_hostcall_number(module_index: usize, trace_index: usize) -> u32 {
    9500 + module_index as u32 * 100 + trace_index as u32
}

fn run_activation_harness(
    index: usize,
    executor: &mut TargetExecutor,
    store: &ManagedStoreRecord,
    code: &CodeObject,
    ledger: &CapabilityLedger,
) -> Result<(), Box<dyn Error>> {
    let activation = executor
        .start_activation(
            &store.store,
            code,
            ActivationEntry::Symbol("vmos_service_entry".to_owned()),
        )
        .map_err(|error| error.message())?;
    if let Some(spec) = code.hostcalls.iter().find(|spec| spec.number < 9000) {
        let generation = ledger
            .generation_of(&code.package, &spec.object)
            .unwrap_or(1);
        let mut frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            code,
            spec.number,
            &spec.object,
            &spec.operation,
            generation,
        );
        if let Some(cap_arg) = capability_handle_arg_for(ledger, &code.package, spec) {
            frame = frame.with_cap_args(vec![cap_arg]);
        }
        executor
            .invoke_hostcall(code, frame.to_wire_frame(), ledger)
            .map_err(|error| error.message())?;
    }
    executor
        .return_exit(activation)
        .map_err(|error| error.message())?;

    if index == 0 {
        for (number, object, operation) in [
            (9000, "mmio.denied", "map"),
            (9001, "dma.denied", "map"),
            (9002, "irq.denied", "bind"),
            (9003, "dmw.denied", "open"),
            (9004, "code-publish.denied", "publish"),
            (9006, "packet-device.denied", "rx"),
            (9007, "device.denied", "read"),
            (9008, "virtqueue.denied", "kick"),
            (9009, "timer.denied", "arm"),
            (9010, "guest-memory.denied", "read"),
            (9011, "snapshot.denied", "enter"),
            (9012, "fault-domain.denied", "restart"),
            (9013, "event-log.denied", "append"),
            (9014, "store-control.denied", "kill"),
        ] {
            let denied = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("capability_gate".to_owned()),
                )
                .map_err(|error| error.message())?;
            let _ = executor.invoke_hostcall(
                code,
                HostcallFrame::new_bound(denied, &store.store, code, number, object, operation, 1)
                    .to_wire_frame(),
                ledger,
            );
        }
        if let Some(spec) = code.hostcalls.iter().find(|spec| spec.number < 9000) {
            let bad_abi = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("bad_hostcall_abi".to_owned()),
                )
                .map_err(|error| error.message())?;
            let generation = ledger
                .generation_of(&code.package, &spec.object)
                .unwrap_or(1);
            let frame = HostcallFrame::new_bound(
                bad_abi,
                &store.store,
                code,
                spec.number,
                &spec.object,
                &spec.operation,
                generation,
            );
            let mut wire_frame = frame.to_wire_frame();
            wire_frame.abi_version = 0;
            let _ = executor.invoke_hostcall(code, wire_frame, ledger);

            let bad_frame_size = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("bad_hostcall_frame_size".to_owned()),
                )
                .map_err(|error| error.message())?;
            let frame = HostcallFrame::new_bound(
                bad_frame_size,
                &store.store,
                code,
                spec.number,
                &spec.object,
                &spec.operation,
                generation,
            );
            let mut wire_frame = frame.to_wire_frame();
            wire_frame.frame_size = HostcallFrame::FRAME_SIZE + 8;
            let _ = executor.invoke_hostcall(code, wire_frame, ledger);

            if let Some(mut cap_arg) = capability_handle_arg_for(ledger, &code.package, spec) {
                let bad_cap_arg = executor
                    .start_activation(
                        &store.store,
                        code,
                        ActivationEntry::Symbol("bad_capability_handle".to_owned()),
                    )
                    .map_err(|error| error.message())?;
                cap_arg.rights_mask = 0;
                let frame = HostcallFrame::new_bound(
                    bad_cap_arg,
                    &store.store,
                    code,
                    spec.number,
                    &spec.object,
                    &spec.operation,
                    generation,
                )
                .with_cap_args(vec![cap_arg]);
                let _ = executor.invoke_hostcall(code, frame.to_wire_frame(), ledger);
            }
        }

        let dmw = executor
            .start_activation(
                &store.store,
                code,
                ActivationEntry::Symbol("dmw_pending".to_owned()),
            )
            .map_err(|error| error.message())?;
        let lease = executor
            .acquire_dmw_lease(dmw, "dmw.handle-mode.harness")
            .map_err(|error| error.message())?;
        let _ = executor.invoke_hostcall(
            code,
            HostcallFrame::new_bound(dmw, &store.store, code, 9005, "wait.timer", "park", 1)
                .to_wire_frame(),
            ledger,
        );
        executor
            .release_dmw_lease(lease)
            .map_err(|error| error.message())?;

        let pc_trap = executor
            .start_activation(
                &store.store,
                code,
                ActivationEntry::Symbol("pc_trap_ebreak".to_owned()),
            )
            .map_err(|error| error.message())?;
        let trap_map = [TrapMapEntryV1::new(
            ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
            RV64_ENTRY_TRAP_EBREAK_OFFSET,
            RV64_ENTRY_TRAP_EBREAK_OFFSET + 4,
            TrapKindV1::WasmUnreachable,
            0,
            RV64_ENTRY_TRAP_EBREAK_OFFSET,
            0,
        )];
        executor
            .trap_exit_by_pc(
                pc_trap,
                code,
                code.text.start + RV64_ENTRY_TRAP_EBREAK_OFFSET,
                &trap_map,
            )
            .map_err(|error| error.message())?;

        for class in [
            TargetTrapClass::GuestTrap,
            TargetTrapClass::SupervisorStoreTrap,
            TargetTrapClass::CapabilityTrap,
            TargetTrapClass::WindowTrap,
            TargetTrapClass::HostcallTrap,
            TargetTrapClass::CodeObjectTrap,
            TargetTrapClass::SubstrateFault,
        ] {
            executor.synthetic_trap(
                class,
                store.store.id,
                Some(activation),
                Some(code),
                None,
                "target executor v1 typed trap harness",
            );
        }
    }
    Ok(())
}

fn target_artifact_image(
    id: u64,
    entry: &ValidatedArtifactEntry,
    plan: &ValidatedArtifactPlan,
) -> TargetArtifactImage {
    let mut image = TargetArtifactImage::new(
        id,
        &entry.package,
        &entry.artifact_name,
        &entry.role,
        &plan.artifact_profile,
        &entry.target_artifact_sha256,
        &entry.abi_fingerprint,
        &entry.manifest_binding_hash,
        &entry.cwasm_sha256,
        TargetMemoryPlan::new(
            entry.resource_limits.max_memory_pages,
            entry.resource_limits.max_table_elements,
            entry.resource_limits.max_hostcalls_per_activation,
        ),
    );
    image.exports = entry.expected_exports.clone();
    image.payload_len = entry.cwasm_sha256.len();
    image
        .address_map
        .push(TargetAddressMapEntry::new("vmos_service_entry", 0, 64));
    image.trap_metadata.push(TargetTrapMetadata::new(
        TargetTrapClass::CodeObjectTrap,
        "vmos_service_entry",
        0,
    ));
    let mut next_hostcall = 1;
    for capability in &entry.capabilities {
        image.capabilities.push(TargetCapabilitySpec {
            object: capability.name.clone(),
            operations: capability.rights.clone(),
            lifetime: capability.lifetime.clone(),
            class: CapabilityClass::from_object(&capability.name),
        });
        for right in &capability.rights {
            let category = hostcall_category_for_object(&capability.name);
            image.hostcalls.push(HostcallSpec::new(
                next_hostcall,
                &format!("hostcall.{}.{}", capability.name, right),
                category,
                &capability.name,
                right,
                matches!(category, HostcallCategory::Wait | HostcallCategory::Timer),
            ));
            next_hostcall += 1;
        }
    }
    image.hostcalls.push(HostcallSpec::new(
        9000,
        "hostcall.mmio.denied",
        HostcallCategory::Mmio,
        "mmio.denied",
        "map",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9001,
        "hostcall.dma.denied",
        HostcallCategory::Dma,
        "dma.denied",
        "map",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9002,
        "hostcall.irq.denied",
        HostcallCategory::Irq,
        "irq.denied",
        "bind",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9003,
        "hostcall.dmw.denied",
        HostcallCategory::Dmw,
        "dmw.denied",
        "open",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9004,
        "hostcall.code-publish.denied",
        HostcallCategory::CodePublish,
        "code-publish.denied",
        "publish",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9005,
        "hostcall.wait.pending",
        HostcallCategory::Wait,
        "wait.timer",
        "park",
        true,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9006,
        "hostcall.packet-device.denied",
        HostcallCategory::PacketDevice,
        "packet-device.denied",
        "rx",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9007,
        "hostcall.device.denied",
        HostcallCategory::Device,
        "device.denied",
        "read",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9008,
        "hostcall.virtqueue.denied",
        HostcallCategory::Virtqueue,
        "virtqueue.denied",
        "kick",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9009,
        "hostcall.timer.denied",
        HostcallCategory::Timer,
        "timer.denied",
        "arm",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9010,
        "hostcall.guest-memory.denied",
        HostcallCategory::GuestMemory,
        "guest-memory.denied",
        "read",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9011,
        "hostcall.snapshot.denied",
        HostcallCategory::Snapshot,
        "snapshot.denied",
        "enter",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9012,
        "hostcall.fault-domain.denied",
        HostcallCategory::FaultDomain,
        "fault-domain.denied",
        "restart",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9013,
        "hostcall.event-log.denied",
        HostcallCategory::EventLog,
        "event-log.denied",
        "append",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9014,
        "hostcall.store-control.denied",
        HostcallCategory::StoreControl,
        "store-control.denied",
        "kill",
        false,
    ));
    image
}

fn hostcall_category_for_object(object: &str) -> HostcallCategory {
    if object.starts_with("packet-device.") {
        HostcallCategory::PacketDevice
    } else if object.starts_with("code-publish.") || object.starts_with("code-object.") {
        HostcallCategory::CodePublish
    } else if object.starts_with("device.") {
        HostcallCategory::Device
    } else if object.starts_with("mmio.") {
        HostcallCategory::Mmio
    } else if object.starts_with("dma.") {
        HostcallCategory::Dma
    } else if object.starts_with("irq.") {
        HostcallCategory::Irq
    } else if object.starts_with("virtqueue.") {
        HostcallCategory::Virtqueue
    } else if object.starts_with("dmw.") {
        HostcallCategory::Dmw
    } else if object.starts_with("code-publish.") {
        HostcallCategory::CodePublish
    } else if object.starts_with("snapshot.") {
        HostcallCategory::Snapshot
    } else if object.starts_with("guest-memory.") {
        HostcallCategory::GuestMemory
    } else if object.starts_with("timer.") {
        HostcallCategory::Timer
    } else if object.starts_with("fault-domain.") {
        HostcallCategory::FaultDomain
    } else if object.starts_with("event-log.") {
        HostcallCategory::EventLog
    } else if object.starts_with("store-control.") {
        HostcallCategory::StoreControl
    } else if object.starts_with("wait.") {
        HostcallCategory::Wait
    } else {
        HostcallCategory::Service
    }
}

fn expected_target_artifacts(plan: &ValidatedArtifactPlan) -> Vec<ExpectedTargetArtifact> {
    plan.modules
        .iter()
        .map(|entry| {
            ExpectedTargetArtifact::new(
                &entry.package,
                &entry.artifact_name,
                &plan.artifact_profile,
                &entry.target_artifact_sha256,
                &entry.abi_fingerprint,
                &entry.manifest_binding_hash,
                &entry.cwasm_sha256,
            )
        })
        .collect()
}

fn grant_verified_capabilities(
    ledger: &mut CapabilityLedger,
    verified: &VerifiedArtifact,
    store_id: u64,
    store_generation: u64,
) -> Result<(), &'static str> {
    for capability in &verified.capabilities {
        let operations = capability
            .operations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        ledger
            .grant_manifest_binding(
                &verified.package,
                &capability.object,
                &operations,
                &capability.lifetime,
                capability.class,
                Some(store_id),
                Some(store_generation),
                None,
                "target-executor-v1",
            )
            .map_err(|error| error.message())?;
    }
    Ok(())
}

fn capability_handle_arg_for(
    ledger: &CapabilityLedger,
    subject: &str,
    spec: &HostcallSpec,
) -> Option<CapabilityHandleArg> {
    let capability = ledger.check(subject, &spec.object, &spec.operation).ok()?;
    let index = capability
        .operations
        .as_slice()
        .iter()
        .position(|right| right == &spec.operation)?;
    Some(CapabilityHandleArg::from_record(
        capability,
        1u64 << index,
        &[spec.operation.as_str()],
    ))
}

fn semantic_store_id(semantic: &SemanticGraph, package: &str) -> Result<u64, Box<dyn Error>> {
    semantic
        .stores()
        .iter()
        .find(|store| store.package == package)
        .map(|store| store.id)
        .ok_or_else(|| format!("semantic graph missing store {package}").into())
}

fn prepare_migration_package(
    artifact_root: &Path,
    migration_path: Option<PathBuf>,
    manifest: &ArtifactBundleManifest,
    semantic: &SemanticGraph,
    target_v1: &TargetExecutorV1Report,
) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = migration_path {
        return Ok(path);
    }

    let path = artifact_root.join("semantic-package-v1.json");
    semantic
        .check_invariants()
        .map_err(|error| format!("semantic invariant failed before package write: {error:?}"))?;
    let package = demo_migration_package(manifest, semantic, target_v1);
    fs::write(&path, serde_json::to_vec_pretty(&package)?)?;
    Ok(path)
}

fn demo_migration_package(
    manifest: &ArtifactBundleManifest,
    semantic: &SemanticGraph,
    target_v1: &TargetExecutorV1Report,
) -> MigrationPackageManifest {
    let logical_capabilities = semantic
        .capabilities()
        .records()
        .iter()
        .map(|capability| MigrationCapabilityManifest {
            subject: capability.subject.clone(),
            object: capability.object.clone(),
            rights: capability.operations.as_slice().to_vec(),
            lifetime: capability.lifetime.clone(),
            class: capability.class.as_str().to_owned(),
            source: capability.source.clone(),
            owner_store: capability.owner_store,
            owner_store_generation: capability.owner_store_generation,
            owner_task: capability.owner_task.map(u64::from),
            generation: capability.generation,
            revoked: capability.revoked,
        })
        .collect::<Vec<_>>();
    let capability_count = logical_capabilities.len();
    let wait_records = target_v1
        .wait_records
        .iter()
        .cloned()
        .chain(semantic.wait_records().iter().map(wait_record_manifest))
        .collect::<Vec<_>>();
    let roots = semantic_roots(&logical_capabilities, semantic, target_v1);
    MigrationPackageManifest {
        schema_version: 1,
        package_format: "vmos-semantic-package-v1".to_owned(),
        package_id: "target-executor-semantic-package-v1".to_owned(),
        source: MigrationHostManifest {
            arch: "x86_64".to_owned(),
        },
        target: MigrationTargetManifest {
            arch_requirement: "target-native".to_owned(),
        },
        required_artifact_profile: RequiredArtifactProfileManifest {
            artifact_profile: manifest.artifact_profile.clone(),
            target_arch: "target-native".to_owned(),
            machine_abi_version: manifest.target.machine_abi_version.clone(),
            supervisor_abi_version: manifest.target.supervisor_abi_version.clone(),
            wasm_feature_profile: manifest.target.wasm_feature_profile.clone(),
            memory64: manifest.target.memory64,
            multi_memory: manifest.target.multi_memory,
            dmw_layout: manifest.target.dmw_layout.clone(),
            network_contract_version: manifest.target.network_contract_version.clone(),
            compiler_engine: manifest.compiler.engine.clone(),
            compiler_execution_mode: manifest.compiler.execution_mode.clone(),
            artifact_format: manifest.compiler.artifact_format.clone(),
            runtime_executor_abi: manifest.compiler.runtime_executor_abi.clone(),
        },
        guest: GuestStateManifest {
            canonical_isa: "riscv64".to_owned(),
            register_count: 33,
            memory_page_count: 0,
            vma_count: 0,
            signal_queue_count: 0,
            note: "host-side package proving cross-ISA restore/rebind boundaries".to_owned(),
        },
        semantic: SemanticSnapshotManifest {
            barrier_id: 1,
            event_log_cursor: semantic.event_log().cursor(),
            roots,
            pending_wait_count: semantic.pending_wait_count(),
            hart_count: semantic.hart_count(),
            task_count: semantic.task_count(),
            task_record_count: semantic.tasks().len(),
            runtime_activation_count: semantic.runtime_activation_count(),
            runnable_queue_count: semantic.runnable_queue_count(),
            activation_context_count: semantic.activation_context_count(),
            saved_context_count: semantic.saved_context_count(),
            timer_interrupt_count: semantic.timer_interrupt_count(),
            ipi_event_count: semantic.ipi_event_count(),
            remote_preempt_count: semantic.remote_preempt_count(),
            preemption_count: semantic.preemption_count(),
            scheduler_decision_count: semantic.scheduler_decision_count(),
            activation_resume_count: semantic.activation_resume_count(),
            activation_wait_count: semantic.activation_wait_count(),
            activation_cleanup_count: semantic.activation_cleanup_count(),
            preemption_latency_sample_count: semantic.preemption_latency_sample_count(),
            hart_event_attribution_count: semantic.hart_event_attribution_count(),
            resource_count: semantic.resource_count(),
            authority_count: semantic.authority_count(),
            active_authority_count: semantic.active_authority_count(),
            wait_token_count: wait_records.len(),
            wait_record_count: wait_records.len(),
            capability_count,
            capability_record_count: target_v1.capability_records.len(),
            fault_domain_count: semantic.fault_domain_count(),
            store_count: semantic.store_count(),
            store_record_count: target_v1.store_records.len(),
            transaction_count: 0,
            active_transaction_count: 0,
            fast_path_plan_count: semantic.fast_path_plan_count(),
            active_fast_path_plan_count: semantic.active_fast_path_plan_count(),
            boundary_count: semantic.boundary_count(),
            artifact_verification_count: semantic.artifact_verification_count(),
            store_activation_count: semantic.store_activation_count(),
            executor_transition_count: semantic.store_executor_transition_count(),
            target_artifact_count: target_v1.target_artifacts.len(),
            code_object_count: target_v1.code_objects.len(),
            activation_record_count: target_v1.activation_records.len(),
            trap_record_count: target_v1.trap_records.len(),
            hostcall_trace_count: target_v1.hostcall_trace.len(),
            migration_object_count: target_v1.migration_objects.len(),
            tombstone_count: target_v1.tombstones.len(),
            contract_violation_count: target_v1.contract_violations.len(),
            cleanup_transaction_count: target_v1.cleanup_transactions.len(),
            memory_policy_count: target_v1.memory_policies.len(),
            snapshot_validation_violation_count: target_v1.snapshot_validation.violation_count,
            replay_validation_violation_count: target_v1.replay_validation.violation_count,
            substrate_event_count: target_v1.substrate_events.len(),
            command_result_count: target_v1.command_results.len(),
            interface_event_count: target_v1.interface_events.len(),
            target_artifacts: target_v1.target_artifacts.clone(),
            hart_records: semantic.harts().iter().map(hart_record_manifest).collect(),
            task_records: semantic.tasks().iter().map(task_record_manifest).collect(),
            runtime_activation_records: semantic
                .runtime_activations()
                .iter()
                .map(runtime_activation_record_manifest)
                .collect(),
            runnable_queues: semantic
                .runnable_queues()
                .iter()
                .map(runnable_queue_manifest)
                .collect(),
            activation_contexts: semantic
                .activation_contexts()
                .iter()
                .map(activation_context_manifest)
                .collect(),
            saved_contexts: semantic
                .saved_contexts()
                .iter()
                .map(saved_context_manifest)
                .collect(),
            timer_interrupts: semantic
                .timer_interrupts()
                .iter()
                .map(timer_interrupt_manifest)
                .collect(),
            ipi_events: semantic
                .ipi_events()
                .iter()
                .map(ipi_event_manifest)
                .collect(),
            remote_preempts: semantic
                .remote_preempts()
                .iter()
                .map(remote_preempt_manifest)
                .collect(),
            preemptions: semantic
                .preemptions()
                .iter()
                .map(preemption_manifest)
                .collect(),
            scheduler_decisions: semantic
                .scheduler_decisions()
                .iter()
                .map(scheduler_decision_manifest)
                .collect(),
            activation_resumes: semantic
                .activation_resumes()
                .iter()
                .map(activation_resume_manifest)
                .collect(),
            activation_waits: semantic
                .activation_waits()
                .iter()
                .map(activation_wait_manifest)
                .collect(),
            activation_cleanups: semantic
                .activation_cleanups()
                .iter()
                .map(activation_cleanup_manifest)
                .collect(),
            preemption_latency_samples: semantic
                .preemption_latency_samples()
                .iter()
                .map(preemption_latency_manifest)
                .collect(),
            hart_event_attributions: semantic
                .hart_event_attributions()
                .iter()
                .map(hart_event_attribution_manifest)
                .collect(),
            code_objects: target_v1.code_objects.clone(),
            store_records: target_v1.store_records.clone(),
            capability_records: target_v1.capability_records.clone(),
            wait_records,
            activation_records: target_v1.activation_records.clone(),
            trap_records: target_v1.trap_records.clone(),
            hostcall_trace: target_v1.hostcall_trace.clone(),
            migration_objects: target_v1.migration_objects.clone(),
            tombstones: target_v1.tombstones.clone(),
            contract_violations: target_v1.contract_violations.clone(),
            cleanup_transactions: target_v1.cleanup_transactions.clone(),
            memory_policies: target_v1.memory_policies.clone(),
            snapshot_validation: target_v1.snapshot_validation.clone(),
            replay_validation: target_v1.replay_validation.clone(),
            substrate_events: target_v1.substrate_events.clone(),
            command_results: target_v1.command_results.clone(),
            interface_events: target_v1.interface_events.clone(),
            network_socket_count: 1,
            network_rx_queue_bytes: 0,
        },
        logical_capabilities,
        substrate_boundary: SubstrateBoundaryManifest {
            timer_epoch: semantic.timer_epoch(),
            pending_irq_causes: 0,
            pending_dma_completions: 0,
            active_dmw_lease_count: 0,
            active_mmio_authority_count: 0,
            active_dma_authority_count: 0,
            active_irq_authority_count: 0,
            active_packet_device_authority_count: 0,
            active_virtio_queue_authority_count: 0,
            pending_network_inputs: 0,
            random_epoch: 0,
            scheduler_decision_cursor: semantic.event_count() as u64,
            cow_epoch: 1,
            background_copy_pages: 0,
            native_state_policy:
                "target rebuilds page tables, DMW slots, IRQ registrations, stores, and code cache"
                    .to_owned(),
        },
        not_migrated: vec![
            "host raw pointers".to_owned(),
            "native stacks".to_owned(),
            "active semantic transactions".to_owned(),
            "active DMW leases".to_owned(),
            "DMA/IOMMU mappings".to_owned(),
            "MMIO mappings".to_owned(),
            "IRQ registrations".to_owned(),
            "translated guest code cache".to_owned(),
        ],
    }
}

fn semantic_roots(
    capabilities: &[MigrationCapabilityManifest],
    semantic: &SemanticGraph,
    target_v1: &TargetExecutorV1Report,
) -> SemanticRootSetManifest {
    SemanticRootSetManifest {
        hart_roots: semantic
            .harts()
            .iter()
            .map(|hart| {
                format!(
                    "hart id={} hardware_id={} label={} state={} generation={} boot={} current={}@{}",
                    hart.id,
                    hart.hardware_id,
                    hart.label,
                    hart.state.as_str(),
                    hart.generation,
                    hart.boot,
                    hart.current_activation
                        .map(|activation| activation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    hart.current_activation_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned())
                )
            })
            .collect(),
        task_roots: semantic
            .tasks()
            .iter()
            .map(|task| {
                format!(
                    "task:{}:{}:{}:gen{}",
                    task.id,
                    task.frontend.as_str(),
                    task.state.as_str(),
                    task.generation
                )
            })
            .collect(),
        task_record_roots: semantic
            .tasks()
            .iter()
            .map(|task| format!("task-record id={} state={} generation={}", task.id, task.state.as_str(), task.generation))
            .collect(),
        runtime_activation_roots: semantic
            .runtime_activations()
            .iter()
            .map(|activation| {
                format!(
                    "runtime-activation id={} task={}@{} state={} generation={} queue={}@{}",
                    activation.id,
                    activation.owner_task,
                    activation.owner_task_generation,
                    activation.state.as_str(),
                    activation.generation,
                    activation
                        .runnable_queue
                        .map(|queue| queue.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    activation
                        .runnable_queue_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned())
                )
            })
            .collect(),
        runnable_queue_roots: semantic
            .runnable_queues()
            .iter()
            .map(|queue| {
                format!(
                    "runnable-queue id={} label={} state={} generation={} entries={}",
                    queue.id,
                    queue.label,
                    queue.state.as_str(),
                    queue.generation,
                    queue.entries.len()
                )
            })
            .collect(),
        activation_context_roots: semantic
            .activation_contexts()
            .iter()
            .map(|context| {
                format!(
                    "activation-context id={} activation={}@{} state={} generation={} saved={}@{}",
                    context.id,
                    context.activation,
                    context.activation_generation,
                    context.state.as_str(),
                    context.generation,
                    context
                        .current_saved_context
                        .map(|saved| saved.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    context
                        .current_saved_context_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned())
                )
            })
            .collect(),
        saved_context_roots: semantic
            .saved_contexts()
            .iter()
            .map(|saved| {
                format!(
                    "saved-context id={} context={}@{} activation={}@{} state={} reason={} pc={:#x} sp={:#x} generation={}",
                    saved.id,
                    saved.context,
                    saved.context_generation,
                    saved.activation,
                    saved.activation_generation,
                    saved.state.as_str(),
                    saved.reason.as_str(),
                    saved.pc,
                    saved.sp,
                    saved.generation
                )
            })
            .collect(),
        timer_interrupt_roots: semantic
            .timer_interrupts()
            .iter()
            .map(|interrupt| {
                format!(
                    "timer-interrupt id={} epoch={} hart={} target={}@{} state={} generation={}",
                    interrupt.id,
                    interrupt.timer_epoch,
                    interrupt.hart,
                    interrupt
                        .target_activation
                        .map(|activation| activation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    interrupt
                        .target_activation_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    interrupt.state.as_str(),
                    interrupt.generation
                )
            })
            .collect(),
        ipi_event_roots: semantic
            .ipi_events()
            .iter()
            .map(|ipi| {
                format!(
                    "ipi-event id={} kind={} source_hart={}@{} target_hart={}@{} state={} generation={}",
                    ipi.id,
                    ipi.kind.as_str(),
                    ipi.source_hart,
                    ipi.source_hart_generation,
                    ipi.target_hart,
                    ipi.target_hart_generation,
                    ipi.state.as_str(),
                    ipi.generation
                )
            })
            .collect(),
        remote_preempt_roots: semantic
            .remote_preempts()
            .iter()
            .map(|remote| {
                format!(
                    "remote-preempt id={} ipi={}@{} source_hart={}@{} target_hart={}@{}->{} activation={}@{}->{} queue={}@{} state={} generation={}",
                    remote.id,
                    remote.ipi,
                    remote.ipi_generation,
                    remote.source_hart,
                    remote.source_hart_generation,
                    remote.target_hart,
                    remote.target_hart_generation_before,
                    remote.target_hart_generation_after,
                    remote.activation,
                    remote.activation_generation_before,
                    remote.activation_generation_after,
                    remote.queue,
                    remote.queue_generation,
                    remote.state.as_str(),
                    remote.generation
                )
            })
            .collect(),
        preemption_roots: semantic
            .preemptions()
            .iter()
            .map(|preemption| {
                format!(
                    "preemption id={} activation={}@{}->{} timer={}@{} queue={}@{} state={} generation={}",
                    preemption.id,
                    preemption.activation,
                    preemption.activation_generation_before,
                    preemption.activation_generation_after,
                    preemption.timer_interrupt,
                    preemption.timer_interrupt_generation,
                    preemption.queue,
                    preemption.queue_generation,
                    preemption.state.as_str(),
                    preemption.generation
                )
            })
            .collect(),
        scheduler_decision_roots: semantic
            .scheduler_decisions()
            .iter()
            .map(|decision| {
                format!(
                    "scheduler-decision id={} queue={}@{} activation={}@{} state={} generation={}",
                    decision.id,
                    decision.queue,
                    decision.queue_generation,
                    decision.selected_activation,
                    decision.selected_activation_generation,
                    decision.state.as_str(),
                    decision.generation
                )
            })
            .collect(),
        activation_resume_roots: semantic
            .activation_resumes()
            .iter()
            .map(|resume| {
                format!(
                    "activation-resume id={} decision={}@{} activation={}@{}->{} state={} generation={}",
                    resume.id,
                    resume.scheduler_decision,
                    resume.scheduler_decision_generation,
                    resume.activation,
                    resume.activation_generation_before,
                    resume.activation_generation_after,
                    resume.state.as_str(),
                    resume.generation
                )
            })
            .collect(),
        activation_wait_roots: semantic
            .activation_waits()
            .iter()
            .map(|activation_wait| {
                format!(
                    "activation-wait id={} activation={}@{}->{} wait={}@{} state={} generation={}",
                    activation_wait.id,
                    activation_wait.activation,
                    activation_wait.activation_generation_before,
                    activation_wait.activation_generation_after_block,
                    activation_wait.wait,
                    activation_wait.wait_generation,
                    activation_wait.state.as_str(),
                    activation_wait.generation
                )
            })
            .collect(),
        activation_cleanup_roots: semantic
            .activation_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "activation-cleanup id={} store={}@{}->{} activation={}@{}->{} wait={}@{} state={} generation={}",
                    cleanup.id,
                    cleanup.store,
                    cleanup.target_store_generation,
                    cleanup.result_store_generation,
                    cleanup.activation,
                    cleanup.activation_generation_before,
                    cleanup.activation_generation_after,
                    cleanup
                        .wait
                        .map(|wait| wait.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .wait_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup.state.as_str(),
                    cleanup.generation
                )
            })
            .collect(),
        preemption_latency_roots: semantic
            .preemption_latency_samples()
            .iter()
            .map(|sample| {
                format!(
                    "preemption-latency id={} timer={}@{} preemption={}@{} decision={}@{} resume={}@{} events={} measured_nanos={} budget_nanos={} state={} generation={}",
                    sample.id,
                    sample.timer_interrupt,
                    sample.timer_interrupt_generation,
                    sample.preemption,
                    sample.preemption_generation,
                    sample.scheduler_decision,
                    sample.scheduler_decision_generation,
                    sample.activation_resume,
                    sample.activation_resume_generation,
                    sample.interrupt_to_resume_events,
                    sample.measured_nanos,
                    sample.budget_nanos,
                    sample.state.as_str(),
                    sample.generation
                )
            })
            .collect(),
        hart_event_attribution_roots: semantic
            .hart_event_attributions()
            .iter()
            .map(|attribution| {
                format!(
                    "hart-event-attribution id={} hart={}@{} hardware_id={} event={} kind={} generation={}",
                    attribution.id,
                    attribution.hart,
                    attribution.hart_generation,
                    attribution.hardware_hart,
                    attribution.event,
                    attribution.event_kind,
                    attribution.generation
                )
            })
            .collect(),
        resource_roots: semantic
            .resources()
            .iter()
            .map(|resource| {
                format!(
                    "resource id={} kind={} generation={} live={}",
                    resource.id,
                    resource.kind.as_str(),
                    resource.generation,
                    resource.live
                )
            })
            .collect(),
        authority_roots: semantic
            .authority_bindings()
            .iter()
            .map(|authority| {
                format!(
                    "authority:{}:{}:{}:gen{}:{}",
                    authority.id,
                    authority.subject,
                    authority.object,
                    authority.generation,
                    authority.state.as_str()
                )
            })
            .collect(),
        wait_roots: target_v1
            .wait_records
            .iter()
            .map(|wait| {
                format!(
                    "wait id={} state={} generation={}",
                    wait.id, wait.state, wait.generation
                )
            })
            .chain(semantic.wait_records().iter().map(|wait| {
                format!(
                    "wait id={} state={} generation={}",
                    wait.id,
                    wait.state.as_str(),
                    wait.generation
                )
            }))
            .collect(),
        store_roots: semantic
            .stores()
            .iter()
            .map(|store| {
                format!(
                    "store id={} package={} state={} generation={}",
                    store.id,
                    store.package,
                    store.state.as_str(),
                    store.generation
                )
            })
            .collect(),
        capability_roots: capabilities
            .iter()
            .map(|capability| {
                format!(
                    "cap:{}:{}:{}:{}:gen{}:{}",
                    capability.subject,
                    capability.class,
                    capability.object,
                    capability.rights.join("+"),
                    capability.generation,
                    capability.source
                )
            })
            .collect(),
        target_store_record_roots: target_v1
            .store_records
            .iter()
            .map(|store| {
                format!(
                    "target-store id={} package={} artifact={} state={} generation={} fault_domain={}",
                    store.id,
                    store.package,
                    store.artifact,
                    store.state,
                    store.generation,
                    store.fault_domain
                )
            })
            .collect(),
        target_capability_record_roots: target_v1
            .capability_records
            .iter()
            .map(|capability| {
                format!(
                    "target-capability id={} subject={} object={} class={} rights={} generation={} owner_store={}@{} revoked={} source={}",
                    capability.id,
                    capability.subject,
                    capability.object,
                    capability.class,
                    capability.rights.join("+"),
                    capability.generation,
                    capability
                        .owner_store
                        .map(|store| store.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    capability
                        .owner_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    capability.revoked,
                    capability.source
                )
            })
            .collect(),
        fast_path_roots: semantic
            .fast_path_plans()
            .iter()
            .map(|plan| {
                format!(
                    "fastpath:{}:gen{}:valid{}",
                    plan.id, plan.generation, plan.valid
                )
            })
            .collect(),
        boundary_roots: semantic
            .boundaries()
            .iter()
            .map(|boundary| boundary.summary())
            .collect(),
        artifact_verification_roots: semantic
            .artifact_verifications()
            .iter()
            .map(|artifact| artifact.summary())
            .collect(),
        store_activation_roots: semantic
            .store_activations()
            .iter()
            .map(|activation| activation.summary())
            .collect(),
        executor_transition_roots: semantic
            .store_executor_transition_tail(semantic.store_executor_transition_count()),
        target_artifact_roots: target_v1
            .target_artifacts
            .iter()
            .map(|artifact| {
                format!(
                    "target-artifact id={} package={} artifact={} profile={} artifact_hash={} abi={} code_hash={}",
                    artifact.id,
                    artifact.package,
                    artifact.artifact_name,
                    artifact.target_profile,
                    artifact.artifact_hash,
                    artifact.abi_fingerprint,
                    artifact.code_hash
                )
            })
            .collect(),
        code_object_roots: target_v1
            .code_objects
            .iter()
            .map(|code| {
                let store = code
                    .bound_store
                    .map(|store| {
                        format!(
                            "{store}@{}",
                            code.bound_store_generation
                                .map(|generation| generation.to_string())
                                .unwrap_or_else(|| "unknown".to_owned())
                        )
                    })
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "code-object id={} artifact={} package={} state={} store={} generation={}",
                    code.id, code.artifact_id, code.package, code.state, store, code.generation
                )
            })
            .collect(),
        activation_record_roots: target_v1
            .activation_records
            .iter()
            .map(|activation| {
                let wait = activation
                    .blocked_wait
                    .map(|wait| wait.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                let trap = activation
                    .trap
                    .map(|trap| trap.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "activation id={} store={} store_generation={} code={} code_generation={} state={} entry={} wait={} trap={} dmw={}",
                    activation.id,
                    activation.store,
                    activation.store_generation,
                    activation.code_object,
                    activation.code_generation,
                    activation.state,
                    activation.entry,
                    wait,
                    trap,
                    activation.active_dmw_leases
                )
            })
            .collect(),
        trap_roots: target_v1
            .trap_records
            .iter()
            .map(|trap| {
                let store = trap
                    .store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                let activation = trap
                    .activation
                    .map(|activation| activation.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "trap id={} class={} store={} activation={} effect={} detail={}",
                    trap.id, trap.class, store, activation, trap.effect, trap.detail
                )
            })
            .collect(),
        hostcall_trace_roots: target_v1
            .hostcall_trace
            .iter()
            .map(|trace| {
                format!(
                    "hostcall abi={} frame_size={} seq={} caller_offset={} record_mode={} activation={} activation_generation={} store={} code={} artifact={}@{} number={} category={} subject={} object={} op={} cap_args={} allowed={} result={} ret={}",
                    trace.abi_version,
                    trace.frame_size,
                    trace.hostcall_seq,
                    trace.caller_offset,
                    trace.record_mode,
                    trace.activation,
                    trace.activation_generation,
                    trace.store,
                    trace.code_object,
                    trace.artifact,
                    trace.artifact_generation,
                    trace.hostcall_number,
                    trace.category,
                    trace.subject,
                    trace.object,
                    trace.operation,
                    trace.cap_args.len(),
                    trace.allowed,
                    trace.result,
                    trace.ret_tag
                )
            })
            .collect(),
        migration_object_roots: target_v1
            .migration_objects
            .iter()
            .map(|object| {
                format!(
                    "migration-object object={} class={} reason={}",
                    object.object, object.class, object.reason
                )
            })
            .collect(),
        tombstone_roots: target_v1
            .tombstones
            .iter()
            .map(|tombstone| {
                format!(
                    "tombstone kind={} id={} generation={} died_at={} reason={}",
                    tombstone.kind,
                    tombstone.id,
                    tombstone.generation,
                    tombstone.died_at,
                    tombstone.reason
                )
            })
            .collect(),
        contract_violation_roots: target_v1
            .contract_violations
            .iter()
            .map(|violation| {
                let to = violation.to.as_ref().map_or_else(
                    || "none".to_owned(),
                    |to| format!("{}:{}@{}", to.kind, to.id, to.generation),
                );
                format!(
                    "contract-violation kind={} edge={} from={}:{}@{} to={} detail={}",
                    violation.kind,
                    violation.edge,
                    violation.from.kind,
                    violation.from.id,
                    violation.from.generation,
                    to,
                    violation.detail
                )
            })
            .collect(),
        cleanup_roots: target_v1
            .cleanup_transactions
            .iter()
            .map(|cleanup| {
                format!(
                    "cleanup id={} target_store={}@{} result_store_generation={} activation={} code={} generation={} state={} reason={} released_dmw={} cancelled_waits={} revoked_caps={} dropped_resources={} unbound_code={} effect={} steps={}",
                    cleanup.id,
                    cleanup.store,
                    cleanup.store_generation,
                    cleanup
                        .result_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .activation
                        .zip(cleanup.activation_generation)
                        .map(|(activation, generation)| format!("{activation}@{generation}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .code_object
                        .zip(cleanup.code_generation)
                        .map(|(code, generation)| format!("{code}@{generation}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup.generation,
                    cleanup.state,
                    cleanup.reason,
                    cleanup.released_dmw_leases,
                    cleanup.cancelled_waits,
                    cleanup.revoked_capabilities.len(),
                    cleanup.dropped_resources,
                    cleanup.unbound_code_object,
                    cleanup.effect,
                    cleanup
                        .steps
                        .iter()
                        .map(|step| format!("{}:{}", step.step, step.state))
                        .collect::<Vec<_>>()
                        .join("|")
                )
            })
            .collect(),
        memory_policy_roots: target_v1
            .memory_policies
            .iter()
            .map(|policy| {
                format!(
                    "memory-policy class={} owner={} perms={} migration={} snapshot={} cleanup={} alias_guest={} cross_pending={} executable={}",
                    policy.class,
                    policy.owner_kind,
                    policy.permissions,
                    policy.migration_policy,
                    policy.snapshot_policy,
                    policy.cleanup_policy,
                    policy.can_alias_guest_memory,
                    policy.can_cross_pending,
                    policy.can_be_executable
                )
            })
            .collect(),
        snapshot_validation_roots: validation_roots(&target_v1.snapshot_validation),
        replay_validation_roots: validation_roots(&target_v1.replay_validation),
        substrate_event_roots: target_v1
            .substrate_events
            .iter()
            .map(|event| {
                format!(
                    "substrate-event:{}:{}:{} requester={}",
                    event.event_kind,
                    event.authority,
                    event.operation,
                    event.requester.as_deref().unwrap_or("none")
                )
            })
            .collect(),
        command_result_roots: target_v1
            .command_results
            .iter()
            .map(|result| {
                format!(
                    "command-result:{}:{}:{} issuer={}",
                    result.id, result.command, result.status, result.issuer
                )
            })
            .collect(),
        interface_event_roots: target_v1
            .interface_events
            .iter()
            .map(|event| {
                format!(
                    "interface-event:{}:{}:{} requester={}",
                    event.interface_kind,
                    event.interface,
                    event.operation,
                    event.requester.as_deref().unwrap_or("none")
                )
            })
            .collect(),
        event_log_tail: semantic
            .event_log_tail(16)
            .iter()
            .map(|event| event.summary())
            .chain(target_v1.target_event_tail.iter().cloned())
            .collect(),
    }
}

fn target_artifact_manifest(image: &TargetArtifactImage) -> TargetArtifactImageManifest {
    TargetArtifactImageManifest {
        id: image.id,
        package: image.package.clone(),
        artifact_name: image.artifact_name.clone(),
        role: image.role.clone(),
        kind: image.kind.as_str().to_owned(),
        target_profile: image.target_profile.clone(),
        artifact_hash: image.artifact_hash.clone(),
        abi_fingerprint: image.abi_fingerprint.clone(),
        manifest_binding_hash: image.manifest_binding_hash.clone(),
        code_hash: image.code_hash.clone(),
        exports: image.exports.clone(),
        imports: image.imports.clone(),
        hostcalls: image.hostcalls.iter().map(hostcall_manifest).collect(),
        capabilities: image
            .capabilities
            .iter()
            .map(target_capability_manifest)
            .collect(),
        memory_plan: TargetMemoryPlanManifest {
            max_memory_pages: image.memory_plan.max_memory_pages,
            max_table_elements: image.memory_plan.max_table_elements,
            max_hostcalls_per_activation: image.memory_plan.max_hostcalls_per_activation,
        },
        trap_metadata: image
            .trap_metadata
            .iter()
            .map(trap_metadata_manifest)
            .collect(),
        address_map: image.address_map.iter().map(address_map_manifest).collect(),
        payload_len: image.payload_len,
    }
}

fn code_object_manifest(code: &CodeObject) -> CodeObjectManifest {
    CodeObjectManifest {
        id: code.id,
        artifact_id: code.artifact_id,
        package: code.package.clone(),
        owner_profile: code.owner_profile.clone(),
        generation: code.generation,
        state: code.state.as_str().to_owned(),
        bound_store: code.bound_store,
        bound_store_generation: code.bound_store_generation,
        hostcall_table: code.hostcall_table,
        text_start: code.text.start,
        text_len: code.text.len,
        text_permission: code.text.permission.as_str().to_owned(),
        rodata_start: code.rodata.start,
        rodata_len: code.rodata.len,
        rodata_permission: code.rodata.permission.as_str().to_owned(),
        code_hash: code.code_hash.clone(),
        hostcalls: code.hostcalls.iter().map(hostcall_manifest).collect(),
        trap_metadata: code
            .trap_metadata
            .iter()
            .map(trap_metadata_manifest)
            .collect(),
        address_map: code.address_map.iter().map(address_map_manifest).collect(),
    }
}

fn store_record_manifest(store: &StoreRecord) -> StoreRecordManifest {
    StoreRecordManifest {
        id: store.id,
        package: store.package.clone(),
        artifact: store.artifact.clone(),
        role: store.role.clone(),
        fault_policy: store.fault_policy.clone(),
        fault_domain: store.fault_domain,
        resource: store.resource,
        state: store.state.as_str().to_owned(),
        generation: store.generation,
        restart_count: store.restart_count,
    }
}

fn hart_record_manifest(hart: &semantic_core::HartRecord) -> HartRecordManifest {
    HartRecordManifest {
        id: u64::from(hart.id),
        hardware_id: hart.hardware_id,
        label: hart.label.clone(),
        state: hart.state.as_str().to_owned(),
        generation: hart.generation,
        boot: hart.boot,
        current_activation: hart.current_activation,
        current_activation_generation: hart.current_activation_generation,
        current_task: hart.current_task.map(u64::from),
        current_task_generation: hart.current_task_generation,
        current_store: hart.current_store,
        current_store_generation: hart.current_store_generation,
        last_event: hart.last_event,
        last_current_event: hart.last_current_event,
        note: hart.note.clone(),
    }
}

fn task_record_manifest(task: &semantic_core::TaskRecord) -> TaskRecordManifest {
    TaskRecordManifest {
        id: u64::from(task.id),
        label: task.label.clone(),
        frontend: task.frontend.as_str().to_owned(),
        state: task.state.as_str().to_owned(),
        generation: task.generation,
        fault_domain: task.fault_domain,
        pending_wait: task.pending_wait,
        resources: task.resources.clone(),
    }
}

fn runtime_activation_record_manifest(
    activation: &semantic_core::RuntimeActivationRecord,
) -> RuntimeActivationRecordManifest {
    RuntimeActivationRecordManifest {
        id: activation.id,
        owner_task: u64::from(activation.owner_task),
        owner_task_generation: activation.owner_task_generation,
        owner_store: activation.owner_store,
        owner_store_generation: activation.owner_store_generation,
        code_object: activation.code_object.map(contract_object_ref_manifest),
        generation: activation.generation,
        state: activation.state.as_str().to_owned(),
        runnable_queue: activation.runnable_queue,
        runnable_queue_generation: activation.runnable_queue_generation,
        last_event: activation.last_event,
    }
}

fn runnable_queue_manifest(queue: &semantic_core::RunnableQueueRecord) -> RunnableQueueManifest {
    RunnableQueueManifest {
        id: queue.id,
        label: queue.label.clone(),
        generation: queue.generation,
        state: queue.state.as_str().to_owned(),
        owner_hart: queue.owner_hart,
        owner_hart_generation: queue.owner_hart_generation,
        entries: queue
            .entries
            .iter()
            .map(|entry| RunnableQueueEntryManifest {
                activation: entry.activation,
                activation_generation: entry.activation_generation,
                enqueued_at: entry.enqueued_at,
            })
            .collect(),
    }
}

fn activation_context_manifest(
    context: &semantic_core::ActivationContextRecord,
) -> ActivationContextManifest {
    ActivationContextManifest {
        id: context.id,
        activation: context.activation,
        activation_generation: context.activation_generation,
        owner_task: u64::from(context.owner_task),
        owner_task_generation: context.owner_task_generation,
        owner_store: context.owner_store,
        owner_store_generation: context.owner_store_generation,
        generation: context.generation,
        state: context.state.as_str().to_owned(),
        current_saved_context: context.current_saved_context,
        current_saved_context_generation: context.current_saved_context_generation,
        last_event: context.last_event,
    }
}

fn saved_context_manifest(saved: &semantic_core::SavedContextRecord) -> SavedContextManifest {
    SavedContextManifest {
        id: saved.id,
        context: saved.context,
        context_generation: saved.context_generation,
        activation: saved.activation,
        activation_generation: saved.activation_generation,
        owner_task: u64::from(saved.owner_task),
        owner_task_generation: saved.owner_task_generation,
        source_preemption: saved.source_preemption,
        source_preemption_generation: saved.source_preemption_generation,
        generation: saved.generation,
        state: saved.state.as_str().to_owned(),
        reason: saved.reason.as_str().to_owned(),
        pc: saved.pc,
        sp: saved.sp,
        flags: saved.flags,
        integer_registers: saved.integer_registers,
        saved_at_event: saved.saved_at_event,
        note: saved.note.clone(),
    }
}

fn timer_interrupt_manifest(
    interrupt: &semantic_core::TimerInterruptRecord,
) -> TimerInterruptManifest {
    TimerInterruptManifest {
        id: interrupt.id,
        timer_epoch: interrupt.timer_epoch,
        hart: u64::from(interrupt.hart),
        hart_generation: Some(interrupt.hart_generation),
        hardware_hart: Some(interrupt.hardware_hart),
        target_activation: interrupt.target_activation,
        target_activation_generation: interrupt.target_activation_generation,
        target_task: interrupt.target_task.map(u64::from),
        target_task_generation: interrupt.target_task_generation,
        generation: interrupt.generation,
        state: interrupt.state.as_str().to_owned(),
        recorded_at_event: interrupt.recorded_at_event,
        note: interrupt.note.clone(),
    }
}

fn ipi_event_manifest(ipi: &semantic_core::IpiEventRecord) -> IpiEventManifest {
    IpiEventManifest {
        id: ipi.id,
        source_hart: u64::from(ipi.source_hart),
        source_hart_generation: ipi.source_hart_generation,
        source_hardware_hart: ipi.source_hardware_hart,
        target_hart: u64::from(ipi.target_hart),
        target_hart_generation: ipi.target_hart_generation,
        target_hardware_hart: ipi.target_hardware_hart,
        kind: ipi.kind.as_str().to_owned(),
        generation: ipi.generation,
        state: ipi.state.as_str().to_owned(),
        recorded_at_event: ipi.recorded_at_event,
        reason: ipi.reason.clone(),
        note: ipi.note.clone(),
    }
}

fn remote_preempt_manifest(remote: &semantic_core::RemotePreemptRecord) -> RemotePreemptManifest {
    RemotePreemptManifest {
        id: remote.id,
        ipi: remote.ipi,
        ipi_generation: remote.ipi_generation,
        source_hart: u64::from(remote.source_hart),
        source_hart_generation: remote.source_hart_generation,
        target_hart: u64::from(remote.target_hart),
        target_hart_generation_before: remote.target_hart_generation_before,
        target_hart_generation_after: remote.target_hart_generation_after,
        activation: remote.activation,
        activation_generation_before: remote.activation_generation_before,
        activation_generation_after: remote.activation_generation_after,
        queue: remote.queue,
        queue_generation: remote.queue_generation,
        generation: remote.generation,
        state: remote.state.as_str().to_owned(),
        preempted_at_event: remote.preempted_at_event,
        note: remote.note.clone(),
    }
}

fn hart_event_attribution_manifest(
    attribution: &semantic_core::HartEventAttributionRecord,
) -> HartEventAttributionManifest {
    HartEventAttributionManifest {
        id: attribution.id,
        hart: u64::from(attribution.hart),
        hart_generation: attribution.hart_generation,
        hardware_hart: attribution.hardware_hart,
        event: attribution.event,
        event_source: attribution.event_source.clone(),
        event_kind: attribution.event_kind.clone(),
        activation: attribution.activation,
        activation_generation: attribution.activation_generation,
        task: attribution.task.map(u64::from),
        task_generation: attribution.task_generation,
        store: attribution.store,
        store_generation: attribution.store_generation,
        generation: attribution.generation,
        state: attribution.state.as_str().to_owned(),
        note: attribution.note.clone(),
    }
}

fn preemption_manifest(preemption: &semantic_core::PreemptionRecord) -> PreemptionManifest {
    PreemptionManifest {
        id: preemption.id,
        activation: preemption.activation,
        activation_generation_before: preemption.activation_generation_before,
        activation_generation_after: preemption.activation_generation_after,
        timer_interrupt: preemption.timer_interrupt,
        timer_interrupt_generation: preemption.timer_interrupt_generation,
        queue: preemption.queue,
        queue_generation: preemption.queue_generation,
        generation: preemption.generation,
        state: preemption.state.as_str().to_owned(),
        preempted_at_event: preemption.preempted_at_event,
        note: preemption.note.clone(),
    }
}

fn scheduler_decision_manifest(
    decision: &semantic_core::SchedulerDecisionRecord,
) -> SchedulerDecisionManifest {
    SchedulerDecisionManifest {
        id: decision.id,
        queue: decision.queue,
        queue_generation: decision.queue_generation,
        selected_activation: decision.selected_activation,
        selected_activation_generation: decision.selected_activation_generation,
        owner_task: u64::from(decision.owner_task),
        owner_task_generation: decision.owner_task_generation,
        generation: decision.generation,
        state: decision.state.as_str().to_owned(),
        decided_at_event: decision.decided_at_event,
        reason: decision.reason.clone(),
        note: decision.note.clone(),
    }
}

fn activation_resume_manifest(
    resume: &semantic_core::ActivationResumeRecord,
) -> ActivationResumeManifest {
    ActivationResumeManifest {
        id: resume.id,
        scheduler_decision: resume.scheduler_decision,
        scheduler_decision_generation: resume.scheduler_decision_generation,
        activation: resume.activation,
        activation_generation_before: resume.activation_generation_before,
        activation_generation_after: resume.activation_generation_after,
        owner_task: u64::from(resume.owner_task),
        owner_task_generation: resume.owner_task_generation,
        queue: resume.queue,
        queue_generation: resume.queue_generation,
        context: resume.context,
        context_generation_before: resume.context_generation_before,
        context_generation_after: resume.context_generation_after,
        saved_context: resume.saved_context,
        saved_context_generation: resume.saved_context_generation,
        generation: resume.generation,
        state: resume.state.as_str().to_owned(),
        resumed_at_event: resume.resumed_at_event,
        note: resume.note.clone(),
    }
}

fn activation_wait_manifest(wait: &semantic_core::ActivationWaitRecord) -> ActivationWaitManifest {
    ActivationWaitManifest {
        id: wait.id,
        activation: wait.activation,
        activation_generation_before: wait.activation_generation_before,
        activation_generation_after_block: wait.activation_generation_after_block,
        activation_generation_after_cancel: wait.activation_generation_after_cancel,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        owner_task: u64::from(wait.owner_task),
        owner_task_generation: wait.owner_task_generation,
        queue: wait.queue,
        queue_generation: wait.queue_generation,
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        blocked_at_event: wait.blocked_at_event,
        completed_at_event: wait.completed_at_event,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: wait.note.clone(),
    }
}

fn activation_cleanup_manifest(
    cleanup: &semantic_core::ActivationCleanupRecord,
) -> ActivationCleanupManifest {
    ActivationCleanupManifest {
        id: cleanup.id,
        store: cleanup.store,
        target_store_generation: cleanup.target_store_generation,
        result_store_generation: cleanup.result_store_generation,
        activation: cleanup.activation,
        activation_generation_before: cleanup.activation_generation_before,
        activation_generation_after: cleanup.activation_generation_after,
        wait: cleanup.wait,
        wait_generation: cleanup.wait_generation,
        owner_task: u64::from(cleanup.owner_task),
        owner_task_generation_before: cleanup.owner_task_generation_before,
        owner_task_generation_after: cleanup.owner_task_generation_after,
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        steps: cleanup
            .steps
            .iter()
            .map(|step| ActivationCleanupStepManifest {
                kind: step.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(step.target),
                observed_generation: step.observed_generation,
                status: step.status.as_str().to_owned(),
                event: step.event,
            })
            .collect(),
        note: cleanup.note.clone(),
    }
}

fn preemption_latency_manifest(
    sample: &semantic_core::PreemptionLatencySampleRecord,
) -> PreemptionLatencySampleManifest {
    PreemptionLatencySampleManifest {
        id: sample.id,
        timer_interrupt: sample.timer_interrupt,
        timer_interrupt_generation: sample.timer_interrupt_generation,
        preemption: sample.preemption,
        preemption_generation: sample.preemption_generation,
        scheduler_decision: sample.scheduler_decision,
        scheduler_decision_generation: sample.scheduler_decision_generation,
        activation_resume: sample.activation_resume,
        activation_resume_generation: sample.activation_resume_generation,
        activation: sample.activation,
        activation_generation_before: sample.activation_generation_before,
        activation_generation_after: sample.activation_generation_after,
        queue: sample.queue,
        queue_generation: sample.queue_generation,
        interrupt_recorded_at_event: sample.interrupt_recorded_at_event,
        preempted_at_event: sample.preempted_at_event,
        decided_at_event: sample.decided_at_event,
        resumed_at_event: sample.resumed_at_event,
        interrupt_to_preempt_events: sample.interrupt_to_preempt_events,
        preempt_to_decision_events: sample.preempt_to_decision_events,
        decision_to_resume_events: sample.decision_to_resume_events,
        interrupt_to_resume_events: sample.interrupt_to_resume_events,
        measured_nanos: sample.measured_nanos,
        budget_nanos: sample.budget_nanos,
        generation: sample.generation,
        state: sample.state.as_str().to_owned(),
        recorded_at_event: sample.recorded_at_event,
        note: sample.note.clone(),
    }
}

fn wait_record_manifest(wait: &semantic_core::WaitRecord) -> WaitRecordManifest {
    WaitRecordManifest {
        id: wait.id,
        owner_task: wait.owner_task.map(u64::from),
        owner_task_generation: wait.owner_task_generation,
        owner_store: wait.owner_store,
        owner_store_generation: wait.owner_store_generation,
        kind: wait.kind.as_str().to_owned(),
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        blockers: wait
            .blockers
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        deadline: wait.deadline,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        restart_policy: wait.restart_policy.as_str().to_owned(),
        saved_context: wait.saved_context.clone(),
    }
}

fn capability_record_manifest(capability: &CapabilityRecord) -> CapabilityRecordManifest {
    CapabilityRecordManifest {
        id: capability.id,
        subject: capability.subject.clone(),
        object: capability.object.clone(),
        object_ref: capability.object_ref.map(authority_object_ref_manifest),
        rights: capability.operations.as_slice().to_vec(),
        lifetime: capability.lifetime.clone(),
        class: capability.class.as_str().to_owned(),
        owner_store: capability.owner_store,
        owner_store_generation: capability.owner_store_generation,
        owner_task: capability.owner_task.map(u64::from),
        source: capability.source.clone(),
        generation: capability.generation,
        parent: capability.parent,
        manifest_decl: capability.manifest_decl,
        debug_object_label: capability.debug_object_label.clone(),
        revoked: capability.revoked,
    }
}

fn activation_record_manifest(
    activation: &semantic_core::ActivationRecord,
) -> ActivationRecordManifest {
    ActivationRecordManifest {
        id: activation.id,
        store: activation.store,
        store_generation: activation.store_generation,
        code_object: activation.code_object,
        code_generation: activation.code_generation,
        artifact: activation.artifact,
        entry: activation.entry.summary(),
        generation: activation.generation,
        state: activation.state.as_str().to_owned(),
        start_event: activation.start_event,
        exit_event: activation.exit_event,
        active_dmw_leases: activation.active_dmw_leases,
        blocked_wait: activation.blocked_wait,
        trap: activation.trap,
        return_tag: activation.return_tag.map(|tag| tag.as_str().to_owned()),
    }
}

fn trap_record_manifest(trap: &semantic_core::TargetTrapRecord) -> TrapRecordManifest {
    TrapRecordManifest {
        id: trap.id,
        generation: trap.generation,
        class: trap.class.as_str().to_owned(),
        store: trap.store,
        store_generation: trap.store_generation,
        activation: trap.activation,
        activation_generation: trap.activation_generation,
        code_object: trap.code_object,
        code_generation: trap.code_generation,
        artifact: trap.artifact,
        artifact_generation: trap.artifact_generation,
        offset: trap.offset,
        target_pc: trap.target_pc,
        trap_kind: trap.trap_kind.clone(),
        function_index: trap.function_index,
        wasm_offset: trap.wasm_offset,
        debug_symbol: trap.debug_symbol,
        classification_status: trap.classification_status.clone(),
        hostcall: trap.hostcall.clone(),
        fault_policy: trap.fault_policy.clone(),
        effect: trap.effect.summary(),
        detail: trap.detail.clone(),
    }
}

fn hostcall_trace_manifest(trace: &HostcallTraceRecord) -> HostcallTraceManifest {
    HostcallTraceManifest {
        id: trace.id,
        generation: trace.generation,
        abi_version: trace.abi_version.clone(),
        frame_size: trace.frame_size,
        flags: trace.flags,
        activation: trace.activation,
        activation_generation: trace.activation_generation,
        store: trace.store,
        store_generation: trace.store_generation,
        code_object: trace.code_object,
        code_generation: trace.code_generation,
        artifact: trace.artifact,
        artifact_generation: trace.artifact_generation,
        hostcall_number: trace.hostcall_number,
        hostcall_seq: trace.hostcall_seq,
        caller_offset: trace.caller_offset,
        name: trace.name.clone(),
        category: trace.category.as_str().to_owned(),
        subject: trace.subject.clone(),
        object: trace.object.clone(),
        operation: trace.operation.clone(),
        args: trace.args,
        cap_args: trace.cap_args.iter().map(cap_arg_manifest).collect(),
        record_mode: trace.record_mode.as_str().to_owned(),
        allowed: trace.allowed,
        result: trace.result.clone(),
        ret_tag: trace.ret_tag.as_str().to_owned(),
        ret0: trace.ret0,
        ret1: trace.ret1,
        trap_out: trace.trap_out,
        trap_generation_out: trace.trap_generation_out,
        wait_token_out: trace.wait_token_out,
        wait_token_generation_out: trace.wait_token_generation_out,
    }
}

fn cap_arg_manifest(arg: &CapabilityHandleArg) -> CapabilityHandleArgManifest {
    CapabilityHandleArgManifest {
        id: arg.id,
        object: arg.object.clone(),
        generation: arg.generation,
        owner_store: arg.owner_store,
        owner_store_generation: arg.owner_store_generation,
        handle_slot: arg.handle_slot,
        handle_generation: arg.handle_generation,
        handle_tag: arg.handle_tag,
        rights_mask: arg.rights_mask,
        rights: arg.rights.clone(),
    }
}

fn substrate_event_manifests(events: &[EventRecord]) -> Vec<SubstrateEventManifest> {
    events.iter().filter_map(substrate_event_manifest).collect()
}

fn substrate_event_manifest(event: &EventRecord) -> Option<SubstrateEventManifest> {
    match &event.kind {
        EventKind::SubstrateUnsupported {
            authority,
            operation,
            requester,
            artifact,
            store,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "unsupported".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: None,
                explanation: format!(
                    "{requester_label} observed {authority}::{operation} as unsupported"
                ),
            })
        }
        EventKind::SubstrateCapabilityDenied {
            authority,
            operation,
            requester,
            artifact,
            store,
            capability,
            capability_generation,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "capability-denied".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: capability.map(|id| CapabilityHandleArgManifest {
                    id,
                    object: "substrate-capability".to_owned(),
                    generation: capability_generation.unwrap_or(0),
                    owner_store: None,
                    owner_store_generation: None,
                    handle_slot: 0,
                    handle_generation: 0,
                    handle_tag: 0,
                    rights_mask: 0,
                    rights: Vec::new(),
                }),
                explanation: format!(
                    "{requester_label} was denied {authority}::{operation} by capability gate"
                ),
            })
        }
        _ => None,
    }
}

fn command_result_manifest(result: &CommandResult) -> CommandResultManifest {
    CommandResultManifest {
        id: result.command_id,
        issuer: result.issuer.clone(),
        command: result.command.to_owned(),
        status: result.status.as_str().to_owned(),
        events: result.events.clone(),
        effects: result
            .effects
            .iter()
            .map(|effect| CommandEffectManifest {
                kind: effect.kind.clone(),
                target: effect.target.map(contract_object_ref_manifest),
            })
            .collect(),
        violations: result.violations.clone(),
    }
}

fn interface_event_manifests(events: &[EventRecord]) -> Vec<InterfaceEventManifest> {
    events.iter().filter_map(interface_event_manifest).collect()
}

fn interface_event_manifest(event: &EventRecord) -> Option<InterfaceEventManifest> {
    match &event.kind {
        EventKind::InterfaceUnsupported {
            interface_kind,
            interface,
            operation,
            requester,
            artifact,
            store,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(InterfaceEventManifest {
                id: event.id,
                epoch: event.epoch,
                interface_kind: interface_kind.clone(),
                interface: interface.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                explanation: format!(
                    "{requester_label} observed {interface_kind} {interface}::{operation} as unsupported"
                ),
            })
        }
        _ => None,
    }
}

fn migration_object_manifest(record: &MigrationObjectRecord) -> MigrationObjectManifest {
    MigrationObjectManifest {
        object: record.object.clone(),
        class: record.class.as_str().to_owned(),
        reason: record.reason.clone(),
    }
}

fn tombstone_manifest(record: &TombstoneRecord) -> TombstoneManifest {
    TombstoneManifest {
        kind: record.kind.as_str().to_owned(),
        id: record.id,
        generation: record.generation,
        died_at: record.died_at,
        reason: record.reason.clone(),
    }
}

fn contract_object_ref_manifest(reference: ContractObjectRef) -> ContractObjectRefManifest {
    ContractObjectRefManifest {
        kind: reference.kind.as_str().to_owned(),
        id: reference.id,
        generation: reference.generation,
    }
}

fn authority_object_ref_manifest(reference: AuthorityObjectRef) -> AuthorityObjectRefManifest {
    match reference {
        AuthorityObjectRef::Internal { class, object } => AuthorityObjectRefManifest {
            scope: "internal".to_owned(),
            class: class.as_str().to_owned(),
            object: contract_object_ref_manifest(object),
        },
        AuthorityObjectRef::External { class, object } => AuthorityObjectRefManifest {
            scope: "external".to_owned(),
            class: class.as_str().to_owned(),
            object: contract_object_ref_manifest(object),
        },
    }
}

fn contract_violation_manifest(violation: &ContractViolation) -> ContractViolationManifest {
    ContractViolationManifest {
        kind: violation.kind.as_str().to_owned(),
        edge: violation.edge.clone(),
        from: contract_object_ref_manifest(violation.from),
        to: violation.to.map(contract_object_ref_manifest),
        detail: violation.detail.clone(),
    }
}

fn cleanup_transaction_manifest(
    cleanup: &semantic_core::FaultCleanupTransaction,
) -> CleanupTransactionManifest {
    CleanupTransactionManifest {
        id: cleanup.id,
        store: cleanup.store,
        store_generation: cleanup.store_generation,
        target_store_generation: cleanup.store_generation,
        result_store_generation: cleanup.result_store_generation,
        activation: cleanup.activation,
        activation_generation: cleanup.activation_generation,
        code_object: cleanup.code_object,
        code_generation: cleanup.code_generation,
        generation: cleanup.generation,
        started_at: cleanup.started_at,
        finished_at: cleanup.finished_at,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        released_dmw_leases: cleanup.released_dmw_leases,
        cancelled_waits: cleanup.cancelled_waits,
        revoked_capabilities: cleanup.revoked_capabilities.clone(),
        revoked_capability_refs: cleanup
            .revoked_capability_refs
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        dropped_resources: cleanup.dropped_resources,
        unbound_code_object: cleanup.unbound_code_object,
        effect: cleanup.effect.summary(),
        steps: cleanup
            .steps
            .iter()
            .map(|step| CleanupStepManifest {
                step: step.step.as_str().to_owned(),
                state: step.state.as_str().to_owned(),
                detail: step.detail.clone(),
                target: step.target.map(contract_object_ref_manifest),
                observed_generation: step.observed_generation,
                error: step.error.clone(),
                idempotency_key: step.idempotency_key.clone(),
                event_seq: step.event_seq,
            })
            .collect(),
        effects: cleanup
            .effects
            .iter()
            .map(|effect| CleanupEffectManifest {
                kind: effect.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(effect.target),
                expected_generation: effect.expected_generation,
                status: effect.status.as_str().to_owned(),
                event_seq: effect.event_seq,
            })
            .collect(),
    }
}

fn memory_policy_manifest(policy: &MemoryClassPolicy) -> MemoryClassPolicyManifest {
    MemoryClassPolicyManifest {
        class: policy.class.as_str().to_owned(),
        owner_kind: policy.owner_kind.as_str().to_owned(),
        permissions: policy.permissions.summary(),
        migration_policy: policy.migratable.as_str().to_owned(),
        snapshot_policy: policy.snapshot_policy.as_str().to_owned(),
        cleanup_policy: policy.cleanup_policy.as_str().to_owned(),
        can_alias_guest_memory: policy.can_alias_guest_memory,
        can_cross_pending: policy.can_cross_pending,
        can_be_executable: policy.can_be_executable,
    }
}

fn boundary_validation_report_manifest(
    report: &BoundaryValidationReport,
) -> BoundaryValidationReportManifest {
    BoundaryValidationReportManifest {
        validator: report.validator.as_str().to_owned(),
        ok: report.is_ok(),
        violation_count: report.violations.len(),
        violations: report
            .violations
            .iter()
            .map(boundary_validation_violation_manifest)
            .collect(),
    }
}

fn boundary_validation_violation_manifest(
    violation: &BoundaryValidationViolation,
) -> BoundaryValidationViolationManifest {
    BoundaryValidationViolationManifest {
        validator: violation.validator.as_str().to_owned(),
        kind: violation.kind.as_str().to_owned(),
        object: violation.object.clone(),
        detail: violation.detail.clone(),
    }
}

fn validation_roots(report: &BoundaryValidationReportManifest) -> Vec<String> {
    let mut roots = Vec::new();
    roots.push(format!(
        "boundary-validation validator={} ok={} violations={}",
        report.validator, report.ok, report.violation_count
    ));
    roots.extend(report.violations.iter().map(|violation| {
        format!(
            "boundary-validation validator={} kind={} object={} detail={}",
            violation.validator, violation.kind, violation.object, violation.detail
        )
    }));
    roots
}

fn hostcall_manifest(hostcall: &HostcallSpec) -> HostcallSpecManifest {
    HostcallSpecManifest {
        number: hostcall.number,
        name: hostcall.name.clone(),
        category: hostcall.category.as_str().to_owned(),
        object: hostcall.object.clone(),
        operation: hostcall.operation.clone(),
        may_pending: hostcall.may_pending,
    }
}

fn target_capability_manifest(capability: &TargetCapabilitySpec) -> TargetCapabilitySpecManifest {
    TargetCapabilitySpecManifest {
        object: capability.object.clone(),
        operations: capability.operations.clone(),
        lifetime: capability.lifetime.clone(),
        class: capability.class.as_str().to_owned(),
    }
}

fn trap_metadata_manifest(metadata: &TargetTrapMetadata) -> TargetTrapMetadataManifest {
    TargetTrapMetadataManifest {
        class: metadata.class.as_str().to_owned(),
        symbol: metadata.symbol.clone(),
        offset: metadata.offset,
    }
}

fn address_map_manifest(entry: &TargetAddressMapEntry) -> TargetAddressMapEntryManifest {
    TargetAddressMapEntryManifest {
        symbol: entry.symbol.clone(),
        offset: entry.offset,
        len: entry.len,
    }
}

fn validate_bundle_manifest(
    manifest: &ArtifactBundleManifest,
) -> Result<ValidatedArtifactPlan, Box<dyn Error>> {
    build_validated_artifact_plan(manifest).map_err(Into::into)
}

fn validate_migration_package(
    package: &MigrationPackageManifest,
    manifest: &ArtifactBundleManifest,
) -> Result<(), Box<dyn Error>> {
    validate_migration_against_manifest(package, manifest)?;
    validate_replay_quiescent(package)?;
    Ok(())
}

fn restore_migration_package(
    package: &MigrationPackageManifest,
    semantic: &SemanticGraph,
    plan: &ValidatedArtifactPlan,
) -> Result<(), Box<dyn Error>> {
    if package.semantic.fault_domain_count > semantic.fault_domain_count() {
        return Err(
            "migration package requires more fault domains than the executor rebuilt".into(),
        );
    }
    if package.semantic.store_count > semantic.store_count() {
        return Err("migration package requires more stores than the executor rebuilt".into());
    }
    if package.semantic.capability_count > semantic.capability_count() {
        return Err(
            "migration package requires more capabilities than the executor rebound".into(),
        );
    }
    for capability in &package.logical_capabilities {
        let Some(module) = plan.entry(&capability.subject) else {
            return Err(format!(
                "migration package capability subject {} is not in target load plan",
                capability.subject
            )
            .into());
        };
        let Some(target_capability) = module
            .capabilities
            .iter()
            .find(|target| target.name == capability.object)
        else {
            return Err(format!(
                "target manifest cannot satisfy capability {}::{}",
                capability.subject, capability.object
            )
            .into());
        };
        if target_capability.lifetime != capability.lifetime {
            return Err(format!(
                "target manifest lifetime mismatch for {}::{}",
                capability.subject, capability.object
            )
            .into());
        }
        for right in &capability.rights {
            if !target_capability
                .rights
                .iter()
                .any(|target_right| target_right == right)
            {
                return Err(format!(
                    "target manifest cannot satisfy right {} for {}::{}",
                    right, capability.subject, capability.object
                )
                .into());
            }
            semantic
                .capabilities()
                .check(&capability.subject, &capability.object, right)
                .map_err(|_| {
                    format!(
                        "target executor failed to rebind capability {}::{} right {}",
                        capability.subject, capability.object, right
                    )
                })?;
        }
    }

    println!(
        "migration restore/rebind demo package={} source_arch={} target_requirement={} guest_isa={}",
        package.package_id,
        package.source.arch,
        package.target.arch_requirement,
        package.guest.canonical_isa
    );
    println!(
        "restore plan: import semantic roots harts={} tasks={} resources={} authorities={}/{} waits={} pending_waits={} transactions={} active_transactions={} fastpath={}/{} boundaries={} artifacts={} activations={} executor_transitions={} sockets={} rx_bytes={} event_cursor={}",
        package.semantic.hart_count,
        package.semantic.task_count,
        package.semantic.resource_count,
        package.semantic.active_authority_count,
        package.semantic.authority_count,
        package.semantic.wait_token_count,
        package.semantic.pending_wait_count,
        package.semantic.transaction_count,
        package.semantic.active_transaction_count,
        package.semantic.active_fast_path_plan_count,
        package.semantic.fast_path_plan_count,
        package.semantic.boundary_count,
        package.semantic.artifact_verification_count,
        package.semantic.store_activation_count,
        package.semantic.executor_transition_count,
        package.semantic.network_socket_count,
        package.semantic.network_rx_queue_bytes,
        package.semantic.event_log_cursor
    );
    println!(
        "restore plan: rebuilt {} stores across {} fault domains and rebound {} logical capabilities",
        semantic.store_count(),
        semantic.fault_domain_count(),
        package.logical_capabilities.len()
    );
    println!(
        "restore plan: not migrated = {}",
        package.not_migrated.join(", ")
    );
    Ok(())
}

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

fn read_manifest(artifact_root: &Path) -> Result<ArtifactBundleManifest, Box<dyn Error>> {
    let bytes = fs::read(artifact_root.join("manifest.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_migration_package(path: &Path) -> Result<MigrationPackageManifest, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest dir")?);
    Ok(manifest_dir
        .parent()
        .ok_or("target_executor must live in workspace root")?
        .to_path_buf())
}
