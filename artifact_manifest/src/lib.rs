use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArtifactBundleManifest {
    pub schema_version: u32,
    pub artifact_profile: String,
    #[serde(default)]
    pub runtime_mode: String,
    #[serde(default)]
    pub contract: SupervisorContractManifest,
    pub target: TargetManifest,
    pub compiler: CompilerManifest,
    pub modules: Vec<ModuleArtifactManifest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SupervisorContractManifest {
    pub contract_version: String,
    pub supervisor_world: String,
    pub catalog_fingerprint: String,
    pub package_set_fingerprint: String,
    pub module_count: usize,
    pub required_packages: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetManifest {
    pub arch: String,
    pub machine_abi_version: String,
    pub supervisor_abi_version: String,
    pub wasm_feature_profile: String,
    pub memory64: bool,
    pub multi_memory: bool,
    pub dmw_layout: String,
    #[serde(default)]
    pub linux_abi_profile: String,
    #[serde(default)]
    pub artifact_signature_profile: String,
    #[serde(default)]
    pub network_contract_version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompilerManifest {
    pub engine: String,
    pub engine_version: String,
    pub execution_mode: String,
    pub artifact_format: String,
    #[serde(default)]
    pub target_artifact_format: String,
    #[serde(default)]
    pub runtime_executor_abi: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModuleArtifactManifest {
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub fault_policy: String,
    pub wasm_path: String,
    pub cwasm_path: String,
    #[serde(default)]
    pub target_artifact_path: String,
    pub wasm_sha256: String,
    pub cwasm_sha256: String,
    #[serde(default)]
    pub target_artifact_sha256: String,
    #[serde(default)]
    pub code_payload_format: String,
    pub expected_exports: Vec<String>,
    pub exports: Vec<ExternManifest>,
    pub imports: Vec<ImportManifest>,
    pub capabilities: Vec<CapabilityManifest>,
    #[serde(default)]
    pub abi_fingerprint: String,
    #[serde(default)]
    pub service_dependencies: Vec<String>,
    #[serde(default)]
    pub resource_limits: ResourceLimitsManifest,
    #[serde(default)]
    pub interfaces: InterfaceRequirementManifest,
    pub signature: SignatureManifest,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct ResourceLimitsManifest {
    pub max_memory_pages: u32,
    pub max_table_elements: u32,
    pub max_hostcalls_per_activation: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExternManifest {
    pub name: String,
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImportManifest {
    pub module: String,
    pub name: String,
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CapabilityManifest {
    pub name: String,
    pub rights: Vec<String>,
    pub lifetime: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct InterfaceRequirementManifest {
    #[serde(default)]
    pub required_wasi_worlds: Vec<String>,
    #[serde(default)]
    pub optional_wasi_worlds: Vec<String>,
    #[serde(default)]
    pub custom_wit_worlds: Vec<String>,
    #[serde(default)]
    pub wit_package_versions: Vec<String>,
    #[serde(default)]
    pub component_model_version: String,
    #[serde(default)]
    pub wasi_profile: String,
    #[serde(default)]
    pub hostcall_abi_version: String,
    #[serde(default)]
    pub capability_abi_version: String,
    #[serde(default)]
    pub semantic_contract_version: String,
    #[serde(default)]
    pub substrate_profile_required: String,
    #[serde(default)]
    pub substrate_authorities: SubstrateAuthorityRequirementManifest,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubstrateAuthorityRequirementManifest {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub optional: Vec<String>,
    #[serde(default)]
    pub forbidden: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureManifest {
    pub scheme: String,
    pub artifact_hash: String,
    pub manifest_binding_hash: String,
    pub signer: String,
    #[serde(default)]
    pub public_key_hint: String,
    #[serde(default)]
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationPackageManifest {
    pub schema_version: u32,
    #[serde(default)]
    pub package_format: String,
    pub package_id: String,
    pub source: MigrationHostManifest,
    pub target: MigrationTargetManifest,
    pub required_artifact_profile: RequiredArtifactProfileManifest,
    pub guest: GuestStateManifest,
    pub semantic: SemanticSnapshotManifest,
    pub logical_capabilities: Vec<MigrationCapabilityManifest>,
    pub substrate_boundary: SubstrateBoundaryManifest,
    pub not_migrated: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationHostManifest {
    pub arch: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationTargetManifest {
    pub arch_requirement: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequiredArtifactProfileManifest {
    pub artifact_profile: String,
    pub target_arch: String,
    pub machine_abi_version: String,
    pub supervisor_abi_version: String,
    pub wasm_feature_profile: String,
    pub memory64: bool,
    pub multi_memory: bool,
    pub dmw_layout: String,
    #[serde(default)]
    pub network_contract_version: String,
    pub compiler_engine: String,
    pub compiler_execution_mode: String,
    pub artifact_format: String,
    #[serde(default)]
    pub runtime_executor_abi: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuestStateManifest {
    pub canonical_isa: String,
    pub register_count: u32,
    pub memory_page_count: u64,
    pub vma_count: u32,
    pub signal_queue_count: u32,
    pub note: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SemanticSnapshotManifest {
    pub barrier_id: u64,
    pub event_log_cursor: u64,
    #[serde(default)]
    pub roots: SemanticRootSetManifest,
    #[serde(default)]
    pub pending_wait_count: usize,
    #[serde(default)]
    pub hart_count: usize,
    pub task_count: usize,
    #[serde(default)]
    pub task_record_count: usize,
    #[serde(default)]
    pub runtime_activation_count: usize,
    #[serde(default)]
    pub runnable_queue_count: usize,
    #[serde(default)]
    pub activation_context_count: usize,
    #[serde(default)]
    pub saved_context_count: usize,
    #[serde(default)]
    pub timer_interrupt_count: usize,
    #[serde(default)]
    pub preemption_count: usize,
    #[serde(default)]
    pub scheduler_decision_count: usize,
    #[serde(default)]
    pub activation_resume_count: usize,
    #[serde(default)]
    pub activation_wait_count: usize,
    #[serde(default)]
    pub activation_cleanup_count: usize,
    #[serde(default)]
    pub preemption_latency_sample_count: usize,
    pub resource_count: usize,
    #[serde(default)]
    pub authority_count: usize,
    #[serde(default)]
    pub active_authority_count: usize,
    pub wait_token_count: usize,
    #[serde(default)]
    pub wait_record_count: usize,
    pub capability_count: usize,
    #[serde(default)]
    pub capability_record_count: usize,
    pub fault_domain_count: usize,
    #[serde(default)]
    pub store_count: usize,
    #[serde(default)]
    pub store_record_count: usize,
    #[serde(default)]
    pub transaction_count: usize,
    #[serde(default)]
    pub active_transaction_count: usize,
    #[serde(default)]
    pub fast_path_plan_count: usize,
    #[serde(default)]
    pub active_fast_path_plan_count: usize,
    #[serde(default)]
    pub boundary_count: usize,
    #[serde(default)]
    pub artifact_verification_count: usize,
    #[serde(default)]
    pub store_activation_count: usize,
    #[serde(default)]
    pub executor_transition_count: usize,
    #[serde(default)]
    pub target_artifact_count: usize,
    #[serde(default)]
    pub code_object_count: usize,
    #[serde(default)]
    pub activation_record_count: usize,
    #[serde(default)]
    pub trap_record_count: usize,
    #[serde(default)]
    pub hostcall_trace_count: usize,
    #[serde(default)]
    pub migration_object_count: usize,
    #[serde(default)]
    pub tombstone_count: usize,
    #[serde(default)]
    pub contract_violation_count: usize,
    #[serde(default)]
    pub cleanup_transaction_count: usize,
    #[serde(default)]
    pub memory_policy_count: usize,
    #[serde(default)]
    pub snapshot_validation_violation_count: usize,
    #[serde(default)]
    pub replay_validation_violation_count: usize,
    #[serde(default)]
    pub substrate_event_count: usize,
    #[serde(default)]
    pub command_result_count: usize,
    #[serde(default)]
    pub interface_event_count: usize,
    #[serde(default)]
    pub target_artifacts: Vec<TargetArtifactImageManifest>,
    #[serde(default)]
    pub hart_records: Vec<HartRecordManifest>,
    #[serde(default)]
    pub task_records: Vec<TaskRecordManifest>,
    #[serde(default)]
    pub runtime_activation_records: Vec<RuntimeActivationRecordManifest>,
    #[serde(default)]
    pub runnable_queues: Vec<RunnableQueueManifest>,
    #[serde(default)]
    pub activation_contexts: Vec<ActivationContextManifest>,
    #[serde(default)]
    pub saved_contexts: Vec<SavedContextManifest>,
    #[serde(default)]
    pub timer_interrupts: Vec<TimerInterruptManifest>,
    #[serde(default)]
    pub preemptions: Vec<PreemptionManifest>,
    #[serde(default)]
    pub scheduler_decisions: Vec<SchedulerDecisionManifest>,
    #[serde(default)]
    pub activation_resumes: Vec<ActivationResumeManifest>,
    #[serde(default)]
    pub activation_waits: Vec<ActivationWaitManifest>,
    #[serde(default)]
    pub activation_cleanups: Vec<ActivationCleanupManifest>,
    #[serde(default)]
    pub preemption_latency_samples: Vec<PreemptionLatencySampleManifest>,
    #[serde(default)]
    pub code_objects: Vec<CodeObjectManifest>,
    #[serde(default)]
    pub store_records: Vec<StoreRecordManifest>,
    #[serde(default)]
    pub capability_records: Vec<CapabilityRecordManifest>,
    #[serde(default)]
    pub wait_records: Vec<WaitRecordManifest>,
    #[serde(default)]
    pub activation_records: Vec<ActivationRecordManifest>,
    #[serde(default)]
    pub trap_records: Vec<TrapRecordManifest>,
    #[serde(default)]
    pub hostcall_trace: Vec<HostcallTraceManifest>,
    #[serde(default)]
    pub migration_objects: Vec<MigrationObjectManifest>,
    #[serde(default)]
    pub tombstones: Vec<TombstoneManifest>,
    #[serde(default)]
    pub contract_violations: Vec<ContractViolationManifest>,
    #[serde(default)]
    pub cleanup_transactions: Vec<CleanupTransactionManifest>,
    #[serde(default)]
    pub memory_policies: Vec<MemoryClassPolicyManifest>,
    #[serde(default)]
    pub snapshot_validation: BoundaryValidationReportManifest,
    #[serde(default)]
    pub replay_validation: BoundaryValidationReportManifest,
    #[serde(default)]
    pub substrate_events: Vec<SubstrateEventManifest>,
    #[serde(default)]
    pub command_results: Vec<CommandResultManifest>,
    #[serde(default)]
    pub interface_events: Vec<InterfaceEventManifest>,
    #[serde(default)]
    pub network_socket_count: u32,
    #[serde(default)]
    pub network_rx_queue_bytes: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SemanticRootSetManifest {
    #[serde(default)]
    pub hart_roots: Vec<String>,
    #[serde(default)]
    pub task_roots: Vec<String>,
    #[serde(default)]
    pub task_record_roots: Vec<String>,
    #[serde(default)]
    pub runtime_activation_roots: Vec<String>,
    #[serde(default)]
    pub runnable_queue_roots: Vec<String>,
    #[serde(default)]
    pub activation_context_roots: Vec<String>,
    #[serde(default)]
    pub saved_context_roots: Vec<String>,
    #[serde(default)]
    pub timer_interrupt_roots: Vec<String>,
    #[serde(default)]
    pub preemption_roots: Vec<String>,
    #[serde(default)]
    pub scheduler_decision_roots: Vec<String>,
    #[serde(default)]
    pub activation_resume_roots: Vec<String>,
    #[serde(default)]
    pub activation_wait_roots: Vec<String>,
    #[serde(default)]
    pub activation_cleanup_roots: Vec<String>,
    #[serde(default)]
    pub preemption_latency_roots: Vec<String>,
    #[serde(default)]
    pub resource_roots: Vec<String>,
    #[serde(default)]
    pub authority_roots: Vec<String>,
    #[serde(default)]
    pub wait_roots: Vec<String>,
    #[serde(default)]
    pub store_roots: Vec<String>,
    #[serde(default)]
    pub capability_roots: Vec<String>,
    #[serde(default)]
    pub target_store_record_roots: Vec<String>,
    #[serde(default)]
    pub target_capability_record_roots: Vec<String>,
    #[serde(default)]
    pub fast_path_roots: Vec<String>,
    #[serde(default)]
    pub boundary_roots: Vec<String>,
    #[serde(default)]
    pub artifact_verification_roots: Vec<String>,
    #[serde(default)]
    pub store_activation_roots: Vec<String>,
    #[serde(default)]
    pub executor_transition_roots: Vec<String>,
    #[serde(default)]
    pub target_artifact_roots: Vec<String>,
    #[serde(default)]
    pub code_object_roots: Vec<String>,
    #[serde(default)]
    pub activation_record_roots: Vec<String>,
    #[serde(default)]
    pub trap_roots: Vec<String>,
    #[serde(default)]
    pub hostcall_trace_roots: Vec<String>,
    #[serde(default)]
    pub migration_object_roots: Vec<String>,
    #[serde(default)]
    pub tombstone_roots: Vec<String>,
    #[serde(default)]
    pub contract_violation_roots: Vec<String>,
    #[serde(default)]
    pub cleanup_roots: Vec<String>,
    #[serde(default)]
    pub memory_policy_roots: Vec<String>,
    #[serde(default)]
    pub snapshot_validation_roots: Vec<String>,
    #[serde(default)]
    pub replay_validation_roots: Vec<String>,
    #[serde(default)]
    pub substrate_event_roots: Vec<String>,
    #[serde(default)]
    pub command_result_roots: Vec<String>,
    #[serde(default)]
    pub interface_event_roots: Vec<String>,
    #[serde(default)]
    pub event_log_tail: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HartRecordManifest {
    pub id: u64,
    pub hardware_id: u32,
    pub label: String,
    pub state: String,
    pub generation: u64,
    pub boot: bool,
    pub last_event: Option<u64>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SubstrateEventManifest {
    pub id: u64,
    pub epoch: u64,
    pub event_kind: String,
    pub authority: String,
    pub operation: String,
    pub requester: Option<String>,
    pub artifact: Option<u64>,
    pub store: Option<u64>,
    #[serde(default)]
    pub capability: Option<CapabilityHandleArgManifest>,
    pub explanation: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CommandResultManifest {
    pub id: u64,
    pub issuer: String,
    pub command: String,
    pub status: String,
    pub events: Vec<u64>,
    #[serde(default)]
    pub effects: Vec<CommandEffectManifest>,
    #[serde(default)]
    pub violations: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CommandEffectManifest {
    pub kind: String,
    #[serde(default)]
    pub target: Option<ContractObjectRefManifest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct InterfaceEventManifest {
    pub id: u64,
    pub epoch: u64,
    pub interface_kind: String,
    pub interface: String,
    pub operation: String,
    pub requester: Option<String>,
    pub artifact: Option<u64>,
    pub store: Option<u64>,
    pub explanation: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TaskRecordManifest {
    pub id: u64,
    pub label: String,
    pub frontend: String,
    pub state: String,
    pub generation: u64,
    pub fault_domain: Option<u64>,
    pub pending_wait: Option<u64>,
    #[serde(default)]
    pub resources: Vec<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuntimeActivationRecordManifest {
    pub id: u64,
    pub owner_task: u64,
    #[serde(default)]
    pub owner_task_generation: u64,
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    #[serde(default)]
    pub code_object: Option<ContractObjectRefManifest>,
    pub generation: u64,
    pub state: String,
    pub runnable_queue: Option<u64>,
    #[serde(default)]
    pub runnable_queue_generation: Option<u64>,
    pub last_event: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RunnableQueueEntryManifest {
    pub activation: u64,
    pub activation_generation: u64,
    pub enqueued_at: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RunnableQueueManifest {
    pub id: u64,
    pub label: String,
    pub generation: u64,
    pub state: String,
    #[serde(default)]
    pub entries: Vec<RunnableQueueEntryManifest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationContextManifest {
    pub id: u64,
    pub activation: u64,
    pub activation_generation: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub current_saved_context: Option<u64>,
    #[serde(default)]
    pub current_saved_context_generation: Option<u64>,
    pub last_event: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SavedContextManifest {
    pub id: u64,
    pub context: u64,
    pub context_generation: u64,
    pub activation: u64,
    pub activation_generation: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    #[serde(default)]
    pub source_preemption: Option<u64>,
    #[serde(default)]
    pub source_preemption_generation: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub reason: String,
    pub pc: u64,
    pub sp: u64,
    pub flags: u64,
    pub integer_registers: u16,
    pub saved_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TimerInterruptManifest {
    pub id: u64,
    pub timer_epoch: u64,
    pub hart: u32,
    pub target_activation: Option<u64>,
    #[serde(default)]
    pub target_activation_generation: Option<u64>,
    pub target_task: Option<u64>,
    #[serde(default)]
    pub target_task_generation: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PreemptionManifest {
    pub id: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub timer_interrupt: u64,
    pub timer_interrupt_generation: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub generation: u64,
    pub state: String,
    pub preempted_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SchedulerDecisionManifest {
    pub id: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub selected_activation: u64,
    pub selected_activation_generation: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    pub generation: u64,
    pub state: String,
    pub decided_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationResumeManifest {
    pub id: u64,
    pub scheduler_decision: u64,
    pub scheduler_decision_generation: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub context: Option<u64>,
    #[serde(default)]
    pub context_generation_before: Option<u64>,
    #[serde(default)]
    pub context_generation_after: Option<u64>,
    pub saved_context: Option<u64>,
    #[serde(default)]
    pub saved_context_generation: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub resumed_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationWaitManifest {
    pub id: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after_block: u64,
    #[serde(default)]
    pub activation_generation_after_cancel: Option<u64>,
    pub wait: u64,
    pub wait_generation: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    pub queue: Option<u64>,
    #[serde(default)]
    pub queue_generation: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub blocked_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    #[serde(default)]
    pub cancel_reason: Option<String>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationCleanupManifest {
    pub id: u64,
    pub store: u64,
    pub target_store_generation: u64,
    pub result_store_generation: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub wait: Option<u64>,
    #[serde(default)]
    pub wait_generation: Option<u64>,
    pub owner_task: u64,
    pub owner_task_generation_before: u64,
    pub owner_task_generation_after: u64,
    pub generation: u64,
    pub state: String,
    pub reason: String,
    pub started_at_event: u64,
    pub completed_at_event: u64,
    #[serde(default)]
    pub steps: Vec<ActivationCleanupStepManifest>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationCleanupStepManifest {
    pub kind: String,
    pub target: ContractObjectRefManifest,
    pub observed_generation: u64,
    pub status: String,
    #[serde(default)]
    pub event: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PreemptionLatencySampleManifest {
    pub id: u64,
    pub timer_interrupt: u64,
    pub timer_interrupt_generation: u64,
    pub preemption: u64,
    pub preemption_generation: u64,
    pub scheduler_decision: u64,
    pub scheduler_decision_generation: u64,
    pub activation_resume: u64,
    pub activation_resume_generation: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub interrupt_recorded_at_event: u64,
    pub preempted_at_event: u64,
    pub decided_at_event: u64,
    pub resumed_at_event: u64,
    pub interrupt_to_preempt_events: u64,
    pub preempt_to_decision_events: u64,
    pub decision_to_resume_events: u64,
    pub interrupt_to_resume_events: u64,
    pub measured_nanos: u64,
    pub budget_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetArtifactImageManifest {
    pub id: u64,
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub kind: String,
    pub target_profile: String,
    #[serde(default)]
    pub artifact_hash: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    pub exports: Vec<String>,
    pub imports: Vec<String>,
    pub hostcalls: Vec<HostcallSpecManifest>,
    pub capabilities: Vec<TargetCapabilitySpecManifest>,
    pub memory_plan: TargetMemoryPlanManifest,
    pub trap_metadata: Vec<TargetTrapMetadataManifest>,
    pub address_map: Vec<TargetAddressMapEntryManifest>,
    pub payload_len: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetMemoryPlanManifest {
    pub max_memory_pages: u32,
    pub max_table_elements: u32,
    pub max_hostcalls_per_activation: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HostcallSpecManifest {
    pub number: u32,
    pub name: String,
    pub category: String,
    pub object: String,
    pub operation: String,
    pub may_pending: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetCapabilitySpecManifest {
    pub object: String,
    pub operations: Vec<String>,
    pub lifetime: String,
    pub class: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetTrapMetadataManifest {
    pub class: String,
    pub symbol: String,
    pub offset: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetAddressMapEntryManifest {
    pub symbol: String,
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CodeObjectManifest {
    pub id: u64,
    pub artifact_id: u64,
    pub package: String,
    pub owner_profile: String,
    pub generation: u64,
    pub state: String,
    pub bound_store: Option<u64>,
    #[serde(default)]
    pub bound_store_generation: Option<u64>,
    pub hostcall_table: Option<u64>,
    pub text_start: u64,
    pub text_len: u64,
    pub text_permission: String,
    pub rodata_start: u64,
    pub rodata_len: u64,
    pub rodata_permission: String,
    pub code_hash: String,
    pub hostcalls: Vec<HostcallSpecManifest>,
    pub trap_metadata: Vec<TargetTrapMetadataManifest>,
    pub address_map: Vec<TargetAddressMapEntryManifest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StoreRecordManifest {
    pub id: u64,
    pub package: String,
    pub artifact: String,
    pub role: String,
    pub fault_policy: String,
    pub fault_domain: u64,
    pub resource: Option<u64>,
    pub state: String,
    pub generation: u64,
    pub restart_count: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CapabilityRecordManifest {
    pub id: u64,
    pub subject: String,
    pub object: String,
    #[serde(default)]
    pub object_ref: Option<AuthorityObjectRefManifest>,
    pub rights: Vec<String>,
    pub lifetime: String,
    pub class: String,
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    pub owner_task: Option<u64>,
    pub source: String,
    pub generation: u64,
    #[serde(default)]
    pub parent: Option<u64>,
    #[serde(default)]
    pub manifest_decl: bool,
    #[serde(default)]
    pub debug_object_label: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuthorityObjectRefManifest {
    pub scope: String,
    pub class: String,
    pub object: ContractObjectRefManifest,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WaitRecordManifest {
    pub id: u64,
    pub owner_task: Option<u64>,
    #[serde(default)]
    pub owner_task_generation: Option<u64>,
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    pub kind: String,
    pub generation: u64,
    pub state: String,
    #[serde(default)]
    pub blockers: Vec<ContractObjectRefManifest>,
    pub deadline: Option<u64>,
    pub cancel_reason: Option<String>,
    pub restart_policy: String,
    pub saved_context: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationRecordManifest {
    pub id: u64,
    pub store: u64,
    #[serde(default)]
    pub store_generation: u64,
    pub code_object: u64,
    #[serde(default)]
    pub code_generation: u64,
    pub artifact: u64,
    pub entry: String,
    pub generation: u64,
    pub state: String,
    pub start_event: u64,
    pub exit_event: Option<u64>,
    pub active_dmw_leases: u32,
    pub blocked_wait: Option<u64>,
    pub trap: Option<u64>,
    pub return_tag: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TrapRecordManifest {
    pub id: u64,
    #[serde(default)]
    pub generation: u64,
    pub class: String,
    pub store: Option<u64>,
    #[serde(default)]
    pub store_generation: Option<u64>,
    pub activation: Option<u64>,
    #[serde(default)]
    pub activation_generation: Option<u64>,
    pub code_object: Option<u64>,
    #[serde(default)]
    pub code_generation: Option<u64>,
    pub artifact: Option<u64>,
    #[serde(default)]
    pub artifact_generation: Option<u64>,
    pub offset: Option<u64>,
    #[serde(default)]
    pub target_pc: Option<u64>,
    #[serde(default)]
    pub trap_kind: Option<String>,
    #[serde(default)]
    pub function_index: Option<u32>,
    #[serde(default)]
    pub wasm_offset: Option<u64>,
    #[serde(default)]
    pub debug_symbol: Option<u32>,
    #[serde(default)]
    pub classification_status: Option<String>,
    pub hostcall: Option<String>,
    pub fault_policy: String,
    pub effect: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HostcallTraceManifest {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub abi_version: String,
    #[serde(default)]
    pub frame_size: u16,
    #[serde(default)]
    pub flags: u32,
    pub activation: u64,
    #[serde(default)]
    pub activation_generation: u64,
    #[serde(default)]
    pub store: u64,
    #[serde(default)]
    pub store_generation: u64,
    #[serde(default)]
    pub code_object: u64,
    #[serde(default)]
    pub code_generation: u64,
    #[serde(default)]
    pub artifact: u64,
    #[serde(default)]
    pub artifact_generation: u64,
    pub hostcall_number: u32,
    #[serde(default)]
    pub hostcall_seq: u64,
    #[serde(default)]
    pub caller_offset: u64,
    pub name: String,
    pub category: String,
    #[serde(default)]
    pub subject: String,
    pub object: String,
    pub operation: String,
    #[serde(default)]
    pub args: [u64; 6],
    #[serde(default)]
    pub cap_args: Vec<CapabilityHandleArgManifest>,
    #[serde(default)]
    pub record_mode: String,
    pub allowed: bool,
    pub result: String,
    #[serde(default)]
    pub ret_tag: String,
    #[serde(default)]
    pub ret0: u64,
    #[serde(default)]
    pub ret1: u64,
    #[serde(default)]
    pub trap_out: Option<u64>,
    #[serde(default)]
    pub trap_generation_out: Option<u64>,
    #[serde(default)]
    pub wait_token_out: Option<u64>,
    #[serde(default)]
    pub wait_token_generation_out: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CapabilityHandleArgManifest {
    pub id: u64,
    pub object: String,
    pub generation: u64,
    #[serde(default)]
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    #[serde(default)]
    pub handle_slot: u32,
    #[serde(default)]
    pub handle_generation: u32,
    #[serde(default)]
    pub handle_tag: u64,
    pub rights_mask: u64,
    pub rights: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MigrationObjectManifest {
    pub object: String,
    pub class: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TombstoneManifest {
    pub kind: String,
    pub id: u64,
    pub generation: u64,
    pub died_at: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ContractObjectRefManifest {
    pub kind: String,
    pub id: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ContractViolationManifest {
    pub kind: String,
    pub edge: String,
    pub from: ContractObjectRefManifest,
    pub to: Option<ContractObjectRefManifest>,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CleanupStepManifest {
    pub step: String,
    pub state: String,
    pub detail: String,
    #[serde(default)]
    pub target: Option<ContractObjectRefManifest>,
    #[serde(default)]
    pub observed_generation: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub idempotency_key: String,
    #[serde(default)]
    pub event_seq: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CleanupEffectManifest {
    pub kind: String,
    pub target: ContractObjectRefManifest,
    pub expected_generation: u64,
    pub status: String,
    pub event_seq: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CleanupTransactionManifest {
    pub id: u64,
    pub store: u64,
    #[serde(default)]
    pub store_generation: u64,
    #[serde(default)]
    pub target_store_generation: u64,
    #[serde(default)]
    pub result_store_generation: Option<u64>,
    pub activation: Option<u64>,
    #[serde(default)]
    pub activation_generation: Option<u64>,
    pub code_object: Option<u64>,
    #[serde(default)]
    pub code_generation: Option<u64>,
    pub generation: u64,
    #[serde(default)]
    pub started_at: u64,
    #[serde(default)]
    pub finished_at: Option<u64>,
    pub state: String,
    pub reason: String,
    pub released_dmw_leases: u32,
    pub cancelled_waits: u32,
    pub revoked_capabilities: Vec<u64>,
    #[serde(default)]
    pub revoked_capability_refs: Vec<ContractObjectRefManifest>,
    pub dropped_resources: u32,
    pub unbound_code_object: bool,
    pub effect: String,
    pub steps: Vec<CleanupStepManifest>,
    #[serde(default)]
    pub effects: Vec<CleanupEffectManifest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MemoryClassPolicyManifest {
    pub class: String,
    pub owner_kind: String,
    pub permissions: String,
    pub migration_policy: String,
    pub snapshot_policy: String,
    pub cleanup_policy: String,
    pub can_alias_guest_memory: bool,
    pub can_cross_pending: bool,
    pub can_be_executable: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BoundaryValidationViolationManifest {
    pub validator: String,
    pub kind: String,
    pub object: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BoundaryValidationReportManifest {
    pub validator: String,
    pub ok: bool,
    pub violation_count: usize,
    pub violations: Vec<BoundaryValidationViolationManifest>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubstrateBoundaryManifest {
    pub timer_epoch: u64,
    pub pending_irq_causes: u32,
    pub pending_dma_completions: u32,
    pub active_dmw_lease_count: u32,
    #[serde(default)]
    pub active_mmio_authority_count: u32,
    #[serde(default)]
    pub active_dma_authority_count: u32,
    #[serde(default)]
    pub active_irq_authority_count: u32,
    #[serde(default)]
    pub active_packet_device_authority_count: u32,
    #[serde(default)]
    pub active_virtio_queue_authority_count: u32,
    #[serde(default)]
    pub pending_network_inputs: u32,
    #[serde(default)]
    pub random_epoch: u64,
    #[serde(default)]
    pub scheduler_decision_cursor: u64,
    #[serde(default)]
    pub cow_epoch: u64,
    #[serde(default)]
    pub background_copy_pages: u64,
    pub native_state_policy: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationCapabilityManifest {
    pub subject: String,
    pub object: String,
    pub rights: Vec<String>,
    pub lifetime: String,
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    #[serde(default)]
    pub owner_task: Option<u64>,
    pub generation: u64,
    #[serde(default)]
    pub revoked: bool,
}
