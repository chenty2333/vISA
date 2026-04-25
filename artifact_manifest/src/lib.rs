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
    pub wasm_sha256: String,
    pub cwasm_sha256: String,
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
    pub task_count: usize,
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
    pub target_artifacts: Vec<TargetArtifactImageManifest>,
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
    pub network_socket_count: u32,
    #[serde(default)]
    pub network_rx_queue_bytes: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SemanticRootSetManifest {
    #[serde(default)]
    pub task_roots: Vec<String>,
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
    pub event_log_tail: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetArtifactImageManifest {
    pub id: u64,
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub kind: String,
    pub target_profile: String,
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
    pub owner_store: Option<u64>,
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
    pub activation: Option<u64>,
    pub code_object: Option<u64>,
    #[serde(default)]
    pub code_generation: Option<u64>,
    pub artifact: Option<u64>,
    #[serde(default)]
    pub artifact_generation: Option<u64>,
    pub offset: Option<u64>,
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
    pub wait_token_out: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CapabilityHandleArgManifest {
    pub id: u64,
    pub object: String,
    pub generation: u64,
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
    pub owner_task: Option<u64>,
    pub generation: u64,
    #[serde(default)]
    pub revoked: bool,
}
