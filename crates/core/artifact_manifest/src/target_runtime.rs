use serde::{Deserialize, Serialize};

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
    #[serde(default)]
    pub hash_status: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    #[serde(default)]
    pub signature_scheme: String,
    #[serde(default)]
    pub signature_status: String,
    #[serde(default)]
    pub signature_verified: bool,
    #[serde(default)]
    pub signer: String,
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
    #[serde(default)]
    pub simd_requirement: CodeObjectSimdRequirementManifest,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CodeObjectSimdRequirementManifest {
    pub uses_simd: bool,
    pub declared: bool,
    pub required_abi: String,
    pub min_vector_register_count: u16,
    pub min_vector_register_bits: u16,
    pub target_feature_set: Option<ContractObjectRefManifest>,
    pub status: String,
    pub note: String,
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
pub struct SimdTrapAttributionManifest {
    pub classification: String,
    pub required_abi: String,
    pub min_vector_register_count: u16,
    pub min_vector_register_bits: u16,
    pub target_feature_set: Option<ContractObjectRefManifest>,
    pub code_requirement_status: String,
    pub note: String,
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
    #[serde(default)]
    pub attribution_status: String,
    #[serde(default)]
    pub simd_attribution: Option<SimdTrapAttributionManifest>,
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
    #[serde(default)]
    pub subject_source: String,
    pub object: String,
    pub operation: String,
    #[serde(default)]
    pub args: [u64; 6],
    #[serde(default)]
    pub cap_args: Vec<CapabilityHandleArgManifest>,
    #[serde(default)]
    pub record_mode: String,
    pub allowed: bool,
    #[serde(default)]
    pub gate_status: String,
    pub result: String,
    #[serde(default)]
    pub denial_reason: Option<String>,
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
    #[serde(default)]
    pub state_digest: String,
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
