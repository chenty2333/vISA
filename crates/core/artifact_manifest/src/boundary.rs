use serde::{Deserialize, Serialize};

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
    #[serde(default)]
    pub evidence_boundary: String,
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
