use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationObjectClass {
    Migrated,
    Rebuilt,
    NeverMigrated,
}

impl MigrationObjectClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Migrated => "migrated",
            Self::Rebuilt => "rebuilt",
            Self::NeverMigrated => "never-migrated",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationObjectRecord {
    pub object: String,
    pub class: MigrationObjectClass,
    pub reason: String,
}

impl MigrationObjectRecord {
    pub fn new(object: &str, class: MigrationObjectClass, reason: &str) -> Self {
        Self { object: object.to_string(), class, reason: reason.to_string() }
    }

    pub fn summary(&self) -> String {
        format!(
            "migration-object object={} class={} reason={}",
            self.object,
            self.class.as_str(),
            self.reason
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmwLeaseRecord {
    pub id: DmwLeaseId,
    pub activation: ActivationId,
    pub handle: String,
    pub generation: Generation,
    pub active: bool,
}

impl DmwLeaseRecord {
    pub fn summary(&self) -> String {
        format!(
            "dmw-lease id={} activation={} handle={} generation={} active={}",
            self.id, self.activation, self.handle, self.generation, self.active
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupStep {
    StopNewActivation,
    SealActivation,
    PreventHostcalls,
    ReleaseDmwLeases,
    CancelWaitTokens,
    RevokeCapabilities,
    DropResourceArena,
    UnbindCodeObject,
    MarkStoreState,
    RecordTransition,
    EmitTombstones,
    RecordFailureEffect,
    EmitReport,
}

impl CleanupStep {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StopNewActivation => "stop-new-activation",
            Self::SealActivation => "seal-activation",
            Self::PreventHostcalls => "prevent-hostcalls",
            Self::ReleaseDmwLeases => "release-dmw-leases",
            Self::CancelWaitTokens => "cancel-wait-tokens",
            Self::RevokeCapabilities => "revoke-capabilities",
            Self::DropResourceArena => "drop-resource-arena",
            Self::UnbindCodeObject => "unbind-code-object",
            Self::MarkStoreState => "mark-store-state",
            Self::RecordTransition => "record-transition",
            Self::EmitTombstones => "emit-tombstones",
            Self::RecordFailureEffect => "record-failure-effect",
            Self::EmitReport => "emit-report",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupStepState {
    NotStarted,
    Done,
    SkippedStaleGeneration,
    FailedRecoverable,
    FailedFatal,
}

impl CleanupStepState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not-started",
            Self::Done => "done",
            Self::SkippedStaleGeneration => "skipped-stale-generation",
            Self::FailedRecoverable => "failed-recoverable",
            Self::FailedFatal => "failed-fatal",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupStepRecord {
    pub step: CleanupStep,
    pub target: Option<ContractObjectRef>,
    pub observed_generation: Option<Generation>,
    pub state: CleanupStepState,
    pub detail: String,
    pub error: Option<String>,
    pub idempotency_key: String,
    pub event_seq: EventId,
}

impl CleanupStepRecord {
    pub fn done(step: CleanupStep, detail: &str) -> Self {
        Self {
            step,
            target: None,
            observed_generation: None,
            state: CleanupStepState::Done,
            detail: detail.to_string(),
            error: None,
            idempotency_key: step.as_str().to_string(),
            event_seq: 0,
        }
    }

    pub fn pending(step: CleanupStep) -> Self {
        Self {
            step,
            target: None,
            observed_generation: None,
            state: CleanupStepState::NotStarted,
            detail: String::new(),
            error: None,
            idempotency_key: step.as_str().to_string(),
            event_seq: 0,
        }
    }

    pub fn skipped_stale_generation(
        step: CleanupStep,
        target: ContractObjectRef,
        observed_generation: Generation,
        event_seq: EventId,
    ) -> Self {
        Self {
            step,
            target: Some(target),
            observed_generation: Some(observed_generation),
            state: CleanupStepState::SkippedStaleGeneration,
            detail: "stale generation did not mutate newer object".to_string(),
            error: Some("stale-generation".to_string()),
            idempotency_key: step.as_str().to_string(),
            event_seq,
        }
    }

    pub fn with_target(mut self, target: ContractObjectRef) -> Self {
        self.target = Some(target);
        self
    }

    pub fn with_observed_generation(mut self, generation: Generation) -> Self {
        self.observed_generation = Some(generation);
        self
    }

    pub fn with_event_seq(mut self, event_seq: EventId) -> Self {
        self.event_seq = event_seq;
        self
    }

    pub fn summary(&self) -> String {
        let target =
            self.target.map(ContractObjectRef::summary).unwrap_or_else(|| "none".to_string());
        let observed = self
            .observed_generation
            .map(|generation| generation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let error = self.error.clone().unwrap_or_else(|| "none".to_string());
        format!(
            "{}:{}:{}:target={}:observed={}:error={}:event={}:key={}",
            self.step.as_str(),
            self.state.as_str(),
            self.detail,
            target,
            observed,
            error,
            self.event_seq,
            self.idempotency_key
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupTransactionState {
    Pending,
    Completed,
    SkippedStaleGeneration,
}

impl CleanupTransactionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::SkippedStaleGeneration => "skipped-stale-generation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupEffectKind {
    StopNewActivation,
    SealActivation,
    ReleaseLeases,
    CancelWaits,
    RevokeCapability,
    DropResources,
    UnbindCode,
    MarkStoreDead,
    EmitTombstone,
    RecordFailureEffect,
}

impl CleanupEffectKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StopNewActivation => "stop-new-activation",
            Self::SealActivation => "seal-activation",
            Self::ReleaseLeases => "release-leases",
            Self::CancelWaits => "cancel-waits",
            Self::RevokeCapability => "revoke-capability",
            Self::DropResources => "drop-resources",
            Self::UnbindCode => "unbind-code",
            Self::MarkStoreDead => "mark-store-dead",
            Self::EmitTombstone => "emit-tombstone",
            Self::RecordFailureEffect => "record-failure-effect",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupEffectStatus {
    Applied,
    AlreadyApplied,
    SkippedStaleGeneration,
}

impl CleanupEffectStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::AlreadyApplied => "already-applied",
            Self::SkippedStaleGeneration => "skipped-stale-generation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupEffectRecord {
    pub kind: CleanupEffectKind,
    pub target: ContractObjectRef,
    pub expected_generation: Generation,
    pub status: CleanupEffectStatus,
    pub event_seq: EventId,
}

impl CleanupEffectRecord {
    pub const fn new(
        kind: CleanupEffectKind,
        target: ContractObjectRef,
        expected_generation: Generation,
        status: CleanupEffectStatus,
        event_seq: EventId,
    ) -> Self {
        Self { kind, target, expected_generation, status, event_seq }
    }

    pub fn summary(&self) -> String {
        format!(
            "{}:{}:{}@{}:event={}",
            self.kind.as_str(),
            self.status.as_str(),
            self.target.summary(),
            self.expected_generation,
            self.event_seq
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultCleanupTransaction {
    pub id: CleanupTransactionId,
    pub store: StoreId,
    pub store_generation: Generation,
    pub result_store_generation: Option<Generation>,
    pub activation: Option<ActivationId>,
    pub activation_generation: Option<Generation>,
    pub code_object: Option<CodeObjectId>,
    pub code_generation: Option<Generation>,
    pub generation: Generation,
    pub started_at: EventId,
    pub finished_at: Option<EventId>,
    pub state: CleanupTransactionState,
    pub reason: String,
    pub steps: Vec<CleanupStepRecord>,
    pub effects: Vec<CleanupEffectRecord>,
    pub released_dmw_leases: u32,
    pub cancelled_waits: u32,
    pub revoked_capabilities: Vec<CapabilityId>,
    pub revoked_capability_refs: Vec<ContractObjectRef>,
    pub dropped_resources: u32,
    pub unbound_code_object: bool,
    pub state_digest: String,
    pub effect: FailureEffect,
}

impl FaultCleanupTransaction {
    pub fn summary(&self) -> String {
        format!(
            "cleanup id={} target_store={}@{} result_store_generation={} activation={} code={} generation={} started={} finished={} state={} reason={} released_dmw={} cancelled_waits={} revoked_caps={} dropped_resources={} unbound_code={} state_digest={} effect={} steps={} effects={}",
            self.id,
            self.store,
            self.store_generation,
            self.result_store_generation
                .map(|generation| generation.to_string())
                .unwrap_or_else(|| "none".to_string()),
            self.activation
                .zip(self.activation_generation)
                .map(|(activation, generation)| format!("{activation}@{generation}"))
                .unwrap_or_else(|| "none".to_string()),
            self.code_object
                .zip(self.code_generation)
                .map(|(code, generation)| format!("{code}@{generation}"))
                .unwrap_or_else(|| "none".to_string()),
            self.generation,
            self.started_at,
            self.finished_at.map(|event| event.to_string()).unwrap_or_else(|| "none".to_string()),
            self.state.as_str(),
            self.reason,
            self.released_dmw_leases,
            self.cancelled_waits,
            self.revoked_capabilities.len(),
            self.dropped_resources,
            self.unbound_code_object,
            self.state_digest,
            self.effect.summary(),
            self.steps.iter().map(CleanupStepRecord::summary).collect::<Vec<_>>().join("|"),
            self.effects.iter().map(CleanupEffectRecord::summary).collect::<Vec<_>>().join("|")
        )
    }
}
