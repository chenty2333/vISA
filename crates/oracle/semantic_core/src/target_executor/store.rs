use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedStoreRecord {
    pub store: StoreRecord,
    pub resource_arena: String,
    pub rebind_policy: String,
}

impl ManagedStoreRecord {
    pub fn summary(&self) -> String {
        format!(
            "store id={} package={} state={} generation={} domain={} arena={} rebind_policy={}",
            self.store.id,
            self.store.package,
            self.store.state.as_str(),
            self.store.generation,
            self.store.fault_domain,
            self.resource_arena,
            self.rebind_policy
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetStoreManagerError {
    StoreMissing,
    InvalidTransition,
}

impl TargetStoreManagerError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::StoreMissing => "store is missing",
            Self::InvalidTransition => "invalid store lifecycle transition",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TargetStoreManager {
    next_store_id: StoreId,
    next_tombstone_event: EventId,
    records: Vec<ManagedStoreRecord>,
    tombstones: Vec<TombstoneRecord>,
}

impl TargetStoreManager {
    pub const fn new() -> Self {
        Self {
            next_store_id: 1,
            next_tombstone_event: 1,
            records: Vec::new(),
            tombstones: Vec::new(),
        }
    }

    pub fn register_verified_artifact(
        &mut self,
        artifact: &VerifiedArtifact,
        fault_policy: &str,
        rebind_policy: &str,
    ) -> StoreId {
        let id = self.next_store_id;
        self.next_store_id += 1;
        self.register_verified_artifact_with_id(id, artifact, fault_policy, rebind_policy)
    }

    pub fn register_verified_artifact_with_id(
        &mut self,
        store_id: StoreId,
        artifact: &VerifiedArtifact,
        fault_policy: &str,
        rebind_policy: &str,
    ) -> StoreId {
        self.next_store_id = self.next_store_id.max(store_id + 1);
        self.records.push(ManagedStoreRecord {
            store: StoreRecord {
                id: store_id,
                package: artifact.package.clone(),
                artifact: artifact.artifact_name.clone(),
                owner_profile: artifact.target_profile.clone(),
                role: artifact.role.clone(),
                fault_policy: fault_policy.to_string(),
                fault_domain: store_id,
                resource: None,
                state: StoreState::Instantiating,
                generation: 1,
                restart_count: 0,
            },
            resource_arena: format!("store-arena:{}", artifact.package),
            rebind_policy: rebind_policy.to_string(),
        });
        store_id
    }

    pub fn register_store_record(
        &mut self,
        store: StoreRecord,
        rebind_policy: &str,
    ) -> Result<StoreId, TargetStoreManagerError> {
        if store.id == 0 || self.records.iter().any(|record| record.store.id == store.id) {
            return Err(TargetStoreManagerError::InvalidTransition);
        }
        let store_id = store.id;
        self.next_store_id = self.next_store_id.max(store_id + 1);
        self.records.push(ManagedStoreRecord {
            resource_arena: format!("store-arena:{}", store.package),
            rebind_policy: rebind_policy.to_string(),
            store,
        });
        Ok(store_id)
    }

    pub fn set_running(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        self.set_state(store, StoreState::Running)
    }

    pub fn begin_draining(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        self.set_state(store, StoreState::Draining)
    }

    pub fn drop_store(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        self.set_state(store, StoreState::Dead)?;
        let generation =
            self.record(store).ok_or(TargetStoreManagerError::StoreMissing)?.store.generation;
        self.record_tombstone(ContractObjectKind::Store, store, generation, "store-dead");
        Ok(())
    }

    pub fn rebind_store(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        let record = self.record_mut(store)?;
        if !matches!(record.store.state, StoreState::Restarting | StoreState::Dead) {
            return Err(TargetStoreManagerError::InvalidTransition);
        }
        record.store.state = StoreState::Rebinding;
        record.store.generation += 1;
        record.store.restart_count += 1;
        Ok(())
    }

    pub fn record(&self, store: StoreId) -> Option<&ManagedStoreRecord> {
        self.records.iter().find(|record| record.store.id == store)
    }

    pub fn records(&self) -> &[ManagedStoreRecord] {
        &self.records
    }

    pub fn tombstones(&self) -> &[TombstoneRecord] {
        &self.tombstones
    }

    pub fn restore_records(
        &mut self,
        records: &[ManagedStoreRecord],
        tombstones: &[TombstoneRecord],
    ) -> bool {
        let mut restored_records = Vec::new();
        for record in records {
            if record.store.id == 0
                || record.store.generation == 0
                || restored_records
                    .iter()
                    .any(|existing: &ManagedStoreRecord| existing.store.id == record.store.id)
            {
                return false;
            }
            restored_records.push(record.clone());
        }
        let mut restored_tombstones = Vec::new();
        for tombstone in tombstones {
            if tombstone.kind != ContractObjectKind::Store
                || tombstone.id == 0
                || tombstone.generation == 0
                || restored_tombstones.iter().any(|existing: &TombstoneRecord| {
                    existing.object_ref() == tombstone.object_ref()
                })
            {
                return false;
            }
            restored_tombstones.push(tombstone.clone());
        }
        let record_next =
            restored_records.iter().map(|record| record.store.id + 1).max().unwrap_or(1);
        let tombstone_next =
            restored_tombstones.iter().map(|tombstone| tombstone.id + 1).max().unwrap_or(1);
        self.next_store_id = record_next.max(tombstone_next);
        self.next_tombstone_event =
            restored_tombstones.iter().map(|tombstone| tombstone.died_at + 1).max().unwrap_or(1);
        self.records = restored_records;
        self.tombstones = restored_tombstones;
        true
    }

    fn set_state(
        &mut self,
        store: StoreId,
        state: StoreState,
    ) -> Result<(), TargetStoreManagerError> {
        let record = self.record_mut(store)?;
        record.store.state = state;
        record.store.generation += 1;
        Ok(())
    }

    pub fn record_mut(
        &mut self,
        store: StoreId,
    ) -> Result<&mut ManagedStoreRecord, TargetStoreManagerError> {
        self.records
            .iter_mut()
            .find(|record| record.store.id == store)
            .ok_or(TargetStoreManagerError::StoreMissing)
    }

    pub fn record_current_tombstone(
        &mut self,
        store: StoreId,
        reason: &str,
    ) -> Result<(), TargetStoreManagerError> {
        let generation =
            self.record(store).ok_or(TargetStoreManagerError::StoreMissing)?.store.generation;
        self.record_tombstone(ContractObjectKind::Store, store, generation, reason);
        Ok(())
    }

    fn record_tombstone(
        &mut self,
        kind: ContractObjectKind,
        id: u64,
        generation: Generation,
        reason: &str,
    ) {
        let event = self.next_tombstone_event;
        self.next_tombstone_event += 1;
        self.tombstones.push(TombstoneRecord::new(kind, id, generation, event, reason));
    }
}

impl Default for TargetStoreManager {
    fn default() -> Self {
        Self::new()
    }
}
