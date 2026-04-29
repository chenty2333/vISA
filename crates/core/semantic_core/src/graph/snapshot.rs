use super::*;

impl SemanticGraph {
    pub fn record_snapshot_barrier_enter(&mut self, barrier: SnapshotBarrierId) {
        self.event_log.push("snapshot", EventKind::SnapshotBarrierEnter { barrier });
    }
    pub fn record_snapshot_barrier_exit(&mut self, barrier: SnapshotBarrierId) {
        self.event_log.push("snapshot", EventKind::SnapshotBarrierExit { barrier });
    }
    pub fn migration_package(
        &self,
        package_id: &str,
        source_host_arch: &str,
        target_host_arch_hint: &str,
        required_artifact_profile: ArtifactProfile,
        guest: GuestStateSnapshot,
        substrate_boundary: SubstrateBoundarySnapshot,
        barrier_id: SnapshotBarrierId,
        dmw_quiescent: bool,
    ) -> MigrationPackage {
        MigrationPackage {
            schema_version: 1,
            package_id: package_id.to_string(),
            source_host_arch: source_host_arch.to_string(),
            target_host_arch_hint: target_host_arch_hint.to_string(),
            required_artifact_profile,
            guest,
            substrate_boundary: substrate_boundary.clone(),
            semantic: SemanticSnapshot {
                harts: self.harts.clone(),
                barrier: SnapshotBarrierSnapshot {
                    id: barrier_id,
                    event_log_cursor: self.event_log.cursor(),
                    pending_wait_count: self.pending_wait_count(),
                    live_resource_count: self.live_resource_count(),
                    active_transaction_count: self.active_transaction_count(),
                    active_dmw_lease_count: substrate_boundary.active_dmw_lease_count,
                    dmw_quiescent,
                },
                tasks: self.tasks.clone(),
                resources: self.resources.clone(),
                authority_bindings: self.authority_bindings.clone(),
                waits: self.domains.wait.waits.clone(),
                fault_domains: self.fault_domains.clone(),
                stores: self.stores.clone(),
                transactions: self.transactions.clone(),
                fast_path_plans: self.fast_path_plans.clone(),
                boundaries: self.boundaries.clone(),
                artifact_verifications: self.artifact_verifications.clone(),
                store_activations: self.store_activations.clone(),
                capabilities: self.domains.capability.capabilities.records().to_vec(),
            },
        }
    }
}
