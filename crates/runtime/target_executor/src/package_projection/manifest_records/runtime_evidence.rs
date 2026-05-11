use vms_runtime::VisaRuntimeEvidenceSnapshot;

use super::{super::super::*, *};

#[derive(Clone, Debug, Default)]
pub struct RuntimeEvidenceTargetRuntimeManifests {
    pub target_artifacts: Vec<TargetArtifactImageManifest>,
    pub code_objects: Vec<CodeObjectManifest>,
    pub store_records: Vec<StoreRecordManifest>,
    pub capability_records: Vec<CapabilityRecordManifest>,
    pub wait_records: Vec<WaitRecordManifest>,
    pub activation_records: Vec<ActivationRecordManifest>,
    pub trap_records: Vec<TrapRecordManifest>,
    pub hostcall_trace: Vec<HostcallTraceManifest>,
    pub cleanup_transactions: Vec<CleanupTransactionManifest>,
    pub tombstones: Vec<TombstoneManifest>,
    pub substrate_events: Vec<SubstrateEventManifest>,
}

pub fn runtime_evidence_target_runtime_manifests(
    evidence: &VisaRuntimeEvidenceSnapshot,
) -> RuntimeEvidenceTargetRuntimeManifests {
    let graph = &evidence.contract_graph;
    RuntimeEvidenceTargetRuntimeManifests {
        target_artifacts: runtime_evidence_target_artifact_manifests(evidence),
        code_objects: graph.code_objects.iter().map(code_object_manifest).collect(),
        store_records: graph.stores.iter().map(store_record_manifest).collect(),
        capability_records: graph.capabilities.iter().map(capability_record_manifest).collect(),
        wait_records: graph.waits.iter().map(wait_record_manifest).collect(),
        activation_records: graph.activations.iter().map(activation_record_manifest).collect(),
        trap_records: graph.traps.iter().map(trap_record_manifest).collect(),
        hostcall_trace: graph.hostcalls.iter().map(hostcall_trace_manifest).collect(),
        cleanup_transactions: graph
            .cleanup_transactions
            .iter()
            .map(cleanup_transaction_manifest)
            .collect(),
        tombstones: graph.tombstones.iter().map(tombstone_manifest).collect(),
        substrate_events: runtime_evidence_substrate_event_manifests(evidence),
    }
}

#[cfg(test)]
mod tests {
    use vms_runtime::{
        VisaRuntimeEvidenceSnapshot, VisaSubstrateAuthorityExtractionEvidence,
        VisaSubstrateUnsupportedEvidence,
    };

    use super::*;

    #[test]
    fn runtime_evidence_target_runtime_manifest_bundle_projects_package_ready_records() {
        let mut image = TargetArtifactImage::new(
            29,
            "native-visa",
            "native-visa-artifact",
            "visa-native-workload",
            "snapshot-replay",
            "artifact-hash",
            "abi-fingerprint",
            "manifest-binding",
            "code-hash",
            TargetMemoryPlan::new(4, 2, 16),
        );
        image.imports.push("vms.hostcall_1".to_owned());
        image.exports.push("visa_start".to_owned());

        let mut registry = ArtifactRegistry::new();
        let verified = registry.verify(image).expect("verify artifact");
        let store = StoreRecord {
            id: 7,
            package: "native-visa".to_owned(),
            artifact: "native-visa-artifact".to_owned(),
            role: "visa-native-workload".to_owned(),
            fault_policy: "restartable".to_owned(),
            fault_domain: 3,
            resource: None,
            state: StoreState::Running,
            generation: 5,
            restart_count: 2,
        };
        let evidence = VisaRuntimeEvidenceSnapshot {
            contract_graph: semantic_core::ContractGraphSnapshot {
                artifacts: vec![verified],
                stores: vec![store],
                ..Default::default()
            },
            event_log_cursor: 11,
            runtime_events: Vec::new(),
            authority_extractions: vec![VisaSubstrateAuthorityExtractionEvidence {
                event_id: 9,
                event_epoch: 4,
                authority: "DmaAuthority".to_owned(),
                operation: "dma_alloc".to_owned(),
                requester: Some("native-visa".to_owned()),
                artifact_id: Some(29),
                store_id: Some(7),
                capability_id: Some(13),
                capability_generation: Some(2),
            }],
            unsupported_substrate_events: vec![VisaSubstrateUnsupportedEvidence {
                event_id: 8,
                event_epoch: 3,
                authority: "ConsoleAuthority".to_owned(),
                operation: "console_write".to_owned(),
                requester: Some("native-visa".to_owned()),
                artifact_id: Some(29),
                store_id: Some(7),
            }],
        };

        let bundle = runtime_evidence_target_runtime_manifests(&evidence);

        assert_eq!(bundle.target_artifacts.len(), 1);
        assert_eq!(bundle.target_artifacts[0].id, 29);
        assert_eq!(bundle.target_artifacts[0].imports, vec![String::from("vms.hostcall_1")]);
        assert_eq!(bundle.target_artifacts[0].exports, vec![String::from("visa_start")]);
        assert_eq!(bundle.store_records.len(), 1);
        assert_eq!(bundle.store_records[0].id, 7);
        assert_eq!(bundle.store_records[0].state, "running");
        assert_eq!(bundle.store_records[0].generation, 5);
        assert_eq!(bundle.substrate_events.len(), 2);
        assert_eq!(bundle.substrate_events[0].event_kind, "unsupported");
        assert_eq!(bundle.substrate_events[0].id, 8);
        assert_eq!(bundle.substrate_events[1].event_kind, "authority-extracted");
        assert_eq!(bundle.substrate_events[1].capability.as_ref().map(|cap| cap.id), Some(13));
    }
}
