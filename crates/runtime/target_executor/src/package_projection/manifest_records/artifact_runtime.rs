use visa_runtime::VisaRuntimeEvidenceSnapshot;

use super::{super::super::*, *};

pub(crate) fn target_artifact_manifest(image: &TargetArtifactImage) -> TargetArtifactImageManifest {
    TargetArtifactImageManifest {
        id: image.id,
        package: image.package.clone(),
        artifact_name: image.artifact_name.clone(),
        role: image.role.clone(),
        kind: image.kind.as_str().to_owned(),
        target_profile: image.target_profile.clone(),
        artifact_hash: image.artifact_hash.clone(),
        hash_status: image.hash_status.clone(),
        abi_fingerprint: image.abi_fingerprint.clone(),
        manifest_binding_hash: image.manifest_binding_hash.clone(),
        code_hash: image.code_hash.clone(),
        signature_scheme: image.signature_scheme.clone(),
        signature_status: image.signature_status.clone(),
        signature_verified: image.signature_verified,
        signer: image.signer.clone(),
        exports: image.exports.clone(),
        imports: image.imports.clone(),
        hostcalls: image.hostcalls.iter().map(hostcall_manifest).collect(),
        capabilities: image.capabilities.iter().map(target_capability_manifest).collect(),
        memory_plan: TargetMemoryPlanManifest {
            max_memory_pages: image.memory_plan.max_memory_pages,
            max_table_elements: image.memory_plan.max_table_elements,
            max_hostcalls_per_activation: image.memory_plan.max_hostcalls_per_activation,
        },
        trap_metadata: image.trap_metadata.iter().map(trap_metadata_manifest).collect(),
        address_map: image.address_map.iter().map(address_map_manifest).collect(),
        payload_len: image.payload_len,
    }
}

pub fn runtime_evidence_target_artifact_manifests(
    evidence: &VisaRuntimeEvidenceSnapshot,
) -> Vec<TargetArtifactImageManifest> {
    evidence.contract_graph.artifacts.iter().map(verified_artifact_manifest).collect()
}

fn verified_artifact_manifest(artifact: &VerifiedArtifact) -> TargetArtifactImageManifest {
    TargetArtifactImageManifest {
        id: artifact.artifact_id,
        package: artifact.package.clone(),
        artifact_name: artifact.artifact_name.clone(),
        role: artifact.role.clone(),
        kind: "target-artifact-image-v1".to_owned(),
        target_profile: artifact.target_profile.clone(),
        artifact_hash: artifact.artifact_hash.clone(),
        hash_status: artifact.hash_status.clone(),
        abi_fingerprint: artifact.abi_fingerprint.clone(),
        manifest_binding_hash: artifact.manifest_binding_hash.clone(),
        code_hash: artifact.code_hash.clone(),
        signature_scheme: artifact.signature_scheme.clone(),
        signature_status: artifact.signature_status.clone(),
        signature_verified: artifact.signature_verified,
        signer: artifact.signer.clone(),
        exports: artifact.exports.clone(),
        imports: artifact.imports.clone(),
        hostcalls: artifact.hostcalls.iter().map(hostcall_manifest).collect(),
        capabilities: artifact.capabilities.iter().map(target_capability_manifest).collect(),
        memory_plan: TargetMemoryPlanManifest {
            max_memory_pages: artifact.memory_plan.max_memory_pages,
            max_table_elements: artifact.memory_plan.max_table_elements,
            max_hostcalls_per_activation: artifact.memory_plan.max_hostcalls_per_activation,
        },
        trap_metadata: artifact.trap_metadata.iter().map(trap_metadata_manifest).collect(),
        address_map: artifact.address_map.iter().map(address_map_manifest).collect(),
        payload_len: artifact.payload_len,
    }
}

pub(crate) fn code_object_manifest(code: &CodeObject) -> CodeObjectManifest {
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
        trap_metadata: code.trap_metadata.iter().map(trap_metadata_manifest).collect(),
        address_map: code.address_map.iter().map(address_map_manifest).collect(),
        simd_requirement: CodeObjectSimdRequirementManifest {
            uses_simd: code.simd_requirement.uses_simd,
            declared: code.simd_requirement.declared,
            required_abi: code.simd_requirement.required_abi.clone(),
            min_vector_register_count: code.simd_requirement.min_vector_register_count,
            min_vector_register_bits: code.simd_requirement.min_vector_register_bits,
            target_feature_set: code
                .simd_requirement
                .target_feature_set
                .map(contract_object_ref_manifest),
            status: code.simd_requirement.status.as_str().to_owned(),
            note: code.simd_requirement.note.clone(),
        },
    }
}

pub(crate) fn store_record_manifest(store: &StoreRecord) -> StoreRecordManifest {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_evidence_projects_verified_artifacts_to_target_manifest() {
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
        image.hash_status = "verified".to_owned();
        image.signature_scheme = "dev-ed25519".to_owned();
        image.signature_status = "verified".to_owned();
        image.signature_verified = true;
        image.signer = "dev-key".to_owned();
        image.imports.push("visa.hostcall_1".to_owned());
        image.exports.push("visa_start".to_owned());
        image.hostcalls.push(HostcallSpec::new(
            1,
            "visa.console.write",
            HostcallCategory::Service,
            "visa.console",
            "write",
            false,
        ));
        image.capabilities.push(TargetCapabilitySpec::new(
            "visa.console",
            &["write"],
            "activation",
        ));
        image.trap_metadata.push(TargetTrapMetadata::new(
            TargetTrapClass::GuestTrap,
            "visa_start",
            4,
        ));
        image.address_map.push(TargetAddressMapEntry::new("visa_start", 0, 32));
        image.payload_len = 128;

        let mut registry = ArtifactRegistry::new();
        let verified = registry.verify(image).expect("verify artifact");
        let evidence = VisaRuntimeEvidenceSnapshot {
            contract_graph: semantic_core::ContractGraphSnapshot {
                artifacts: vec![verified],
                ..Default::default()
            },
            event_log_cursor: 0,
            runtime_events: Vec::new(),
            authority_extractions: Vec::new(),
            unsupported_substrate_events: Vec::new(),
        };

        let manifests = runtime_evidence_target_artifact_manifests(&evidence);

        assert_eq!(manifests.len(), 1);
        let manifest = &manifests[0];
        assert_eq!(manifest.id, 29);
        assert_eq!(manifest.kind, "target-artifact-image-v1");
        assert_eq!(manifest.role, "visa-native-workload");
        assert_eq!(manifest.artifact_hash, "artifact-hash");
        assert_eq!(manifest.hash_status, "verified");
        assert_eq!(manifest.signature_scheme, "dev-ed25519");
        assert!(manifest.signature_verified);
        assert_eq!(manifest.imports, vec![String::from("visa.hostcall_1")]);
        assert_eq!(manifest.exports, vec![String::from("visa_start")]);
        assert_eq!(manifest.hostcalls.len(), 1);
        assert_eq!(manifest.hostcalls[0].name, "visa.console.write");
        assert_eq!(manifest.capabilities.len(), 1);
        assert_eq!(manifest.memory_plan.max_hostcalls_per_activation, 16);
        assert_eq!(manifest.trap_metadata.len(), 1);
        assert_eq!(manifest.address_map.len(), 1);
        assert_eq!(manifest.payload_len, 128);
    }
}
