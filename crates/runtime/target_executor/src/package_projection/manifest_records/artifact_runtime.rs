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
