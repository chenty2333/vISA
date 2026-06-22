use artifact_manifest::{
    AuthorityObjectRefManifest, CleanupEffectManifest, CleanupStepManifest,
    ContractObjectRefManifest, ContractViolationManifest,
};
use semantic_core::{
    AuthorityObjectRef, CapabilityClass, ContractGraphSnapshot, ExternalObjectDeclaration,
    FrontendKind, RestartPolicy, SemanticCommand, SemanticGraph, SemanticWaitKind,
    WaitCancelReason, WaitState,
    target_executor::{CleanupStep, ContractObjectKind, ContractObjectRef},
    validate_contract_graph,
};

use super::*;

mod artifact_io_views;
mod block_fs_views;
mod core_views;
mod graph_replay;
mod network_views;
mod replay_fixtures;
mod runtime_views;
mod simd_display_integrated_views;

fn minimal_graph_package() -> MigrationPackageManifest {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "package_format": "visa-semantic-package-v1",
        "package_id": "graph-test",
        "source": { "arch": "x86_64" },
        "target": { "arch_requirement": "target-native" },
        "required_artifact_profile": {
            "artifact_profile": "host-validation",
            "target_arch": "target-native",
            "machine_abi_version": "test",
            "supervisor_abi_version": "test",
            "wasm_feature_profile": "test",
            "memory64": false,
            "multi_memory": false,
            "dmw_layout": "logical",
            "network_contract_version": "test",
            "compiler_engine": "wasmtime",
            "compiler_execution_mode": "precompiled-core-module",
            "artifact_format": "target-artifact-image-v1",
            "runtime_executor_abi": "visa-runtime-only-executor-v0"
        },
        "guest": {
            "canonical_isa": "riscv64",
            "register_count": 33,
            "memory_page_count": 0,
            "vma_count": 0,
            "signal_queue_count": 0,
            "note": "test"
        },
        "semantic": {
            "barrier_id": 1,
            "event_log_cursor": 0,
            "task_count": 0,
            "resource_count": 0,
            "wait_token_count": 0,
            "capability_count": 0,
            "fault_domain_count": 0
        },
        "logical_capabilities": [],
        "substrate_boundary": {
            "timer_epoch": 0,
            "pending_irq_causes": 0,
            "pending_dma_completions": 0,
            "active_dmw_lease_count": 0,
            "active_mmio_authority_count": 0,
            "active_dma_authority_count": 0,
            "active_irq_authority_count": 0,
            "active_packet_device_authority_count": 0,
            "active_virtio_queue_authority_count": 0,
            "pending_network_inputs": 0,
            "random_epoch": 0,
            "scheduler_decision_cursor": 0,
            "cow_epoch": 0,
            "background_copy_pages": 0,
            "native_state_policy": "test"
        },
        "not_migrated": []
    }))
    .expect("minimal graph package")
}

fn add_native_portable_execution_chain(package: &mut MigrationPackageManifest) {
    let hostcall = artifact_manifest::HostcallSpecManifest {
        number: 1,
        name: "visa.console.write".to_owned(),
        category: "console".to_owned(),
        object: "visa.console".to_owned(),
        operation: "write".to_owned(),
        may_pending: false,
    };
    package.semantic.target_artifact_count = 1;
    package.semantic.roots.target_artifact_roots = vec!["target-artifact id=1".to_owned()];
    package.semantic.target_artifacts = vec![artifact_manifest::TargetArtifactImageManifest {
        id: 1,
        package: "native-visa".to_owned(),
        artifact_name: "visa-native-artifact".to_owned(),
        role: "visa-native-workload".to_owned(),
        kind: "target-artifact-image".to_owned(),
        target_profile: "minimal-bare-metal".to_owned(),
        abi_fingerprint: "native-visa-abi".to_owned(),
        manifest_binding_hash: "native-visa-binding".to_owned(),
        code_hash: "native-visa-code".to_owned(),
        exports: vec!["visa_start".to_owned()],
        hostcalls: vec![hostcall.clone()],
        memory_plan: artifact_manifest::TargetMemoryPlanManifest {
            max_memory_pages: 16,
            max_table_elements: 0,
            max_hostcalls_per_activation: 16,
        },
        payload_len: 64,
        ..Default::default()
    }];

    package.semantic.code_object_count = 1;
    package.semantic.roots.code_object_roots = vec!["code-object id=1".to_owned()];
    package.semantic.code_objects = vec![artifact_manifest::CodeObjectManifest {
        id: 1,
        artifact_id: 1,
        package: "native-visa".to_owned(),
        owner_profile: "minimal-bare-metal".to_owned(),
        generation: 1,
        state: "published".to_owned(),
        text_permission: "rx".to_owned(),
        rodata_permission: "r".to_owned(),
        code_hash: "native-visa-code".to_owned(),
        hostcalls: vec![hostcall.clone()],
        ..Default::default()
    }];

    package.semantic.store_record_count = 1;
    package.semantic.roots.target_store_record_roots = vec!["store id=1".to_owned()];
    package.semantic.store_records = vec![artifact_manifest::StoreRecordManifest {
        id: 1,
        package: "native-visa".to_owned(),
        artifact: "visa-native-artifact".to_owned(),
        owner_profile: "minimal-bare-metal".to_owned(),
        role: "visa-native-workload".to_owned(),
        fault_policy: "abort".to_owned(),
        fault_domain: 1,
        state: "running".to_owned(),
        generation: 1,
        ..Default::default()
    }];

    package.semantic.activation_record_count = 1;
    package.semantic.roots.activation_record_roots = vec!["activation id=1".to_owned()];
    package.semantic.activation_records = vec![artifact_manifest::ActivationRecordManifest {
        id: 1,
        store: 1,
        store_generation: 1,
        code_object: 1,
        code_generation: 1,
        artifact: 1,
        profile: "minimal-bare-metal".to_owned(),
        entry: "visa_start".to_owned(),
        generation: 1,
        state: "running".to_owned(),
        ..Default::default()
    }];

    package.semantic.trap_record_count = 1;
    package.semantic.roots.trap_roots = vec!["trap id=1".to_owned()];
    package.semantic.trap_records = vec![artifact_manifest::TrapRecordManifest {
        id: 1,
        generation: 1,
        class: "fault".to_owned(),
        store: Some(1),
        store_generation: Some(1),
        activation: Some(1),
        activation_generation: Some(1),
        code_object: Some(1),
        code_generation: Some(1),
        artifact: Some(1),
        artifact_generation: Some(1),
        offset: Some(16),
        trap_kind: Some("hostcall-fault".to_owned()),
        attribution_status: "trap-map-attributed".to_owned(),
        fault_policy: "abort".to_owned(),
        effect: "trap".to_owned(),
        detail: "target trap evidence".to_owned(),
        ..Default::default()
    }];

    package.semantic.hostcall_trace_count = 1;
    package.semantic.roots.hostcall_trace_roots = vec!["hostcall id=1".to_owned()];
    package.semantic.hostcall_trace = vec![artifact_manifest::HostcallTraceManifest {
        id: 1,
        generation: 1,
        activation: 1,
        code_object: 1,
        artifact: 1,
        hostcall_number: 1,
        name: "visa.console.write".to_owned(),
        category: "console".to_owned(),
        object: "visa.console".to_owned(),
        operation: "write".to_owned(),
        allowed: true,
        result: "ok".to_owned(),
        ..Default::default()
    }];
}
