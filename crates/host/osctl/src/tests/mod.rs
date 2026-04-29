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

#[test]
fn store_view_v1_exposes_stable_identity_state_and_references() {
    let view = store_view_v1(&StoreRecordManifest {
        id: 7,
        package: "vfs_service".to_owned(),
        artifact: "vfs_service.cwasm".to_owned(),
        role: "service".to_owned(),
        fault_policy: "restartable".to_owned(),
        fault_domain: 3,
        resource: Some(9),
        state: "running".to_owned(),
        generation: 2,
        restart_count: 1,
    });
    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "store");
    assert_eq!(view["id"], 7);
    assert_eq!(view["generation"], 2);
    assert_eq!(view["references"]["fault_domain"], 3);
}

#[test]
fn capability_view_v1_exposes_object_ref_generation_and_state() {
    let view = capability_view_v1(&CapabilityRecordManifest {
        id: 4,
        subject: "driver".to_owned(),
        object: "packet-device.net0".to_owned(),
        object_ref: Some(AuthorityObjectRefManifest {
            scope: "internal".to_owned(),
            class: "packet-device".to_owned(),
            object: ContractObjectRefManifest {
                kind: "resource".to_owned(),
                id: 99,
                generation: 1,
            },
        }),
        rights: vec!["rx".to_owned()],
        lifetime: "store".to_owned(),
        class: "packet-device".to_owned(),
        owner_store: Some(1),
        owner_store_generation: Some(1),
        owner_task: None,
        source: "manifest".to_owned(),
        generation: 3,
        parent: None,
        manifest_decl: true,
        debug_object_label: "packet-device.net0".to_owned(),
        revoked: false,
    });
    assert_eq!(view["kind"], "capability");
    assert_eq!(view["state"], "active");
    assert_eq!(view["owner"]["store_generation"], 1);
    assert_eq!(view["references"]["object_ref"]["object"]["generation"], 1);
    assert_eq!(view["generation"], 3);
}

#[test]
fn wait_view_v1_exposes_blockers_cancel_reason_and_restart_policy() {
    let view = wait_view_v1(&WaitRecordManifest {
        id: 8,
        owner_task: Some(2),
        owner_task_generation: Some(3),
        owner_store: Some(1),
        owner_store_generation: Some(1),
        kind: "timer".to_owned(),
        generation: 1,
        state: "cancelled".to_owned(),
        blockers: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 4,
            generation: 1,
        }],
        deadline: Some(100),
        cancel_reason: Some("capability-revoked".to_owned()),
        restart_policy: "restart-if-allowed".to_owned(),
        saved_context: Some("ctx".to_owned()),
    });
    assert_eq!(view["kind"], "wait");
    assert_eq!(view["owner"]["task_generation"], 3);
    assert_eq!(view["owner"]["store_generation"], 1);
    assert_eq!(view["references"]["blockers"][0]["kind"], "capability");
    assert_eq!(view["cancel_reason"], "capability-revoked");
    assert_eq!(view["restart_policy"], "restart-if-allowed");
}

#[test]
fn wait_view_v1_exposes_linux_wait_service_convergence_state() {
    let epoll = wait_view_v1(&WaitRecordManifest {
        id: 30_001,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(5),
        owner_store_generation: Some(2),
        kind: "epoll".to_owned(),
        generation: 1,
        state: "pending".to_owned(),
        blockers: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 3,
            generation: 1,
        }],
        deadline: Some(250),
        cancel_reason: None,
        restart_policy: "restart-with-adjusted-timeout".to_owned(),
        saved_context: Some("linux-wait-service:epoll_wait:pending".to_owned()),
    });
    assert_eq!(epoll["kind"], "wait");
    assert_eq!(epoll["kind_name"], "epoll");
    assert_eq!(epoll["state"], "pending");
    assert_eq!(epoll["owner"]["store"], 5);
    assert_eq!(epoll["owner"]["store_generation"], 2);
    assert_eq!(epoll["references"]["blockers"][0]["kind"], "capability");
    assert_eq!(epoll["restart_policy"], "restart-with-adjusted-timeout");
    assert_eq!(epoll["saved_context"], "linux-wait-service:epoll_wait:pending");

    let futex = wait_view_v1(&WaitRecordManifest {
        id: 30_007,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(6),
        owner_store_generation: Some(2),
        kind: "futex".to_owned(),
        generation: 1,
        state: "cancelled".to_owned(),
        blockers: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 4,
            generation: 1,
        }],
        deadline: Some(1_250),
        cancel_reason: Some("timeout".to_owned()),
        restart_policy: "internal-only".to_owned(),
        saved_context: Some("linux-wait-service:futex_wait:timeout-cancel".to_owned()),
    });
    assert_eq!(futex["kind_name"], "futex");
    assert_eq!(futex["state"], "cancelled");
    assert_eq!(futex["cancel_reason"], "timeout");
    assert_eq!(futex["last_error"], "timeout");
    assert_eq!(futex["saved_context"], "linux-wait-service:futex_wait:timeout-cancel");
}

fn b4_core_view_package() -> MigrationPackageManifest {
    let target_store = ContractObjectRefManifest { kind: "store".to_owned(), id: 1, generation: 2 };
    let mut package = minimal_graph_package();
    package.package_id = "b4-core-view-boundary".to_owned();
    package.semantic.store_records.push(StoreRecordManifest {
        id: 1,
        package: "driver_virtio_net".to_owned(),
        artifact: "driver.cwasm".to_owned(),
        role: "driver".to_owned(),
        fault_policy: "restartable".to_owned(),
        fault_domain: 1,
        resource: Some(9),
        state: "running".to_owned(),
        generation: 2,
        restart_count: 1,
    });
    package.semantic.capability_records.push(CapabilityRecordManifest {
        id: 4,
        subject: "driver_virtio_net".to_owned(),
        object: "packet-device.net0".to_owned(),
        object_ref: Some(AuthorityObjectRefManifest {
            scope: "internal".to_owned(),
            class: "packet-device".to_owned(),
            object: ContractObjectRefManifest {
                kind: "resource".to_owned(),
                id: 99,
                generation: 1,
            },
        }),
        rights: vec!["rx".to_owned()],
        lifetime: "store".to_owned(),
        class: "packet-device".to_owned(),
        owner_store: Some(1),
        owner_store_generation: Some(2),
        owner_task: None,
        source: "manifest".to_owned(),
        generation: 1,
        parent: None,
        manifest_decl: true,
        debug_object_label: "packet-device.net0".to_owned(),
        revoked: false,
    });
    package.semantic.wait_records.push(WaitRecordManifest {
        id: 8,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(1),
        owner_store_generation: Some(2),
        kind: "device-irq".to_owned(),
        generation: 1,
        state: "pending".to_owned(),
        blockers: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 4,
            generation: 1,
        }],
        deadline: None,
        cancel_reason: None,
        restart_policy: "restart-if-allowed".to_owned(),
        saved_context: None,
    });
    package.semantic.cleanup_transactions.push(CleanupTransactionManifest {
        id: 5,
        store: 1,
        store_generation: 2,
        target_store_generation: 2,
        result_store_generation: Some(2),
        activation: None,
        activation_generation: None,
        code_object: None,
        code_generation: None,
        generation: 1,
        started_at: 10,
        finished_at: Some(11),
        state: "completed".to_owned(),
        reason: "fault".to_owned(),
        released_dmw_leases: 1,
        cancelled_waits: 1,
        revoked_capabilities: vec![4],
        revoked_capability_refs: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 4,
            generation: 2,
        }],
        dropped_resources: 1,
        unbound_code_object: true,
        state_digest: "store:1@2:dead|code:none|activations=[]|leases=[]|caps=[]".to_owned(),
        effect: "errno".to_owned(),
        steps: vec![CleanupStepManifest {
            step: "mark-store-state".to_owned(),
            state: "done".to_owned(),
            detail: "store marked dead".to_owned(),
            target: Some(target_store.clone()),
            observed_generation: Some(2),
            error: None,
            idempotency_key: "mark-store-state".to_owned(),
            event_seq: 11,
        }],
        effects: vec![CleanupEffectManifest {
            kind: "mark-store-dead".to_owned(),
            target: target_store,
            expected_generation: 2,
            status: "applied".to_owned(),
            event_seq: 11,
        }],
    });
    package.semantic.command_results.push(CommandResultManifest {
        id: 12,
        issuer: "b4-test".to_owned(),
        command: "validate-contract-graph".to_owned(),
        status: "applied".to_owned(),
        events: vec![10, 11],
        effects: Vec::new(),
        violations: Vec::new(),
    });
    package
}

#[test]
fn stable_view_collection_v1_covers_core_object_families() {
    let package = b4_core_view_package();
    for (kind, expected_item_kind) in [
        ("store", "store"),
        ("capability", "capability"),
        ("wait", "wait"),
        ("cleanup", "cleanup"),
        ("command", "command"),
    ] {
        let view =
            stable_view_collection_v1(kind, "list", &package, None).expect("core view collection");
        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["schema_version"], OSCTL_JSON_SCHEMA_VERSION);
        assert_eq!(view["kind"], expected_item_kind);
        assert_eq!(view["command"], format!("{expected_item_kind}.list"));
        assert_eq!(view["package"], "b4-core-view-boundary");
        assert_eq!(view["count"], 1);
        assert_eq!(view["items"][0]["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["items"][0]["kind"], expected_item_kind);
        assert!(view["items"][0]["references"].is_object());
    }

    let selected = stable_view_collection_v1("capability", "show", &package, Some("4"))
        .expect("show selected capability");
    assert_eq!(selected["command"], "capability.show");
    assert_eq!(selected["count"], 1);
    assert_eq!(selected["items"][0]["id"], 4);

    let missing = stable_view_collection_v1("capability", "show", &package, Some("404"))
        .expect_err("missing show id must be a JSON-path error before rendering");
    assert!(missing.to_string().contains("object id 404 not found"));
}

#[test]
fn contract_validation_view_v1_exposes_contract_and_structure_errors_as_json() {
    let mut package = minimal_graph_package();
    package.package_id = "b4-contract-error".to_owned();
    package.semantic.contract_violation_count = 1;
    package.semantic.contract_violations.push(ContractViolationManifest {
        kind: "dangling-edge".to_owned(),
        edge: "store->missing-task".to_owned(),
        from: ContractObjectRefManifest { kind: "store".to_owned(), id: 1, generation: 1 },
        to: Some(ContractObjectRefManifest { kind: "task".to_owned(), id: 9, generation: 1 }),
        detail: "edge references missing target".to_owned(),
    });

    let contract_error = contract_validation_view_v1(&package, None);
    assert_eq!(contract_error["schema"], VIEW_SCHEMA_V1);
    assert_eq!(contract_error["schema_version"], OSCTL_JSON_SCHEMA_VERSION);
    assert_eq!(contract_error["kind"], "contract-validation");
    assert_eq!(contract_error["ok"], false);
    assert_eq!(contract_error["state"], "failed");
    assert_eq!(contract_error["contract"]["violation_count"], 1);
    assert_eq!(contract_error["violations"][0]["code"], "dangling-edge");
    assert_eq!(contract_error["violations"][0]["subject"]["generation"], 1);
    assert_eq!(contract_error["last_error"], "contract-validation-failed");

    let structure_error = contract_validation_view_v1(&package, Some("missing roots"));
    assert_eq!(structure_error["ok"], false);
    assert_eq!(
        structure_error["structure_validation"]["violations"][0]["code"],
        "package-structure"
    );
    assert_eq!(structure_error["violations"][1]["code"], "package-structure");
    assert_eq!(structure_error["last_error"], "missing roots");
}

fn c1_manifest_stub() -> ArtifactBundleManifest {
    ArtifactBundleManifest {
        schema_version: 1,
        artifact_profile: "host-validation".to_owned(),
        runtime_mode: "research".to_owned(),
        contract: artifact_manifest::SupervisorContractManifest {
            contract_version: "vmos-supervisor-contract-v2".to_owned(),
            supervisor_world: "semantic:supervisor".to_owned(),
            catalog_fingerprint: "catalog".to_owned(),
            package_set_fingerprint: "packages".to_owned(),
            module_count: 1,
            required_packages: vec!["console_service".to_owned()],
        },
        target: artifact_manifest::TargetManifest {
            arch: "x86_64".to_owned(),
            machine_abi_version: "vmos-machine-abi-v0".to_owned(),
            supervisor_abi_version: "vmos-supervisor-abi-v0".to_owned(),
            wasm_feature_profile: "wasm32-core-mvp-single-memory".to_owned(),
            memory64: false,
            multi_memory: false,
            dmw_layout: "logical-activation-leases-v0".to_owned(),
            linux_abi_profile: "linux-x86_64-demo-socket-v0".to_owned(),
            artifact_signature_profile: "prototype-self-signed-sha256".to_owned(),
            network_contract_version: "vmos-network-contract-v2".to_owned(),
        },
        compiler: artifact_manifest::CompilerManifest {
            engine: "wasmtime".to_owned(),
            engine_version: "43.0.1".to_owned(),
            execution_mode: "precompiled-core-module".to_owned(),
            artifact_format: "target-artifact-image-v1".to_owned(),
            target_artifact_format: "target-artifact-image-v1".to_owned(),
            runtime_executor_abi: "vmos-runtime-only-executor-v0".to_owned(),
        },
        modules: vec![artifact_manifest::ModuleArtifactManifest {
            package: "console_service".to_owned(),
            artifact_name: "driver_console".to_owned(),
            role: "driver".to_owned(),
            fault_policy: "restartable".to_owned(),
            wasm_path: "target/test/console_service.wasm".to_owned(),
            cwasm_path: "target/test/console_service.cwasm".to_owned(),
            target_artifact_path: "target/test/console_service.tart".to_owned(),
            wasm_sha256: "wasm-hash".to_owned(),
            cwasm_sha256: "code-hash".to_owned(),
            target_artifact_sha256: "artifact-hash".to_owned(),
            code_payload_format: "cwasm".to_owned(),
            expected_exports: vec!["memory".to_owned()],
            exports: Vec::new(),
            imports: Vec::new(),
            capabilities: vec![artifact_manifest::CapabilityManifest {
                name: "console.write".to_owned(),
                rights: vec!["write".to_owned()],
                lifetime: "activation".to_owned(),
            }],
            abi_fingerprint: "abi".to_owned(),
            service_dependencies: Vec::new(),
            resource_limits: artifact_manifest::ResourceLimitsManifest {
                max_memory_pages: 16,
                max_table_elements: 0,
                max_hostcalls_per_activation: 64,
            },
            interfaces: artifact_manifest::InterfaceRequirementManifest::default(),
            signature: artifact_manifest::SignatureManifest {
                scheme: "prototype-self-signed-sha256".to_owned(),
                artifact_hash: "artifact-hash".to_owned(),
                manifest_binding_hash: "binding".to_owned(),
                signer: "vmos-aotc-dev".to_owned(),
                public_key_hint: "prototype-dev-key".to_owned(),
                signature: "unsigned-prototype-signature".to_owned(),
            },
        }],
    }
}

fn c1_plan_stub() -> ValidatedArtifactPlan {
    ValidatedArtifactPlan {
        artifact_profile: "host-validation".to_owned(),
        runtime_mode: "research".to_owned(),
        contract_version: "vmos-supervisor-contract-v2".to_owned(),
        supervisor_world: "semantic:supervisor".to_owned(),
        target_arch: "x86_64".to_owned(),
        compiler_engine: "wasmtime".to_owned(),
        compiler_execution_mode: "precompiled-core-module".to_owned(),
        artifact_format: "target-artifact-image-v1".to_owned(),
        target_artifact_format: "target-artifact-image-v1".to_owned(),
        runtime_executor_abi: "vmos-runtime-only-executor-v0".to_owned(),
        modules: vec![ValidatedArtifactEntry {
            package: "console_service".to_owned(),
            artifact_name: "driver_console".to_owned(),
            role: "driver".to_owned(),
            fault_policy: "restartable".to_owned(),
            wasm_path: "target/test/console_service.wasm".to_owned(),
            cwasm_path: "target/test/console_service.cwasm".to_owned(),
            target_artifact_path: "target/test/console_service.tart".to_owned(),
            wasm_sha256: "wasm-hash".to_owned(),
            cwasm_sha256: "code-hash".to_owned(),
            target_artifact_sha256: "artifact-hash".to_owned(),
            code_payload_format: "cwasm".to_owned(),
            expected_exports: vec!["memory".to_owned()],
            capabilities: vec![artifact_manifest::CapabilityManifest {
                name: "console.write".to_owned(),
                rights: vec!["write".to_owned()],
                lifetime: "activation".to_owned(),
            }],
            abi_fingerprint: "abi".to_owned(),
            service_dependencies: Vec::new(),
            resource_limits: artifact_manifest::ResourceLimitsManifest {
                max_memory_pages: 16,
                max_table_elements: 0,
                max_hostcalls_per_activation: 64,
            },
            interfaces: artifact_manifest::InterfaceRequirementManifest::default(),
            signature_scheme: "prototype-self-signed-sha256".to_owned(),
            signer: "vmos-aotc-dev".to_owned(),
            manifest_binding_hash: "binding".to_owned(),
            hash_status: contract_core::ARTIFACT_HASH_STATUS_MANIFEST_BOUND.to_owned(),
            signature_status: contract_core::ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED
                .to_owned(),
            signature_verified: contract_core::ARTIFACT_SIGNATURE_VERIFIED_DEFAULT,
        }],
    }
}

#[test]
fn artifact_plan_view_v1_exposes_acceptance_and_rejection_policy_status() {
    let manifest = c1_manifest_stub();
    let plan = c1_plan_stub();
    let accepted = artifact_plan_view_v1(&manifest, Some(&plan), None);

    assert_eq!(accepted["schema"], VIEW_SCHEMA_V1);
    assert_eq!(accepted["schema_version"], OSCTL_JSON_SCHEMA_VERSION);
    assert_eq!(accepted["kind"], "artifact-plan");
    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["state"], "accepted");
    assert_eq!(accepted["package_roots"][0], "console_service");
    assert_eq!(accepted["target_profile"]["artifact_profile"], "host-validation");
    assert_eq!(
        accepted["modules"][0]["artifact_manifest"]["target_artifact_sha256"],
        "artifact-hash"
    );
    assert_eq!(accepted["modules"][0]["capability_manifest"][0]["name"], "console.write");
    assert_eq!(
        accepted["modules"][0]["target_profile"]["hash_status"],
        contract_core::ARTIFACT_HASH_STATUS_MANIFEST_BOUND
    );
    assert_eq!(
        accepted["modules"][0]["target_profile"]["signature_status"],
        contract_core::ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED
    );
    assert_eq!(accepted["modules"][0]["target_profile"]["signature_verified"], false);
    assert_eq!(accepted["last_error"], serde_json::Value::Null);

    let rejected =
        artifact_plan_view_v1(&manifest, None, Some("console_service target hash mismatch"));
    assert_eq!(rejected["accepted"], false);
    assert_eq!(rejected["state"], "rejected");
    assert_eq!(rejected["modules"][0]["target_profile"]["hash_status"], "rejected");
    assert_eq!(rejected["modules"][0]["target_profile"]["signature_status"], "rejected");
    assert_eq!(rejected["last_error"], "console_service target hash mismatch");
}

#[test]
fn io_cleanup_view_v1_exposes_steps_effects_and_generations() {
    let view = io_cleanup_view_v1(&IoCleanupManifest {
        id: 47,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 1,
        generation: 1,
        state: "completed".to_owned(),
        reason: "device-fault".to_owned(),
        started_at_event: 51,
        completed_at_event: 57,
        cancelled_io_waits: vec![ContractObjectRefManifest {
            kind: "io-wait".to_owned(),
            id: 46,
            generation: 1,
        }],
        revoked_device_capabilities: vec![ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 42,
            generation: 1,
        }],
        revoked_capabilities: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 7,
            generation: 1,
        }],
        released_dma_buffers: vec![ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 38,
            generation: 1,
        }],
        released_mmio_regions: vec![ContractObjectRefManifest {
            kind: "mmio-region-object".to_owned(),
            id: 39,
            generation: 1,
        }],
        released_irq_lines: vec![ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 40,
            generation: 1,
        }],
        steps: vec![artifact_manifest::IoCleanupStepManifest {
            kind: "cancel-io-waits".to_owned(),
            target: ContractObjectRefManifest { kind: "store".to_owned(), id: 1, generation: 2 },
            observed_generation: 2,
            status: "done".to_owned(),
            event: Some(52),
        }],
        note: "io cleanup".to_owned(),
    });
    assert_eq!(view["kind"], "io-cleanup");
    assert_eq!(view["owner"]["driver_store"]["generation"], 2);
    assert_eq!(view["references"]["cancelled_io_waits"][0]["kind"], "io-wait");
    assert_eq!(view["references"]["released_dma_buffers"][0]["generation"], 1);
    assert_eq!(view["steps"][0]["kind"], "cancel-io-waits");
    assert_eq!(view["last_transition"]["completed_at_event"], 57);
}

#[test]
fn io_fault_injection_view_v1_exposes_target_cleanup_and_generations() {
    let view = io_fault_injection_view_v1(&IoFaultInjectionManifest {
        id: 48,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 1,
        target: ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 40,
            generation: 1,
        },
        cleanup: 47,
        cleanup_generation: 1,
        generation: 1,
        kind: "device-fault".to_owned(),
        state: "completed".to_owned(),
        injected_at_event: 58,
        note: "io fault".to_owned(),
    });
    assert_eq!(view["kind"], "io-fault-injection");
    assert_eq!(view["owner"]["driver_store"]["generation"], 2);
    assert_eq!(view["references"]["target"]["kind"], "irq-line-object");
    assert_eq!(view["references"]["cleanup"]["id"], 47);
    assert_eq!(view["fault"]["kind"], "device-fault");
    assert_eq!(view["last_transition"]["injected_at_event"], 58);
}

#[test]
fn io_validation_report_view_v1_exposes_counts_and_violations() {
    let view = io_validation_report_view_v1(&IoValidationReportManifest {
        id: 49,
        generation: 1,
        state: "failed".to_owned(),
        validated_at_event: 59,
        event_log_cursor: 58,
        observed_device_count: 1,
        observed_queue_count: 1,
        observed_descriptor_count: 1,
        observed_dma_buffer_count: 1,
        observed_mmio_region_count: 1,
        observed_irq_line_count: 1,
        observed_irq_event_count: 1,
        observed_device_capability_count: 1,
        observed_driver_binding_count: 1,
        observed_io_wait_count: 1,
        observed_io_cleanup_count: 1,
        observed_io_fault_injection_count: 1,
        violation_count: 1,
        violations: vec![artifact_manifest::IoValidationViolationManifest {
            code: "stale-generation".to_owned(),
            subject: ContractObjectRefManifest {
                kind: "io-wait".to_owned(),
                id: 41,
                generation: 1,
            },
            relation: "io-wait->driver-binding".to_owned(),
            message: "bad generation".to_owned(),
        }],
        note: "io validator".to_owned(),
    });
    assert_eq!(view["kind"], "io-validation-report");
    assert_eq!(view["observed"]["devices"], 1);
    assert_eq!(view["observed"]["io_fault_injections"], 1);
    assert_eq!(view["validation"]["ok"], false);
    assert_eq!(view["validation"]["violation_count"], 1);
    assert_eq!(view["validation"]["violations"][0]["subject"]["kind"], "io-wait");
    assert_eq!(view["last_transition"]["validated_at_event"], 59);
}

#[test]
fn packet_device_view_v1_exposes_contract_and_device_generation() {
    let view = packet_device_object_view_v1(&PacketDeviceObjectManifest {
        id: 51,
        name: "net0".to_owned(),
        device: 17,
        device_generation: 2,
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        frame_format_version: 2,
        max_payload_len: 512,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 60,
        note: "packet device".to_owned(),
    });
    assert_eq!(view["kind"], "packet-device");
    assert_eq!(view["owner"]["device"]["kind"], "device");
    assert_eq!(view["owner"]["device"]["generation"], 2);
    assert_eq!(view["contract"]["mtu"], 1500);
    assert_eq!(view["contract"]["rx_queue_depth"], 4);
    assert_eq!(view["contract"]["max_payload_len"], 512);
    assert_eq!(view["identity"]["mac"][5], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 60);
}

#[test]
fn packet_buffer_view_v1_exposes_contract_and_packet_device_generation() {
    let view = packet_buffer_object_view_v1(&PacketBufferObjectManifest {
        id: 52,
        packet_device: 51,
        packet_device_generation: 3,
        direction: "rx".to_owned(),
        frame_format_version: 2,
        capacity: 512,
        payload_len: 64,
        sequence: 9,
        generation: 1,
        state: "filled".to_owned(),
        recorded_at_event: 61,
        note: "packet buffer".to_owned(),
    });
    assert_eq!(view["kind"], "packet-buffer");
    assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
    assert_eq!(view["owner"]["packet_device"]["generation"], 3);
    assert_eq!(view["contract"]["direction"], "rx");
    assert_eq!(view["contract"]["capacity"], 512);
    assert_eq!(view["contract"]["payload_len"], 64);
    assert_eq!(view["contract"]["sequence"], 9);
    assert_eq!(view["last_transition"]["recorded_at_event"], 61);
}

#[test]
fn packet_queue_view_v1_exposes_role_depth_and_packet_device_generation() {
    let view = packet_queue_object_view_v1(&PacketQueueObjectManifest {
        id: 53,
        name: "net0-rx0".to_owned(),
        packet_device: 51,
        packet_device_generation: 3,
        role: "rx".to_owned(),
        queue_index: 0,
        depth: 4,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 62,
        note: "packet queue".to_owned(),
    });
    assert_eq!(view["kind"], "packet-queue");
    assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
    assert_eq!(view["owner"]["packet_device"]["generation"], 3);
    assert_eq!(view["identity"]["name"], "net0-rx0");
    assert_eq!(view["identity"]["role"], "rx");
    assert_eq!(view["identity"]["queue_index"], 0);
    assert_eq!(view["contract"]["depth"], 4);
    assert_eq!(view["last_transition"]["recorded_at_event"], 62);
}

#[test]
fn packet_descriptor_view_v1_exposes_queue_buffer_and_length() {
    let view = packet_descriptor_object_view_v1(&PacketDescriptorObjectManifest {
        id: 54,
        packet_queue: 53,
        packet_queue_generation: 2,
        packet_buffer: 52,
        packet_buffer_generation: 3,
        slot: 1,
        length: 64,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 63,
        note: "packet descriptor".to_owned(),
    });
    assert_eq!(view["kind"], "packet-descriptor");
    assert_eq!(view["owner"]["packet_queue"]["kind"], "packet-queue");
    assert_eq!(view["owner"]["packet_queue"]["generation"], 2);
    assert_eq!(view["owner"]["packet_buffer"]["kind"], "packet-buffer");
    assert_eq!(view["owner"]["packet_buffer"]["generation"], 3);
    assert_eq!(view["identity"]["slot"], 1);
    assert_eq!(view["contract"]["length"], 64);
    assert_eq!(view["last_transition"]["recorded_at_event"], 63);
}

#[test]
fn fake_net_backend_view_v1_exposes_packet_device_and_profile_contract() {
    let view = fake_net_backend_object_view_v1(&FakeNetBackendObjectManifest {
        id: 55,
        name: "fake-net0".to_owned(),
        packet_device: 51,
        packet_device_generation: 4,
        provider: "service_core".to_owned(),
        profile: "fake-net-v1".to_owned(),
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        frame_format_version: 2,
        max_payload_len: 512,
        deterministic_seed: 7,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 64,
        note: "fake backend".to_owned(),
    });
    assert_eq!(view["kind"], "fake-net-backend");
    assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
    assert_eq!(view["owner"]["packet_device"]["generation"], 4);
    assert_eq!(view["identity"]["provider"], "service_core");
    assert_eq!(view["identity"]["profile"], "fake-net-v1");
    assert_eq!(view["contract"]["mtu"], 1500);
    assert_eq!(view["contract"]["mac"][5], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 64);
}

#[test]
fn virtio_net_backend_view_v1_exposes_driver_binding_and_profile_contract() {
    let view = virtio_net_backend_object_view_v1(&VirtioNetBackendObjectManifest {
        id: 56,
        name: "virtio-net0-backend".to_owned(),
        packet_device: 51,
        packet_device_generation: 4,
        driver_binding: 57,
        driver_binding_generation: 2,
        device: 50,
        device_generation: 4,
        provider: "substrate_virtio".to_owned(),
        profile: "virtio-net-backend-skeleton-v1".to_owned(),
        model: "virtio-net".to_owned(),
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        frame_format_version: 2,
        max_payload_len: 512,
        device_features: 32,
        driver_features: 32,
        negotiated_features: 32,
        rx_queue_index: 0,
        tx_queue_index: 1,
        queue_size: 4,
        irq_vector: 5,
        generation: 1,
        state: "skeleton-ready".to_owned(),
        recorded_at_event: 65,
        note: "virtio backend".to_owned(),
    });
    assert_eq!(view["kind"], "virtio-net-backend");
    assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
    assert_eq!(view["owner"]["driver_binding"]["kind"], "driver-store-binding");
    assert_eq!(view["owner"]["driver_binding"]["generation"], 2);
    assert_eq!(view["identity"]["provider"], "substrate_virtio");
    assert_eq!(view["identity"]["profile"], "virtio-net-backend-skeleton-v1");
    assert_eq!(view["contract"]["negotiated_features"], 32);
    assert_eq!(view["contract"]["queue_size"], 4);
    assert_eq!(view["last_transition"]["recorded_at_event"], 65);
}

#[test]
fn network_rx_interrupt_view_v1_exposes_irq_and_rx_queue_generations() {
    let view = network_rx_interrupt_view_v1(&NetworkRxInterruptManifest {
        id: 58,
        virtio_net_backend: 56,
        virtio_net_backend_generation: 1,
        irq_event: 59,
        irq_event_generation: 2,
        packet_device: 51,
        packet_device_generation: 4,
        rx_queue: 53,
        rx_queue_generation: 3,
        ready_descriptors: 1,
        sequence: 9,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 66,
        note: "rx interrupt".to_owned(),
    });
    assert_eq!(view["kind"], "network-rx-interrupt");
    assert_eq!(view["owner"]["virtio_net_backend"]["kind"], "virtio-net-backend");
    assert_eq!(view["owner"]["packet_device"]["generation"], 4);
    assert_eq!(view["references"]["irq_event"]["kind"], "irq-event");
    assert_eq!(view["references"]["irq_event"]["generation"], 2);
    assert_eq!(view["references"]["rx_queue"]["generation"], 3);
    assert_eq!(view["readiness"]["ready_descriptors"], 1);
    assert_eq!(view["readiness"]["sequence"], 9);
    assert_eq!(view["last_transition"]["recorded_at_event"], 66);
}

#[test]
fn network_rx_wait_resolution_view_v1_exposes_wait_and_interrupt_generations() {
    let view = network_rx_wait_resolution_view_v1(&NetworkRxWaitResolutionManifest {
        id: 60,
        io_wait: 61,
        io_wait_generation: 2,
        wait: 62,
        wait_generation: 3,
        rx_interrupt: 58,
        rx_interrupt_generation: 1,
        irq_event: 59,
        irq_event_generation: 2,
        packet_device: 51,
        packet_device_generation: 4,
        rx_queue: 53,
        rx_queue_generation: 3,
        ready_descriptors: 1,
        sequence: 9,
        generation: 1,
        state: "resolved".to_owned(),
        resolved_at_event: 67,
        note: "rx wait resolution".to_owned(),
    });
    assert_eq!(view["kind"], "network-rx-wait-resolution");
    assert_eq!(view["owner"]["io_wait"]["kind"], "io-wait");
    assert_eq!(view["owner"]["io_wait"]["generation"], 2);
    assert_eq!(view["references"]["wait"]["kind"], "wait-token");
    assert_eq!(view["references"]["wait"]["generation"], 3);
    assert_eq!(view["references"]["rx_interrupt"]["kind"], "network-rx-interrupt");
    assert_eq!(view["references"]["rx_queue"]["generation"], 3);
    assert_eq!(view["readiness"]["sequence"], 9);
    assert_eq!(view["last_transition"]["resolved_at_event"], 67);
}

#[test]
fn network_tx_capability_gate_view_v1_exposes_capability_and_descriptor_generations() {
    let view = network_tx_capability_gate_view_v1(&NetworkTxCapabilityGateManifest {
        id: 68,
        driver_store: 7,
        driver_store_generation: 2,
        packet_device: 51,
        packet_device_generation: 4,
        tx_queue: 53,
        tx_queue_generation: 3,
        packet_descriptor: 54,
        packet_descriptor_generation: 2,
        packet_buffer: 52,
        packet_buffer_generation: 3,
        device_capability: 69,
        device_capability_generation: 1,
        capability: 70,
        capability_generation: 5,
        handle_slot: 4,
        handle_generation: 5,
        handle_tag: 99,
        operation: "tx".to_owned(),
        byte_len: 64,
        sequence: 9,
        generation: 1,
        state: "allowed".to_owned(),
        recorded_at_event: 68,
        note: "tx gate".to_owned(),
    });
    assert_eq!(view["kind"], "network-tx-capability-gate");
    assert_eq!(view["owner"]["driver_store"]["kind"], "store");
    assert_eq!(view["owner"]["driver_store"]["generation"], 2);
    assert_eq!(view["references"]["packet_descriptor"]["kind"], "packet-descriptor");
    assert_eq!(view["references"]["packet_descriptor"]["generation"], 2);
    assert_eq!(view["references"]["device_capability"]["kind"], "device-capability");
    assert_eq!(view["references"]["capability"]["generation"], 5);
    assert_eq!(view["authority"]["operation"], "tx");
    assert_eq!(view["authority"]["handle_slot"], 4);
    assert_eq!(view["tx"]["byte_len"], 64);
    assert_eq!(view["last_transition"]["recorded_at_event"], 68);
}

#[test]
fn network_tx_completion_view_v1_exposes_gate_backend_and_descriptor_generations() {
    let view = network_tx_completion_view_v1(&NetworkTxCompletionManifest {
        id: 71,
        tx_gate: 68,
        tx_gate_generation: 2,
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 72,
        backend_generation: 3,
        driver_store: 7,
        driver_store_generation: 4,
        packet_device: 51,
        packet_device_generation: 5,
        tx_queue: 53,
        tx_queue_generation: 6,
        packet_descriptor: 54,
        packet_descriptor_generation: 7,
        packet_buffer: 52,
        packet_buffer_generation: 8,
        byte_len: 64,
        sequence: 9,
        completion_sequence: 10,
        generation: 1,
        state: "completed".to_owned(),
        completed_at_event: 73,
        note: "tx completion".to_owned(),
    });
    assert_eq!(view["kind"], "network-tx-completion");
    assert_eq!(view["owner"]["backend"]["kind"], "virtio-net-backend");
    assert_eq!(view["owner"]["backend"]["generation"], 3);
    assert_eq!(view["references"]["tx_gate"]["kind"], "network-tx-capability-gate");
    assert_eq!(view["references"]["tx_gate"]["generation"], 2);
    assert_eq!(view["references"]["packet_descriptor"]["kind"], "packet-descriptor");
    assert_eq!(view["references"]["packet_descriptor"]["generation"], 7);
    assert_eq!(view["references"]["packet_buffer"]["generation"], 8);
    assert_eq!(view["tx"]["completion_sequence"], 10);
    assert_eq!(view["last_transition"]["completed_at_event"], 73);
}

#[test]
fn network_stack_adapter_view_v1_exposes_smoltcp_profile_and_queue_generations() {
    let view = network_stack_adapter_view_v1(&NetworkStackAdapterManifest {
        id: 74,
        implementation: "smoltcp".to_owned(),
        implementation_version: "0.13.0".to_owned(),
        profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_owned(),
        medium: "ethernet".to_owned(),
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 72,
        backend_generation: 3,
        packet_device: 51,
        packet_device_generation: 5,
        rx_queue: 53,
        rx_queue_generation: 6,
        tx_queue: 54,
        tx_queue_generation: 7,
        mac: [2, 0x76, 0x6d, 0x6f, 0x73, 1],
        ipv4_addr: [10, 0, 2, 15],
        ipv4_prefix_len: 24,
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        max_payload_len: 512,
        socket_capacity: 0,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 75,
        note: "smoltcp adapter".to_owned(),
    });
    assert_eq!(view["kind"], "network-stack-adapter");
    assert_eq!(view["owner"]["backend"]["kind"], "virtio-net-backend");
    assert_eq!(view["owner"]["backend"]["generation"], 3);
    assert_eq!(view["references"]["packet_device"]["generation"], 5);
    assert_eq!(view["references"]["rx_queue"]["generation"], 6);
    assert_eq!(view["references"]["tx_queue"]["generation"], 7);
    assert_eq!(view["adapter"]["implementation"], "smoltcp");
    assert_eq!(view["adapter"]["socket_capacity"], 0);
    assert_eq!(view["network"]["ipv4_prefix_len"], 24);
    assert_eq!(view["last_transition"]["recorded_at_event"], 75);
}

#[test]
fn socket_object_view_v1_exposes_adapter_store_and_socket_contract() {
    let view = socket_object_view_v1(&SocketObjectManifest {
        id: 76,
        adapter: 74,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 3,
        domain: 2,
        socket_type: 1,
        protocol: 0,
        canonical_protocol: 6,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        generation: 1,
        state: "created".to_owned(),
        created_at_event: 77,
        note: "socket object".to_owned(),
    });
    assert_eq!(view["kind"], "socket-object");
    assert_eq!(view["owner"]["store"]["kind"], "store");
    assert_eq!(view["owner"]["store"]["generation"], 3);
    assert_eq!(view["references"]["adapter"]["kind"], "network-stack-adapter");
    assert_eq!(view["references"]["adapter"]["generation"], 1);
    assert_eq!(view["socket"]["domain"], 2);
    assert_eq!(view["socket"]["type"], 1);
    assert_eq!(view["socket"]["canonical_protocol"], 6);
    assert_eq!(view["socket"]["family"], "inet");
    assert_eq!(view["socket"]["transport"], "tcp");
    assert_eq!(view["last_transition"]["created_at_event"], 77);
}

#[test]
fn endpoint_object_view_v1_exposes_socket_store_and_endpoint_contract() {
    let view = endpoint_object_view_v1(&EndpointObjectManifest {
        id: 78,
        socket: 76,
        socket_generation: 1,
        adapter: 74,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 3,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        local_addr: [0, 0, 0, 0],
        local_port: 0,
        remote_addr: [0, 0, 0, 0],
        remote_port: 0,
        generation: 1,
        state: "allocated".to_owned(),
        created_at_event: 79,
        note: "endpoint object".to_owned(),
    });
    assert_eq!(view["kind"], "endpoint-object");
    assert_eq!(view["owner"]["store"]["kind"], "store");
    assert_eq!(view["owner"]["store"]["generation"], 3);
    assert_eq!(view["owner"]["socket"]["kind"], "socket-object");
    assert_eq!(view["references"]["socket"]["generation"], 1);
    assert_eq!(view["references"]["adapter"]["kind"], "network-stack-adapter");
    assert_eq!(view["endpoint"]["family"], "inet");
    assert_eq!(view["endpoint"]["transport"], "tcp");
    assert_eq!(view["endpoint"]["local_port"], 0);
    assert_eq!(view["endpoint"]["remote_port"], 0);
    assert_eq!(view["last_transition"]["created_at_event"], 79);
}

#[test]
fn socket_operation_view_v1_exposes_endpoint_operation_and_generations() {
    let view = socket_operation_view_v1(&SocketOperationManifest {
        id: 80,
        endpoint: 78,
        endpoint_generation: 1,
        socket: 76,
        socket_generation: 2,
        adapter: 74,
        adapter_generation: 3,
        owner_store: 7,
        owner_store_generation: 4,
        operation: "connect".to_owned(),
        local_addr: [10, 0, 2, 15],
        local_port: 40000,
        remote_addr: [10, 0, 2, 2],
        remote_port: 80,
        backlog: 0,
        byte_len: 0,
        sequence: 2,
        generation: 1,
        state: "applied".to_owned(),
        recorded_at_event: 81,
        note: "socket operation".to_owned(),
    });
    assert_eq!(view["kind"], "socket-operation");
    assert_eq!(view["owner"]["endpoint"]["kind"], "endpoint-object");
    assert_eq!(view["owner"]["endpoint"]["generation"], 1);
    assert_eq!(view["references"]["socket"]["kind"], "socket-object");
    assert_eq!(view["references"]["socket"]["generation"], 2);
    assert_eq!(view["references"]["adapter"]["generation"], 3);
    assert_eq!(view["references"]["owner_store"]["generation"], 4);
    assert_eq!(view["operation"]["name"], "connect");
    assert_eq!(view["operation"]["sequence"], 2);
    assert_eq!(view["operation"]["local_port"], 40000);
    assert_eq!(view["operation"]["remote_port"], 80);
    assert_eq!(view["last_transition"]["recorded_at_event"], 81);
}

#[test]
fn socket_wait_view_v1_exposes_wait_endpoint_and_readiness_generations() {
    let view = socket_wait_view_v1(&SocketWaitManifest {
        id: 82,
        wait: 900,
        wait_generation: 2,
        endpoint: 78,
        endpoint_generation: 3,
        socket: 76,
        socket_generation: 4,
        adapter: 74,
        adapter_generation: 5,
        owner_store: 7,
        owner_store_generation: 6,
        wait_kind: "socket-readable".to_owned(),
        blocker: ContractObjectRefManifest {
            kind: "endpoint-object".to_owned(),
            id: 78,
            generation: 3,
        },
        generation: 1,
        state: "resolved".to_owned(),
        created_at_event: 83,
        completed_at_event: Some(84),
        cancel_reason: None,
        ready_sequence: Some(9),
        byte_len: Some(19),
        note: "socket wait".to_owned(),
    });
    assert_eq!(view["kind"], "socket-wait");
    assert_eq!(view["owner"]["wait"]["kind"], "wait-token");
    assert_eq!(view["owner"]["wait"]["generation"], 2);
    assert_eq!(view["owner"]["endpoint"]["kind"], "endpoint-object");
    assert_eq!(view["owner"]["endpoint"]["generation"], 3);
    assert_eq!(view["references"]["socket"]["generation"], 4);
    assert_eq!(view["references"]["adapter"]["generation"], 5);
    assert_eq!(view["references"]["owner_store"]["generation"], 6);
    assert_eq!(view["references"]["blocker"]["kind"], "endpoint-object");
    assert_eq!(view["wait"]["kind"], "socket-readable");
    assert_eq!(view["wait"]["ready_sequence"], 9);
    assert_eq!(view["wait"]["byte_len"], 19);
    assert_eq!(view["last_transition"]["completed_at_event"], 84);
}

#[test]
fn network_backpressure_view_v1_exposes_policy_refs_and_drops() {
    let view = network_backpressure_view_v1(&NetworkBackpressureManifest {
        id: 85,
        adapter: 74,
        adapter_generation: 5,
        packet_device: 51,
        packet_device_generation: 6,
        packet_queue: 53,
        packet_queue_generation: 7,
        endpoint: Some(76),
        endpoint_generation: Some(8),
        socket: Some(75),
        socket_generation: Some(9),
        owner_store: Some(7),
        owner_store_generation: Some(10),
        direction: "tx".to_owned(),
        reason: "queue-full".to_owned(),
        action: "reject-send".to_owned(),
        queue_depth: 4,
        queue_limit: 4,
        dropped_packets: 0,
        dropped_bytes: 0,
        sequence: 11,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 86,
        note: "backpressure".to_owned(),
    });
    assert_eq!(view["kind"], "network-backpressure");
    assert_eq!(view["owner"]["adapter"]["kind"], "network-stack-adapter");
    assert_eq!(view["owner"]["adapter"]["generation"], 5);
    assert_eq!(view["references"]["packet_queue"]["generation"], 7);
    assert_eq!(view["references"]["endpoint"]["kind"], "endpoint-object");
    assert_eq!(view["references"]["socket"]["generation"], 9);
    assert_eq!(view["references"]["owner_store"]["generation"], 10);
    assert_eq!(view["policy"]["direction"], "tx");
    assert_eq!(view["policy"]["reason"], "queue-full");
    assert_eq!(view["policy"]["action"], "reject-send");
    assert_eq!(view["policy"]["queue_depth"], 4);
    assert_eq!(view["policy"]["dropped_packets"], 0);
    assert_eq!(view["last_transition"]["recorded_at_event"], 86);
}

#[test]
fn network_driver_cleanup_view_v1_exposes_cleanup_effects_and_generations() {
    let view = network_driver_cleanup_view_v1(&NetworkDriverCleanupManifest {
        id: 87,
        io_cleanup: 70,
        io_cleanup_generation: 1,
        driver_store: 7,
        driver_store_generation: 3,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 2,
        packet_device: 51,
        packet_device_generation: 4,
        adapter: 74,
        adapter_generation: 5,
        backend: ContractObjectRefManifest {
            kind: "virtio-net-backend-object".to_owned(),
            id: 85,
            generation: 6,
        },
        cancelled_socket_waits: vec![ContractObjectRefManifest {
            kind: "socket-wait".to_owned(),
            id: 90,
            generation: 1,
        }],
        cancelled_wait_tokens: vec![ContractObjectRefManifest {
            kind: "wait-token".to_owned(),
            id: 91,
            generation: 1,
        }],
        revoked_packet_capabilities: vec![ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 92,
            generation: 1,
        }],
        generation: 1,
        state: "completed".to_owned(),
        started_at_event: 88,
        completed_at_event: Some(89),
        reason: "device-fault".to_owned(),
        note: "network cleanup".to_owned(),
    });
    assert_eq!(view["kind"], "network-driver-cleanup");
    assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
    assert_eq!(view["owner"]["packet_device"]["generation"], 4);
    assert_eq!(view["references"]["io_cleanup"]["kind"], "io-cleanup");
    assert_eq!(view["references"]["driver_binding"]["generation"], 2);
    assert_eq!(view["references"]["backend"]["kind"], "virtio-net-backend-object");
    assert_eq!(view["references"]["cancelled_socket_waits"][0]["id"], 90);
    assert_eq!(view["references"]["cancelled_wait_tokens"][0]["id"], 91);
    assert_eq!(view["references"]["revoked_packet_capabilities"][0]["id"], 92);
    assert_eq!(view["cleanup"]["reason"], "device-fault");
    assert_eq!(view["cleanup"]["cancelled_socket_wait_count"], 1);
    assert_eq!(view["last_transition"]["completed_at_event"], 89);
}

#[test]
fn network_generation_audit_view_v1_exposes_exact_generation_refs() {
    let view = network_generation_audit_view_v1(&NetworkGenerationAuditManifest {
        id: 93,
        adapter: 74,
        adapter_generation: 5,
        packet_device: 51,
        packet_device_generation: 4,
        packet_queue: 89,
        packet_queue_generation: 7,
        packet_descriptor: 90,
        packet_descriptor_generation: 8,
        packet_buffer: 91,
        packet_buffer_generation: 9,
        dma_buffer: ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 92,
            generation: 10,
        },
        device_capability: ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 94,
            generation: 11,
        },
        rejected_packet_generation_probes: 2,
        rejected_dma_generation_probes: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 95,
        note: "generation audit".to_owned(),
    });
    assert_eq!(view["kind"], "network-generation-audit");
    assert_eq!(view["owner"]["adapter"]["kind"], "network-stack-adapter");
    assert_eq!(view["owner"]["adapter"]["generation"], 5);
    assert_eq!(view["references"]["packet_descriptor"]["generation"], 8);
    assert_eq!(view["references"]["packet_buffer"]["generation"], 9);
    assert_eq!(view["references"]["dma_buffer"]["kind"], "dma-buffer-object");
    assert_eq!(view["references"]["dma_buffer"]["generation"], 10);
    assert_eq!(view["references"]["device_capability"]["kind"], "device-capability");
    assert_eq!(view["audit"]["rejected_packet_generation_probes"], 2);
    assert_eq!(view["audit"]["rejected_dma_generation_probes"], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 95);
}

#[test]
fn network_fault_injection_view_v1_exposes_packet_loss_and_error_evidence() {
    let view = network_fault_injection_view_v1(&NetworkFaultInjectionManifest {
        id: 96,
        adapter: 74,
        adapter_generation: 5,
        packet_device: 51,
        packet_device_generation: 4,
        packet_queue: 89,
        packet_queue_generation: 7,
        packet_descriptor: Some(90),
        packet_descriptor_generation: Some(8),
        packet_buffer: Some(91),
        packet_buffer_generation: Some(9),
        endpoint: Some(92),
        endpoint_generation: Some(10),
        socket: Some(93),
        socket_generation: Some(11),
        owner_store: Some(94),
        owner_store_generation: Some(12),
        direction: "tx".to_owned(),
        kind: "packet-error".to_owned(),
        effect: "report-error".to_owned(),
        injected_packets: 1,
        dropped_packets: 0,
        error_packets: 1,
        error_code: "injected-checksum-error".to_owned(),
        sequence: 18,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 97,
        note: "packet error injection".to_owned(),
    });
    assert_eq!(view["kind"], "network-fault-injection");
    assert_eq!(view["owner"]["adapter"]["kind"], "network-stack-adapter");
    assert_eq!(view["references"]["packet_queue"]["generation"], 7);
    assert_eq!(view["references"]["packet_descriptor"]["generation"], 8);
    assert_eq!(view["references"]["packet_buffer"]["generation"], 9);
    assert_eq!(view["references"]["endpoint"]["generation"], 10);
    assert_eq!(view["injection"]["kind"], "packet-error");
    assert_eq!(view["injection"]["effect"], "report-error");
    assert_eq!(view["injection"]["error_code"], "injected-checksum-error");
    assert_eq!(view["last_transition"]["recorded_at_event"], 97);
}

#[test]
fn network_benchmark_view_v1_exposes_throughput_latency_metrics() {
    let view = network_benchmark_view_v1(&NetworkBenchmarkManifest {
        id: 98,
        scenario: "host-validation-network-throughput-latency".to_owned(),
        adapter: 74,
        adapter_generation: 5,
        packet_device: 51,
        packet_device_generation: 4,
        tx_queue: 89,
        tx_queue_generation: 7,
        rx_queue: 88,
        rx_queue_generation: 6,
        tx_completion: 99,
        tx_completion_generation: 1,
        rx_wait_resolution: 100,
        rx_wait_resolution_generation: 1,
        endpoint: 92,
        endpoint_generation: 10,
        socket: 93,
        socket_generation: 11,
        owner_store: 94,
        owner_store_generation: 12,
        backpressure: Some(96),
        backpressure_generation: Some(1),
        sample_packets: 3,
        sample_bytes: 6000,
        tx_completed_packets: 1,
        rx_resolved_packets: 1,
        dropped_packets: 1,
        measured_nanos: 120_000,
        budget_nanos: 250_000,
        throughput_bytes_per_sec: 50_000_000,
        p50_latency_nanos: 18_000,
        p99_latency_nanos: 48_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 101,
        note: "network benchmark".to_owned(),
    });
    assert_eq!(view["kind"], "network-benchmark");
    assert_eq!(view["owner"]["adapter"]["generation"], 5);
    assert_eq!(view["references"]["tx_completion"]["kind"], "network-tx-completion");
    assert_eq!(view["references"]["rx_wait_resolution"]["kind"], "network-rx-wait-resolution");
    assert_eq!(view["references"]["backpressure"]["generation"], 1);
    assert_eq!(view["benchmark"]["sample_packets"], 3);
    assert_eq!(view["benchmark"]["throughput_bytes_per_sec"], 50_000_000);
    assert_eq!(view["benchmark"]["p99_latency_nanos"], 48_000);
    assert_eq!(view["last_transition"]["recorded_at_event"], 101);
}

#[test]
fn network_recovery_benchmark_view_v1_exposes_recovery_metrics() {
    let view = network_recovery_benchmark_view_v1(&NetworkRecoveryBenchmarkManifest {
        id: 99,
        scenario: "host-validation-network-driver-recovery".to_owned(),
        cleanup: 100,
        cleanup_generation: 1,
        io_cleanup: 70,
        io_cleanup_generation: 2,
        adapter: 74,
        adapter_generation: 5,
        packet_device: 51,
        packet_device_generation: 4,
        backend: ContractObjectRefManifest {
            kind: "virtio-net-backend-object".to_owned(),
            id: 85,
            generation: 3,
        },
        driver_store: 7,
        driver_store_generation: 8,
        fault_injection: Some(102),
        fault_injection_generation: Some(1),
        recovery_start_event: 33,
        recovery_complete_event: 34,
        cancelled_socket_waits: 1,
        revoked_packet_capabilities: 1,
        recovery_nanos: 90_000,
        budget_nanos: 200_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 103,
        note: "network recovery benchmark".to_owned(),
    });
    assert_eq!(view["kind"], "network-recovery-benchmark");
    assert_eq!(view["owner"]["driver_store"]["generation"], 8);
    assert_eq!(view["references"]["cleanup"]["kind"], "network-driver-cleanup");
    assert_eq!(view["references"]["backend"]["kind"], "virtio-net-backend-object");
    assert_eq!(view["references"]["fault_injection"]["kind"], "network-fault-injection");
    assert_eq!(view["benchmark"]["recovery_nanos"], 90_000);
    assert_eq!(view["benchmark"]["within_budget"], true);
    assert_eq!(view["last_transition"]["recorded_at_event"], 103);
}

#[test]
fn block_device_view_v1_exposes_device_and_sector_contract() {
    let view = block_device_object_view_v1(&BlockDeviceObjectManifest {
        id: 104,
        name: "blk0".to_owned(),
        device: 35,
        device_generation: 1,
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 104,
        note: "block device".to_owned(),
    });
    assert_eq!(view["kind"], "block-device");
    assert_eq!(view["owner"]["device"]["kind"], "device");
    assert_eq!(view["references"]["device"]["generation"], 1);
    assert_eq!(view["identity"]["name"], "blk0");
    assert_eq!(view["contract"]["sector_size"], 512);
    assert_eq!(view["contract"]["sector_count"], 4096);
    assert_eq!(view["contract"]["read_only"], false);
    assert_eq!(view["contract"]["max_transfer_sectors"], 128);
    assert_eq!(view["last_transition"]["recorded_at_event"], 104);
}

#[test]
fn block_range_view_v1_exposes_sector_and_byte_ranges() {
    let view = block_range_object_view_v1(&BlockRangeObjectManifest {
        id: 105,
        block_device: 104,
        block_device_generation: 1,
        start_sector: 64,
        sector_count: 8,
        byte_offset: 32768,
        byte_len: 4096,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 105,
        note: "block range".to_owned(),
    });
    assert_eq!(view["kind"], "block-range");
    assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["sector_range"]["start_sector"], 64);
    assert_eq!(view["sector_range"]["sector_count"], 8);
    assert_eq!(view["byte_range"]["byte_offset"], 32768);
    assert_eq!(view["byte_range"]["byte_len"], 4096);
    assert_eq!(view["last_transition"]["recorded_at_event"], 105);
}

#[test]
fn block_request_view_v1_exposes_range_and_operation_contract() {
    let view = block_request_object_view_v1(&BlockRequestObjectManifest {
        id: 106,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "submitted".to_owned(),
        recorded_at_event: 106,
        note: "block request".to_owned(),
    });
    assert_eq!(view["kind"], "block-request");
    assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
    assert_eq!(view["references"]["block_range"]["kind"], "block-range");
    assert_eq!(view["references"]["block_range"]["generation"], 1);
    assert_eq!(view["request"]["operation"], "read");
    assert_eq!(view["request"]["sequence"], 1);
    assert_eq!(view["request"]["byte_len"], 4096);
    assert_eq!(view["last_transition"]["recorded_at_event"], 106);
}

#[test]
fn block_completion_view_v1_exposes_request_and_result_contract() {
    let view = block_completion_object_view_v1(&BlockCompletionObjectManifest {
        id: 107,
        block_request: 106,
        block_request_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        sequence: 1,
        completed_bytes: 4096,
        status: "success".to_owned(),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 107,
        note: "block completion".to_owned(),
    });
    assert_eq!(view["kind"], "block-completion");
    assert_eq!(view["owner"]["block_request"]["kind"], "block-request");
    assert_eq!(view["references"]["block_request"]["generation"], 1);
    assert_eq!(view["references"]["block_range"]["kind"], "block-range");
    assert_eq!(view["completion"]["sequence"], 1);
    assert_eq!(view["completion"]["completed_bytes"], 4096);
    assert_eq!(view["completion"]["status"], "success");
    assert_eq!(view["last_transition"]["recorded_at_event"], 107);
}

#[test]
fn block_wait_view_v1_exposes_wait_token_and_completion_contract() {
    let view = block_wait_view_v1(&BlockWaitManifest {
        id: 108,
        wait: 109,
        wait_generation: 1,
        block_request: 106,
        block_request_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "resolved".to_owned(),
        created_at_event: 108,
        completed_at_event: Some(110),
        completion: Some(107),
        completion_generation: Some(1),
        cancel_reason: None,
        note: "block wait".to_owned(),
    });
    assert_eq!(view["kind"], "block-wait");
    assert_eq!(view["owner"]["wait"]["kind"], "wait-token");
    assert_eq!(view["references"]["block_request"]["generation"], 1);
    assert_eq!(view["references"]["completion"]["kind"], "block-completion");
    assert_eq!(view["wait"]["operation"], "read");
    assert_eq!(view["wait"]["sequence"], 1);
    assert_eq!(view["wait"]["byte_len"], 4096);
    assert_eq!(view["last_transition"]["completed_at_event"], 110);
}

#[test]
fn fake_block_backend_view_v1_exposes_block_device_and_profile_contract() {
    let view = fake_block_backend_object_view_v1(&FakeBlockBackendObjectManifest {
        id: 111,
        name: "fake-block0".to_owned(),
        block_device: 104,
        block_device_generation: 1,
        provider: "service_core".to_owned(),
        profile: "fake-block-v1".to_owned(),
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        deterministic_seed: 0x766d_6f73_626c_6b31,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 111,
        note: "fake block backend".to_owned(),
    });
    assert_eq!(view["kind"], "fake-block-backend");
    assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
    assert_eq!(view["owner"]["block_device"]["generation"], 1);
    assert_eq!(view["identity"]["provider"], "service_core");
    assert_eq!(view["identity"]["profile"], "fake-block-v1");
    assert_eq!(view["contract"]["sector_size"], 512);
    assert_eq!(view["contract"]["sector_count"], 4096);
    assert_eq!(view["contract"]["max_transfer_sectors"], 128);
    assert_eq!(view["last_transition"]["recorded_at_event"], 111);
}

#[test]
fn virtio_blk_backend_view_v1_exposes_driver_binding_and_profile_contract() {
    let view = virtio_blk_backend_object_view_v1(&VirtioBlkBackendObjectManifest {
        id: 112,
        name: "virtio-blk0-backend".to_owned(),
        block_device: 104,
        block_device_generation: 1,
        driver_binding: 130,
        driver_binding_generation: 1,
        device: 35,
        device_generation: 1,
        provider: "substrate_virtio".to_owned(),
        profile: "virtio-blk-backend-skeleton-v1".to_owned(),
        model: "virtio-blk".to_owned(),
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        device_features: 0x40,
        driver_features: 0x40,
        negotiated_features: 0x40,
        request_queue_index: 0,
        queue_size: 8,
        irq_vector: 6,
        generation: 1,
        state: "skeleton-ready".to_owned(),
        recorded_at_event: 112,
        note: "virtio block backend".to_owned(),
    });
    assert_eq!(view["kind"], "virtio-blk-backend");
    assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
    assert_eq!(view["owner"]["driver_binding"]["kind"], "driver-store-binding");
    assert_eq!(view["references"]["device"]["kind"], "device");
    assert_eq!(view["identity"]["provider"], "substrate_virtio");
    assert_eq!(view["identity"]["profile"], "virtio-blk-backend-skeleton-v1");
    assert_eq!(view["identity"]["model"], "virtio-blk");
    assert_eq!(view["contract"]["sector_size"], 512);
    assert_eq!(view["contract"]["queue_size"], 8);
    assert_eq!(view["contract"]["irq_vector"], 6);
    assert_eq!(view["last_transition"]["recorded_at_event"], 112);
}

#[test]
fn block_read_path_view_v1_exposes_backend_request_completion_and_digest() {
    let view = block_read_path_view_v1(&BlockReadPathManifest {
        id: 113,
        backend_kind: "fake-block-backend".to_owned(),
        backend: 111,
        backend_generation: 1,
        block_request: 106,
        block_request_generation: 1,
        block_completion: 107,
        block_completion_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        sequence: 1,
        completed_bytes: 4096,
        data_digest: 0xfeed,
        generation: 1,
        state: "completed".to_owned(),
        recorded_at_event: 113,
        note: "block read path".to_owned(),
    });
    assert_eq!(view["kind"], "block-read-path");
    assert_eq!(view["owner"]["block_request"]["kind"], "block-request");
    assert_eq!(view["references"]["backend"]["kind"], "fake-block-backend");
    assert_eq!(view["references"]["block_completion"]["kind"], "block-completion");
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["read"]["completed_bytes"], 4096);
    assert_eq!(view["read"]["data_digest"], 0xfeed);
    assert_eq!(view["last_transition"]["recorded_at_event"], 113);
}

#[test]
fn block_write_path_view_v1_exposes_backend_request_completion_and_payload_digest() {
    let view = block_write_path_view_v1(&BlockWritePathManifest {
        id: 114,
        backend_kind: "fake-block-backend".to_owned(),
        backend: 111,
        backend_generation: 1,
        block_request: 106,
        block_request_generation: 1,
        block_completion: 107,
        block_completion_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        sequence: 2,
        completed_bytes: 4096,
        payload_digest: 0xbeef,
        generation: 1,
        state: "completed".to_owned(),
        recorded_at_event: 114,
        note: "block write path".to_owned(),
    });
    assert_eq!(view["kind"], "block-write-path");
    assert_eq!(view["owner"]["block_request"]["kind"], "block-request");
    assert_eq!(view["references"]["backend"]["kind"], "fake-block-backend");
    assert_eq!(view["references"]["block_completion"]["kind"], "block-completion");
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["write"]["completed_bytes"], 4096);
    assert_eq!(view["write"]["payload_digest"], 0xbeef);
    assert_eq!(view["last_transition"]["recorded_at_event"], 114);
}

#[test]
fn block_request_queue_view_v1_exposes_entries_depth_and_generations() {
    let view = block_request_queue_view_v1(&BlockRequestQueueManifest {
        id: 115,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 111,
        backend_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        depth: 4,
        entries: vec![
            artifact_manifest::BlockRequestQueueEntryManifest {
                request: 106,
                request_generation: 1,
                completion: Some(107),
                completion_generation: Some(1),
                sequence: 1,
                operation: "read".to_owned(),
                byte_len: 4096,
                state: "completed".to_owned(),
            },
            artifact_manifest::BlockRequestQueueEntryManifest {
                request: 108,
                request_generation: 1,
                completion: None,
                completion_generation: None,
                sequence: 2,
                operation: "write".to_owned(),
                byte_len: 4096,
                state: "pending".to_owned(),
            },
        ],
        pending_count: 1,
        completed_count: 1,
        first_sequence: 1,
        last_sequence: 2,
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 115,
        note: "block request queue".to_owned(),
    });
    assert_eq!(view["kind"], "block-request-queue");
    assert_eq!(view["owner"]["backend"]["kind"], "fake-block-backend");
    assert_eq!(view["references"]["entries"][0]["request"]["kind"], "block-request");
    assert_eq!(view["references"]["entries"][0]["completion"]["kind"], "block-completion");
    assert_eq!(view["references"]["entries"][1]["completion"], serde_json::Value::Null);
    assert_eq!(view["queue"]["depth"], 4);
    assert_eq!(view["queue"]["pending_count"], 1);
    assert_eq!(view["queue"]["completed_count"], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 115);
}

#[test]
fn block_dma_buffer_view_v1_exposes_request_dma_and_buffer_contract() {
    let view = block_dma_buffer_view_v1(&BlockDmaBufferManifest {
        id: 116,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 111,
        backend_generation: 1,
        block_request: 108,
        block_request_generation: 1,
        dma_buffer: 210,
        dma_buffer_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        descriptor: 209,
        descriptor_generation: 1,
        queue: 208,
        queue_generation: 1,
        operation: "write".to_owned(),
        access: "read-write".to_owned(),
        byte_len: 4096,
        buffer_len: 4096,
        buffer_digest: 0xb10,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 116,
        note: "block dma buffer".to_owned(),
    });
    assert_eq!(view["kind"], "block-dma-buffer");
    assert_eq!(view["owner"]["backend"]["kind"], "fake-block-backend");
    assert_eq!(view["owner"]["block_request"]["generation"], 1);
    assert_eq!(view["references"]["dma_buffer"]["kind"], "dma-buffer");
    assert_eq!(view["references"]["descriptor"]["id"], 209);
    assert_eq!(view["references"]["queue"]["generation"], 1);
    assert_eq!(view["buffer"]["operation"], "write");
    assert_eq!(view["buffer"]["buffer_digest"], 0xb10);
    assert_eq!(view["last_transition"]["dma_buffer_generation"], 1);
}

#[test]
fn block_page_object_view_v1_exposes_page_and_block_dma_contract() {
    let view = block_page_object_view_v1(&BlockPageObjectManifest {
        id: 117,
        block_dma_buffer: 116,
        block_dma_buffer_generation: 1,
        block_request: 108,
        block_request_generation: 1,
        block_completion: 109,
        block_completion_generation: 1,
        dma_buffer: 210,
        dma_buffer_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        aspace: ContractObjectRefManifest {
            kind: "guest-address-space".to_owned(),
            id: 301,
            generation: 1,
        },
        vma_region: ContractObjectRefManifest {
            kind: "vma-region".to_owned(),
            id: 302,
            generation: 1,
        },
        page: ContractObjectRefManifest { kind: "page-object".to_owned(), id: 303, generation: 1 },
        page_dirty_generation: 2,
        page_backing: "file-backed".to_owned(),
        cow_state: "none".to_owned(),
        page_state: "live".to_owned(),
        page_offset: 0,
        byte_len: 4096,
        operation: "write".to_owned(),
        generation: 1,
        state: "integrated".to_owned(),
        recorded_at_event: 117,
        note: "block page object".to_owned(),
    });
    assert_eq!(view["kind"], "block-page-object");
    assert_eq!(view["owner"]["page"]["kind"], "page-object");
    assert_eq!(view["owner"]["block_dma_buffer"]["kind"], "block-dma-buffer");
    assert_eq!(view["references"]["aspace"]["id"], 301);
    assert_eq!(view["references"]["vma_region"]["generation"], 1);
    assert_eq!(view["references"]["block_completion"]["id"], 109);
    assert_eq!(view["page"]["dirty_generation"], 2);
    assert_eq!(view["page"]["backing"], "file-backed");
    assert_eq!(view["page"]["byte_len"], 4096);
    assert_eq!(view["last_transition"]["recorded_at_event"], 117);
}

#[test]
fn buffer_cache_object_view_v1_exposes_page_and_block_range_contract() {
    let view = buffer_cache_object_view_v1(&BufferCacheObjectManifest {
        id: 118,
        block_page_object: 117,
        block_page_object_generation: 1,
        block_dma_buffer: 116,
        block_dma_buffer_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        aspace: ContractObjectRefManifest {
            kind: "guest-address-space".to_owned(),
            id: 301,
            generation: 1,
        },
        vma_region: ContractObjectRefManifest {
            kind: "vma-region".to_owned(),
            id: 302,
            generation: 1,
        },
        page: ContractObjectRefManifest { kind: "page-object".to_owned(), id: 303, generation: 1 },
        page_dirty_generation: 2,
        page_offset: 0,
        block_offset: 0,
        byte_len: 4096,
        operation: "write".to_owned(),
        cache_state: "dirty".to_owned(),
        coherency_epoch: 7,
        generation: 1,
        state: "dirty".to_owned(),
        recorded_at_event: 118,
        note: "buffer cache object".to_owned(),
    });
    assert_eq!(view["kind"], "buffer-cache-object");
    assert_eq!(view["owner"]["page"]["kind"], "page-object");
    assert_eq!(view["owner"]["block_range"]["kind"], "block-range");
    assert_eq!(view["references"]["block_page_object"]["kind"], "block-page-object");
    assert_eq!(view["references"]["block_dma_buffer"]["generation"], 1);
    assert_eq!(view["references"]["aspace"]["id"], 301);
    assert_eq!(view["cache"]["page_dirty_generation"], 2);
    assert_eq!(view["cache"]["cache_state"], "dirty");
    assert_eq!(view["cache"]["coherency_epoch"], 7);
    assert_eq!(view["last_transition"]["recorded_at_event"], 118);
}

#[test]
fn file_object_view_v1_exposes_cache_file_and_page_contract() {
    let view = file_object_view_v1(&FileObjectManifest {
        id: 119,
        buffer_cache_object: 118,
        buffer_cache_object_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        page: ContractObjectRefManifest { kind: "page-object".to_owned(), id: 303, generation: 1 },
        page_dirty_generation: 2,
        namespace: "rootfs".to_owned(),
        file_key: "demo-file".to_owned(),
        path: "/demo/file.txt".to_owned(),
        file_offset: 0,
        byte_len: 4096,
        file_size: 4096,
        content_digest: 0xB13,
        cache_state: "dirty".to_owned(),
        generation: 1,
        state: "dirty".to_owned(),
        recorded_at_event: 119,
        note: "file object".to_owned(),
    });
    assert_eq!(view["kind"], "file-object");
    assert_eq!(view["owner"]["namespace"], "rootfs");
    assert_eq!(view["owner"]["file_key"], "demo-file");
    assert_eq!(view["references"]["buffer_cache_object"]["kind"], "buffer-cache-object");
    assert_eq!(view["references"]["block_range"]["generation"], 1);
    assert_eq!(view["references"]["page"]["id"], 303);
    assert_eq!(view["file"]["content_digest"], 0xB13);
    assert_eq!(view["file"]["cache_state"], "dirty");
    assert_eq!(view["last_transition"]["recorded_at_event"], 119);
}

#[test]
fn directory_object_view_v1_exposes_file_entry_contract() {
    let view = directory_object_view_v1(&DirectoryObjectManifest {
        id: 120,
        file_object: 119,
        file_object_generation: 1,
        namespace: "rootfs".to_owned(),
        directory_key: "demo-dir".to_owned(),
        directory_path: "/demo".to_owned(),
        entry_name: "file.txt".to_owned(),
        child_file_key: "demo-file".to_owned(),
        child_path: "/demo/file.txt".to_owned(),
        entry_kind: "file".to_owned(),
        file_size: 4096,
        content_digest: 0xB13,
        generation: 1,
        state: "cached".to_owned(),
        recorded_at_event: 120,
        note: "directory object".to_owned(),
    });
    assert_eq!(view["kind"], "directory-object");
    assert_eq!(view["owner"]["namespace"], "rootfs");
    assert_eq!(view["owner"]["directory_key"], "demo-dir");
    assert_eq!(view["owner"]["entry_name"], "file.txt");
    assert_eq!(view["references"]["file_object"]["kind"], "file-object");
    assert_eq!(view["references"]["file_object"]["id"], 119);
    assert_eq!(view["directory"]["entry_kind"], "file");
    assert_eq!(view["directory"]["child_path"], "/demo/file.txt");
    assert_eq!(view["directory"]["content_digest"], 0xB13);
    assert_eq!(view["last_transition"]["recorded_at_event"], 120);
}

#[test]
fn fat_adapter_object_view_v1_exposes_read_write_adapter_contract() {
    let view = fat_adapter_object_view_v1(&FatAdapterObjectManifest {
        id: 121,
        directory_object: 120,
        directory_object_generation: 1,
        file_object: 119,
        file_object_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        implementation: "fatfs".to_owned(),
        version: "0.3.6".to_owned(),
        profile: "fatfs-read-write-demo-v1".to_owned(),
        volume_label: "VMOSFAT".to_owned(),
        image_bytes: 1_048_576,
        adapter_path: "DEMO.TXT".to_owned(),
        semantic_path: "/demo/file.txt".to_owned(),
        bytes_written: 35,
        bytes_read: 35,
        write_digest: 0x1234,
        read_digest: 0x1234,
        file_content_digest: 0xB13,
        generation: 1,
        state: "verified".to_owned(),
        recorded_at_event: 121,
        note: "fat adapter object".to_owned(),
    });
    assert_eq!(view["kind"], "fat-adapter-object");
    assert_eq!(view["owner"]["implementation"], "fatfs");
    assert_eq!(view["owner"]["profile"], "fatfs-read-write-demo-v1");
    assert_eq!(view["references"]["directory_object"]["kind"], "directory-object");
    assert_eq!(view["references"]["file_object"]["id"], 119);
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["fat"]["bytes_written"], 35);
    assert_eq!(view["fat"]["read_digest"], 0x1234);
    assert_eq!(view["fat"]["file_content_digest"], 0xB13);
    assert_eq!(view["last_transition"]["recorded_at_event"], 121);
}

#[test]
fn ext4_adapter_object_view_v1_exposes_read_only_adapter_contract() {
    let view = ext4_adapter_object_view_v1(&Ext4AdapterObjectManifest {
        id: 122,
        directory_object: 120,
        directory_object_generation: 1,
        file_object: 119,
        file_object_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        implementation: "ext4-view".to_owned(),
        version: "0.9.3".to_owned(),
        profile: "ext4-read-only-demo-v1".to_owned(),
        volume_label: "VMOSEXT4".to_owned(),
        image_bytes: 32 * 1024,
        adapter_path: "/demo.txt".to_owned(),
        semantic_path: "/demo/file.txt".to_owned(),
        bytes_read: 34,
        read_digest: 0x6121,
        file_content_digest: 0xB13,
        directory_entries: 1,
        read_only_enforced: true,
        generation: 1,
        state: "verified".to_owned(),
        recorded_at_event: 122,
        note: "ext4 adapter object".to_owned(),
    });
    assert_eq!(view["kind"], "ext4-adapter-object");
    assert_eq!(view["owner"]["implementation"], "ext4-view");
    assert_eq!(view["owner"]["profile"], "ext4-read-only-demo-v1");
    assert_eq!(view["references"]["directory_object"]["kind"], "directory-object");
    assert_eq!(view["references"]["file_object"]["id"], 119);
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["ext4"]["bytes_read"], 34);
    assert_eq!(view["ext4"]["read_digest"], 0x6121);
    assert_eq!(view["ext4"]["file_content_digest"], 0xB13);
    assert_eq!(view["ext4"]["directory_entries"], 1);
    assert_eq!(view["ext4"]["read_only_enforced"], true);
    assert_eq!(view["last_transition"]["recorded_at_event"], 122);
}

#[test]
fn file_handle_capability_view_v1_exposes_file_and_capability_gate() {
    let view = file_handle_capability_view_v1(&FileHandleCapabilityManifest {
        id: 123,
        owner_store: 7,
        owner_store_generation: 3,
        file_object: 119,
        file_object_generation: 1,
        directory_object: 120,
        directory_object_generation: 1,
        capability: 44,
        capability_generation: 5,
        handle_slot: 9,
        handle_generation: 5,
        handle_tag: 0xFEED,
        operation: "read".to_owned(),
        file_offset: 0,
        byte_len: 512,
        content_digest: 0xB13,
        generation: 1,
        state: "allowed".to_owned(),
        recorded_at_event: 123,
        note: "file handle capability".to_owned(),
    });
    assert_eq!(view["kind"], "file-handle-capability");
    assert_eq!(view["owner"]["store"]["id"], 7);
    assert_eq!(view["owner"]["operation"], "read");
    assert_eq!(view["references"]["file_object"]["kind"], "file-object");
    assert_eq!(view["references"]["file_object"]["id"], 119);
    assert_eq!(view["references"]["directory_object"]["id"], 120);
    assert_eq!(view["references"]["capability"]["generation"], 5);
    assert_eq!(view["handle"]["slot"], 9);
    assert_eq!(view["handle"]["generation"], 5);
    assert_eq!(view["handle"]["tag"], 0xFEED);
    assert_eq!(view["file_access"]["byte_len"], 512);
    assert_eq!(view["file_access"]["content_digest"], 0xB13);
    assert_eq!(view["last_transition"]["recorded_at_event"], 123);
}

#[test]
fn fs_wait_view_v1_exposes_file_handle_wait_contract() {
    let view = fs_wait_view_v1(&FsWaitManifest {
        id: 124,
        wait: 55,
        wait_generation: 1,
        owner_store: 7,
        owner_store_generation: 3,
        file_object: 119,
        file_object_generation: 1,
        directory_object: 120,
        directory_object_generation: 1,
        file_handle_capability: 123,
        file_handle_capability_generation: 1,
        operation: "read".to_owned(),
        blocker: ContractObjectRefManifest {
            kind: "file-handle-capability".to_owned(),
            id: 123,
            generation: 1,
        },
        sequence: 9,
        byte_len: 512,
        generation: 1,
        state: "cancelled".to_owned(),
        created_at_event: 124,
        completed_at_event: Some(125),
        cancel_reason: Some("close-fd".to_owned()),
        note: "fs wait".to_owned(),
    });
    assert_eq!(view["kind"], "fs-wait");
    assert_eq!(view["owner"]["store"]["id"], 7);
    assert_eq!(view["owner"]["operation"], "read");
    assert_eq!(view["references"]["wait"]["kind"], "wait-token");
    assert_eq!(view["references"]["file_handle_capability"]["kind"], "file-handle-capability");
    assert_eq!(view["references"]["file_object"]["id"], 119);
    assert_eq!(view["references"]["blocker"]["id"], 123);
    assert_eq!(view["wait"]["sequence"], 9);
    assert_eq!(view["wait"]["cancel_reason"], "close-fd");
    assert_eq!(view["last_error"]["cancel_reason"], "close-fd");
    assert_eq!(view["last_transition"]["completed_at_event"], 125);
}

#[test]
fn block_driver_cleanup_view_v1_exposes_cleanup_effects_and_generations() {
    let view = block_driver_cleanup_view_v1(&BlockDriverCleanupManifest {
        id: 126,
        io_cleanup: 44,
        io_cleanup_generation: 1,
        driver_store: 7,
        driver_store_generation: 3,
        device: 30,
        device_generation: 1,
        driver_binding: 33,
        driver_binding_generation: 1,
        block_device: 31,
        block_device_generation: 1,
        backend: ContractObjectRefManifest {
            kind: "virtio-blk-backend-object".to_owned(),
            id: 34,
            generation: 1,
        },
        cancelled_block_waits: vec![ContractObjectRefManifest {
            kind: "block-wait".to_owned(),
            id: 103,
            generation: 1,
        }],
        cancelled_wait_tokens: vec![ContractObjectRefManifest {
            kind: "wait-token".to_owned(),
            id: 102,
            generation: 1,
        }],
        revoked_device_capabilities: vec![ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 32,
            generation: 1,
        }],
        released_dma_buffers: vec![ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 106,
            generation: 1,
        }],
        generation: 1,
        state: "completed".to_owned(),
        started_at_event: 126,
        completed_at_event: Some(127),
        reason: "virtio-blk-device-fault".to_owned(),
        note: "block driver cleanup".to_owned(),
    });
    assert_eq!(view["kind"], "block-driver-cleanup");
    assert_eq!(view["owner"]["driver_store"]["generation"], 3);
    assert_eq!(view["owner"]["block_device"]["id"], 31);
    assert_eq!(view["references"]["io_cleanup"]["id"], 44);
    assert_eq!(view["references"]["backend"]["kind"], "virtio-blk-backend-object");
    assert_eq!(view["references"]["cancelled_block_waits"][0]["id"], 103);
    assert_eq!(view["references"]["cancelled_wait_tokens"][0]["id"], 102);
    assert_eq!(view["references"]["revoked_device_capabilities"][0]["id"], 32);
    assert_eq!(view["references"]["released_dma_buffers"][0]["id"], 106);
    assert_eq!(view["cleanup"]["reason"], "virtio-blk-device-fault");
    assert_eq!(view["cleanup"]["cancelled_block_wait_count"], 1);
    assert_eq!(view["cleanup"]["released_dma_buffer_count"], 1);
    assert_eq!(view["cleanup"]["revoked_device_capability_count"], 1);
    assert_eq!(view["last_transition"]["completed_at_event"], 127);
}

#[test]
fn block_pending_io_policy_view_v1_exposes_retry_and_eio_policy() {
    let retry_policy = BlockPendingIoPolicyManifest {
        id: 127,
        block_wait: 103,
        block_wait_generation: 1,
        wait: 102,
        wait_generation: 1,
        block_request: 101,
        block_request_generation: 1,
        retry_request: Some(112),
        retry_request_generation: Some(1),
        block_device: 31,
        block_device_generation: 1,
        block_range: 100,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 2,
        byte_len: 4096,
        action: "retry".to_owned(),
        errno: 11,
        retry_attempt: 1,
        max_retries: 2,
        generation: 1,
        state: "retry-scheduled".to_owned(),
        recorded_at_event: 128,
        note: "pending io retry policy".to_owned(),
    };
    let view = block_pending_io_policy_view_v1(&retry_policy);
    assert_eq!(view["kind"], "block-pending-io-policy");
    assert_eq!(view["owner"]["block_wait"]["id"], 103);
    assert_eq!(view["references"]["wait"]["kind"], "wait-token");
    assert_eq!(view["references"]["retry_request"]["id"], 112);
    assert_eq!(view["policy"]["action"], "retry");
    assert_eq!(view["policy"]["retry_attempt"], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 128);
    assert!(view["last_error"].is_null());

    let eio = block_pending_io_policy_view_v1(&BlockPendingIoPolicyManifest {
        id: 129,
        retry_request: None,
        retry_request_generation: None,
        action: "eio".to_owned(),
        errno: 5,
        retry_attempt: 0,
        max_retries: 0,
        state: "eio-returned".to_owned(),
        recorded_at_event: 130,
        note: "pending io eio policy".to_owned(),
        ..retry_policy
    });
    assert_eq!(eio["last_error"]["errno"], 5);
}

#[test]
fn block_request_generation_audit_view_v1_exposes_exact_generation_refs() {
    let view = block_request_generation_audit_view_v1(&BlockRequestGenerationAuditManifest {
        id: 131,
        block_device: 2,
        block_device_generation: 3,
        block_range: 5,
        block_range_generation: 7,
        block_request: 11,
        block_request_generation: 13,
        backend: ContractObjectRefManifest {
            kind: "fake-block-backend-object".to_owned(),
            id: 17,
            generation: 19,
        },
        dma_buffer: ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 23,
            generation: 29,
        },
        rejected_completion_generation_probes: 1,
        rejected_wait_generation_probes: 2,
        rejected_dma_generation_probes: 3,
        rejected_queue_generation_probes: 4,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 31,
        note: "stale request generation audit".to_owned(),
    });
    assert_eq!(view["kind"], "block-request-generation-audit");
    assert_eq!(view["owner"]["block_request"]["generation"], 13);
    assert_eq!(view["references"]["backend"]["kind"], "fake-block-backend-object");
    assert_eq!(view["references"]["backend"]["generation"], 19);
    assert_eq!(view["references"]["dma_buffer"]["kind"], "dma-buffer-object");
    assert_eq!(view["references"]["dma_buffer"]["generation"], 29);
    assert_eq!(view["audit"]["rejected_completion_generation_probes"], 1);
    assert_eq!(view["audit"]["rejected_wait_generation_probes"], 2);
    assert_eq!(view["audit"]["rejected_dma_generation_probes"], 3);
    assert_eq!(view["audit"]["rejected_queue_generation_probes"], 4);
    assert_eq!(view["last_transition"]["recorded_at_event"], 31);
}

#[test]
fn block_benchmark_view_v1_exposes_iops_latency_and_exact_refs() {
    let view = block_benchmark_view_v1(&BlockBenchmarkManifest {
        id: 132,
        scenario: "fake-block-read-write-iops-latency-v1".to_owned(),
        backend: ContractObjectRefManifest {
            kind: "fake-block-backend-object".to_owned(),
            id: 26,
            generation: 1,
        },
        block_device: 2,
        block_device_generation: 1,
        block_range: 5,
        block_range_generation: 1,
        read_path: 39,
        read_path_generation: 1,
        write_path: 48,
        write_path_generation: 1,
        request_queue: 53,
        request_queue_generation: 1,
        block_dma_buffer: 61,
        block_dma_buffer_generation: 1,
        sample_requests: 2,
        sample_bytes: 8192,
        read_completed_requests: 1,
        write_completed_requests: 1,
        queue_completed_requests: 2,
        measured_nanos: 40_000,
        budget_nanos: 80_000,
        iops: 50_000,
        throughput_bytes_per_sec: 204_800_000,
        p50_latency_nanos: 18_000,
        p99_latency_nanos: 35_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 487,
        note: "disk benchmark".to_owned(),
    });
    assert_eq!(view["kind"], "block-benchmark");
    assert_eq!(view["references"]["backend"]["kind"], "fake-block-backend-object");
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["references"]["read_path"]["id"], 39);
    assert_eq!(view["references"]["write_path"]["id"], 48);
    assert_eq!(view["references"]["request_queue"]["id"], 53);
    assert_eq!(view["references"]["block_dma_buffer"]["id"], 61);
    assert_eq!(view["benchmark"]["sample_requests"], 2);
    assert_eq!(view["benchmark"]["iops"], 50_000);
    assert_eq!(view["benchmark"]["throughput_bytes_per_sec"], 204_800_000);
    assert_eq!(view["benchmark"]["p99_latency_nanos"], 35_000);
    assert_eq!(view["last_transition"]["recorded_at_event"], 487);
}

#[test]
fn block_recovery_benchmark_view_v1_exposes_cleanup_latency_and_effects() {
    let view = block_recovery_benchmark_view_v1(&BlockRecoveryBenchmarkManifest {
        id: 135,
        scenario: "host-validation-disk-driver-recovery".to_owned(),
        cleanup: 107,
        cleanup_generation: 1,
        io_cleanup: 108,
        io_cleanup_generation: 1,
        backend: ContractObjectRefManifest {
            kind: "virtio-blk-backend-object".to_owned(),
            id: 34,
            generation: 1,
        },
        block_device: 31,
        block_device_generation: 1,
        driver_store: 7,
        driver_store_generation: 3,
        device: 30,
        device_generation: 1,
        driver_binding: 33,
        driver_binding_generation: 1,
        recovery_start_event: 125,
        recovery_complete_event: 126,
        cancelled_block_waits: 1,
        cancelled_wait_tokens: 1,
        released_dma_buffers: 1,
        revoked_device_capabilities: 1,
        recovery_nanos: 70_000,
        budget_nanos: 150_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 488,
        note: "disk recovery benchmark".to_owned(),
    });
    assert_eq!(view["kind"], "block-recovery-benchmark");
    assert_eq!(view["references"]["cleanup"]["kind"], "block-driver-cleanup");
    assert_eq!(view["references"]["io_cleanup"]["id"], 108);
    assert_eq!(view["references"]["backend"]["kind"], "virtio-blk-backend-object");
    assert_eq!(view["references"]["block_device"]["id"], 31);
    assert_eq!(view["references"]["driver_store"]["generation"], 3);
    assert_eq!(view["benchmark"]["cancelled_block_waits"], 1);
    assert_eq!(view["benchmark"]["released_dma_buffers"], 1);
    assert_eq!(view["benchmark"]["recovery_nanos"], 70_000);
    assert_eq!(view["last_transition"]["recorded_at_event"], 488);
}

#[test]
fn target_feature_set_view_v1_exposes_simd_discovery() {
    let view = target_feature_set_view_v1(&TargetFeatureSetManifest {
        id: 21_000,
        name: "riscv64-qemu-virt-research-target".to_owned(),
        discovery_source: "target-runtime-default-profile".to_owned(),
        target_profile: "riscv64-qemu-virt-research".to_owned(),
        target_arch: "riscv64".to_owned(),
        base_isa: "rv64imac".to_owned(),
        simd_abi: "riscv-v".to_owned(),
        simd_supported: false,
        vector_register_count: 0,
        vector_register_bits: 0,
        scalar_fallback: true,
        unsupported_reason: "default profile does not declare RVV/SIMD".to_owned(),
        generation: 1,
        state: "discovered".to_owned(),
        recorded_at_event: 489,
        note: "target feature discovery".to_owned(),
    });
    assert_eq!(view["kind"], "target-feature-set");
    assert_eq!(view["owner"]["target_profile"], "riscv64-qemu-virt-research");
    assert_eq!(view["features"]["base_isa"], "rv64imac");
    assert_eq!(view["features"]["simd"]["abi"], "riscv-v");
    assert_eq!(view["features"]["simd"]["supported"], false);
    assert_eq!(view["features"]["simd"]["scalar_fallback"], true);
    assert_eq!(view["last_transition"]["recorded_at_event"], 489);
}

#[test]
fn vector_state_view_v1_exposes_owner_and_simd_shape() {
    let view = vector_state_view_v1(&VectorStateManifest {
        id: 22_000,
        owner_activation: ContractObjectRefManifest {
            kind: "activation".to_owned(),
            id: 7,
            generation: 3,
        },
        owner_store: ContractObjectRefManifest { kind: "store".to_owned(), id: 2, generation: 5 },
        code_object: ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 9,
            generation: 4,
        },
        target_feature_set: ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 21_000,
            generation: 1,
        },
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: "unavailable".to_owned(),
        recorded_at_event: 490,
        note: "v4 vector state".to_owned(),
    });
    assert_eq!(view["kind"], "vector-state");
    assert_eq!(view["owner"]["activation"]["generation"], 3);
    assert_eq!(view["owner"]["store"]["generation"], 5);
    assert_eq!(view["references"]["code_object"]["id"], 9);
    assert_eq!(view["references"]["target_feature_set"]["generation"], 1);
    assert_eq!(view["simd"]["register_bytes"], 512);
    assert_eq!(view["last_error"], "simd-unavailable");
}

#[test]
fn simd_fault_injection_view_v1_exposes_fault_and_exact_refs() {
    let view = simd_fault_injection_view_v1(&SimdFaultInjectionManifest {
        id: 22_010,
        activation: ContractObjectRefManifest {
            kind: "activation".to_owned(),
            id: 11,
            generation: 4,
        },
        code_object: ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 9,
            generation: 4,
        },
        trap: ContractObjectRefManifest { kind: "trap".to_owned(), id: 33, generation: 1 },
        target_feature_set: ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 21_010,
            generation: 1,
        },
        vector_state: None,
        kind: "unsupported-feature".to_owned(),
        effect: "activation-trapped".to_owned(),
        required_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        injected_faults: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 491,
        note: "v10 SIMD fault injection".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "simd-fault-injection");
    assert_eq!(view["owner"]["activation"]["generation"], 4);
    assert_eq!(view["references"]["code_object"]["id"], 9);
    assert_eq!(view["references"]["trap"]["generation"], 1);
    assert_eq!(view["references"]["target_feature_set"]["id"], 21_010);
    assert!(view["references"]["vector_state"].is_null());
    assert_eq!(view["fault"]["kind"], "unsupported-feature");
    assert_eq!(view["fault"]["effect"], "activation-trapped");
    assert_eq!(view["fault"]["required_abi"], "riscv-v");
    assert_eq!(view["fault"]["vector_register_count"], 32);
    assert_eq!(view["fault"]["vector_register_bits"], 128);
    assert_eq!(view["fault"]["injected_faults"], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 491);
}

#[test]
fn simd_benchmark_view_v1_exposes_scalar_vector_metrics_and_refs() {
    let view = simd_benchmark_view_v1(&SimdBenchmarkManifest {
        id: 22_011,
        target_feature_set: ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 21_011,
            generation: 1,
        },
        scalar_code_object: ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 41,
            generation: 4,
        },
        vector_code_object: ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 42,
            generation: 5,
        },
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        workload_units: 4096,
        scalar_nanos: 120_000,
        vector_nanos: 40_000,
        speedup_milli: 3000,
        context_overhead_nanos: 80_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 492,
        note: "v11 SIMD benchmark".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "simd-benchmark");
    assert_eq!(view["owner"]["target_feature_set"]["id"], 21_011);
    assert_eq!(view["references"]["scalar_code_object"]["generation"], 4);
    assert_eq!(view["references"]["vector_code_object"]["generation"], 5);
    assert_eq!(view["simd"]["abi"], "riscv-v");
    assert_eq!(view["simd"]["vector_register_count"], 32);
    assert_eq!(view["metrics"]["workload_units"], 4096);
    assert_eq!(view["metrics"]["scalar_nanos"], 120_000);
    assert_eq!(view["metrics"]["vector_nanos"], 40_000);
    assert_eq!(view["metrics"]["speedup_milli"], 3000);
    assert_eq!(view["metrics"]["context_overhead_nanos"], 80_000);
    assert_eq!(view["last_transition"]["recorded_at_event"], 492);
}

#[test]
fn simd_context_switch_benchmark_view_v1_exposes_overhead_and_refs() {
    let view = simd_context_switch_benchmark_view_v1(&SimdContextSwitchBenchmarkManifest {
        id: 22_012,
        preemption: ContractObjectRefManifest {
            kind: "preemption".to_owned(),
            id: 9_070,
            generation: 1,
        },
        activation_resume: ContractObjectRefManifest {
            kind: "activation-resume".to_owned(),
            id: 9_071,
            generation: 1,
        },
        saved_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_002,
            generation: 1,
        },
        restored_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_003,
            generation: 1,
        },
        target_feature_set: ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 21_002,
            generation: 1,
        },
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        sample_count: 64,
        scalar_context_switch_nanos: 30_000,
        vector_context_switch_nanos: 46_384,
        overhead_nanos: 16_384,
        budget_nanos: 50_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 493,
        note: "v12 SIMD context switch benchmark".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "simd-context-switch-benchmark");
    assert_eq!(view["owner"]["activation_resume"]["id"], 9_071);
    assert_eq!(view["references"]["preemption"]["generation"], 1);
    assert_eq!(view["references"]["saved_vector_state"]["id"], 22_002);
    assert_eq!(view["references"]["restored_vector_state"]["id"], 22_003);
    assert_eq!(view["simd"]["abi"], "riscv-v");
    assert_eq!(view["metrics"]["sample_count"], 64);
    assert_eq!(view["metrics"]["scalar_context_switch_nanos"], 30_000);
    assert_eq!(view["metrics"]["vector_context_switch_nanos"], 46_384);
    assert_eq!(view["metrics"]["overhead_nanos"], 16_384);
    assert_eq!(view["metrics"]["budget_nanos"], 50_000);
    assert_eq!(view["last_transition"]["recorded_at_event"], 493);
}

#[test]
fn framebuffer_object_view_v1_exposes_geometry_and_authority_boundary() {
    let view = framebuffer_object_view_v1(&FramebufferObjectManifest {
        id: 23_001,
        name: "fb0".to_owned(),
        resource: 101,
        resource_generation: 2,
        width: 800,
        height: 600,
        stride_bytes: 3200,
        pixel_format: "xrgb8888".to_owned(),
        byte_len: 1_920_000,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 494,
        note: "g0 framebuffer object".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-object");
    assert_eq!(view["owner"]["resource"]["id"], 101);
    assert_eq!(view["references"]["resource"]["generation"], 2);
    assert_eq!(view["geometry"]["width"], 800);
    assert_eq!(view["geometry"]["height"], 600);
    assert_eq!(view["geometry"]["stride_bytes"], 3200);
    assert_eq!(view["geometry"]["pixel_format"], "xrgb8888");
    assert_eq!(view["geometry"]["byte_len"], 1_920_000);
    assert_eq!(
        view["authority"]["write_requires"],
        "display-capability-and-framebuffer-window-lease"
    );
    assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 494);
}

#[test]
fn display_object_view_v1_exposes_mode_and_framebuffer_ref() {
    let view = display_object_view_v1(&DisplayObjectManifest {
        id: 23_101,
        name: "display0".to_owned(),
        framebuffer: 23_001,
        framebuffer_generation: 1,
        mode_name: "800x600@60".to_owned(),
        width: 800,
        height: 600,
        refresh_millihz: 60_000,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 495,
        note: "g1 display object".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-object");
    assert_eq!(view["owner"]["framebuffer"]["id"], 23_001);
    assert_eq!(view["references"]["framebuffer"]["generation"], 1);
    assert_eq!(view["mode"]["name"], "800x600@60");
    assert_eq!(view["mode"]["width"], 800);
    assert_eq!(view["mode"]["height"], 600);
    assert_eq!(view["mode"]["refresh_millihz"], 60_000);
    assert_eq!(
        view["authority"]["write_requires"],
        "display-capability-and-framebuffer-window-lease"
    );
    assert_eq!(view["authority"]["flush_requires"], "display-capability");
    assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 495);
}

#[test]
fn display_capability_view_v1_exposes_handle_and_generation_refs() {
    let view = display_capability_view_v1(&DisplayCapabilityManifest {
        id: 23_201,
        owner_store: 12,
        owner_store_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        capability: 25,
        capability_generation: 1,
        handle_slot: 8,
        handle_generation: 1,
        handle_tag: 99,
        operations: vec!["flush".to_owned(), "lease".to_owned()],
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 496,
        note: "g2 display capability".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-capability");
    assert_eq!(view["owner"]["store"]["id"], 12);
    assert_eq!(view["references"]["display"]["id"], 23_101);
    assert_eq!(view["references"]["framebuffer"]["generation"], 1);
    assert_eq!(view["references"]["capability"]["id"], 25);
    assert_eq!(view["authority"]["class"], "display");
    assert_eq!(view["authority"]["operations"][0], "flush");
    assert_eq!(view["authority"]["operations"][1], "lease");
    assert_eq!(view["authority"]["handle"]["slot"], 8);
    assert_eq!(view["authority"]["write_requires_framebuffer_window_lease"], true);
    assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 496);
}

#[test]
fn framebuffer_window_lease_view_v1_exposes_window_and_authority_refs() {
    let view = framebuffer_window_lease_view_v1(&FramebufferWindowLeaseManifest {
        id: 23_301,
        owner_store: 12,
        owner_store_generation: 2,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        x: 0,
        y: 0,
        width: 800,
        height: 600,
        byte_offset: 0,
        byte_len: 1_920_000,
        access: "write".to_owned(),
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 497,
        note: "g3 framebuffer window lease".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-window-lease");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["display_capability"]["id"], 23_201);
    assert_eq!(view["references"]["display"]["generation"], 1);
    assert_eq!(view["references"]["framebuffer"]["id"], 23_001);
    assert_eq!(view["window"]["width"], 800);
    assert_eq!(view["window"]["byte_len"], 1_920_000);
    assert_eq!(view["authority"]["requires_display_capability_operation"], "lease");
    assert_eq!(view["authority"]["write_requires_this_lease"], true);
    assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 497);
}

#[test]
fn framebuffer_mapping_view_v1_exposes_handle_mode_mapping_refs() {
    let view = framebuffer_mapping_view_v1(&FramebufferMappingManifest {
        id: 23_401,
        owner_store: 12,
        owner_store_generation: 2,
        framebuffer_window_lease: 23_301,
        framebuffer_window_lease_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        map_handle_slot: 3,
        map_handle_generation: 1,
        map_handle_tag: 0x4d41505f4642,
        x: 0,
        y: 0,
        width: 800,
        height: 600,
        byte_offset: 0,
        byte_len: 1_920_000,
        access: "write".to_owned(),
        mode: "handle-mode".to_owned(),
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 498,
        note: "g4 framebuffer mapping".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-mapping");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_window_lease"]["id"], 23_301);
    assert_eq!(view["references"]["display_capability"]["id"], 23_201);
    assert_eq!(view["references"]["framebuffer"]["id"], 23_001);
    assert_eq!(view["map_handle"]["slot"], 3);
    assert_eq!(view["map_handle"]["mode"], "handle-mode");
    assert_eq!(view["window"]["byte_len"], 1_920_000);
    assert_eq!(view["authority"]["requires_framebuffer_window_lease"], true);
    assert_eq!(view["authority"]["raw_pointer_exposed"], false);
    assert_eq!(view["authority"]["pixel_write_allowed"], false);
    assert_eq!(view["authority"]["flush_allowed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 498);
}

#[test]
fn framebuffer_write_view_v1_exposes_semantic_pixel_write_refs() {
    let view = framebuffer_write_view_v1(&FramebufferWriteManifest {
        id: 23_501,
        owner_store: 12,
        owner_store_generation: 2,
        framebuffer_mapping: 23_401,
        framebuffer_mapping_generation: 1,
        framebuffer_window_lease: 23_301,
        framebuffer_window_lease_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        map_handle_slot: 3,
        map_handle_generation: 1,
        map_handle_tag: 0x4d41505f4642,
        x: 0,
        y: 0,
        width: 800,
        height: 1,
        byte_offset: 0,
        byte_len: 3200,
        pixel_format: "xrgb8888".to_owned(),
        payload_digest: 12_345,
        generation: 1,
        state: "applied".to_owned(),
        recorded_at_event: 499,
        note: "g5 framebuffer write".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-write");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_mapping"]["id"], 23_401);
    assert_eq!(view["references"]["framebuffer_window_lease"]["id"], 23_301);
    assert_eq!(view["map_handle"]["slot"], 3);
    assert_eq!(view["write"]["byte_len"], 3200);
    assert_eq!(view["write"]["pixel_format"], "xrgb8888");
    assert_eq!(view["authority"]["requires_framebuffer_mapping"], true);
    assert_eq!(view["authority"]["raw_pointer_exposed"], false);
    assert_eq!(view["authority"]["flush_allowed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 499);
}

#[test]
fn framebuffer_flush_region_view_v1_exposes_flush_refs() {
    let view = framebuffer_flush_region_view_v1(&FramebufferFlushRegionManifest {
        id: 23_601,
        owner_store: 12,
        owner_store_generation: 2,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        x: 0,
        y: 0,
        width: 800,
        height: 1,
        byte_offset: 0,
        byte_len: 3200,
        pixel_format: "xrgb8888".to_owned(),
        payload_digest: 12_345,
        generation: 1,
        state: "applied".to_owned(),
        recorded_at_event: 500,
        note: "g6 framebuffer flush".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-flush-region");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_write"]["id"], 23_501);
    assert_eq!(view["references"]["display_capability"]["id"], 23_201);
    assert_eq!(view["flush"]["byte_len"], 3200);
    assert_eq!(view["flush"]["pixel_format"], "xrgb8888");
    assert_eq!(view["authority"]["requires_display_capability_flush"], true);
    assert_eq!(view["authority"]["requires_framebuffer_write"], true);
    assert_eq!(view["authority"]["raw_pointer_exposed"], false);
    assert_eq!(view["authority"]["real_present_executed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 500);
}

#[test]
fn framebuffer_dirty_region_view_v1_exposes_dirty_tracking_refs() {
    let view = framebuffer_dirty_region_view_v1(&FramebufferDirtyRegionManifest {
        id: 23_701,
        owner_store: 12,
        owner_store_generation: 2,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        framebuffer_flush_region: Some(23_601),
        framebuffer_flush_region_generation: Some(1),
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        x: 0,
        y: 0,
        width: 800,
        height: 1,
        byte_offset: 0,
        byte_len: 3200,
        pixel_format: "xrgb8888".to_owned(),
        payload_digest: 12_345,
        generation: 1,
        state: "clean".to_owned(),
        dirty_at_event: 499,
        cleaned_at_event: Some(500),
        recorded_at_event: 501,
        note: "g7 framebuffer dirty region".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-dirty-region");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_write"]["id"], 23_501);
    assert_eq!(view["references"]["framebuffer_flush_region"]["id"], 23_601);
    assert_eq!(view["region"]["byte_len"], 3200);
    assert_eq!(view["region"]["pixel_format"], "xrgb8888");
    assert_eq!(view["authority"]["requires_framebuffer_write"], true);
    assert_eq!(view["authority"]["clean_state_requires_flush_region"], true);
    assert_eq!(view["authority"]["raw_pointer_exposed"], false);
    assert_eq!(view["authority"]["real_present_executed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 501);
}

#[test]
fn display_event_log_view_v1_exposes_event_window_refs() {
    let view = display_event_log_view_v1(&DisplayEventLogManifest {
        id: 23_801,
        owner_store: 12,
        owner_store_generation: 2,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        framebuffer_dirty_region: 23_701,
        framebuffer_dirty_region_generation: 1,
        first_event: 494,
        last_event: 501,
        event_count: 8,
        flush_count: 1,
        dirty_region_count: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 502,
        note: "g8 display event log".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-event-log");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_dirty_region"]["id"], 23_701);
    assert_eq!(view["window"]["first_event"], 494);
    assert_eq!(view["window"]["last_event"], 501);
    assert_eq!(view["window"]["event_count"], 8);
    assert_eq!(view["window"]["flush_count"], 1);
    assert_eq!(view["window"]["dirty_region_count"], 1);
    assert_eq!(view["authority"]["read_only_control_plane"], true);
    assert_eq!(view["authority"]["raw_event_storage_exposed"], false);
    assert_eq!(view["authority"]["real_present_executed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 502);
}

#[test]
fn display_cleanup_view_v1_exposes_cleanup_effects_and_generations() {
    let view = display_cleanup_view_v1(&DisplayCleanupManifest {
        id: 23_901,
        owner_store: 12,
        owner_store_generation: 2,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        generation: 1,
        state: "completed".to_owned(),
        reason: "display-window-cleanup".to_owned(),
        started_at_event: 503,
        completed_at_event: 505,
        unmapped_framebuffer_mappings: vec![ContractObjectRefManifest {
            kind: "framebuffer-mapping".to_owned(),
            id: 23_401,
            generation: 1,
        }],
        released_framebuffer_window_leases: vec![ContractObjectRefManifest {
            kind: "framebuffer-window-lease".to_owned(),
            id: 23_301,
            generation: 1,
        }],
        revoked_display_capabilities: vec![ContractObjectRefManifest {
            kind: "display-capability".to_owned(),
            id: 23_201,
            generation: 1,
        }],
        revoked_capabilities: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 77,
            generation: 2,
        }],
        steps: Vec::new(),
        note: "g9 display cleanup".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-cleanup");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["display_capability"]["id"], 23_201);
    assert_eq!(view["cleanup"]["reason"], "display-window-cleanup");
    assert_eq!(view["cleanup"]["unmapped_framebuffer_mappings"][0]["kind"], "framebuffer-mapping");
    assert_eq!(view["cleanup"]["released_framebuffer_window_leases"][0]["id"], 23_301);
    assert_eq!(view["cleanup"]["revoked_display_capabilities"][0]["generation"], 1);
    assert_eq!(view["cleanup"]["revoked_capabilities"][0]["generation"], 2);
    assert_eq!(view["authority"]["releases_handle_mode_mappings"], true);
    assert_eq!(view["authority"]["real_present_executed"], false);
    assert_eq!(view["last_transition"]["completed_at_event"], 505);
}

#[test]
fn display_snapshot_barrier_view_v1_exposes_quiescent_display_boundary() {
    let view = display_snapshot_barrier_view_v1(&DisplaySnapshotBarrierManifest {
        id: 24_001,
        owner_store: 12,
        owner_store_generation: 2,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        display_cleanup: Some(23_901),
        display_cleanup_generation: Some(1),
        active_framebuffer_window_lease_count: 0,
        active_framebuffer_mapping_count: 0,
        dirty_framebuffer_region_count: 0,
        snapshot_validation_ok: true,
        generation: 1,
        state: "validated".to_owned(),
        validated_at_event: 506,
        reason: "display-snapshot-barrier".to_owned(),
        note: "g10 display snapshot".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-snapshot-barrier");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["display_cleanup"]["id"], 23_901);
    assert_eq!(view["snapshot"]["snapshot_validation_ok"], true);
    assert_eq!(view["snapshot"]["active_framebuffer_window_lease_count"], 0);
    assert_eq!(view["authority"]["requires_no_active_framebuffer_lease"], true);
    assert_eq!(view["authority"]["real_snapshot_cow_executed"], false);
    assert_eq!(view["last_transition"]["validated_at_event"], 506);
}

#[test]
fn display_panic_last_frame_view_v1_exposes_panic_safe_summary() {
    let view = display_panic_last_frame_view_v1(&DisplayPanicLastFrameManifest {
        id: 25_001,
        owner_store: 12,
        owner_store_generation: 2,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        display_snapshot_barrier: 24_001,
        display_snapshot_barrier_generation: 1,
        display_event_log: 23_801,
        display_event_log_generation: 1,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        framebuffer_flush_region: 23_601,
        framebuffer_flush_region_generation: 1,
        x: 0,
        y: 0,
        width: 800,
        height: 1,
        byte_offset: 0,
        byte_len: 3200,
        pixel_format: "xrgb8888".to_owned(),
        payload_digest: 12_345,
        summary_digest: 54_321,
        summary_record_bytes: 512,
        panic_epoch: 1,
        panic_cpu: 0,
        panic_reason_code: 1,
        panic_record_kind: "contract-panic-summary-v1".to_owned(),
        raw_framebuffer_bytes_exported: false,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 507,
        note: "g11 display panic last-frame".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-panic-last-frame");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["display_snapshot_barrier"]["id"], 24_001);
    assert_eq!(view["references"]["display_event_log"]["id"], 23_801);
    assert_eq!(view["frame"]["payload_digest"], 12_345);
    assert_eq!(view["frame"]["summary_digest"], 54_321);
    assert_eq!(view["panic"]["record_kind"], "contract-panic-summary-v1");
    assert_eq!(view["panic"]["summary_record_bytes"], 512);
    assert_eq!(view["panic"]["raw_framebuffer_bytes_exported"], false);
    assert_eq!(view["authority"]["panic_path_allocates"], false);
    assert_eq!(view["authority"]["real_panic_ring_write_executed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 507);
}

#[test]
fn framebuffer_benchmark_view_v1_exposes_semantic_display_metrics() {
    let view = framebuffer_benchmark_view_v1(&FramebufferBenchmarkManifest {
        id: 25_101,
        scenario: "display-g12-single-flush".to_owned(),
        owner_store: 12,
        owner_store_generation: 2,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 1,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        framebuffer_flush_region: 23_601,
        framebuffer_flush_region_generation: 1,
        display_event_log: 23_801,
        display_event_log_generation: 1,
        display_snapshot_barrier: 24_001,
        display_snapshot_barrier_generation: 1,
        sample_frames: 1,
        sample_bytes: 3200,
        frame_area_pixels: 800,
        write_nanos: 40_000,
        flush_nanos: 60_000,
        measured_nanos: 100_000,
        budget_nanos: 200_000,
        throughput_bytes_per_sec: 32_000_000,
        flushes_per_sec_milli: 10_000_000,
        p50_latency_nanos: 100_000,
        p99_latency_nanos: 100_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 508,
        note: "g12 framebuffer benchmark".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-benchmark");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_write"]["id"], 23_501);
    assert_eq!(view["references"]["framebuffer_flush_region"]["id"], 23_601);
    assert_eq!(view["references"]["display_snapshot_barrier"]["id"], 24_001);
    assert_eq!(view["benchmark"]["sample_bytes"], 3200);
    assert_eq!(view["benchmark"]["throughput_bytes_per_sec"], 32_000_000);
    assert_eq!(view["benchmark"]["flushes_per_sec_milli"], 10_000_000);
    assert_eq!(view["authority"]["real_scanout_measured"], false);
    assert_eq!(view["authority"]["uses_semantic_write_flush_evidence"], true);
    assert_eq!(view["last_transition"]["recorded_at_event"], 508);
}

#[test]
fn integrated_smp_preemption_cleanup_view_v1_exposes_runtime_closure_refs() {
    let view = integrated_smp_preemption_cleanup_view_v1(&IntegratedSmpPreemptionCleanupManifest {
        id: 26_001,
        scenario: "x0-smp-preemption-cleanup".to_owned(),
        stress_run: 9_501,
        stress_run_generation: 1,
        preemption: 9_001,
        preemption_generation: 1,
        timer_interrupt: 9_001,
        timer_interrupt_generation: 1,
        saved_context: 9_002,
        saved_context_generation: 1,
        remote_preempt: 9_001,
        remote_preempt_generation: 1,
        activation_cleanup: 9_001,
        activation_cleanup_generation: 1,
        smp_cleanup_quiescence: 9_301,
        smp_cleanup_quiescence_generation: 1,
        cleanup_store: 14,
        target_store_generation: 2,
        result_store_generation: 3,
        cleanup_activation: 77,
        cleanup_activation_generation_after: 4,
        hart_count: 2,
        invariant_checks: 7,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 570,
        note: "x0 integrated runtime".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-smp-preemption-cleanup");
    assert_eq!(view["owner"]["cleanup_store"]["generation"], 2);
    assert_eq!(view["owner"]["runtime_activation"]["id"], 77);
    assert_eq!(view["owner"]["runtime_activation"]["generation_after_cleanup"], 4);
    assert_eq!(
        view["owner"]["runtime_activation"]["note"],
        "runtime-preemptive-activation-not-target-executor-object"
    );
    assert_eq!(view["references"]["smp_stress_run"]["id"], 9_501);
    assert_eq!(view["references"]["remote_preempt"]["generation"], 1);
    assert_eq!(view["references"]["activation_cleanup"]["id"], 9_001);
    assert_eq!(view["references"]["smp_cleanup_quiescence"]["id"], 9_301);
    assert_eq!(view["closure"]["hart_count"], 2);
    assert_eq!(view["closure"]["result_store_generation"], 3);
    assert_eq!(view["closure"]["invariant_checks"], 7);
    assert_eq!(view["authority"]["real_smp_preemption_executed"], false);
    assert_eq!(view["authority"]["uses_semantic_preemption_cleanup_evidence"], true);
    assert_eq!(view["last_transition"]["recorded_at_event"], 570);
}

#[test]
fn integrated_smp_network_fault_view_v1_exposes_network_fault_under_smp_refs() {
    let view = integrated_smp_network_fault_view_v1(&IntegratedSmpNetworkFaultManifest {
        id: 26_101,
        scenario: "x1-smp-network-driver-fault".to_owned(),
        network_driver_cleanup: 10_051,
        network_driver_cleanup_generation: 1,
        smp_stress_run: 9_501,
        smp_stress_run_generation: 1,
        remote_preempt: 9_001,
        remote_preempt_generation: 1,
        smp_cleanup_quiescence: 9_301,
        smp_cleanup_quiescence_generation: 1,
        driver_store: 7,
        driver_store_generation: 3,
        packet_device: 10_002,
        packet_device_generation: 1,
        adapter: 10_025,
        adapter_generation: 1,
        backend: ContractObjectRefManifest {
            kind: "virtio-net-backend-object".to_owned(),
            id: 10_010,
            generation: 1,
        },
        io_cleanup: 10_052,
        io_cleanup_generation: 1,
        cancelled_socket_wait_count: 1,
        cancelled_wait_token_count: 1,
        revoked_packet_capability_count: 1,
        hart_count: 2,
        invariant_checks: 7,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 571,
        note: "x1 integrated network fault".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-smp-network-fault");
    assert_eq!(view["owner"]["driver_store"]["generation"], 3);
    assert_eq!(view["owner"]["packet_device"]["id"], 10_002);
    assert_eq!(view["references"]["network_driver_cleanup"]["id"], 10_051);
    assert_eq!(view["references"]["smp_stress_run"]["id"], 9_501);
    assert_eq!(view["references"]["remote_preempt"]["generation"], 1);
    assert_eq!(view["references"]["smp_cleanup_quiescence"]["id"], 9_301);
    assert_eq!(view["references"]["backend"]["kind"], "virtio-net-backend-object");
    assert_eq!(view["references"]["io_cleanup"]["id"], 10_052);
    assert_eq!(view["closure"]["hart_count"], 2);
    assert_eq!(view["closure"]["cancelled_socket_wait_count"], 1);
    assert_eq!(view["closure"]["revoked_packet_capability_count"], 1);
    assert_eq!(view["authority"]["adapter_internal_state_is_not_semantic_truth"], true);
    assert_eq!(view["authority"]["real_network_driver_fault_executed"], false);
    assert_eq!(view["last_transition"]["event"], 571);
}

#[test]
fn integrated_disk_preempt_fault_view_v1_exposes_pending_io_and_preemption_refs() {
    let view = integrated_disk_preempt_fault_view_v1(&IntegratedDiskPreemptFaultManifest {
        id: 26_201,
        scenario: "x2-disk-pending-io-fault-under-preemption".to_owned(),
        preemption: 9_070,
        preemption_generation: 1,
        timer_interrupt: 9_070,
        timer_interrupt_generation: 1,
        block_pending_io_policy: 20_124,
        block_pending_io_policy_generation: 1,
        block_wait: 20_118,
        block_wait_generation: 1,
        wait: 20_117,
        wait_generation: 1,
        block_request: 20_116,
        block_request_generation: 1,
        retry_request: None,
        retry_request_generation: None,
        block_device: 20_002,
        block_device_generation: 1,
        block_range: 20_005,
        block_range_generation: 1,
        driver_store: Some(15),
        driver_store_generation: Some(2),
        action: "eio".to_owned(),
        errno: 5,
        preempted_activation: 88,
        preempted_activation_generation_after: 4,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 572,
        note: "x2 integrated disk preempt fault".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-disk-preempt-fault");
    assert_eq!(view["owner"]["driver_store"]["id"], 15);
    assert_eq!(view["references"]["preemption"]["id"], 9_070);
    assert_eq!(view["references"]["timer_interrupt"]["generation"], 1);
    assert_eq!(view["references"]["block_pending_io_policy"]["id"], 20_124);
    assert_eq!(view["references"]["block_wait"]["id"], 20_118);
    assert_eq!(view["references"]["wait"]["kind"], "wait-token");
    assert_eq!(view["references"]["block_request"]["id"], 20_116);
    assert_eq!(view["references"]["retry_request"], serde_json::Value::Null);
    assert_eq!(view["references"]["block_device"]["id"], 20_002);
    assert_eq!(view["references"]["block_range"]["id"], 20_005);
    assert_eq!(view["closure"]["action"], "eio");
    assert_eq!(view["closure"]["errno"], 5);
    assert_eq!(view["closure"]["preempted_activation"]["id"], 88);
    assert_eq!(view["authority"]["adapter_internal_state_is_not_semantic_truth"], true);
    assert_eq!(view["authority"]["real_disk_fault_executed"], false);
    assert_eq!(view["last_transition"]["event"], 572);
}

#[test]
fn integrated_simd_migration_view_v1_exposes_vector_rehome_refs() {
    let view = integrated_simd_migration_view_v1(&IntegratedSimdMigrationManifest {
        id: 26_301,
        scenario: "x3-simd-task-migration-across-harts".to_owned(),
        activation_migration: 9_080,
        activation_migration_generation: 1,
        target_feature_set: 21_003,
        target_feature_set_generation: 1,
        source_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_004,
            generation: 1,
        },
        migrated_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_005,
            generation: 1,
        },
        activation: 89,
        activation_generation_before: 2,
        activation_generation_after: 3,
        context: 9_080,
        context_generation_after: 3,
        source_hart: 8,
        source_hart_generation: 2,
        target_hart: 9,
        target_hart_generation: 2,
        source_queue: 9_080,
        source_queue_generation: 2,
        target_queue: 9_081,
        target_queue_generation: 2,
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 573,
        note: "x3 integrated SIMD migration".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-simd-migration");
    assert_eq!(view["owner"]["activation"]["id"], 89);
    assert_eq!(view["owner"]["source_hart"]["id"], 8);
    assert_eq!(view["owner"]["target_hart"]["id"], 9);
    assert_eq!(view["references"]["activation_migration"]["id"], 9_080);
    assert_eq!(view["references"]["target_feature_set"]["id"], 21_003);
    assert_eq!(view["references"]["source_vector_state"]["id"], 22_004);
    assert_eq!(view["references"]["migrated_vector_state"]["id"], 22_005);
    assert_eq!(view["references"]["context"]["generation"], 3);
    assert_eq!(view["closure"]["simd_abi"], "riscv-v");
    assert_eq!(view["closure"]["requires_clean_vector_context"], true);
    assert_eq!(view["closure"]["requires_source_vector_dropped"], true);
    assert_eq!(view["authority"]["adapter_internal_state_is_not_semantic_truth"], true);
    assert_eq!(view["authority"]["real_vector_register_payload_migrated"], false);
    assert_eq!(view["last_transition"]["event"], 573);
}

#[test]
fn integrated_simd_migration_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_simd_migration_count = 1;
    package.semantic.integrated_simd_migrations.push(IntegratedSimdMigrationManifest {
        id: 26_301,
        scenario: "x3-simd-task-migration-across-harts".to_owned(),
        activation_migration: 9_080,
        activation_migration_generation: 1,
        target_feature_set: 21_003,
        target_feature_set_generation: 1,
        source_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_004,
            generation: 1,
        },
        migrated_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_005,
            generation: 1,
        },
        activation: 89,
        activation_generation_before: 2,
        activation_generation_after: 3,
        context: 9_080,
        context_generation_after: 3,
        source_hart: 8,
        source_hart_generation: 2,
        target_hart: 9,
        target_hart_generation: 2,
        source_queue: 9_080,
        source_queue_generation: 2,
        target_queue: 9_081,
        target_queue_generation: 2,
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 573,
        note: "x3 integrated SIMD migration".to_owned(),
    });

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "integrated-simd-migration"));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-simd-migration"
        && edge["relation"] == "integrated-source-vector-state"
        && edge["to"]["kind"] == "vector-state"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-simd-migration"
        && edge["relation"] == "integrated-migrated-vector-state"
        && edge["to"]["kind"] == "vector-state"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-simd-migration"
        && edge["relation"] == "integrated-activation-migration"
        && edge["to"]["kind"] == "activation-migration"
        && edge["to"]["generation"] == 1));
}

#[test]
fn integrated_network_disk_io_view_v1_exposes_benchmark_refs() {
    let view = integrated_network_disk_io_view_v1(&IntegratedNetworkDiskIoManifest {
        id: 26_401,
        scenario: "x4-network-disk-concurrent-io".to_owned(),
        network_benchmark: 10_067,
        network_benchmark_generation: 1,
        block_benchmark: 20_132,
        block_benchmark_generation: 1,
        network_owner_store: 9,
        network_owner_store_generation: 3,
        network_adapter: 10_025,
        network_adapter_generation: 1,
        packet_device: 10_002,
        packet_device_generation: 1,
        socket: 10_031,
        socket_generation: 1,
        block_backend: ContractObjectRefManifest {
            kind: "fake-block-backend-object".to_owned(),
            id: 20_026,
            generation: 1,
        },
        block_device: 20_002,
        block_device_generation: 1,
        block_request_queue: 20_053,
        block_request_queue_generation: 1,
        block_dma_buffer: 20_061,
        block_dma_buffer_generation: 1,
        network_sample_bytes: 6_000,
        block_sample_bytes: 8_192,
        network_sample_packets: 3,
        block_sample_requests: 2,
        concurrent_window_nanos: 120_000,
        combined_throughput_bytes_per_sec: 118_266_666,
        max_p99_latency_nanos: 48_000,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 574,
        note: "x4 integrated IO concurrency".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-network-disk-io");
    assert_eq!(view["owner"]["network_owner_store"]["generation"], 3);
    assert_eq!(view["references"]["network_benchmark"]["id"], 10_067);
    assert_eq!(view["references"]["block_benchmark"]["id"], 20_132);
    assert_eq!(view["references"]["block_backend"]["kind"], "fake-block-backend-object");
    assert_eq!(view["references"]["block_dma_buffer"]["id"], 20_061);
    assert_eq!(view["closure"]["network_sample_bytes"], 6_000);
    assert_eq!(view["closure"]["block_sample_bytes"], 8_192);
    assert_eq!(view["closure"]["concurrent_window_nanos"], 120_000);
    assert_eq!(view["closure"]["combined_throughput_bytes_per_sec"], 118_266_666);
    assert_eq!(view["authority"]["adapter_internal_state_is_not_semantic_truth"], true);
    assert_eq!(view["authority"]["real_concurrent_hardware_io_executed"], false);
}

#[test]
fn integrated_network_disk_io_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_network_disk_io_count = 1;
    package.semantic.integrated_network_disk_ios.push(IntegratedNetworkDiskIoManifest {
        id: 26_401,
        scenario: "x4-network-disk-concurrent-io".to_owned(),
        network_benchmark: 10_067,
        network_benchmark_generation: 1,
        block_benchmark: 20_132,
        block_benchmark_generation: 1,
        network_owner_store: 9,
        network_owner_store_generation: 3,
        network_adapter: 10_025,
        network_adapter_generation: 1,
        packet_device: 10_002,
        packet_device_generation: 1,
        socket: 10_031,
        socket_generation: 1,
        block_backend: ContractObjectRefManifest {
            kind: "fake-block-backend-object".to_owned(),
            id: 20_026,
            generation: 1,
        },
        block_device: 20_002,
        block_device_generation: 1,
        block_request_queue: 20_053,
        block_request_queue_generation: 1,
        block_dma_buffer: 20_061,
        block_dma_buffer_generation: 1,
        network_sample_bytes: 6_000,
        block_sample_bytes: 8_192,
        network_sample_packets: 3,
        block_sample_requests: 2,
        concurrent_window_nanos: 120_000,
        combined_throughput_bytes_per_sec: 118_266_666,
        max_p99_latency_nanos: 48_000,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 574,
        note: "x4 integrated IO concurrency".to_owned(),
    });

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "integrated-network-disk-io"));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-network-disk-io"
        && edge["relation"] == "integrated-network-benchmark"
        && edge["to"]["kind"] == "network-benchmark"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-network-disk-io"
        && edge["relation"] == "integrated-block-dma-buffer"
        && edge["to"]["kind"] == "block-dma-buffer"
        && edge["to"]["generation"] == 1));
}

#[test]
fn integrated_display_scheduler_load_view_v1_exposes_display_and_scheduler_refs() {
    let view = integrated_display_scheduler_load_view_v1(&IntegratedDisplaySchedulerLoadManifest {
        id: 26_501,
        scenario: "x5-display-update-during-scheduler-load".to_owned(),
        framebuffer_benchmark: 25_101,
        framebuffer_benchmark_generation: 1,
        scheduler_decision: 9_001,
        scheduler_decision_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        owner_task: 7,
        owner_task_generation: 1,
        queue: 9_002,
        queue_generation: 2,
        selected_activation: 9_002,
        selected_activation_generation: 4,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 1,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        framebuffer_flush_region: 23_601,
        framebuffer_flush_region_generation: 1,
        display_event_log: 23_801,
        display_event_log_generation: 1,
        sample_frames: 1,
        sample_bytes: 3_200,
        scheduler_load_units: 1,
        display_measured_nanos: 100_000,
        scheduler_decided_at_event: 50,
        display_recorded_at_event: 571,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 575,
        note: "x5 integrated display scheduler load".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-display-scheduler-load");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_benchmark"]["id"], 25_101);
    assert_eq!(view["references"]["scheduler_decision"]["id"], 9_001);
    assert_eq!(view["references"]["selected_activation"]["generation"], 4);
    assert_eq!(view["closure"]["sample_bytes"], 3_200);
    assert_eq!(view["closure"]["scheduler_load_units"], 1);
    assert_eq!(view["authority"]["real_display_hardware_executed"], false);
    assert_eq!(view["authority"]["real_preemptive_scheduler_executed"], false);
}

#[test]
fn integrated_display_scheduler_load_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_display_scheduler_load_count = 1;
    package.semantic.integrated_display_scheduler_loads.push(
        IntegratedDisplaySchedulerLoadManifest {
            id: 26_501,
            scenario: "x5-display-update-during-scheduler-load".to_owned(),
            framebuffer_benchmark: 25_101,
            framebuffer_benchmark_generation: 1,
            scheduler_decision: 9_001,
            scheduler_decision_generation: 1,
            owner_store: 1,
            owner_store_generation: 2,
            owner_task: 7,
            owner_task_generation: 1,
            queue: 9_002,
            queue_generation: 2,
            selected_activation: 9_002,
            selected_activation_generation: 4,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            display_capability: 23_201,
            display_capability_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            sample_frames: 1,
            sample_bytes: 3_200,
            scheduler_load_units: 1,
            display_measured_nanos: 100_000,
            scheduler_decided_at_event: 50,
            display_recorded_at_event: 571,
            invariant_checks: 6,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 575,
            note: "x5 integrated display scheduler load".to_owned(),
        },
    );

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "integrated-display-scheduler-load"));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-display-scheduler-load"
        && edge["relation"] == "integrated-framebuffer-benchmark"
        && edge["to"]["kind"] == "framebuffer-benchmark"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-display-scheduler-load"
        && edge["relation"] == "integrated-scheduler-decision"
        && edge["to"]["kind"] == "scheduler-decision"
        && edge["to"]["generation"] == 1));
}

fn test_integrated_snapshot_io_lease_barrier_manifest() -> IntegratedSnapshotIoLeaseBarrierManifest
{
    IntegratedSnapshotIoLeaseBarrierManifest {
        id: 26_601,
        scenario: "x6-snapshot-barrier-blocks-active-io-leases".to_owned(),
        smp_snapshot_barrier: 9_401,
        smp_snapshot_barrier_generation: 1,
        io_cleanup: 9_967,
        io_cleanup_generation: 1,
        display_snapshot_barrier: 24_001,
        display_snapshot_barrier_generation: 1,
        driver_store: 2,
        driver_store_generation: 2,
        device: 9_701,
        device_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        active_dmw_lease_count: 0,
        in_flight_dma_count: 0,
        raw_dma_binding_count: 0,
        raw_mmio_binding_count: 0,
        active_framebuffer_window_lease_count: 0,
        active_framebuffer_mapping_count: 0,
        dirty_framebuffer_region_count: 0,
        released_dma_buffers: 1,
        released_mmio_regions: 1,
        released_irq_lines: 1,
        released_framebuffer_window_leases: 1,
        revoked_device_capabilities: 4,
        revoked_display_capabilities: 1,
        smp_barrier_event: 117,
        io_cleanup_completed_event: 152,
        display_barrier_event: 567,
        invariant_checks: 7,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 576,
        note: "x6 integrated snapshot/io lease barrier".to_owned(),
    }
}

#[test]
fn integrated_snapshot_io_lease_barrier_view_v1_exposes_barrier_and_cleanup_refs() {
    let view = integrated_snapshot_io_lease_barrier_view_v1(
        &test_integrated_snapshot_io_lease_barrier_manifest(),
    );

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-snapshot-io-lease-barrier");
    assert_eq!(view["owner"]["driver_store"]["generation"], 2);
    assert_eq!(view["owner"]["device"]["id"], 9_701);
    assert_eq!(view["owner"]["display"]["id"], 23_101);
    assert_eq!(view["references"]["smp_snapshot_barrier"]["id"], 9_401);
    assert_eq!(view["references"]["io_cleanup"]["id"], 9_967);
    assert_eq!(view["references"]["display_snapshot_barrier"]["id"], 24_001);
    assert_eq!(view["closure"]["active_dmw_lease_count"], 0);
    assert_eq!(view["closure"]["in_flight_dma_count"], 0);
    assert_eq!(view["closure"]["released_dma_buffers"], 1);
    assert_eq!(view["closure"]["released_mmio_regions"], 1);
    assert_eq!(view["closure"]["released_irq_lines"], 1);
    assert_eq!(view["closure"]["released_framebuffer_window_leases"], 1);
    assert_eq!(view["closure"]["requires_clean_smp_snapshot_barrier"], true);
    assert_eq!(view["closure"]["requires_completed_io_cleanup"], true);
    assert_eq!(view["closure"]["requires_clean_display_snapshot_barrier"], true);
    assert_eq!(view["authority"]["real_snapshot_or_dma_hardware_executed"], false);
    assert_eq!(view["authority"]["real_display_hardware_executed"], false);
    assert_eq!(view["last_transition"]["event"], 576);
}

#[test]
fn integrated_snapshot_io_lease_barrier_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_snapshot_io_lease_barrier_count = 1;
    package
        .semantic
        .integrated_snapshot_io_lease_barriers
        .push(test_integrated_snapshot_io_lease_barrier_manifest());

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(
        !live.iter().any(|edge| { edge["from"]["kind"] == "integrated-snapshot-io-lease-barrier" })
    );

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-snapshot-io-lease-barrier"
        && edge["relation"] == "integrated-smp-snapshot-barrier"
        && edge["to"]["kind"] == "smp-snapshot-barrier"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-snapshot-io-lease-barrier"
        && edge["relation"] == "integrated-io-cleanup"
        && edge["to"]["kind"] == "io-cleanup"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-snapshot-io-lease-barrier"
        && edge["relation"] == "integrated-display-snapshot-barrier"
        && edge["to"]["kind"] == "display-snapshot-barrier"
        && edge["to"]["generation"] == 1));
}

fn test_integrated_code_publish_smp_workload_manifest() -> IntegratedCodePublishSmpWorkloadManifest
{
    IntegratedCodePublishSmpWorkloadManifest {
        id: 26_701,
        scenario: "x7-code-publish-while-smp-workload-active".to_owned(),
        smp_stress_run: 9_501,
        smp_stress_run_generation: 1,
        smp_code_publish_barrier: 9_201,
        smp_code_publish_barrier_generation: 1,
        publish_rendezvous: 9_101,
        publish_rendezvous_generation: 1,
        publish_safe_point: 9_001,
        publish_safe_point_generation: 1,
        hart_count: 2,
        workload_iterations: 3,
        observed_safe_point_count: 3,
        observed_rendezvous_count: 3,
        observed_code_publish_barrier_count: 1,
        code_publish_epoch_before: 0,
        code_publish_epoch_after: 1,
        remote_icache_sync_required: true,
        code_publish_executed: false,
        participant_count: 2,
        stress_event_log_cursor: 117,
        barrier_event: 24,
        stress_recorded_at_event: 118,
        invariant_checks: 7,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 577,
        note: "x7 semantic code publish while smp workload is active".to_owned(),
    }
}

#[test]
fn integrated_code_publish_smp_workload_view_v1_exposes_publish_and_stress_refs() {
    let view = integrated_code_publish_smp_workload_view_v1(
        &test_integrated_code_publish_smp_workload_manifest(),
    );

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-code-publish-smp-workload");
    assert_eq!(view["owner"]["hart_count"], 2);
    assert_eq!(view["references"]["smp_stress_run"]["id"], 9_501);
    assert_eq!(view["references"]["smp_code_publish_barrier"]["id"], 9_201);
    assert_eq!(view["references"]["publish_rendezvous"]["id"], 9_101);
    assert_eq!(view["references"]["publish_safe_point"]["generation"], 1);
    assert_eq!(view["closure"]["code_publish_epoch_before"], 0);
    assert_eq!(view["closure"]["code_publish_epoch_after"], 1);
    assert_eq!(view["closure"]["remote_icache_sync_required"], true);
    assert_eq!(view["closure"]["code_publish_executed"], false);
    assert_eq!(view["authority"]["real_smp_dynamic_code_publish_executed"], false);
    assert_eq!(view["last_transition"]["event"], 577);
}

#[test]
fn integrated_code_publish_smp_workload_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_code_publish_smp_workload_count = 1;
    package
        .semantic
        .integrated_code_publish_smp_workloads
        .push(test_integrated_code_publish_smp_workload_manifest());

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(
        !live.iter().any(|edge| { edge["from"]["kind"] == "integrated-code-publish-smp-workload" })
    );

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-code-publish-smp-workload"
        && edge["relation"] == "integrated-smp-stress-run"
        && edge["to"]["kind"] == "smp-stress-run"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-code-publish-smp-workload"
        && edge["relation"] == "integrated-smp-code-publish-barrier"
        && edge["to"]["kind"] == "smp-code-publish-barrier"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-code-publish-smp-workload"
        && edge["relation"] == "integrated-publish-rendezvous"
        && edge["to"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["generation"] == 1));
}

fn test_integrated_display_panic_manifest() -> IntegratedDisplayPanicManifest {
    IntegratedDisplayPanicManifest {
        id: 26_801,
        scenario: "x8-panic-ring-extraction-after-substrate-panic".to_owned(),
        substrate_panic_event: 578,
        substrate_panic_epoch: 1,
        substrate_panic_cpu: 0,
        substrate_panic_reason_code: 1,
        display_panic_last_frame: 25_001,
        display_panic_last_frame_generation: 1,
        panic_ring_bytes: 65_536,
        panic_record_max_bytes: 4_096,
        panic_ring_oldest_seq: 1,
        panic_ring_newest_seq: 3,
        panic_ring_record_count: 3,
        panic_ring_lost_count: 0,
        jsonl_frame_count: 5,
        contract_panic_summary_records: 1,
        last_frame_summary_records: 1,
        corrupt_record_count: 0,
        truncated_record_count: 0,
        summary_record_bytes: 128,
        raw_framebuffer_bytes_exported: false,
        panic_path_allocates: false,
        invariant_checks: 8,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 579,
        note: "x8 semantic panic ring extraction after substrate panic".to_owned(),
    }
}

#[test]
fn integrated_display_panic_view_v1_exposes_panic_ring_and_last_frame_refs() {
    let view = integrated_display_panic_view_v1(&test_integrated_display_panic_manifest());

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-display-panic");
    assert_eq!(view["owner"]["panic_epoch"], 1);
    assert_eq!(view["owner"]["panic_cpu"], 0);
    assert_eq!(view["references"]["substrate_panic_event"]["id"], 578);
    assert_eq!(view["references"]["display_panic_last_frame"]["id"], 25_001);
    assert_eq!(view["references"]["display_panic_last_frame"]["generation"], 1);
    assert_eq!(view["panic_ring"]["ring_bytes"], 65_536);
    assert_eq!(view["panic_ring"]["record_max_bytes"], 4_096);
    assert_eq!(view["panic_ring"]["record_count"], 3);
    assert_eq!(view["panic_ring"]["jsonl_frame_count"], 5);
    assert_eq!(view["panic_ring"]["contract_panic_summary_records"], 1);
    assert_eq!(view["panic_ring"]["corrupt_record_count"], 0);
    assert_eq!(view["panic_ring"]["truncated_record_count"], 0);
    assert_eq!(view["panic_ring"]["raw_framebuffer_bytes_exported"], false);
    assert_eq!(view["closure"]["requires_display_panic_last_frame"], true);
    assert_eq!(view["closure"]["requires_no_raw_framebuffer_bytes"], true);
    assert_eq!(view["authority"]["target_to_host_extraction_only"], true);
    assert_eq!(view["authority"]["real_substrate_halt_executed"], false);
    assert_eq!(view["last_transition"]["event"], 579);
}

#[test]
fn integrated_display_panic_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_display_panic_count = 1;
    package.semantic.integrated_display_panics.push(test_integrated_display_panic_manifest());

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(!live.iter().any(|edge| { edge["from"]["kind"] == "integrated-display-panic" }));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-display-panic"
        && edge["relation"] == "integrated-display-panic->display-panic-last-frame"
        && edge["to"]["kind"] == "display-panic-last-frame"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-display-panic"
        && edge["relation"] == "integrated-display-panic->substrate-panic-event"
        && edge["to"]["kind"] == "substrate-event"
        && edge["to"]["id"] == 578));
}

fn test_integrated_osctl_trace_replay_manifest() -> IntegratedOsctlTraceReplayManifest {
    IntegratedOsctlTraceReplayManifest {
        id: 26_901,
        scenario: "x9-full-osctl-trace-replay".to_owned(),
        integrated_smp_preemption_cleanup: 26_001,
        integrated_smp_preemption_cleanup_generation: 1,
        integrated_smp_network_fault: 26_101,
        integrated_smp_network_fault_generation: 1,
        integrated_disk_preempt_fault: 26_201,
        integrated_disk_preempt_fault_generation: 1,
        integrated_simd_migration: 26_301,
        integrated_simd_migration_generation: 1,
        integrated_network_disk_io: 26_401,
        integrated_network_disk_io_generation: 1,
        integrated_display_scheduler_load: 26_501,
        integrated_display_scheduler_load_generation: 1,
        integrated_snapshot_io_lease_barrier: 26_601,
        integrated_snapshot_io_lease_barrier_generation: 1,
        integrated_code_publish_smp_workload: 26_701,
        integrated_code_publish_smp_workload_generation: 1,
        integrated_display_panic: 26_801,
        integrated_display_panic_generation: 1,
        replay_event_cursor: 579,
        stable_view_count: 9,
        historical_edge_count: 9,
        replayed_root_count: 9,
        integrated_scenario_count: 9,
        replay_fixture_count: 9,
        contract_validation_ok: true,
        replay_validation_ok: true,
        graph_history_ok: true,
        roots_match_counts: true,
        invariant_checks: 9,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 580,
        note: "x9 full osctl trace replay closure across integrated scenarios".to_owned(),
    }
}

#[test]
fn integrated_osctl_trace_replay_view_v1_exposes_replay_closure() {
    let view =
        integrated_osctl_trace_replay_view_v1(&test_integrated_osctl_trace_replay_manifest());

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-osctl-trace-replay");
    assert_eq!(view["id"], 26_901);
    assert_eq!(view["generation"], 1);
    assert_eq!(view["owner"]["scenario"], "x9-full-osctl-trace-replay");
    assert_eq!(view["owner"]["integrated_scenario_count"], 9);
    assert_eq!(
        view["references"]["x0_smp_preemption_cleanup"]["kind"],
        "integrated-smp-preemption-cleanup"
    );
    assert_eq!(view["references"]["x0_smp_preemption_cleanup"]["id"], 26_001);
    assert_eq!(view["references"]["x8_display_panic"]["id"], 26_801);
    assert_eq!(view["references"]["x8_display_panic"]["generation"], 1);
    assert_eq!(view["replay"]["event_cursor"], 579);
    assert_eq!(view["replay"]["stable_view_count"], 9);
    assert_eq!(view["replay"]["historical_edge_count"], 9);
    assert_eq!(view["replay"]["replay_fixture_count"], 9);
    assert_eq!(view["replay"]["contract_validation_ok"], true);
    assert_eq!(view["replay"]["replay_validation_ok"], true);
    assert_eq!(view["replay"]["graph_history_ok"], true);
    assert_eq!(view["closure"]["requires_x0_to_x8_integrated_evidence"], true);
    assert_eq!(view["authority"]["osctl_is_read_only_control_plane"], true);
    assert_eq!(view["authority"]["adapter_internal_state_is_not_semantic_truth"], true);
    assert_eq!(view["last_transition"]["event"], 580);
}

#[test]
fn integrated_osctl_trace_replay_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_osctl_trace_replay_count = 1;
    package
        .semantic
        .integrated_osctl_trace_replays
        .push(test_integrated_osctl_trace_replay_manifest());

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(!live.iter().any(|edge| { edge["from"]["kind"] == "integrated-osctl-trace-replay" }));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-osctl-trace-replay"
        && edge["relation"] == "integrated-osctl-trace-replay->x0-smp-preemption-cleanup"
        && edge["to"]["kind"] == "integrated-smp-preemption-cleanup"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-osctl-trace-replay"
        && edge["relation"] == "integrated-osctl-trace-replay->x8-display-panic"
        && edge["to"]["kind"] == "integrated-display-panic"
        && edge["to"]["id"] == 26_801
        && edge["to"]["generation"] == 1));
}

#[test]
fn activation_context_view_v1_exposes_vector_clean_dirty_state() {
    let view = activation_context_view_v1(&ActivationContextManifest {
        id: 12,
        activation: 11,
        activation_generation: 3,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: Some(2),
        owner_store_generation: Some(5),
        generation: 4,
        state: "current".to_owned(),
        current_saved_context: None,
        current_saved_context_generation: None,
        vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_000,
            generation: 1,
        }),
        vector_status: "dirty".to_owned(),
        vector_state_event: Some(42),
        last_event: Some(42),
    });

    assert_eq!(view["kind"], "activation-context");
    assert_eq!(view["vector_context"]["status"], "dirty");
    assert_eq!(view["vector_context"]["vector_state"]["kind"], "vector-state");
    assert_eq!(view["vector_context"]["vector_state"]["generation"], 1);
    assert_eq!(view["references"]["vector_state"]["id"], 22_000);
    assert_eq!(view["vector_context"]["last_event"], 42);
}

#[test]
fn saved_context_view_v1_exposes_preempted_vector_state() {
    let view = saved_context_view_v1(&SavedContextManifest {
        id: 13,
        context: 12,
        context_generation: 4,
        activation: 11,
        activation_generation: 4,
        owner_task: 7,
        owner_task_generation: 1,
        source_preemption: Some(6),
        source_preemption_generation: Some(1),
        generation: 2,
        state: "captured".to_owned(),
        reason: "timer-preempt".to_owned(),
        pc: 0x2000,
        sp: 0x9000,
        flags: 0,
        integer_registers: 33,
        vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_002,
            generation: 1,
        }),
        vector_status: "clean".to_owned(),
        vector_saved_at_event: Some(77),
        saved_at_event: 41,
        note: "preempted vector frame".to_owned(),
    });

    assert_eq!(view["kind"], "saved-context");
    assert_eq!(view["references"]["vector_state"]["kind"], "vector-state");
    assert_eq!(view["references"]["vector_state"]["id"], 22_002);
    assert_eq!(view["vector_context"]["status"], "clean");
    assert_eq!(view["vector_context"]["saved_at_event"], 77);
}

#[test]
fn activation_resume_view_v1_exposes_vector_restore_refs() {
    let view = activation_resume_view_v1(&ActivationResumeManifest {
        id: 15,
        scheduler_decision: 14,
        scheduler_decision_generation: 1,
        activation: 11,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 7,
        owner_task_generation: 1,
        queue: 1,
        queue_generation: 1,
        context: Some(12),
        context_generation_before: Some(4),
        context_generation_after: Some(5),
        saved_context: Some(13),
        saved_context_generation: Some(3),
        saved_vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_002,
            generation: 1,
        }),
        restored_vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_003,
            generation: 1,
        }),
        vector_status: "clean".to_owned(),
        vector_restored_at_event: Some(88),
        generation: 1,
        state: "applied".to_owned(),
        resumed_at_event: 87,
        note: "resume restores vector state".to_owned(),
    });

    assert_eq!(view["kind"], "activation-resume");
    assert_eq!(view["vector_restore"]["status"], "clean");
    assert_eq!(view["references"]["saved_vector_state"]["id"], 22_002);
    assert_eq!(view["references"]["restored_vector_state"]["id"], 22_003);
    assert_eq!(view["vector_restore"]["restored_at_event"], 88);
}

#[test]
fn activation_migration_view_v1_exposes_vector_migration_refs() {
    let view = activation_migration_view_v1(&ActivationMigrationManifest {
        id: 71,
        activation: 11,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 7,
        owner_task_generation: 1,
        source_hart: 2,
        source_hart_generation: 4,
        target_hart: 1,
        target_hart_generation: 2,
        source_queue: 2,
        source_queue_generation: 2,
        source_queue_owner_hart_generation: 4,
        target_queue: 3,
        target_queue_generation: 2,
        target_queue_owner_hart_generation: 2,
        context: Some(12),
        context_generation_before: Some(2),
        context_generation_after: Some(3),
        source_vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_004,
            generation: 1,
        }),
        migrated_vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_005,
            generation: 1,
        }),
        vector_status: "clean".to_owned(),
        vector_migrated_at_event: Some(99),
        generation: 1,
        state: "applied".to_owned(),
        migrated_at_event: 98,
        reason: "vector-rebalance".to_owned(),
        note: "cross-hart migration rehomes vector state".to_owned(),
    });

    assert_eq!(view["kind"], "activation-migration");
    assert_eq!(view["vector_migration"]["status"], "clean");
    assert_eq!(view["references"]["context"]["id"], 12);
    assert_eq!(view["references"]["source_vector_state"]["id"], 22_004);
    assert_eq!(view["references"]["migrated_vector_state"]["id"], 22_005);
    assert_eq!(view["vector_migration"]["event"], 99);
}

#[test]
fn preemptive_runtime_views_expose_task_activation_and_scheduler_state() {
    let task = task_view_v1(&TaskRecordManifest {
        id: 7,
        label: "linux-thread-7".to_owned(),
        frontend: "linux-elf".to_owned(),
        state: "runnable".to_owned(),
        generation: 1,
        fault_domain: None,
        pending_wait: None,
        resources: vec![3],
    });
    assert_eq!(task["kind"], "task");
    assert_eq!(task["owner"]["frontend"], "linux-elf");
    assert_eq!(task["references"]["resources"][0], 3);

    let activation = runtime_activation_view_v1(&RuntimeActivationRecordManifest {
        id: 11,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: None,
        owner_store_generation: None,
        code_object: Some(ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 4,
            generation: 1,
        }),
        generation: 2,
        state: "runnable".to_owned(),
        runnable_queue: Some(1),
        runnable_queue_generation: Some(1),
        last_event: Some(9),
    });
    assert_eq!(activation["kind"], "activation");
    assert_eq!(activation["owner"]["task"], 7);
    assert_eq!(activation["owner"]["task_generation"], 1);
    assert_eq!(activation["references"]["runnable_queue"]["id"], 1);
    assert_eq!(activation["references"]["runnable_queue"]["generation"], 1);

    let mut package = minimal_graph_package();
    package.package_id = "p0-test".to_owned();
    package.substrate_boundary.scheduler_decision_cursor = 12;
    package.semantic.hart_count = 2;
    package.semantic.task_record_count = 1;
    package.semantic.runtime_activation_count = 1;
    package.semantic.runnable_queue_count = 1;
    package.semantic.activation_context_count = 1;
    package.semantic.saved_context_count = 1;
    package.semantic.timer_interrupt_count = 1;
    package.semantic.ipi_event_count = 1;
    package.semantic.remote_preempt_count = 1;
    package.semantic.remote_park_count = 1;
    package.semantic.preemption_count = 1;
    package.semantic.scheduler_decision_count = 1;
    package.semantic.cross_hart_scheduler_decision_count = 1;
    package.semantic.activation_migration_count = 1;
    package.semantic.smp_safe_point_count = 1;
    package.semantic.stop_the_world_rendezvous_count = 1;
    package.semantic.smp_code_publish_barrier_count = 1;
    package.semantic.smp_cleanup_quiescence_count = 1;
    package.semantic.smp_snapshot_barrier_count = 1;
    package.semantic.smp_stress_run_count = 1;
    package.semantic.smp_scaling_benchmark_count = 1;
    package.semantic.device_object_count = 1;
    package.semantic.queue_object_count = 1;
    package.semantic.descriptor_object_count = 1;
    package.semantic.dma_buffer_object_count = 1;
    package.semantic.mmio_region_object_count = 1;
    package.semantic.irq_line_object_count = 1;
    package.semantic.irq_event_count = 1;
    package.semantic.device_capability_count = 2;
    package.semantic.driver_store_binding_count = 1;
    package.semantic.io_wait_count = 1;
    package.semantic.wait_token_count = 1;
    package.semantic.wait_record_count = 1;
    package.semantic.activation_resume_count = 1;
    package.semantic.activation_wait_count = 1;
    package.semantic.activation_cleanup_count = 1;
    package.semantic.preemption_latency_sample_count = 1;
    package.semantic.hart_event_attribution_count = 1;
    package.substrate_boundary.timer_epoch = 3;
    package.semantic.hart_records.push(HartRecordManifest {
        id: 1,
        hardware_id: 0,
        label: "boot-hart0".to_owned(),
        state: "idle".to_owned(),
        generation: 2,
        boot: true,
        current_activation: None,
        current_activation_generation: None,
        current_task: None,
        current_task_generation: None,
        current_store: None,
        current_store_generation: None,
        last_event: Some(2),
        last_current_event: None,
        note: "s0 hart object".to_owned(),
    });
    package.semantic.hart_records.push(HartRecordManifest {
        id: 2,
        hardware_id: 1,
        label: "hart1".to_owned(),
        state: "idle".to_owned(),
        generation: 2,
        boot: false,
        current_activation: None,
        current_activation_generation: None,
        current_task: None,
        current_task_generation: None,
        current_store: None,
        current_store_generation: None,
        last_event: Some(4),
        last_current_event: None,
        note: "s5 target hart".to_owned(),
    });
    package.semantic.task_records.push(TaskRecordManifest {
        id: 7,
        label: "linux-thread-7".to_owned(),
        frontend: "linux-elf".to_owned(),
        state: "runnable".to_owned(),
        generation: 1,
        fault_domain: None,
        pending_wait: None,
        resources: Vec::new(),
    });
    package.semantic.runtime_activation_records.push(RuntimeActivationRecordManifest {
        id: 11,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: None,
        owner_store_generation: None,
        code_object: None,
        generation: 2,
        state: "runnable".to_owned(),
        runnable_queue: Some(1),
        runnable_queue_generation: Some(1),
        last_event: Some(9),
    });
    package.semantic.runnable_queues.push(RunnableQueueManifest {
        id: 1,
        label: "main-rq".to_owned(),
        generation: 1,
        state: "active".to_owned(),
        owner_hart: Some(1),
        owner_hart_generation: Some(2),
        entries: vec![artifact_manifest::RunnableQueueEntryManifest {
            activation: 11,
            activation_generation: 2,
            enqueued_at: 9,
        }],
    });
    package.semantic.activation_contexts.push(ActivationContextManifest {
        id: 12,
        activation: 11,
        activation_generation: 2,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: None,
        owner_store_generation: None,
        generation: 2,
        state: "saved".to_owned(),
        current_saved_context: Some(13),
        current_saved_context_generation: Some(1),
        vector_state: None,
        vector_status: "absent".to_owned(),
        vector_state_event: None,
        last_event: Some(10),
    });
    package.semantic.saved_contexts.push(SavedContextManifest {
        id: 13,
        context: 12,
        context_generation: 2,
        activation: 11,
        activation_generation: 2,
        owner_task: 7,
        owner_task_generation: 1,
        source_preemption: Some(15),
        source_preemption_generation: Some(1),
        generation: 1,
        state: "captured".to_owned(),
        reason: "timer-preempt".to_owned(),
        pc: 0x1000,
        sp: 0x8000,
        flags: 0,
        integer_registers: 33,
        vector_state: None,
        vector_status: "absent".to_owned(),
        vector_saved_at_event: None,
        saved_at_event: 10,
        note: "preempted frame".to_owned(),
    });
    package.semantic.timer_interrupts.push(TimerInterruptManifest {
        id: 14,
        timer_epoch: 3,
        hart: 1,
        hart_generation: Some(2),
        hardware_hart: Some(0),
        target_activation: Some(11),
        target_activation_generation: Some(2),
        target_task: Some(7),
        target_task_generation: Some(1),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 11,
        note: "timer tick".to_owned(),
    });
    package.semantic.ipi_events.push(IpiEventManifest {
        id: 23,
        source_hart: 1,
        source_hart_generation: 2,
        source_hardware_hart: 0,
        target_hart: 2,
        target_hart_generation: 2,
        target_hardware_hart: 1,
        kind: "scheduler-kick".to_owned(),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 12,
        reason: "s5-scheduler-kick".to_owned(),
        note: "hart0 kicks hart1".to_owned(),
    });
    package.semantic.remote_preempts.push(RemotePreemptManifest {
        id: 24,
        ipi: 23,
        ipi_generation: 1,
        source_hart: 1,
        source_hart_generation: 2,
        target_hart: 2,
        target_hart_generation_before: 2,
        target_hart_generation_after: 3,
        activation: 11,
        activation_generation_before: 2,
        activation_generation_after: 3,
        queue: 1,
        queue_generation: 1,
        generation: 1,
        state: "applied".to_owned(),
        preempted_at_event: 13,
        note: "remote preempt activation".to_owned(),
    });
    package.semantic.remote_parks.push(RemoteParkManifest {
        id: 25,
        ipi: 23,
        ipi_generation: 1,
        source_hart: 1,
        source_hart_generation: 2,
        target_hart: 2,
        target_hart_generation_before: 3,
        target_hart_generation_after: 4,
        generation: 1,
        state: "parked".to_owned(),
        parked_at_event: 14,
        reason: "remote-maintenance".to_owned(),
        note: "remote park hart".to_owned(),
    });
    package.semantic.hart_event_attributions.push(HartEventAttributionManifest {
        id: 22,
        hart: 1,
        hart_generation: 2,
        hardware_hart: 0,
        event: 11,
        event_source: "timer".to_owned(),
        event_kind: "TimerInterruptRecorded".to_owned(),
        activation: Some(11),
        activation_generation: Some(2),
        task: Some(7),
        task_generation: Some(1),
        store: None,
        store_generation: None,
        generation: 1,
        state: "recorded".to_owned(),
        note: "timer event attributed to hart".to_owned(),
    });
    package.semantic.preemptions.push(PreemptionManifest {
        id: 15,
        activation: 11,
        activation_generation_before: 2,
        activation_generation_after: 3,
        timer_interrupt: 14,
        timer_interrupt_generation: 1,
        queue: 1,
        queue_generation: 1,
        generation: 1,
        state: "applied".to_owned(),
        preempted_at_event: 12,
        note: "preempted".to_owned(),
    });
    package.semantic.scheduler_decisions.push(SchedulerDecisionManifest {
        id: 16,
        queue: 1,
        queue_generation: 1,
        selected_activation: 11,
        selected_activation_generation: 3,
        owner_task: 7,
        owner_task_generation: 1,
        generation: 1,
        state: "recorded".to_owned(),
        decided_at_event: 13,
        reason: "runnable-available".to_owned(),
        note: "select activation".to_owned(),
    });
    package.semantic.cross_hart_scheduler_decisions.push(CrossHartSchedulerDecisionManifest {
        id: 26,
        scheduler_decision: 16,
        scheduler_decision_generation: 1,
        deciding_hart: 2,
        deciding_hart_generation: 2,
        target_hart: 1,
        target_hart_generation: 2,
        queue: 1,
        queue_generation: 1,
        queue_owner_hart_generation: 2,
        selected_activation: 11,
        selected_activation_generation: 3,
        generation: 1,
        state: "recorded".to_owned(),
        decided_at_event: 20,
        reason: "remote-runnable".to_owned(),
        note: "cross hart decision".to_owned(),
    });
    package.semantic.activation_migrations.push(ActivationMigrationManifest {
        id: 27,
        activation: 11,
        activation_generation_before: 3,
        activation_generation_after: 4,
        owner_task: 7,
        owner_task_generation: 1,
        source_hart: 2,
        source_hart_generation: 2,
        target_hart: 1,
        target_hart_generation: 2,
        source_queue: 2,
        source_queue_generation: 1,
        source_queue_owner_hart_generation: 2,
        target_queue: 1,
        target_queue_generation: 1,
        target_queue_owner_hart_generation: 2,
        context: None,
        context_generation_before: None,
        context_generation_after: None,
        source_vector_state: None,
        migrated_vector_state: None,
        vector_status: "absent".to_owned(),
        vector_migrated_at_event: None,
        generation: 1,
        state: "applied".to_owned(),
        migrated_at_event: 21,
        reason: "rebalance".to_owned(),
        note: "activation migration".to_owned(),
    });
    package.semantic.smp_safe_points.push(SmpSafePointManifest {
        id: 28,
        coordinator_hart: 1,
        coordinator_hart_generation: 2,
        participants: vec![
            artifact_manifest::SmpSafePointParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
                current_activation: None,
                current_activation_generation: None,
            },
            artifact_manifest::SmpSafePointParticipantManifest {
                hart: 2,
                hart_generation: 2,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
                current_activation: None,
                current_activation_generation: None,
            },
        ],
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 22,
        reason: "quiescent-boundary".to_owned(),
        note: "smp safe point".to_owned(),
    });
    package.semantic.stop_the_world_rendezvous.push(StopTheWorldRendezvousManifest {
        id: 29,
        epoch: 1,
        safe_point: 28,
        safe_point_generation: 1,
        coordinator_hart: 1,
        coordinator_hart_generation: 2,
        participants: vec![
            artifact_manifest::StopTheWorldRendezvousParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
            },
            artifact_manifest::StopTheWorldRendezvousParticipantManifest {
                hart: 2,
                hart_generation: 2,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
            },
        ],
        stop_new_activations: true,
        generation: 1,
        state: "completed".to_owned(),
        completed_at_event: 23,
        reason: "code-publish-boundary".to_owned(),
        note: "stop the world".to_owned(),
    });
    package.semantic.smp_code_publish_barriers.push(SmpCodePublishBarrierManifest {
        id: 30,
        rendezvous: 29,
        rendezvous_generation: 1,
        rendezvous_epoch: 1,
        code_publish_epoch_before: 0,
        code_publish_epoch_after: 1,
        participants: vec![
            artifact_manifest::SmpCodePublishBarrierParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                last_seen_code_epoch_before: 0,
                last_seen_code_epoch_after: 1,
                semantic_icache_sync: true,
            },
            artifact_manifest::SmpCodePublishBarrierParticipantManifest {
                hart: 2,
                hart_generation: 2,
                hardware_hart: 1,
                last_seen_code_epoch_before: 0,
                last_seen_code_epoch_after: 1,
                semantic_icache_sync: true,
            },
        ],
        remote_icache_sync_required: true,
        code_publish_executed: false,
        generation: 1,
        state: "validated".to_owned(),
        validated_at_event: 24,
        reason: "semantic-code-publish-barrier".to_owned(),
        note: "smp publish barrier".to_owned(),
    });
    package.semantic.smp_cleanup_quiescence.push(SmpCleanupQuiescenceManifest {
        id: 31,
        cleanup: 20,
        cleanup_generation: 1,
        store: 5,
        target_store_generation: 2,
        result_store_generation: 4,
        activation: 11,
        activation_generation_after: 6,
        rendezvous: 29,
        rendezvous_generation: 1,
        rendezvous_epoch: 1,
        participants: vec![
            artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
                current_activation: None,
                current_activation_generation: None,
                current_store: None,
                current_store_generation: None,
                quiesced: true,
            },
            artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                hart: 2,
                hart_generation: 2,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
                current_activation: None,
                current_activation_generation: None,
                current_store: None,
                current_store_generation: None,
                quiesced: true,
            },
        ],
        no_running_activation: true,
        no_pending_wait: true,
        no_live_capability: true,
        no_live_resource: true,
        generation: 1,
        state: "validated".to_owned(),
        validated_at_event: 25,
        reason: "smp-cleanup-quiescence".to_owned(),
        note: "cleanup quiesced".to_owned(),
    });
    package.semantic.smp_snapshot_barriers.push(SmpSnapshotBarrierManifest {
        id: 32,
        rendezvous: 29,
        rendezvous_generation: 1,
        rendezvous_epoch: 1,
        event_log_cursor: 25,
        participants: vec![
            artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
                event_log_cursor_observed: 25,
                snapshot_safe: true,
            },
            artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                hart: 2,
                hart_generation: 2,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
                event_log_cursor_observed: 25,
                snapshot_safe: true,
            },
        ],
        pending_wait_count: 0,
        active_transaction_count: 0,
        active_dmw_lease_count: 0,
        active_nonconvertible_activation_count: 0,
        in_flight_dma_count: 0,
        unsealed_event_log: false,
        unflushed_trap_record_count: 0,
        pending_cleanup_count: 0,
        native_activation_stack_live: false,
        raw_dma_binding_count: 0,
        raw_mmio_binding_count: 0,
        snapshot_validation_ok: true,
        generation: 1,
        state: "validated".to_owned(),
        validated_at_event: 26,
        reason: "smp-snapshot-barrier".to_owned(),
        note: "snapshot barrier".to_owned(),
    });
    package.semantic.smp_stress_runs.push(SmpStressRunManifest {
        id: 33,
        scenario: "s15-smp-stress-property".to_owned(),
        iterations: 3,
        hart_count: 2,
        event_log_cursor: 26,
        observed_safe_point_count: 3,
        observed_rendezvous_count: 3,
        observed_code_publish_barrier_count: 1,
        observed_cleanup_quiescence_count: 1,
        observed_snapshot_barrier_count: 1,
        observed_activation_migration_count: 1,
        observed_remote_preempt_count: 1,
        observed_remote_park_count: 1,
        invariant_checks: 6,
        property_failures: 0,
        last_safe_point: 28,
        last_safe_point_generation: 1,
        last_rendezvous: 29,
        last_rendezvous_generation: 1,
        last_code_publish_barrier: 30,
        last_code_publish_barrier_generation: 1,
        last_cleanup_quiescence: 31,
        last_cleanup_quiescence_generation: 1,
        last_snapshot_barrier: 32,
        last_snapshot_barrier_generation: 1,
        last_activation_migration: 27,
        last_activation_migration_generation: 1,
        last_remote_preempt: 24,
        last_remote_preempt_generation: 1,
        last_remote_park: 25,
        last_remote_park_generation: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 27,
        reason: "smp-stress-property-tests".to_owned(),
        note: "stress run".to_owned(),
    });
    package.semantic.smp_scaling_benchmarks.push(SmpScalingBenchmarkManifest {
        id: 34,
        scenario: "s16-smp-scaling-benchmark".to_owned(),
        stress_run: 33,
        stress_run_generation: 1,
        hart_count: 2,
        workload_units: 6,
        baseline_single_hart_nanos: 120_000,
        measured_smp_nanos: 72_000,
        budget_nanos: 90_000,
        speedup_milli: 1_666,
        efficiency_milli: 833,
        event_log_cursor: 27,
        stress_safe_point_count: 3,
        stress_rendezvous_count: 3,
        stress_property_failures: 0,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 28,
        note: "scaling benchmark".to_owned(),
    });
    package.semantic.device_objects.push(DeviceObjectManifest {
        id: 35,
        name: "fake-io0".to_owned(),
        class: "fake-device".to_owned(),
        resource: 99,
        resource_generation: 1,
        backend: "fake-io-backend".to_owned(),
        bus: "semantic-harness".to_owned(),
        vendor: "vmos".to_owned(),
        model: "fake-io-v1".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 29,
        note: "device object".to_owned(),
    });
    package.semantic.queue_objects.push(QueueObjectManifest {
        id: 36,
        name: "fake-io0-rx".to_owned(),
        role: "rx".to_owned(),
        queue_index: 0,
        depth: 64,
        device: 35,
        device_generation: 1,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 30,
        note: "queue object".to_owned(),
    });
    package.semantic.descriptor_objects.push(DescriptorObjectManifest {
        id: 37,
        queue: 36,
        queue_generation: 1,
        slot: 0,
        access: "read-write".to_owned(),
        length: 2048,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 31,
        note: "descriptor object".to_owned(),
    });
    package.semantic.dma_buffer_objects.push(DmaBufferObjectManifest {
        id: 38,
        descriptor: 37,
        descriptor_generation: 1,
        resource: 100,
        resource_generation: 1,
        access: "read-write".to_owned(),
        length: 2048,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 32,
        note: "dma buffer object".to_owned(),
    });
    package.semantic.mmio_region_objects.push(MmioRegionObjectManifest {
        id: 39,
        device: 35,
        device_generation: 1,
        resource: 101,
        resource_generation: 1,
        region_index: 0,
        offset: 0x1000,
        length: 0x100,
        access: "read-write".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 33,
        note: "mmio region object".to_owned(),
    });
    package.semantic.irq_line_objects.push(IrqLineObjectManifest {
        id: 40,
        device: 35,
        device_generation: 1,
        resource: 102,
        resource_generation: 1,
        irq_number: 5,
        trigger: "level".to_owned(),
        polarity: "active-high".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 34,
        note: "irq line object".to_owned(),
    });
    package.semantic.irq_events.push(IrqEventManifest {
        id: 41,
        irq_line: 40,
        irq_line_generation: 1,
        device: 35,
        device_generation: 1,
        driver_store: 1,
        driver_store_generation: 2,
        irq_number: 5,
        sequence: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 35,
        note: "irq event".to_owned(),
    });
    package.semantic.device_capabilities.push(DeviceCapabilityManifest {
        id: 42,
        driver_store: 1,
        driver_store_generation: 2,
        target: ContractObjectRefManifest {
            kind: "mmio-region-object".to_owned(),
            id: 39,
            generation: 1,
        },
        class: "mmio-region".to_owned(),
        operation: "write32".to_owned(),
        capability: 7,
        capability_generation: 1,
        handle_slot: 3,
        handle_generation: 1,
        handle_tag: 9001,
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 36,
        note: "device capability".to_owned(),
    });
    package.semantic.device_capabilities.push(DeviceCapabilityManifest {
        id: 43,
        driver_store: 1,
        driver_store_generation: 2,
        target: ContractObjectRefManifest {
            kind: "device-object".to_owned(),
            id: 35,
            generation: 1,
        },
        class: "device".to_owned(),
        operation: "probe".to_owned(),
        capability: 8,
        capability_generation: 1,
        handle_slot: 4,
        handle_generation: 1,
        handle_tag: 9002,
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 37,
        note: "device capability".to_owned(),
    });
    package.semantic.driver_store_bindings.push(DriverStoreBindingManifest {
        id: 44,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        device_capability: 43,
        device_capability_generation: 1,
        capability: 8,
        capability_generation: 1,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 38,
        note: "driver store binding".to_owned(),
    });
    package.semantic.wait_records.push(WaitRecordManifest {
        id: 45,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(1),
        owner_store_generation: Some(2),
        kind: "device-irq".to_owned(),
        generation: 1,
        state: "resolved".to_owned(),
        blockers: vec![ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 40,
            generation: 1,
        }],
        deadline: None,
        cancel_reason: None,
        restart_policy: "internal-only".to_owned(),
        saved_context: Some("fake-io0:rx-irq".to_owned()),
    });
    package.semantic.io_waits.push(IoWaitManifest {
        id: 46,
        wait: 45,
        wait_generation: 1,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 1,
        blocker: ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 40,
            generation: 1,
        },
        generation: 1,
        state: "resolved".to_owned(),
        created_at_event: 39,
        completed_at_event: Some(40),
        completion_irq_event: Some(41),
        completion_irq_event_generation: Some(1),
        cancel_reason: None,
        note: "io wait".to_owned(),
    });
    package.semantic.activation_resumes.push(ActivationResumeManifest {
        id: 17,
        scheduler_decision: 16,
        scheduler_decision_generation: 1,
        activation: 11,
        activation_generation_before: 3,
        activation_generation_after: 4,
        owner_task: 7,
        owner_task_generation: 1,
        queue: 1,
        queue_generation: 1,
        context: Some(12),
        context_generation_before: Some(2),
        context_generation_after: Some(3),
        saved_context: Some(13),
        saved_context_generation: Some(2),
        saved_vector_state: None,
        restored_vector_state: None,
        vector_status: "absent".to_owned(),
        vector_restored_at_event: None,
        generation: 1,
        state: "applied".to_owned(),
        resumed_at_event: 14,
        note: "resume activation".to_owned(),
    });
    package.semantic.activation_waits.push(ActivationWaitManifest {
        id: 18,
        activation: 11,
        activation_generation_before: 4,
        activation_generation_after_block: 5,
        activation_generation_after_cancel: Some(6),
        wait: 19,
        wait_generation: 1,
        owner_task: 7,
        owner_task_generation: 2,
        queue: None,
        queue_generation: None,
        generation: 1,
        state: "cancelled".to_owned(),
        blocked_at_event: 15,
        completed_at_event: Some(16),
        cancel_reason: Some("timeout".to_owned()),
        note: "activation wait".to_owned(),
    });
    package.semantic.activation_cleanups.push(ActivationCleanupManifest {
        id: 20,
        store: 3,
        target_store_generation: 2,
        result_store_generation: 4,
        activation: 11,
        activation_generation_before: 5,
        activation_generation_after: 6,
        wait: Some(19),
        wait_generation: Some(1),
        owner_task: 7,
        owner_task_generation_before: 2,
        owner_task_generation_after: 3,
        generation: 1,
        state: "completed".to_owned(),
        reason: "driver-store-fault".to_owned(),
        started_at_event: 17,
        completed_at_event: 18,
        steps: vec![artifact_manifest::ActivationCleanupStepManifest {
            kind: "cancel-wait".to_owned(),
            target: ContractObjectRefManifest {
                kind: "wait-token".to_owned(),
                id: 19,
                generation: 1,
            },
            observed_generation: 1,
            status: "done".to_owned(),
            event: Some(17),
        }],
        note: "cleanup".to_owned(),
    });
    package.semantic.preemption_latency_samples.push(PreemptionLatencySampleManifest {
        id: 21,
        timer_interrupt: 14,
        timer_interrupt_generation: 1,
        preemption: 15,
        preemption_generation: 1,
        scheduler_decision: 16,
        scheduler_decision_generation: 1,
        activation_resume: 17,
        activation_resume_generation: 1,
        activation: 11,
        activation_generation_before: 2,
        activation_generation_after: 4,
        queue: 1,
        queue_generation: 1,
        interrupt_recorded_at_event: 11,
        preempted_at_event: 12,
        decided_at_event: 13,
        resumed_at_event: 14,
        interrupt_to_preempt_events: 1,
        preempt_to_decision_events: 1,
        decision_to_resume_events: 1,
        interrupt_to_resume_events: 3,
        measured_nanos: 8_500,
        budget_nanos: 50_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 19,
        note: "latency sample".to_owned(),
    });
    let hart = hart_view_v1(&package.semantic.hart_records[0]);
    assert_eq!(hart["kind"], "hart");
    assert_eq!(hart["owner"]["hardware_id"], 0);
    assert_eq!(hart["generation"], 2);
    assert_eq!(hart["state"], "idle");
    let current_hart = hart_view_v1(&HartRecordManifest {
        id: 2,
        hardware_id: 1,
        label: "hart1".to_owned(),
        state: "running".to_owned(),
        generation: 3,
        boot: false,
        current_activation: Some(11),
        current_activation_generation: Some(2),
        current_task: Some(7),
        current_task_generation: Some(1),
        current_store: None,
        current_store_generation: None,
        last_event: Some(21),
        last_current_event: Some(21),
        note: "current activation".to_owned(),
    });
    assert_eq!(current_hart["references"]["current_activation"]["generation"], 2);
    assert_eq!(current_hart["references"]["current_task"]["id"], 7);
    let context = activation_context_view_v1(&package.semantic.activation_contexts[0]);
    assert_eq!(context["kind"], "activation-context");
    assert_eq!(context["references"]["activation"]["generation"], 2);
    assert_eq!(context["references"]["current_saved_context"]["generation"], 1);
    let saved = saved_context_view_v1(&package.semantic.saved_contexts[0]);
    assert_eq!(saved["kind"], "saved-context");
    assert_eq!(saved["reason"], "timer-preempt");
    assert_eq!(saved["machine_frame"]["integer_registers"], 33);
    assert_eq!(saved["references"]["activation_context"]["generation"], 2);
    assert_eq!(saved["references"]["source_preemption"]["id"], 15);
    assert_eq!(saved["references"]["source_preemption"]["generation"], 1);
    assert_eq!(saved["vector_context"]["status"], "absent");
    let timer = timer_interrupt_view_v1(&package.semantic.timer_interrupts[0]);
    assert_eq!(timer["kind"], "timer-interrupt");
    assert_eq!(timer["owner"]["timer_epoch"], 3);
    assert_eq!(timer["owner"]["hart"]["id"], 1);
    assert_eq!(timer["owner"]["hart"]["generation"], 2);
    assert_eq!(timer["owner"]["hart"]["hardware_id"], 0);
    assert_eq!(timer["references"]["activation"]["generation"], 2);
    let ipi = ipi_event_view_v1(&package.semantic.ipi_events[0]);
    assert_eq!(ipi["kind"], "ipi-event");
    assert_eq!(ipi["owner"]["source_hart"]["generation"], 2);
    assert_eq!(ipi["owner"]["target_hart"]["hardware_id"], 1);
    assert_eq!(ipi["ipi_kind"], "scheduler-kick");
    let remote = remote_preempt_view_v1(&package.semantic.remote_preempts[0]);
    assert_eq!(remote["kind"], "remote-preempt");
    assert_eq!(remote["references"]["ipi"]["generation"], 1);
    assert_eq!(remote["references"]["activation"]["generation_after"], 3);
    let remote_park = remote_park_view_v1(&package.semantic.remote_parks[0]);
    assert_eq!(remote_park["kind"], "remote-park");
    assert_eq!(remote_park["references"]["ipi"]["id"], 23);
    assert_eq!(remote_park["owner"]["target_hart"]["generation_after"], 4);
    let hart_event = hart_event_attribution_view_v1(&package.semantic.hart_event_attributions[0]);
    assert_eq!(hart_event["kind"], "hart-event-attribution");
    assert_eq!(hart_event["owner"]["hart"]["generation"], 2);
    assert_eq!(hart_event["references"]["event"]["kind"], "TimerInterruptRecorded");
    assert_eq!(hart_event["references"]["activation"]["id"], 11);
    let queue = runnable_queue_view_v1(&package.semantic.runnable_queues[0]);
    assert_eq!(queue["kind"], "runnable-queue");
    assert_eq!(queue["owner"]["hart"]["id"], 1);
    assert_eq!(queue["owner"]["hart"]["generation"], 2);
    let preemption = preemption_view_v1(&package.semantic.preemptions[0]);
    assert_eq!(preemption["kind"], "preemption");
    assert_eq!(preemption["references"]["activation"]["generation_before"], 2);
    assert_eq!(preemption["references"]["activation"]["generation_after"], 3);
    assert_eq!(preemption["references"]["timer_interrupt"]["generation"], 1);
    let decision = scheduler_decision_view_v1(&package.semantic.scheduler_decisions[0]);
    assert_eq!(decision["kind"], "scheduler-decision");
    assert_eq!(decision["references"]["selected_activation"]["generation"], 3);
    assert_eq!(decision["references"]["queue"]["generation"], 1);
    assert_eq!(decision["reason"], "runnable-available");
    let cross_decision =
        cross_hart_scheduler_decision_view_v1(&package.semantic.cross_hart_scheduler_decisions[0]);
    assert_eq!(cross_decision["kind"], "cross-hart-scheduler-decision");
    assert_eq!(cross_decision["owner"]["deciding_hart"]["id"], 2);
    assert_eq!(cross_decision["owner"]["target_hart"]["id"], 1);
    assert_eq!(cross_decision["references"]["scheduler_decision"]["generation"], 1);
    assert_eq!(cross_decision["references"]["queue"]["owner_hart_generation"], 2);
    let migration = activation_migration_view_v1(&package.semantic.activation_migrations[0]);
    assert_eq!(migration["kind"], "activation-migration");
    assert_eq!(migration["owner"]["source_hart"]["id"], 2);
    assert_eq!(migration["owner"]["target_hart"]["id"], 1);
    assert_eq!(migration["references"]["activation"]["generation_after"], 4);
    assert_eq!(migration["references"]["target_queue"]["id"], 1);
    let safe_point = smp_safe_point_view_v1(&package.semantic.smp_safe_points[0]);
    assert_eq!(safe_point["kind"], "smp-safe-point");
    assert_eq!(safe_point["owner"]["coordinator_hart"]["id"], 1);
    assert_eq!(safe_point["references"]["participants"][0]["hart"]["id"], 1);
    assert_eq!(safe_point["references"]["participants"][0]["hart"]["generation"], 2);
    assert_eq!(safe_point["last_transition"]["participant_count"], 2);
    let rendezvous =
        stop_the_world_rendezvous_view_v1(&package.semantic.stop_the_world_rendezvous[0]);
    assert_eq!(rendezvous["kind"], "stop-the-world-rendezvous");
    assert_eq!(rendezvous["epoch"], 1);
    assert_eq!(rendezvous["references"]["safe_point"]["id"], 28);
    assert_eq!(rendezvous["references"]["participants"][1]["hart"]["generation"], 2);
    assert_eq!(rendezvous["stop_new_activations"], true);
    let barrier = smp_code_publish_barrier_view_v1(&package.semantic.smp_code_publish_barriers[0]);
    assert_eq!(barrier["kind"], "smp-code-publish-barrier");
    assert_eq!(barrier["references"]["rendezvous"]["id"], 29);
    assert_eq!(barrier["references"]["participants"][0]["semantic_icache_sync"], true);
    assert_eq!(barrier["last_transition"]["code_publish_epoch_after"], 1);
    assert_eq!(barrier["code_publish_executed"], false);
    let quiescence = smp_cleanup_quiescence_view_v1(&package.semantic.smp_cleanup_quiescence[0]);
    assert_eq!(quiescence["kind"], "smp-cleanup-quiescence");
    assert_eq!(quiescence["references"]["cleanup"]["id"], 20);
    assert_eq!(quiescence["references"]["store"]["target_generation"], 2);
    assert_eq!(quiescence["references"]["store"]["result_generation"], 4);
    assert_eq!(quiescence["references"]["rendezvous"]["id"], 29);
    assert_eq!(quiescence["postconditions"]["no_running_activation"], true);
    assert_eq!(quiescence["references"]["participants"][1]["quiesced"], true);
    let snapshot_barrier = smp_snapshot_barrier_view_v1(&package.semantic.smp_snapshot_barriers[0]);
    assert_eq!(snapshot_barrier["kind"], "smp-snapshot-barrier");
    assert_eq!(snapshot_barrier["references"]["rendezvous"]["id"], 29);
    assert_eq!(snapshot_barrier["last_transition"]["event_log_cursor"], 25);
    assert_eq!(snapshot_barrier["references"]["participants"][1]["snapshot_safe"], true);
    assert_eq!(snapshot_barrier["postconditions"]["snapshot_validation_ok"], true);
    let stress = smp_stress_run_view_v1(&package.semantic.smp_stress_runs[0]);
    assert_eq!(stress["kind"], "smp-stress-run");
    assert_eq!(stress["owner"]["scenario"], "s15-smp-stress-property");
    assert_eq!(stress["coverage"]["iterations"], 3);
    assert_eq!(stress["coverage"]["property_failures"], 0);
    assert_eq!(stress["references"]["last_snapshot_barrier"]["generation"], 1);
    let scaling = smp_scaling_benchmark_view_v1(&package.semantic.smp_scaling_benchmarks[0]);
    assert_eq!(scaling["kind"], "smp-scaling-benchmark");
    assert_eq!(scaling["owner"]["scenario"], "s16-smp-scaling-benchmark");
    assert_eq!(scaling["references"]["stress_run"]["id"], 33);
    assert_eq!(scaling["metrics"]["workload_units"], 6);
    assert_eq!(scaling["metrics"]["measured_smp_nanos"], 72_000);
    assert_eq!(scaling["metrics"]["speedup_milli"], 1_666);
    assert_eq!(scaling["metrics"]["efficiency_milli"], 833);
    assert_eq!(scaling["coverage"]["stress_property_failures"], 0);
    let device = device_object_view_v1(&package.semantic.device_objects[0]);
    assert_eq!(device["kind"], "device");
    assert_eq!(device["owner"]["class"], "fake-device");
    assert_eq!(device["owner"]["backend"], "fake-io-backend");
    assert_eq!(device["references"]["resource"]["generation"], 1);
    assert_eq!(device["identity"]["model"], "fake-io-v1");
    let queue = queue_object_view_v1(&package.semantic.queue_objects[0]);
    assert_eq!(queue["kind"], "queue");
    assert_eq!(queue["owner"]["device"]["id"], 35);
    assert_eq!(queue["owner"]["device"]["generation"], 1);
    assert_eq!(queue["identity"]["role"], "rx");
    assert_eq!(queue["identity"]["queue_index"], 0);
    assert_eq!(queue["capacity"]["depth"], 64);
    let descriptor = descriptor_object_view_v1(&package.semantic.descriptor_objects[0]);
    assert_eq!(descriptor["kind"], "descriptor");
    assert_eq!(descriptor["owner"]["queue"]["id"], 36);
    assert_eq!(descriptor["owner"]["queue"]["generation"], 1);
    assert_eq!(descriptor["identity"]["slot"], 0);
    assert_eq!(descriptor["identity"]["access"], "read-write");
    assert_eq!(descriptor["capacity"]["length"], 2048);
    let dma_buffer = dma_buffer_object_view_v1(&package.semantic.dma_buffer_objects[0]);
    assert_eq!(dma_buffer["kind"], "dma-buffer");
    assert_eq!(dma_buffer["owner"]["descriptor"]["id"], 37);
    assert_eq!(dma_buffer["owner"]["descriptor"]["generation"], 1);
    assert_eq!(dma_buffer["references"]["resource"]["id"], 100);
    assert_eq!(dma_buffer["references"]["resource"]["generation"], 1);
    assert_eq!(dma_buffer["identity"]["access"], "read-write");
    assert_eq!(dma_buffer["capacity"]["length"], 2048);
    let mmio_region = mmio_region_object_view_v1(&package.semantic.mmio_region_objects[0]);
    assert_eq!(mmio_region["kind"], "mmio-region");
    assert_eq!(mmio_region["owner"]["device"]["id"], 35);
    assert_eq!(mmio_region["owner"]["device"]["generation"], 1);
    assert_eq!(mmio_region["references"]["resource"]["id"], 101);
    assert_eq!(mmio_region["references"]["resource"]["generation"], 1);
    assert_eq!(mmio_region["identity"]["region_index"], 0);
    assert_eq!(mmio_region["identity"]["offset"], 0x1000);
    assert_eq!(mmio_region["identity"]["access"], "read-write");
    assert_eq!(mmio_region["capacity"]["length"], 0x100);
    let irq_line = irq_line_object_view_v1(&package.semantic.irq_line_objects[0]);
    assert_eq!(irq_line["kind"], "irq-line");
    assert_eq!(irq_line["owner"]["device"]["id"], 35);
    assert_eq!(irq_line["owner"]["device"]["generation"], 1);
    assert_eq!(irq_line["references"]["resource"]["id"], 102);
    assert_eq!(irq_line["references"]["resource"]["generation"], 1);
    assert_eq!(irq_line["identity"]["irq_number"], 5);
    assert_eq!(irq_line["identity"]["trigger"], "level");
    assert_eq!(irq_line["identity"]["polarity"], "active-high");
    let irq_event = irq_event_view_v1(&package.semantic.irq_events[0]);
    assert_eq!(irq_event["kind"], "irq-event");
    assert_eq!(irq_event["owner"]["device"]["id"], 35);
    assert_eq!(irq_event["owner"]["driver_store"]["id"], 1);
    assert_eq!(irq_event["owner"]["driver_store"]["generation"], 2);
    assert_eq!(irq_event["references"]["irq_line"]["id"], 40);
    assert_eq!(irq_event["references"]["irq_line"]["generation"], 1);
    assert_eq!(irq_event["identity"]["irq_number"], 5);
    assert_eq!(irq_event["identity"]["sequence"], 1);
    let device_capability = device_capability_view_v1(&package.semantic.device_capabilities[0]);
    assert_eq!(device_capability["kind"], "device-capability");
    assert_eq!(device_capability["owner"]["driver_store"]["generation"], 2);
    assert_eq!(device_capability["references"]["target"]["id"], 39);
    assert_eq!(device_capability["references"]["target"]["generation"], 1);
    assert_eq!(device_capability["references"]["capability"]["id"], 7);
    assert_eq!(device_capability["authority"]["class"], "mmio-region");
    assert_eq!(device_capability["authority"]["operation"], "write32");
    assert_eq!(device_capability["authority"]["handle"]["slot"], 3);
    let binding = driver_store_binding_view_v1(&package.semantic.driver_store_bindings[0]);
    assert_eq!(binding["kind"], "driver-store-binding");
    assert_eq!(binding["owner"]["driver_store"]["generation"], 2);
    assert_eq!(binding["owner"]["device"]["id"], 35);
    assert_eq!(binding["references"]["device_capability"]["id"], 43);
    assert_eq!(binding["references"]["capability"]["generation"], 1);
    let io_wait = io_wait_view_v1(&package.semantic.io_waits[0]);
    assert_eq!(io_wait["kind"], "io-wait");
    assert_eq!(io_wait["owner"]["driver_store"]["generation"], 2);
    assert_eq!(io_wait["references"]["wait"]["id"], 45);
    assert_eq!(io_wait["references"]["blocker"]["kind"], "irq-line-object");
    assert_eq!(io_wait["references"]["completion_irq_event"]["id"], 41);
    assert_eq!(io_wait["last_transition"]["completed_at_event"], 40);
    let resume = activation_resume_view_v1(&package.semantic.activation_resumes[0]);
    assert_eq!(resume["kind"], "activation-resume");
    assert_eq!(resume["references"]["activation"]["generation_before"], 3);
    assert_eq!(resume["references"]["activation"]["generation_after"], 4);
    assert_eq!(resume["references"]["scheduler_decision"]["generation"], 1);
    assert_eq!(resume["references"]["saved_context"]["generation"], 2);
    let activation_wait = activation_wait_view_v1(&package.semantic.activation_waits[0]);
    assert_eq!(activation_wait["kind"], "activation-wait");
    assert_eq!(activation_wait["references"]["activation"]["generation_before"], 4);
    assert_eq!(activation_wait["references"]["activation"]["generation_after_block"], 5);
    assert_eq!(activation_wait["references"]["activation"]["generation_after_cancel"], 6);
    assert_eq!(activation_wait["references"]["wait"]["generation"], 1);
    assert_eq!(activation_wait["cancel_reason"], "timeout");
    let activation_cleanup = activation_cleanup_view_v1(&package.semantic.activation_cleanups[0]);
    assert_eq!(activation_cleanup["kind"], "activation-cleanup");
    assert_eq!(activation_cleanup["owner"]["target_store_generation"], 2);
    assert_eq!(activation_cleanup["owner"]["result_store_generation"], 4);
    assert_eq!(activation_cleanup["references"]["activation"]["generation_after"], 6);
    assert_eq!(activation_cleanup["references"]["steps"][0]["target"]["kind"], "wait-token");
    let latency = preemption_latency_view_v1(&package.semantic.preemption_latency_samples[0]);
    assert_eq!(latency["kind"], "preemption-latency");
    assert_eq!(latency["references"]["timer_interrupt"]["generation"], 1);
    assert_eq!(latency["event_window"]["interrupt_to_resume_events"], 3);
    assert_eq!(latency["metrics"]["measured_nanos"], 8_500);
    assert_eq!(latency["metrics"]["within_budget"], true);
    let scheduler = scheduler_view_v1(&package);
    assert_eq!(scheduler["kind"], "scheduler");
    assert_eq!(scheduler["references"]["harts"][0]["hardware_id"], 0);
    assert_eq!(scheduler["last_transition"]["hart_count"], 2);
    assert_eq!(scheduler["references"]["queues"][0]["entries"], 1);
    assert_eq!(scheduler["references"]["queues"][0]["owner_hart"], 1);
    assert_eq!(scheduler["references"]["queues"][0]["owner_hart_generation"], 2);
    assert_eq!(scheduler["references"]["preemptions"][0]["activation"], 11);
    assert_eq!(
        scheduler["references"]["scheduler_decisions"][0]["selected_activation_generation"],
        3
    );
    assert_eq!(scheduler["last_transition"]["activation_context_count"], 1);
    assert_eq!(scheduler["last_transition"]["saved_context_count"], 1);
    assert_eq!(scheduler["last_transition"]["timer_interrupt_count"], 1);
    assert_eq!(scheduler["last_transition"]["ipi_event_count"], 1);
    assert_eq!(scheduler["last_transition"]["remote_preempt_count"], 1);
    assert_eq!(scheduler["last_transition"]["remote_park_count"], 1);
    assert_eq!(scheduler["references"]["ipi_events"][0]["target_hart"], 2);
    assert_eq!(scheduler["references"]["remote_preempts"][0]["activation_generation_after"], 3);
    assert_eq!(scheduler["references"]["remote_parks"][0]["target_hart"], 2);
    assert_eq!(scheduler["last_transition"]["hart_event_attribution_count"], 1);
    assert_eq!(
        scheduler["references"]["hart_event_attributions"][0]["event_kind"],
        "TimerInterruptRecorded"
    );
    assert_eq!(scheduler["last_transition"]["preemption_count"], 1);
    assert_eq!(scheduler["last_transition"]["scheduler_decision_count"], 1);
    assert_eq!(scheduler["last_transition"]["cross_hart_scheduler_decision_count"], 1);
    assert_eq!(scheduler["references"]["cross_hart_scheduler_decisions"][0]["target_hart"], 1);
    assert_eq!(scheduler["last_transition"]["activation_migration_count"], 1);
    assert_eq!(
        scheduler["references"]["activation_migrations"][0]["activation_generation_after"],
        4
    );
    assert_eq!(scheduler["last_transition"]["smp_safe_point_count"], 1);
    assert_eq!(scheduler["references"]["smp_safe_points"][0]["participant_count"], 2);
    assert_eq!(scheduler["last_transition"]["stop_the_world_rendezvous_count"], 1);
    assert_eq!(scheduler["references"]["stop_the_world_rendezvous"][0]["safe_point"], 28);
    assert_eq!(scheduler["last_transition"]["smp_code_publish_barrier_count"], 1);
    assert_eq!(scheduler["references"]["smp_code_publish_barriers"][0]["rendezvous"], 29);
    assert_eq!(scheduler["last_transition"]["smp_cleanup_quiescence_count"], 1);
    assert_eq!(scheduler["references"]["smp_cleanup_quiescence"][0]["cleanup"], 20);
    assert_eq!(scheduler["last_transition"]["smp_snapshot_barrier_count"], 1);
    assert_eq!(scheduler["references"]["smp_snapshot_barriers"][0]["rendezvous"], 29);
    assert_eq!(scheduler["last_transition"]["smp_stress_run_count"], 1);
    assert_eq!(scheduler["references"]["smp_stress_runs"][0]["property_failures"], 0);
    assert_eq!(scheduler["last_transition"]["smp_scaling_benchmark_count"], 1);
    assert_eq!(scheduler["references"]["smp_scaling_benchmarks"][0]["efficiency_milli"], 833);
    assert_eq!(scheduler["last_transition"]["activation_resume_count"], 1);
    assert_eq!(scheduler["last_transition"]["activation_wait_count"], 1);
    assert_eq!(scheduler["last_transition"]["activation_cleanup_count"], 1);
    assert_eq!(scheduler["last_transition"]["preemption_latency_sample_count"], 1);
    assert_eq!(scheduler["last_transition"]["timer_epoch"], 3);
    assert_eq!(scheduler["last_transition"]["scheduler_decision_cursor"], 12);

    let live_edges = live_graph_edges(&package);
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "task"
        && edge["from"]["generation"] == 1
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 2));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "device"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 99
        && edge["relation"] == "device-resource"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "queue"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["to"]["generation"] == 1
        && edge["relation"] == "queue-device"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "descriptor"
        && edge["to"]["kind"] == "queue"
        && edge["to"]["id"] == 36
        && edge["to"]["generation"] == 1
        && edge["relation"] == "descriptor-queue"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "dma-buffer"
        && edge["to"]["kind"] == "descriptor"
        && edge["to"]["id"] == 37
        && edge["to"]["generation"] == 1
        && edge["relation"] == "dma-buffer-descriptor"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "dma-buffer"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 100
        && edge["to"]["generation"] == 1
        && edge["relation"] == "dma-buffer-resource"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "mmio-region"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["to"]["generation"] == 1
        && edge["relation"] == "mmio-region-device"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "mmio-region"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 101
        && edge["to"]["generation"] == 1
        && edge["relation"] == "mmio-region-resource"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "irq-line"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["to"]["generation"] == 1
        && edge["relation"] == "irq-line-device"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "irq-line"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 102
        && edge["to"]["generation"] == 1
        && edge["relation"] == "irq-line-resource"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "activation"
        && edge["to"]["kind"] == "runnable-queue"
        && edge["to"]["generation"] == 1));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "activation"
        && edge["to"]["kind"] == "activation-context"
        && edge["to"]["generation"] == 2));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "activation-context"
        && edge["to"]["kind"] == "saved-context"
        && edge["to"]["generation"] == 1));
    assert!(!live_edges.iter().any(|edge| edge["from"]["kind"] == "timer-interrupt"));
    let history_edges = history_graph_edges(&package);
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "timer-interrupt"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 2
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "preemption"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 3
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "saved-context"
        && edge["to"]["kind"] == "preemption"
        && edge["to"]["generation"] == 1
        && edge["relation"] == "captured-from-preemption"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "scheduler-decision"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 3
        && edge["relation"] == "selected"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"]
        == "cross-hart-scheduler-decision"
        && edge["to"]["kind"] == "hart"
        && edge["to"]["id"] == 1
        && edge["relation"] == "target-hart"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "activation-migration"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 4
        && edge["relation"] == "migrated-to"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-safe-point"
        && edge["to"]["kind"] == "hart"
        && edge["to"]["id"] == 1
        && edge["relation"] == "coordinator-hart"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-safe-point"
        && edge["to"]["kind"] == "hart"
        && edge["to"]["id"] == 2
        && edge["relation"] == "participant-hart"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["kind"] == "smp-safe-point"
        && edge["to"]["id"] == 28
        && edge["relation"] == "rendezvous-safe-point"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["kind"] == "hart"
        && edge["to"]["id"] == 2
        && edge["relation"] == "participant-hart"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-code-publish-barrier"
        && edge["to"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["id"] == 29
        && edge["relation"] == "publish-rendezvous"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-code-publish-barrier"
        && edge["to"]["kind"] == "hart"
        && edge["to"]["id"] == 2
        && edge["relation"] == "participant-hart"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-cleanup-quiescence"
        && edge["to"]["kind"] == "activation-cleanup"
        && edge["to"]["id"] == 20
        && edge["relation"] == "cleanup"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-cleanup-quiescence"
        && edge["to"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["id"] == 29
        && edge["relation"] == "cleanup-rendezvous"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-snapshot-barrier"
        && edge["to"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["id"] == 29
        && edge["relation"] == "snapshot-rendezvous"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-stress-run"
        && edge["to"]["kind"] == "smp-snapshot-barrier"
        && edge["to"]["id"] == 32
        && edge["relation"] == "last-snapshot-barrier"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-scaling-benchmark"
        && edge["to"]["kind"] == "smp-stress-run"
        && edge["to"]["id"] == 33
        && edge["relation"] == "scaling-stress-run"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "device"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 99
        && edge["relation"] == "device-resource"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "queue"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["relation"] == "queue-device"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "descriptor"
        && edge["to"]["kind"] == "queue"
        && edge["to"]["id"] == 36
        && edge["relation"] == "descriptor-queue"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "dma-buffer"
        && edge["to"]["kind"] == "descriptor"
        && edge["to"]["id"] == 37
        && edge["relation"] == "dma-buffer-descriptor"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "dma-buffer"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 100
        && edge["relation"] == "dma-buffer-resource"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "mmio-region"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["relation"] == "mmio-region-device"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "mmio-region"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 101
        && edge["relation"] == "mmio-region-resource"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "irq-line"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["relation"] == "irq-line-device"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "irq-line"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 102
        && edge["relation"] == "irq-line-resource"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "irq-event"
        && edge["to"]["kind"] == "irq-line"
        && edge["to"]["id"] == 40
        && edge["relation"] == "irq-event-line"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "irq-event"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["relation"] == "irq-event-device"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "irq-event"
        && edge["to"]["kind"] == "store"
        && edge["to"]["id"] == 1
        && edge["relation"] == "irq-event-driver-store"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "activation-resume"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 4
        && edge["relation"] == "resumed-to"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "activation-wait"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 6
        && edge["relation"] == "cancelled-to"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "preemption-latency"
        && edge["to"]["kind"] == "activation-resume"
        && edge["to"]["generation"] == 1
        && edge["relation"] == "measured-resume"
        && edge["mode"] == "historical"));
}

#[test]
fn scheduler_view_v1_exposes_current_activation_owners() {
    let mut package = minimal_graph_package();
    package.package_id = "s4-test".to_owned();
    package.semantic.hart_count = 1;
    package.semantic.hart_records.push(HartRecordManifest {
        id: 2,
        hardware_id: 1,
        label: "hart1".to_owned(),
        state: "running".to_owned(),
        generation: 3,
        boot: false,
        current_activation: Some(11),
        current_activation_generation: Some(4),
        current_task: Some(7),
        current_task_generation: Some(1),
        current_store: Some(5),
        current_store_generation: Some(2),
        last_event: Some(21),
        last_current_event: Some(21),
        note: "s4 current owner".to_owned(),
    });

    let scheduler = scheduler_view_v1(&package);
    assert_eq!(scheduler["references"]["current_activation_owners"][0]["hart"]["id"], 2);
    assert_eq!(
        scheduler["references"]["current_activation_owners"][0]["activation"]["generation"],
        4
    );
    assert_eq!(scheduler["references"]["current_activation_owners"][0]["store"]["generation"], 2);
}

#[test]
fn cleanup_view_v1_exposes_steps_effects_and_status() {
    let target = ContractObjectRefManifest { kind: "store".to_owned(), id: 1, generation: 2 };
    let view = cleanup_view_v1(&CleanupTransactionManifest {
        id: 5,
        store: 1,
        store_generation: 2,
        target_store_generation: 1,
        result_store_generation: Some(2),
        activation: None,
        activation_generation: None,
        code_object: None,
        code_generation: None,
        generation: 1,
        started_at: 10,
        finished_at: Some(11),
        state: "completed".to_owned(),
        reason: "fault".to_owned(),
        released_dmw_leases: 1,
        cancelled_waits: 0,
        revoked_capabilities: vec![4],
        revoked_capability_refs: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 4,
            generation: 2,
        }],
        dropped_resources: 1,
        unbound_code_object: true,
        state_digest: "store:1@2:dead|code:none|activations=[]|leases=[]|caps=[]".to_owned(),
        effect: "errno".to_owned(),
        steps: vec![CleanupStepManifest {
            step: "mark-store-state".to_owned(),
            state: "done".to_owned(),
            detail: "store marked dead".to_owned(),
            target: Some(target.clone()),
            observed_generation: Some(2),
            error: None,
            idempotency_key: "mark-store-state".to_owned(),
            event_seq: 11,
        }],
        effects: vec![CleanupEffectManifest {
            kind: "mark-store-dead".to_owned(),
            target,
            expected_generation: 2,
            status: "applied".to_owned(),
            event_seq: 11,
        }],
    });
    assert_eq!(view["kind"], "cleanup");
    assert_eq!(view["steps"][0]["state"], "done");
    assert_eq!(view["effects"][0]["kind"], "mark-store-dead");
    assert_eq!(view["references"]["target_store"]["generation"], 1);
    assert_eq!(view["references"]["result_store"]["generation"], 2);
    assert_eq!(view["references"]["revoked_capabilities"][0]["id"], 4);
    assert_eq!(view["idempotence"]["state_digest_present"], true);
}

#[test]
fn executor_object_views_do_not_dump_internal_schema() {
    let artifact = artifact_view_v1(&TargetArtifactImageManifest {
        id: 2,
        package: "driver_virtio_net".to_owned(),
        artifact_name: "driver_virtio_net".to_owned(),
        role: "driver".to_owned(),
        kind: "target-artifact-image-v1".to_owned(),
        target_profile: "host-validation".to_owned(),
        artifact_hash: "artifact".to_owned(),
        hash_status: "manifest-bound".to_owned(),
        abi_fingerprint: "abi".to_owned(),
        manifest_binding_hash: "binding".to_owned(),
        code_hash: "code".to_owned(),
        signature_scheme: "prototype-self-signed-sha256".to_owned(),
        signature_status: "profile-bound-unverified".to_owned(),
        signature_verified: false,
        signer: "test-signer".to_owned(),
        exports: vec!["memory".to_owned()],
        payload_len: 4096,
        ..TargetArtifactImageManifest::default()
    });
    assert_eq!(artifact["schema"], VIEW_SCHEMA_V1);
    assert_eq!(artifact["kind"], "artifact");
    assert_eq!(artifact["state"], "accepted");
    assert_eq!(artifact["references"]["artifact_hash"], "artifact");
    assert_eq!(artifact["references"]["hash_status"], "manifest-bound");
    assert_eq!(artifact["references"]["manifest_binding_hash"], "binding");
    assert_eq!(artifact["verification"]["signature_status"], "profile-bound-unverified");
    assert_eq!(artifact["verification"]["signature_verified"], false);
    assert_eq!(artifact["last_transition"]["payload_len"], 4096);

    let code = code_object_view_v1(&CodeObjectManifest {
        id: 3,
        artifact_id: 2,
        package: "driver_virtio_net".to_owned(),
        owner_profile: "host-validation".to_owned(),
        generation: 4,
        state: "bound-to-store".to_owned(),
        bound_store: Some(1),
        bound_store_generation: Some(7),
        text_start: 0x1000,
        text_len: 128,
        text_permission: "rx".to_owned(),
        code_hash: "code".to_owned(),
        simd_requirement: artifact_manifest::CodeObjectSimdRequirementManifest {
            uses_simd: true,
            declared: true,
            required_abi: "riscv-v".to_owned(),
            min_vector_register_count: 32,
            min_vector_register_bits: 128,
            target_feature_set: Some(ContractObjectRefManifest {
                kind: "target-feature-set".to_owned(),
                id: 21_000,
                generation: 1,
            }),
            status: "declared".to_owned(),
            note: "requires RVV".to_owned(),
        },
        ..CodeObjectManifest::default()
    });
    assert_eq!(code["kind"], "code-object");
    assert_eq!(code["generation"], 4);
    assert_eq!(code["references"]["bound_store"]["generation"], 7);
    assert_eq!(code["memory"]["text"]["permission"], "rx");
    assert_eq!(code["simd_requirement"]["uses_simd"], true);
    assert_eq!(code["simd_requirement"]["required_abi"], "riscv-v");
    assert_eq!(code["simd_requirement"]["target_feature_set"]["kind"], "target-feature-set");
}

#[test]
fn trace_views_expose_attribution_generations() {
    let activation = activation_view_v1(&ActivationRecordManifest {
        id: 10,
        store: 1,
        store_generation: 2,
        code_object: 3,
        code_generation: 4,
        artifact: 5,
        entry: "_start".to_owned(),
        generation: 6,
        state: "running".to_owned(),
        start_event: 7,
        active_dmw_leases: 1,
        ..ActivationRecordManifest::default()
    });
    assert_eq!(activation["kind"], "activation");
    assert_eq!(activation["owner"]["store_generation"], 2);
    assert_eq!(activation["references"]["code_object"]["generation"], 4);

    let trap = trap_view_v1(&TrapRecordManifest {
        id: 11,
        generation: 1,
        class: "capability-trap".to_owned(),
        store: Some(1),
        store_generation: Some(2),
        activation: Some(10),
        activation_generation: Some(6),
        code_object: Some(3),
        code_generation: Some(4),
        artifact: Some(5),
        artifact_generation: Some(1),
        trap_kind: Some("simd-unsupported".to_owned()),
        attribution_status: "trap-map-attributed".to_owned(),
        simd_attribution: Some(artifact_manifest::SimdTrapAttributionManifest {
            classification: "unsupported-target-profile".to_owned(),
            required_abi: "riscv-v".to_owned(),
            min_vector_register_count: 32,
            min_vector_register_bits: 128,
            target_feature_set: Some(ContractObjectRefManifest {
                kind: "target-feature-set".to_owned(),
                id: 21_000,
                generation: 1,
            }),
            code_requirement_status: "declared".to_owned(),
            note: "SIMD trap attribution".to_owned(),
        }),
        fault_policy: "restart".to_owned(),
        effect: "cleanup".to_owned(),
        detail: "denied".to_owned(),
        ..TrapRecordManifest::default()
    });
    assert_eq!(trap["kind"], "trap");
    assert_eq!(trap["owner"]["activation_generation"], 6);
    assert_eq!(trap["references"]["code_object"]["generation"], 4);
    assert_eq!(trap["simd_attribution"]["classification"], "unsupported-target-profile");
    assert_eq!(trap["simd_attribution"]["target_feature_set"]["generation"], 1);
    assert_eq!(trap["last_error"], "denied");
    assert_eq!(trap["attribution"]["status"], "trap-map-attributed");

    let hostcall = hostcall_trace_view_v1(&HostcallTraceManifest {
        id: 12,
        generation: 1,
        abi_version: "vmos-target-hostcall-frame-v1".to_owned(),
        frame_size: 128,
        activation: 10,
        activation_generation: 6,
        store: 1,
        store_generation: 2,
        code_object: 3,
        code_generation: 4,
        artifact: 5,
        artifact_generation: 7,
        hostcall_number: 64,
        hostcall_seq: 99,
        caller_offset: 16,
        name: "mmio.read32".to_owned(),
        category: "mmio".to_owned(),
        subject: "driver_virtio_net".to_owned(),
        subject_source: "active-store-activation-code-object".to_owned(),
        object: "mmio.bar0".to_owned(),
        operation: "read32".to_owned(),
        allowed: false,
        gate_status: "denied".to_owned(),
        result: "cap-arg-generation".to_owned(),
        denial_reason: Some("cap-arg-generation".to_owned()),
        ..HostcallTraceManifest::default()
    });
    assert_eq!(hostcall["kind"], "hostcall");
    assert_eq!(hostcall["owner"]["activation_generation"], 6);
    assert_eq!(hostcall["references"]["artifact"]["generation"], 7);
    assert_eq!(hostcall["call"]["caller_offset"], 16);
    assert_eq!(hostcall["call"]["subject_source"], "active-store-activation-code-object");
    assert_eq!(hostcall["gate"]["status"], "denied");
    assert_eq!(hostcall["gate"]["denial_reason"], "cap-arg-generation");
    assert_eq!(hostcall["last_error"], "cap-arg-generation");
}

#[test]
fn substrate_event_view_v1_explains_unsupported_authority() {
    let view = substrate_event_view_v1(&SubstrateEventManifest {
        id: 21,
        epoch: 34,
        event_kind: "unsupported".to_owned(),
        authority: "DmaAuthority".to_owned(),
        operation: "dma_alloc".to_owned(),
        requester: Some("driver.fake_net".to_owned()),
        artifact: Some(9),
        store: Some(4),
        capability: None,
        explanation: "driver.fake_net observed DmaAuthority::dma_alloc as unsupported".to_owned(),
    });
    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "substrate-event");
    assert_eq!(view["id"], 21);
    assert_eq!(view["state"], "unsupported");
    assert_eq!(view["authority"], "DmaAuthority");
    assert_eq!(view["operation"], "dma_alloc");
    assert_eq!(view["requester"], "driver.fake_net");
    assert_eq!(view["references"]["artifact"], 9);
    assert_eq!(view["references"]["store"], 4);
    assert_eq!(view["references"]["event_epoch"], 34);
    assert_eq!(
        view["last_error"],
        "driver.fake_net observed DmaAuthority::dma_alloc as unsupported"
    );
}

#[test]
fn command_result_view_v1_exposes_status_events_and_violations() {
    let view = command_result_view_v1(&CommandResultManifest {
        id: 5,
        issuer: "target-executor-command-probe".to_owned(),
        command: "create-wait".to_owned(),
        status: "rejected".to_owned(),
        events: Vec::new(),
        effects: Vec::new(),
        violations: vec!["create-wait requires owner task or owner store".to_owned()],
    });
    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "command");
    assert_eq!(view["id"], 5);
    assert_eq!(view["state"], "rejected");
    assert_eq!(view["issuer"], "target-executor-command-probe");
    assert_eq!(view["command_name"], "create-wait");
    assert_eq!(view["last_transition"]["event_count"], 0);
    assert_eq!(view["last_error"], "create-wait requires owner task or owner store");
}

#[test]
fn interface_event_view_v1_explains_unsupported_interface() {
    let view = interface_event_view_v1(&InterfaceEventManifest {
        id: 8,
        epoch: 13,
        interface_kind: "standard-wasi".to_owned(),
        interface: "wasi:clocks/monotonic-clock".to_owned(),
        operation: "subscribe".to_owned(),
        requester: Some("target-executor-interface-probe".to_owned()),
        artifact: None,
        store: None,
        explanation:
            "target-executor-interface-probe observed standard-wasi wasi:clocks/monotonic-clock::subscribe as unsupported"
                .to_owned(),
    });
    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "interface-event");
    assert_eq!(view["state"], "unsupported");
    assert_eq!(view["interface_kind"], "standard-wasi");
    assert_eq!(view["interface"], "wasi:clocks/monotonic-clock");
    assert_eq!(view["operation"], "subscribe");
    assert_eq!(view["references"]["event_epoch"], 13);
    assert_eq!(
        view["last_error"],
        "target-executor-interface-probe observed standard-wasi wasi:clocks/monotonic-clock::subscribe as unsupported"
    );
}

#[test]
fn graph_json_edges_separate_live_history_and_cleanup_modes() {
    let mut package = minimal_graph_package();
    package.semantic.activation_records.push(ActivationRecordManifest {
        id: 10,
        store: 1,
        store_generation: 2,
        code_object: 3,
        code_generation: 4,
        artifact: 5,
        entry: "_start".to_owned(),
        generation: 6,
        state: "running".to_owned(),
        start_event: 7,
        ..ActivationRecordManifest::default()
    });
    package.semantic.code_objects.push(CodeObjectManifest {
        id: 3,
        artifact_id: 5,
        package: "driver".to_owned(),
        owner_profile: "host-validation".to_owned(),
        generation: 4,
        state: "bound-to-store".to_owned(),
        bound_store: Some(1),
        bound_store_generation: Some(2),
        ..CodeObjectManifest::default()
    });
    package.semantic.capability_records.push(CapabilityRecordManifest {
        id: 20,
        subject: "driver".to_owned(),
        object: "packet-device.net0".to_owned(),
        object_ref: Some(AuthorityObjectRefManifest {
            scope: "internal".to_owned(),
            class: "packet-device".to_owned(),
            object: ContractObjectRefManifest {
                kind: "resource".to_owned(),
                id: 99,
                generation: 1,
            },
        }),
        rights: vec!["rx".to_owned()],
        lifetime: "store".to_owned(),
        class: "packet-device".to_owned(),
        owner_store: Some(1),
        owner_store_generation: Some(2),
        source: "test".to_owned(),
        generation: 1,
        manifest_decl: true,
        ..CapabilityRecordManifest::default()
    });
    package.semantic.wait_records.push(WaitRecordManifest {
        id: 30,
        owner_store: Some(1),
        owner_store_generation: Some(2),
        kind: "device-irq".to_owned(),
        generation: 1,
        state: "pending".to_owned(),
        blockers: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 20,
            generation: 1,
        }],
        restart_policy: "restart-if-allowed".to_owned(),
        ..WaitRecordManifest::default()
    });
    package.semantic.trap_records.push(TrapRecordManifest {
        id: 40,
        generation: 1,
        class: "capability-trap".to_owned(),
        store: Some(1),
        store_generation: Some(2),
        activation: Some(10),
        activation_generation: Some(6),
        code_object: Some(3),
        code_generation: Some(4),
        artifact: Some(5),
        artifact_generation: Some(1),
        fault_policy: "restart".to_owned(),
        effect: "cleanup".to_owned(),
        detail: "denied".to_owned(),
        ..TrapRecordManifest::default()
    });
    package.semantic.hostcall_trace.push(HostcallTraceManifest {
        id: 50,
        generation: 1,
        activation: 10,
        activation_generation: 6,
        store: 1,
        store_generation: 2,
        code_object: 3,
        code_generation: 4,
        artifact: 5,
        artifact_generation: 7,
        hostcall_number: 1,
        name: "hostcall.packet-device.net0.rx".to_owned(),
        category: "packet-device".to_owned(),
        object: "packet-device.net0".to_owned(),
        operation: "rx".to_owned(),
        allowed: true,
        result: "complete".to_owned(),
        trap_out: Some(40),
        trap_generation_out: Some(1),
        ..HostcallTraceManifest::default()
    });
    package.semantic.cleanup_transactions.push(CleanupTransactionManifest {
        id: 60,
        store: 1,
        store_generation: 2,
        target_store_generation: 2,
        activation: Some(10),
        activation_generation: Some(6),
        code_object: Some(3),
        code_generation: Some(4),
        generation: 1,
        started_at: 8,
        finished_at: Some(9),
        state: "completed".to_owned(),
        reason: "fault".to_owned(),
        released_dmw_leases: 0,
        cancelled_waits: 1,
        revoked_capabilities: vec![20],
        revoked_capability_refs: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 20,
            generation: 1,
        }],
        dropped_resources: 0,
        unbound_code_object: true,
        state_digest: "store:1@3:dead|code:3@4:retired|activations=[]|leases=[]|caps=[]".to_owned(),
        effect: "restart".to_owned(),
        steps: Vec::new(),
        effects: Vec::new(),
        result_store_generation: Some(3),
    });
    package.semantic.io_cleanups.push(IoCleanupManifest {
        id: 70,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 1,
        generation: 1,
        state: "completed".to_owned(),
        reason: "device-fault".to_owned(),
        started_at_event: 10,
        completed_at_event: 11,
        cancelled_io_waits: vec![ContractObjectRefManifest {
            kind: "io-wait".to_owned(),
            id: 46,
            generation: 1,
        }],
        revoked_device_capabilities: vec![ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 42,
            generation: 1,
        }],
        revoked_capabilities: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 20,
            generation: 1,
        }],
        released_dma_buffers: vec![ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 38,
            generation: 1,
        }],
        released_mmio_regions: vec![ContractObjectRefManifest {
            kind: "mmio-region-object".to_owned(),
            id: 39,
            generation: 1,
        }],
        released_irq_lines: vec![ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 40,
            generation: 1,
        }],
        steps: Vec::new(),
        note: "io cleanup graph".to_owned(),
    });
    package.semantic.io_fault_injections.push(IoFaultInjectionManifest {
        id: 71,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 1,
        target: ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 40,
            generation: 1,
        },
        cleanup: 70,
        cleanup_generation: 1,
        generation: 1,
        kind: "device-fault".to_owned(),
        state: "completed".to_owned(),
        injected_at_event: 12,
        note: "io fault graph".to_owned(),
    });
    package.semantic.packet_buffer_objects.push(PacketBufferObjectManifest {
        id: 80,
        packet_device: 81,
        packet_device_generation: 1,
        direction: "rx".to_owned(),
        frame_format_version: 2,
        capacity: 512,
        payload_len: 64,
        sequence: 1,
        generation: 1,
        state: "filled".to_owned(),
        recorded_at_event: 13,
        note: "packet buffer graph".to_owned(),
    });
    package.semantic.packet_queue_objects.push(PacketQueueObjectManifest {
        id: 82,
        name: "net0-rx0".to_owned(),
        packet_device: 81,
        packet_device_generation: 1,
        role: "rx".to_owned(),
        queue_index: 0,
        depth: 4,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 14,
        note: "packet queue graph".to_owned(),
    });
    package.semantic.packet_descriptors.push(PacketDescriptorObjectManifest {
        id: 83,
        packet_queue: 82,
        packet_queue_generation: 1,
        packet_buffer: 80,
        packet_buffer_generation: 1,
        slot: 0,
        length: 64,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 15,
        note: "packet descriptor graph".to_owned(),
    });
    package.semantic.fake_net_backends.push(FakeNetBackendObjectManifest {
        id: 84,
        name: "fake-net0".to_owned(),
        packet_device: 81,
        packet_device_generation: 1,
        provider: "service_core".to_owned(),
        profile: "fake-net-v1".to_owned(),
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        frame_format_version: 2,
        max_payload_len: 512,
        deterministic_seed: 7,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 16,
        note: "fake net backend graph".to_owned(),
    });
    package.semantic.virtio_net_backends.push(VirtioNetBackendObjectManifest {
        id: 85,
        name: "virtio-net0-backend".to_owned(),
        packet_device: 81,
        packet_device_generation: 1,
        driver_binding: 70,
        driver_binding_generation: 1,
        device: 61,
        device_generation: 1,
        provider: "substrate_virtio".to_owned(),
        profile: "virtio-net-backend-skeleton-v1".to_owned(),
        model: "virtio-net".to_owned(),
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        frame_format_version: 2,
        max_payload_len: 512,
        device_features: 32,
        driver_features: 32,
        negotiated_features: 32,
        rx_queue_index: 0,
        tx_queue_index: 1,
        queue_size: 4,
        irq_vector: 5,
        generation: 1,
        state: "skeleton-ready".to_owned(),
        recorded_at_event: 17,
        note: "virtio net backend graph".to_owned(),
    });
    package.semantic.network_rx_interrupts.push(NetworkRxInterruptManifest {
        id: 86,
        virtio_net_backend: 85,
        virtio_net_backend_generation: 1,
        irq_event: 41,
        irq_event_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        rx_queue: 82,
        rx_queue_generation: 1,
        ready_descriptors: 1,
        sequence: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 18,
        note: "network rx interrupt graph".to_owned(),
    });
    package.semantic.network_rx_wait_resolutions.push(NetworkRxWaitResolutionManifest {
        id: 87,
        io_wait: 50,
        io_wait_generation: 1,
        wait: 5,
        wait_generation: 1,
        rx_interrupt: 86,
        rx_interrupt_generation: 1,
        irq_event: 41,
        irq_event_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        rx_queue: 82,
        rx_queue_generation: 1,
        ready_descriptors: 1,
        sequence: 1,
        generation: 1,
        state: "resolved".to_owned(),
        resolved_at_event: 19,
        note: "network rx wait resolution graph".to_owned(),
    });
    package.semantic.packet_buffer_objects.push(PacketBufferObjectManifest {
        id: 88,
        packet_device: 81,
        packet_device_generation: 1,
        direction: "tx".to_owned(),
        frame_format_version: 2,
        capacity: 512,
        payload_len: 64,
        sequence: 2,
        generation: 1,
        state: "filled".to_owned(),
        recorded_at_event: 20,
        note: "tx packet buffer graph".to_owned(),
    });
    package.semantic.packet_queue_objects.push(PacketQueueObjectManifest {
        id: 89,
        name: "net0-tx0".to_owned(),
        packet_device: 81,
        packet_device_generation: 1,
        role: "tx".to_owned(),
        queue_index: 1,
        depth: 4,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 21,
        note: "tx packet queue graph".to_owned(),
    });
    package.semantic.packet_descriptors.push(PacketDescriptorObjectManifest {
        id: 90,
        packet_queue: 89,
        packet_queue_generation: 1,
        packet_buffer: 88,
        packet_buffer_generation: 1,
        slot: 0,
        length: 64,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 22,
        note: "tx packet descriptor graph".to_owned(),
    });
    package.semantic.network_tx_capability_gates.push(NetworkTxCapabilityGateManifest {
        id: 91,
        driver_store: 1,
        driver_store_generation: 2,
        packet_device: 81,
        packet_device_generation: 1,
        tx_queue: 89,
        tx_queue_generation: 1,
        packet_descriptor: 90,
        packet_descriptor_generation: 1,
        packet_buffer: 88,
        packet_buffer_generation: 1,
        device_capability: 42,
        device_capability_generation: 1,
        capability: 1,
        capability_generation: 1,
        handle_slot: 1,
        handle_generation: 1,
        handle_tag: 9,
        operation: "tx".to_owned(),
        byte_len: 64,
        sequence: 2,
        generation: 1,
        state: "allowed".to_owned(),
        recorded_at_event: 23,
        note: "network tx capability gate graph".to_owned(),
    });
    package.semantic.network_tx_completions.push(NetworkTxCompletionManifest {
        id: 92,
        tx_gate: 91,
        tx_gate_generation: 1,
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 85,
        backend_generation: 1,
        driver_store: 1,
        driver_store_generation: 2,
        packet_device: 81,
        packet_device_generation: 1,
        tx_queue: 89,
        tx_queue_generation: 1,
        packet_descriptor: 90,
        packet_descriptor_generation: 1,
        packet_buffer: 88,
        packet_buffer_generation: 1,
        byte_len: 64,
        sequence: 2,
        completion_sequence: 1,
        generation: 1,
        state: "completed".to_owned(),
        completed_at_event: 24,
        note: "network tx completion graph".to_owned(),
    });
    package.semantic.network_stack_adapters.push(NetworkStackAdapterManifest {
        id: 93,
        implementation: "smoltcp".to_owned(),
        implementation_version: "0.13.0".to_owned(),
        profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_owned(),
        medium: "ethernet".to_owned(),
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 85,
        backend_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        rx_queue: 82,
        rx_queue_generation: 1,
        tx_queue: 89,
        tx_queue_generation: 1,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        ipv4_addr: [10, 0, 2, 15],
        ipv4_prefix_len: 24,
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        max_payload_len: 512,
        socket_capacity: 0,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 25,
        note: "network stack adapter graph".to_owned(),
    });
    package.semantic.socket_objects.push(SocketObjectManifest {
        id: 94,
        adapter: 93,
        adapter_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        domain: 2,
        socket_type: 1,
        protocol: 0,
        canonical_protocol: 6,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        generation: 1,
        state: "created".to_owned(),
        created_at_event: 26,
        note: "socket object graph".to_owned(),
    });
    package.semantic.endpoint_objects.push(EndpointObjectManifest {
        id: 95,
        socket: 94,
        socket_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        local_addr: [0, 0, 0, 0],
        local_port: 0,
        remote_addr: [0, 0, 0, 0],
        remote_port: 0,
        generation: 1,
        state: "allocated".to_owned(),
        created_at_event: 27,
        note: "endpoint object graph".to_owned(),
    });
    package.semantic.socket_operations.push(SocketOperationManifest {
        id: 96,
        endpoint: 95,
        endpoint_generation: 1,
        socket: 94,
        socket_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        operation: "bind".to_owned(),
        local_addr: [10, 0, 2, 15],
        local_port: 8080,
        remote_addr: [0, 0, 0, 0],
        remote_port: 0,
        backlog: 0,
        byte_len: 0,
        sequence: 1,
        generation: 1,
        state: "applied".to_owned(),
        recorded_at_event: 28,
        note: "socket operation graph".to_owned(),
    });
    package.semantic.socket_waits.push(SocketWaitManifest {
        id: 97,
        wait: 45,
        wait_generation: 1,
        endpoint: 95,
        endpoint_generation: 1,
        socket: 94,
        socket_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        wait_kind: "socket-readable".to_owned(),
        blocker: ContractObjectRefManifest {
            kind: "endpoint-object".to_owned(),
            id: 95,
            generation: 1,
        },
        generation: 1,
        state: "pending".to_owned(),
        created_at_event: 29,
        completed_at_event: None,
        cancel_reason: None,
        ready_sequence: None,
        byte_len: None,
        note: "pending socket wait graph".to_owned(),
    });
    package.semantic.socket_waits.push(SocketWaitManifest {
        id: 98,
        wait: 46,
        wait_generation: 1,
        endpoint: 95,
        endpoint_generation: 1,
        socket: 94,
        socket_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        wait_kind: "socket-readable".to_owned(),
        blocker: ContractObjectRefManifest {
            kind: "endpoint-object".to_owned(),
            id: 95,
            generation: 1,
        },
        generation: 1,
        state: "resolved".to_owned(),
        created_at_event: 30,
        completed_at_event: Some(31),
        cancel_reason: None,
        ready_sequence: Some(1),
        byte_len: Some(19),
        note: "resolved socket wait graph".to_owned(),
    });
    package.semantic.network_backpressures.push(NetworkBackpressureManifest {
        id: 99,
        adapter: 93,
        adapter_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        packet_queue: 89,
        packet_queue_generation: 1,
        endpoint: Some(95),
        endpoint_generation: Some(1),
        socket: Some(94),
        socket_generation: Some(1),
        owner_store: Some(1),
        owner_store_generation: Some(2),
        direction: "tx".to_owned(),
        reason: "queue-full".to_owned(),
        action: "reject-send".to_owned(),
        queue_depth: 4,
        queue_limit: 4,
        dropped_packets: 0,
        dropped_bytes: 0,
        sequence: 2,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 32,
        note: "network backpressure graph".to_owned(),
    });
    package.semantic.network_driver_cleanups.push(NetworkDriverCleanupManifest {
        id: 100,
        io_cleanup: 70,
        io_cleanup_generation: 1,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        backend: ContractObjectRefManifest {
            kind: "virtio-net-backend-object".to_owned(),
            id: 85,
            generation: 1,
        },
        cancelled_socket_waits: vec![ContractObjectRefManifest {
            kind: "socket-wait".to_owned(),
            id: 97,
            generation: 1,
        }],
        cancelled_wait_tokens: vec![ContractObjectRefManifest {
            kind: "wait-token".to_owned(),
            id: 45,
            generation: 1,
        }],
        revoked_packet_capabilities: vec![ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 42,
            generation: 1,
        }],
        generation: 1,
        state: "completed".to_owned(),
        started_at_event: 33,
        completed_at_event: Some(34),
        reason: "device-fault".to_owned(),
        note: "network driver cleanup graph".to_owned(),
    });
    package.semantic.network_generation_audits.push(NetworkGenerationAuditManifest {
        id: 101,
        adapter: 93,
        adapter_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        packet_queue: 89,
        packet_queue_generation: 1,
        packet_descriptor: 88,
        packet_descriptor_generation: 1,
        packet_buffer: 87,
        packet_buffer_generation: 1,
        dma_buffer: ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 50,
            generation: 1,
        },
        device_capability: ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 42,
            generation: 1,
        },
        rejected_packet_generation_probes: 2,
        rejected_dma_generation_probes: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 35,
        note: "network generation audit graph".to_owned(),
    });
    package.semantic.network_fault_injections.push(NetworkFaultInjectionManifest {
        id: 102,
        adapter: 93,
        adapter_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        packet_queue: 89,
        packet_queue_generation: 1,
        packet_descriptor: Some(88),
        packet_descriptor_generation: Some(1),
        packet_buffer: Some(87),
        packet_buffer_generation: Some(1),
        endpoint: Some(95),
        endpoint_generation: Some(1),
        socket: Some(94),
        socket_generation: Some(1),
        owner_store: Some(7),
        owner_store_generation: Some(2),
        direction: "tx".to_owned(),
        kind: "packet-loss".to_owned(),
        effect: "drop-packet".to_owned(),
        injected_packets: 1,
        dropped_packets: 1,
        error_packets: 0,
        error_code: String::new(),
        sequence: 18,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 36,
        note: "network fault injection graph".to_owned(),
    });
    package.semantic.network_benchmarks.push(NetworkBenchmarkManifest {
        id: 103,
        scenario: "host-validation-network-throughput-latency".to_owned(),
        adapter: 93,
        adapter_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        tx_queue: 89,
        tx_queue_generation: 1,
        rx_queue: 82,
        rx_queue_generation: 1,
        tx_completion: 92,
        tx_completion_generation: 1,
        rx_wait_resolution: 87,
        rx_wait_resolution_generation: 1,
        endpoint: 95,
        endpoint_generation: 1,
        socket: 94,
        socket_generation: 1,
        owner_store: 7,
        owner_store_generation: 2,
        backpressure: Some(99),
        backpressure_generation: Some(1),
        sample_packets: 3,
        sample_bytes: 6000,
        tx_completed_packets: 1,
        rx_resolved_packets: 1,
        dropped_packets: 1,
        measured_nanos: 120_000,
        budget_nanos: 250_000,
        throughput_bytes_per_sec: 50_000_000,
        p50_latency_nanos: 18_000,
        p99_latency_nanos: 48_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 37,
        note: "network benchmark graph".to_owned(),
    });
    package.semantic.network_recovery_benchmarks.push(NetworkRecoveryBenchmarkManifest {
        id: 104,
        scenario: "host-validation-network-driver-recovery".to_owned(),
        cleanup: 100,
        cleanup_generation: 1,
        io_cleanup: 70,
        io_cleanup_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        backend: ContractObjectRefManifest {
            kind: "virtio-net-backend-object".to_owned(),
            id: 85,
            generation: 1,
        },
        driver_store: 1,
        driver_store_generation: 2,
        fault_injection: Some(102),
        fault_injection_generation: Some(1),
        recovery_start_event: 33,
        recovery_complete_event: 34,
        cancelled_socket_waits: 1,
        revoked_packet_capabilities: 1,
        recovery_nanos: 90_000,
        budget_nanos: 200_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 38,
        note: "network recovery benchmark graph".to_owned(),
    });
    package.semantic.block_device_objects.push(BlockDeviceObjectManifest {
        id: 105,
        name: "blk0".to_owned(),
        device: 35,
        device_generation: 1,
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 39,
        note: "block device graph".to_owned(),
    });
    package.semantic.block_range_objects.push(BlockRangeObjectManifest {
        id: 106,
        block_device: 105,
        block_device_generation: 1,
        start_sector: 64,
        sector_count: 8,
        byte_offset: 32768,
        byte_len: 4096,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 40,
        note: "block range graph".to_owned(),
    });
    package.semantic.block_request_objects.push(BlockRequestObjectManifest {
        id: 107,
        block_device: 105,
        block_device_generation: 1,
        block_range: 106,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "submitted".to_owned(),
        recorded_at_event: 41,
        note: "block request graph".to_owned(),
    });
    package.semantic.block_completion_objects.push(BlockCompletionObjectManifest {
        id: 108,
        block_request: 107,
        block_request_generation: 1,
        block_device: 105,
        block_device_generation: 1,
        block_range: 106,
        block_range_generation: 1,
        sequence: 1,
        completed_bytes: 4096,
        status: "success".to_owned(),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 42,
        note: "block completion graph".to_owned(),
    });
    package.semantic.block_waits.push(BlockWaitManifest {
        id: 109,
        wait: 110,
        wait_generation: 1,
        block_request: 107,
        block_request_generation: 1,
        block_device: 105,
        block_device_generation: 1,
        block_range: 106,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "resolved".to_owned(),
        created_at_event: 43,
        completed_at_event: Some(44),
        completion: Some(108),
        completion_generation: Some(1),
        cancel_reason: None,
        note: "block wait graph".to_owned(),
    });
    package.semantic.fake_block_backends.push(FakeBlockBackendObjectManifest {
        id: 111,
        name: "fake-block0".to_owned(),
        block_device: 105,
        block_device_generation: 1,
        provider: "service_core".to_owned(),
        profile: "fake-block-v1".to_owned(),
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        deterministic_seed: 7,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 45,
        note: "fake block backend graph".to_owned(),
    });
    package.semantic.virtio_blk_backends.push(VirtioBlkBackendObjectManifest {
        id: 112,
        name: "virtio-blk0-backend".to_owned(),
        block_device: 105,
        block_device_generation: 1,
        driver_binding: 113,
        driver_binding_generation: 1,
        device: 103,
        device_generation: 1,
        provider: "substrate_virtio".to_owned(),
        profile: "virtio-blk-backend-skeleton-v1".to_owned(),
        model: "virtio-blk".to_owned(),
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        device_features: 0x40,
        driver_features: 0x40,
        negotiated_features: 0x40,
        request_queue_index: 0,
        queue_size: 8,
        irq_vector: 6,
        generation: 1,
        state: "skeleton-ready".to_owned(),
        recorded_at_event: 46,
        note: "virtio block backend graph".to_owned(),
    });

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "owns"
        && edge["to"]["kind"] == "activation"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "authorizes"
        && edge["to"]["kind"] == "resource"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "packet-descriptor->packet-queue"
        && edge["from"]["kind"] == "packet-descriptor"
        && edge["to"]["kind"] == "packet-queue"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "packet-descriptor->packet-buffer"
        && edge["from"]["kind"] == "packet-descriptor"
        && edge["to"]["kind"] == "packet-buffer"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "block-device->device"
        && edge["from"]["kind"] == "block-device"
        && edge["to"]["kind"] == "device"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "block-range->block-device"
        && edge["from"]["kind"] == "block-range"
        && edge["to"]["kind"] == "block-device"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "block-request->block-range"
        && edge["from"]["kind"] == "block-request"
        && edge["to"]["kind"] == "block-range"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "fake-block-backend->block-device"
        && edge["from"]["kind"] == "fake-block-backend"
        && edge["to"]["kind"] == "block-device"
        && edge["to"]["generation"] == 1));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "virtio-blk-backend->block-device"
        && edge["from"]["kind"] == "virtio-blk-backend"
        && edge["to"]["kind"] == "block-device"
        && edge["to"]["generation"] == 1));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "virtio-blk-backend->driver-binding"
        && edge["from"]["kind"] == "virtio-blk-backend"
        && edge["to"]["kind"] == "driver-store-binding"));
    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "block-completion->block-request"
        && edge["from"]["kind"] == "block-completion"
        && edge["to"]["kind"] == "block-request"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "block-wait->block-completion"
        && edge["from"]["kind"] == "block-wait"
        && edge["to"]["kind"] == "block-completion"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "fake-net-backend->packet-device"
        && edge["from"]["kind"] == "fake-net-backend"
        && edge["to"]["kind"] == "packet-device"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "virtio-net-backend->packet-device"
        && edge["from"]["kind"] == "virtio-net-backend"
        && edge["to"]["kind"] == "packet-device"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "virtio-net-backend->driver-binding"
        && edge["from"]["kind"] == "virtio-net-backend"
        && edge["to"]["kind"] == "driver-store-binding"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "network-rx-interrupt->virtio-net-backend"
        && edge["from"]["kind"] == "network-rx-interrupt"
        && edge["to"]["kind"] == "virtio-net-backend"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "network-rx-interrupt->rx-queue"
        && edge["from"]["kind"] == "network-rx-interrupt"
        && edge["to"]["kind"] == "packet-queue"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "network-stack-adapter->backend"
        && edge["from"]["kind"] == "network-stack-adapter"
        && edge["to"]["kind"] == "virtio-net-backend"
        && edge["to"]["generation"] == 1));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "network-stack-adapter->rx-queue"
        && edge["from"]["kind"] == "network-stack-adapter"
        && edge["to"]["kind"] == "packet-queue"
        && edge["to"]["id"] == 82));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "network-stack-adapter->tx-queue"
        && edge["from"]["kind"] == "network-stack-adapter"
        && edge["to"]["kind"] == "packet-queue"
        && edge["to"]["id"] == 89));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "socket-object->network-stack-adapter"
        && edge["from"]["kind"] == "socket-object"
        && edge["to"]["kind"] == "network-stack-adapter"
        && edge["to"]["id"] == 93));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "socket-object->owner-store"
        && edge["from"]["kind"] == "socket-object"
        && edge["to"]["kind"] == "store"
        && edge["to"]["generation"] == 2));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "endpoint-object->socket-object"
        && edge["from"]["kind"] == "endpoint-object"
        && edge["to"]["kind"] == "socket-object"
        && edge["to"]["id"] == 94));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "endpoint-object->network-stack-adapter"
        && edge["from"]["kind"] == "endpoint-object"
        && edge["to"]["kind"] == "network-stack-adapter"
        && edge["to"]["id"] == 93));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "endpoint-object->owner-store"
        && edge["from"]["kind"] == "endpoint-object"
        && edge["to"]["kind"] == "store"
        && edge["to"]["generation"] == 2));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "socket-wait->wait-token"
        && edge["from"]["kind"] == "socket-wait"
        && edge["from"]["id"] == 97
        && edge["to"]["kind"] == "wait-token"
        && edge["to"]["generation"] == 1));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "socket-wait->endpoint-object"
        && edge["from"]["kind"] == "socket-wait"
        && edge["from"]["id"] == 97
        && edge["to"]["kind"] == "endpoint-object"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-backpressure"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-driver-cleanup"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-generation-audit"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-fault-injection"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-benchmark"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-recovery-benchmark"));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-operation->endpoint-object"
        && edge["from"]["kind"] == "socket-operation"
        && edge["to"]["kind"] == "endpoint-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-operation->socket-object"
        && edge["from"]["kind"] == "socket-operation"
        && edge["to"]["kind"] == "socket-object"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-operation->network-stack-adapter"
        && edge["from"]["kind"] == "socket-operation"
        && edge["to"]["kind"] == "network-stack-adapter"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-operation->owner-store"
        && edge["from"]["kind"] == "socket-operation"
        && edge["to"]["kind"] == "store"
        && edge["to"]["generation"] == 2));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-wait->wait-token"
        && edge["from"]["kind"] == "socket-wait"
        && edge["from"]["id"] == 98
        && edge["to"]["kind"] == "wait-token"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-wait->endpoint-object"
        && edge["from"]["kind"] == "socket-wait"
        && edge["from"]["id"] == 98
        && edge["to"]["kind"] == "endpoint-object"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-backpressure->packet-queue"
        && edge["from"]["kind"] == "network-backpressure"
        && edge["from"]["id"] == 99
        && edge["to"]["kind"] == "packet-queue"
        && edge["to"]["id"] == 89));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-backpressure->endpoint-object"
        && edge["from"]["kind"] == "network-backpressure"
        && edge["to"]["kind"] == "endpoint-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-driver-cleanup->io-cleanup"
        && edge["from"]["kind"] == "network-driver-cleanup"
        && edge["to"]["kind"] == "io-cleanup"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-driver-cleanup->backend"
        && edge["from"]["kind"] == "network-driver-cleanup"
        && edge["to"]["kind"] == "virtio-net-backend-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["relation"] == "network-driver-cleanup->cancelled-socket-wait"
        && edge["from"]["kind"] == "network-driver-cleanup"
        && edge["to"]["kind"] == "socket-wait"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["relation"] == "network-driver-cleanup->cancelled-wait-token"
        && edge["from"]["kind"] == "network-driver-cleanup"
        && edge["to"]["kind"] == "wait-token"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["relation"] == "network-driver-cleanup->revoked-packet-capability"
        && edge["from"]["kind"] == "network-driver-cleanup"
        && edge["to"]["kind"] == "device-capability"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-generation-audit->packet-descriptor"
        && edge["from"]["kind"] == "network-generation-audit"
        && edge["to"]["kind"] == "packet-descriptor"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-generation-audit->dma-buffer"
        && edge["from"]["kind"] == "network-generation-audit"
        && edge["to"]["kind"] == "dma-buffer-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-generation-audit->device-capability"
        && edge["from"]["kind"] == "network-generation-audit"
        && edge["to"]["kind"] == "device-capability"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-fault-injection->packet-descriptor"
        && edge["from"]["kind"] == "network-fault-injection"
        && edge["to"]["kind"] == "packet-descriptor"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-fault-injection->endpoint-object"
        && edge["from"]["kind"] == "network-fault-injection"
        && edge["to"]["kind"] == "endpoint-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-fault-injection->owner-store"
        && edge["from"]["kind"] == "network-fault-injection"
        && edge["to"]["kind"] == "store"
        && edge["to"]["generation"] == 2));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-benchmark->tx-completion"
        && edge["from"]["kind"] == "network-benchmark"
        && edge["to"]["kind"] == "network-tx-completion"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-benchmark->rx-wait-resolution"
        && edge["from"]["kind"] == "network-benchmark"
        && edge["to"]["kind"] == "network-rx-wait-resolution"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-benchmark->network-backpressure"
        && edge["from"]["kind"] == "network-benchmark"
        && edge["to"]["kind"] == "network-backpressure"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-recovery-benchmark->network-driver-cleanup"
        && edge["from"]["kind"] == "network-recovery-benchmark"
        && edge["to"]["kind"] == "network-driver-cleanup"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-recovery-benchmark->network-fault-injection"
        && edge["from"]["kind"] == "network-recovery-benchmark"
        && edge["to"]["kind"] == "network-fault-injection"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-recovery-benchmark->backend"
        && edge["from"]["kind"] == "network-recovery-benchmark"
        && edge["to"]["kind"] == "virtio-net-backend-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-rx-interrupt->irq-event"
        && edge["from"]["kind"] == "network-rx-interrupt"
        && edge["to"]["kind"] == "irq-event"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-rx-wait-resolution->rx-interrupt"
        && edge["from"]["kind"] == "network-rx-wait-resolution"
        && edge["to"]["kind"] == "network-rx-interrupt"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-rx-wait-resolution->rx-queue"
        && edge["from"]["kind"] == "network-rx-wait-resolution"
        && edge["to"]["kind"] == "packet-queue"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-tx-capability-gate->packet-descriptor"
        && edge["from"]["kind"] == "network-tx-capability-gate"
        && edge["to"]["kind"] == "packet-descriptor"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-tx-capability-gate->capability"
        && edge["from"]["kind"] == "network-tx-capability-gate"
        && edge["to"]["kind"] == "capability"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-tx-completion->tx-gate"
        && edge["from"]["kind"] == "network-tx-completion"
        && edge["to"]["kind"] == "network-tx-capability-gate"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-tx-completion->backend"
        && edge["from"]["kind"] == "network-tx-completion"
        && edge["to"]["kind"] == "virtio-net-backend"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-tx-completion->packet-descriptor"
        && edge["from"]["kind"] == "network-tx-completion"
        && edge["to"]["kind"] == "packet-descriptor"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "hostcall"
        && edge["to"]["kind"] == "activation"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "hostcall"
        && edge["to"]["kind"] == "artifact"
        && edge["to"]["generation"] == 7));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "hostcall"
        && edge["relation"] == "caused"
        && edge["to"]["kind"] == "trap"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["relation"] == "revoked"
        && edge["to"]["kind"] == "capability"));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["from"]["kind"] == "io-cleanup"
        && edge["relation"] == "released-irq-line"
        && edge["to"]["kind"] == "irq-line-object"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "io-cleanup"
        && edge["relation"] == "io-cleanup-driver-store"
        && edge["to"]["generation"] == 2));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["from"]["kind"] == "io-fault-injection"
        && edge["relation"] == "triggered-cleanup"
        && edge["to"]["kind"] == "io-cleanup"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "io-fault-injection"
        && edge["relation"] == "io-fault-target"
        && edge["to"]["kind"] == "irq-line-object"));
}

fn minimal_graph_package() -> MigrationPackageManifest {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "package_format": "vmos-semantic-package-v1",
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
            "runtime_executor_abi": "vmos-runtime-only-executor-v0"
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

#[test]
fn substrate_profile_selection_is_stable_for_json_checks() {
    let host = substrate_capabilities_for_profile("host-validation").expect("host profile");
    let semantic =
        substrate_capabilities_for_profile("semantic-harness").expect("semantic profile");

    assert!(host.artifact_loading);
    assert_eq!(host.dmw.as_str(), "logical");
    assert!(host.mmio);
    assert_eq!(host.snapshot.as_str(), "deterministic-replay");
    assert!(!semantic.artifact_loading);
    assert_eq!(semantic.dma.as_str(), "none");
    assert!(substrate_capabilities_for_profile("unknown-profile").is_none());
}

#[test]
fn interface_profile_selection_is_stable_for_json_checks() {
    let host = interface_capabilities_for_profile("host-validation").expect("host profile");
    let none = interface_capabilities_for_profile("none").expect("none profile");

    assert!(host.custom_wit_worlds.iter().any(|world| world == "semantic:machine"));
    assert!(none.custom_wit_worlds.is_empty());
    assert!(interface_capabilities_for_profile("unknown-profile").is_none());
}

#[test]
fn replay_fixtures_replay_to_expected_final_views() {
    let wait =
        parse_replay_fixture(include_str!("../../fixtures/replay/wait_pending_resume_v1.json"));
    replay_wait_fixture(&wait);

    let capability = parse_replay_fixture(include_str!(
        "../../fixtures/replay/capability_revoke_generation_v1.json"
    ));
    replay_capability_fixture(&capability);

    let cleanup = parse_replay_fixture(include_str!(
        "../../fixtures/replay/driver_fault_cleanup_generation_safe_v1.json"
    ));
    replay_cleanup_fixture(&cleanup);
}

fn parse_replay_fixture(source: &str) -> serde_json::Value {
    let value: serde_json::Value = serde_json::from_str(source).expect("replay fixture JSON");
    assert_eq!(value["schema"], "vmos-replay-fixture-v1");
    assert!(value["commands"].as_array().expect("commands").len() > 0);
    assert!(value["events"].as_array().expect("events").len() > 0);
    assert!(value["validation"]["ok"].as_bool().expect("validation ok"));
    value
}

fn replay_wait_fixture(value: &serde_json::Value) {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
    graph.register_store("bootstrap_a", "bootstrap_a.cwasm", "service", "restartable");
    graph.register_store("bootstrap_b", "bootstrap_b.cwasm", "service", "restartable");
    let owner_store = 3;
    let owner_store_generation = 1;
    let registered_store =
        graph.register_store("timer_service", "timer.cwasm", "service", "restartable");
    assert_eq!(registered_store, owner_store);
    for command in value["commands"].as_array().expect("commands") {
        match command["op"].as_str().expect("op") {
            "CreateWait" => graph
                .apply(SemanticCommand::CreateWait {
                    wait: command["wait"].as_u64().expect("wait"),
                    owner_task: command["owner_task"].as_u64().map(|task| task as u32),
                    owner_store: command["owner_store"].as_u64(),
                    owner_store_generation: Some(
                        command["owner_store_generation"]
                            .as_u64()
                            .unwrap_or(owner_store_generation),
                    ),
                    kind: SemanticWaitKind::Timer,
                    generation: command["generation"].as_u64().expect("generation"),
                    blockers: Vec::new(),
                    deadline: command["deadline"].as_u64(),
                    restart_policy: RestartPolicy::RestartWithAdjustedTimeout,
                    saved_context: None,
                })
                .expect("create wait"),
            "ResolveWait" => graph
                .apply(SemanticCommand::ResolveWait {
                    wait: command["wait"].as_u64().expect("wait"),
                    reason: command["reason"].as_str().expect("reason").to_owned(),
                })
                .expect("resolve wait"),
            "ConsumeWait" => {
                graph.record_wait_consumed(command["wait"].as_u64().expect("wait"));
                continue;
            }
            other => panic!("unsupported wait replay fixture command {other}"),
        };
    }
    let wait = graph.wait_records().iter().find(|wait| wait.id == 21).expect("wait 21");
    assert_eq!(wait.state, WaitState::Consumed);
    assert_eq!(value["final_views"]["wait"]["state"], wait.state.as_str());
    let snapshot = ContractGraphSnapshot {
        waits: graph.wait_records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

fn replay_capability_fixture(value: &serde_json::Value) {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("driver_virtio_net", "driver.cwasm", "driver", "restartable");
    let object = ContractObjectRef::new(ContractObjectKind::Resource, 99, 1);
    let authority = AuthorityObjectRef::internal(CapabilityClass::PacketDevice, object);
    for command in value["commands"].as_array().expect("commands") {
        match command["op"].as_str().expect("op") {
            "GrantCapability" => {
                graph
                    .apply(SemanticCommand::GrantCapability {
                        subject: command["subject"].as_str().expect("subject").to_owned(),
                        debug_object_label: "packet-device.net0".to_owned(),
                        object_ref: authority,
                        operations: vec!["rx".to_owned(), "tx".to_owned()],
                        lifetime: "store".to_owned(),
                        owner_store: command["owner_store"].as_u64().or(Some(store)),
                        owner_store_generation: command["owner_store_generation"]
                            .as_u64()
                            .or(Some(1)),
                        owner_task: None,
                        source: "replay-fixture".to_owned(),
                        manifest_decl: true,
                    })
                    .expect("grant capability");
            }
            "CreateWait" => {
                graph
                    .apply(SemanticCommand::CreateWait {
                        wait: command["wait"].as_u64().expect("wait"),
                        owner_task: None,
                        owner_store: command["owner_store"].as_u64().or(Some(store)),
                        owner_store_generation: command["owner_store_generation"]
                            .as_u64()
                            .or(Some(1)),
                        kind: SemanticWaitKind::DeviceIrq,
                        generation: 1,
                        blockers: vec![ContractObjectRef::new(
                            ContractObjectKind::Capability,
                            command["blocker"]["id"].as_u64().expect("cap blocker"),
                            command["blocker"]["generation"].as_u64().expect("cap generation"),
                        )],
                        deadline: None,
                        restart_policy: RestartPolicy::RestartIfAllowed,
                        saved_context: None,
                    })
                    .expect("create wait");
            }
            "RevokeCapability" => {
                graph
                    .apply(SemanticCommand::RevokeCapability {
                        cap: command["cap"].as_u64().expect("cap"),
                    })
                    .expect("revoke capability");
            }
            "CancelWait" => {
                graph
                    .apply(SemanticCommand::CancelWait {
                        wait: command["wait"].as_u64().expect("wait"),
                        errno: 125,
                        reason: WaitCancelReason::CapabilityRevoked,
                    })
                    .expect("cancel wait");
            }
            other => panic!("unsupported capability replay fixture command {other}"),
        }
    }

    let cap = graph.capabilities().records()[0].clone();
    assert!(cap.revoked);
    assert_eq!(cap.generation, 2);
    assert_eq!(value["final_views"]["capability"]["id"], cap.id);
    let wait = graph.wait_records().iter().find(|wait| wait.id == 22).expect("wait 22");
    assert_eq!(wait.state, WaitState::Cancelled);
    assert_eq!(wait.cancel_reason, Some(WaitCancelReason::CapabilityRevoked));
    let snapshot = ContractGraphSnapshot {
        stores: graph.stores().to_vec(),
        capabilities: graph.capabilities().records().to_vec(),
        waits: graph.wait_records().to_vec(),
        external_objects: vec![ExternalObjectDeclaration::new(
            object,
            "replay-fixture",
            CapabilityClass::PacketDevice.as_str(),
            "packet-device.net0",
        )],
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
    assert_eq!(value["expected_violation_codes"][0], "revoked");
}

fn replay_cleanup_fixture(value: &serde_json::Value) {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("driver_virtio_net", "driver.cwasm", "driver", "restartable");
    assert_eq!(store, 1);
    let mut last_rebind_generation = 1;
    let mut applied_step_status = None;

    for command in value["commands"].as_array().expect("commands") {
        match command["op"].as_str().expect("op") {
            "BeginCleanup" => {
                let target = &command["target_store"];
                assert_eq!(target["id"].as_u64().expect("target id"), store);
                graph
                    .apply(SemanticCommand::BeginCleanup {
                        cleanup: command["cleanup"].as_u64().expect("cleanup"),
                        store,
                        generation: target["generation"].as_u64().expect("generation"),
                        reason: command["reason"].as_str().expect("reason").to_owned(),
                    })
                    .expect("begin cleanup");
            }
            "RebindStore" => {
                let expected = &command["store"];
                assert_eq!(expected["id"].as_u64().expect("store id"), store);
                let rebound = graph.rebind_store_instance(store).expect("rebind store");
                last_rebind_generation = rebound.generation;
                assert_eq!(
                    expected["generation"].as_u64().expect("store generation"),
                    rebound.generation
                );
                assert_eq!(
                    expected["state"].as_str().expect("state"),
                    graph.stores()[0].state.as_str()
                );
            }
            "ApplyCleanupStep" => {
                let target = object_ref_from_json(&command["target"]);
                let observed_generation =
                    command["observed_generation"].as_u64().expect("observed generation");
                if command["status"].as_str() == Some("skipped-stale-generation") {
                    assert_ne!(target.generation, observed_generation);
                }
                graph
                    .apply(SemanticCommand::ApplyCleanupStep {
                        cleanup: command["cleanup"].as_u64().expect("cleanup"),
                        step: cleanup_step_from_json(command["step"].as_str().expect("step")),
                        target,
                        observed_generation,
                    })
                    .expect("apply cleanup step");
                applied_step_status = command["status"].as_str().map(|status| status.to_owned());
            }
            "CommitCleanup" => {
                graph
                    .apply(SemanticCommand::CommitCleanup {
                        cleanup: command["cleanup"].as_u64().expect("cleanup"),
                    })
                    .expect("commit cleanup");
                if let Some(status) = command["status"].as_str() {
                    assert_eq!(applied_step_status.as_deref(), Some(status));
                }
            }
            other => panic!("unsupported cleanup replay fixture command {other}"),
        }
    }

    assert_eq!(last_rebind_generation, 2);
    assert_eq!(
        graph.stores()[0].state.as_str(),
        value["final_views"]["store"]["state"].as_str().expect("store state")
    );
    assert_eq!(value["final_views"]["store"]["generation"], graph.stores()[0].generation);
    for event in value["events"].as_array().expect("events") {
        match event["kind"].as_str().expect("event kind") {
            "CleanupStepApplied" => {
                let expected = format!(
                    "CleanupStepApplied cleanup={} step={} target={} observed_generation={}",
                    event["cleanup"].as_u64().expect("cleanup"),
                    event["step"].as_str().expect("step"),
                    event["target"].as_str().expect("target"),
                    event["observed_generation"].as_u64().expect("observed generation")
                );
                assert!(
                    graph
                        .event_log_tail(16)
                        .iter()
                        .any(|record| record.summary().contains(&expected)),
                    "missing expected event {expected}"
                );
            }
            "StoreRebound" => {
                assert_eq!(
                    event["store"].as_str().expect("store"),
                    format!("{}@{}", store, graph.stores()[0].generation)
                );
            }
            "FaultCleanupStarted" | "FaultCleanupSkipped" => {}
            other => panic!("unsupported cleanup replay fixture event {other}"),
        }
    }
    let digest = cleanup_replay_digest(&graph, store);
    assert_eq!(value["state_digest"]["cleanup_once"], digest);
    assert_eq!(value["state_digest"]["cleanup_once"], value["state_digest"]["cleanup_twice"]);
}

fn object_ref_from_json(value: &serde_json::Value) -> ContractObjectRef {
    let kind = match value["kind"].as_str().expect("object kind") {
        "store" => ContractObjectKind::Store,
        "capability" => ContractObjectKind::Capability,
        "wait-token" | "wait" => ContractObjectKind::WaitToken,
        "cleanup" | "cleanup-transaction" => ContractObjectKind::CleanupTransaction,
        "resource" => ContractObjectKind::Resource,
        other => panic!("unsupported replay fixture object kind {other}"),
    };
    ContractObjectRef::new(
        kind,
        value["id"].as_u64().expect("object id"),
        value["generation"].as_u64().expect("object generation"),
    )
}

fn cleanup_step_from_json(value: &str) -> CleanupStep {
    match value {
        "stop-new-activation" => CleanupStep::StopNewActivation,
        "seal-activation" => CleanupStep::SealActivation,
        "prevent-hostcalls" => CleanupStep::PreventHostcalls,
        "release-dmw-leases" => CleanupStep::ReleaseDmwLeases,
        "cancel-wait-tokens" => CleanupStep::CancelWaitTokens,
        "revoke-capabilities" => CleanupStep::RevokeCapabilities,
        "drop-resource-arena" => CleanupStep::DropResourceArena,
        "unbind-code-object" => CleanupStep::UnbindCodeObject,
        "mark-store-state" => CleanupStep::MarkStoreState,
        "record-transition" => CleanupStep::RecordTransition,
        "emit-tombstones" => CleanupStep::EmitTombstones,
        "record-failure-effect" => CleanupStep::RecordFailureEffect,
        "emit-report" => CleanupStep::EmitReport,
        other => panic!("unsupported cleanup step {other}"),
    }
}

fn cleanup_replay_digest(graph: &SemanticGraph, store: u64) -> String {
    let store = graph.stores().iter().find(|record| record.id == store).expect("digest store");
    format!(
        "store:{}@{}:{}|code:1@1:bound|caps:active",
        store.id,
        store.generation,
        store.state.as_str()
    )
}
