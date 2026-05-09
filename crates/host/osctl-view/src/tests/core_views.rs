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

#[test]
fn external_audit_view_v1_exposes_claims_artifact_mix_and_findings() {
    let report = contract_validate::ExternalMigrationAuditReport {
        package_id: "audit-view-test".to_owned(),
        contract_package_valid: true,
        replay_quiescent: true,
        portable_artifact_execution_claim: true,
        visa_native_portable_artifact_execution_claim: true,
        real_target_substrate_claim: false,
        visa_native_artifact_count: 1,
        frontend_personality_artifact_count: 0,
        linux_weighted_artifact_count: 0,
        findings: vec![contract_validate::ExternalAuditFinding {
            severity: contract_validate::ExternalAuditSeverity::Info,
            code: "no-real-target-substrate-claim",
            detail: "host-side evidence only".to_owned(),
        }],
    };

    let view = external_audit_view_v1(&report);

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["schema_version"], OSCTL_JSON_SCHEMA_VERSION);
    assert_eq!(view["kind"], "external-audit");
    assert_eq!(view["ok"], true);
    assert_eq!(view["claims"]["portable_artifact_execution"], true);
    assert_eq!(view["claims"]["visa_native_portable_artifact_execution"], true);
    assert_eq!(view["claims"]["real_target_substrate"], false);
    assert_eq!(view["artifact_mix"]["visa_native_artifacts"], 1);
    assert_eq!(view["findings"][0]["severity"], "info");
    assert_eq!(view["findings"][0]["code"], "no-real-target-substrate-claim");
    assert_eq!(view["last_transition"]["finding_count"], 1);
    assert_eq!(view["last_transition"]["error_count"], 0);
    assert_eq!(view["last_error"], serde_json::Value::Null);
}

#[test]
fn audit_package_reads_serialized_package_and_returns_success_for_valid_chain() {
    let mut package = minimal_graph_package();
    add_native_portable_execution_chain(&mut package);

    let mut path = std::env::temp_dir();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    path.push(format!("osctl-audit-package-{unique}.json"));
    std::fs::write(&path, serde_json::to_vec(&package).expect("serialize package"))
        .expect("write package");

    let result = audit_package(&path, true);
    let _ = std::fs::remove_file(&path);

    result.expect("valid native portable chain should audit successfully");
}
