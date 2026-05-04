use super::*;

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
            engine_version: "43.0.2".to_owned(),
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
            hash_status: contract_validate::ARTIFACT_HASH_STATUS_MANIFEST_BOUND.to_owned(),
            signature_status: contract_validate::ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED
                .to_owned(),
            signature_verified: contract_validate::ARTIFACT_SIGNATURE_VERIFIED_DEFAULT,
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
        contract_validate::ARTIFACT_HASH_STATUS_MANIFEST_BOUND
    );
    assert_eq!(
        accepted["modules"][0]["target_profile"]["signature_status"],
        contract_validate::ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED
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
