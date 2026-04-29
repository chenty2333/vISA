use super::super::*;
pub(crate) fn stable_view_collection_v1(
    kind: &str,
    subcommand: &str,
    package: &MigrationPackageManifest,
    id: Option<&str>,
) -> Result<serde_json::Value, Box<dyn Error>> {
    if subcommand != "show" && subcommand != "list" {
        return Err(format!(
            "{kind} syntax is: osctl {kind} show|list [--json] <migration.json> [id]"
        )
        .into());
    }
    let views = stable_views_for_kind(kind, package)?;
    let views = if subcommand == "show" {
        let id = id.ok_or_else(|| format!("{kind} show requires an id"))?;
        let selected = select_view_by_id(views, id)?;
        vec![selected]
    } else {
        views
    };
    let count = views.len();
    Ok(serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "schema_version": OSCTL_JSON_SCHEMA_VERSION,
        "kind": canonical_view_kind(kind),
        "command": format!("{}.{}", canonical_view_kind(kind), subcommand),
        "package": &package.package_id,
        "count": count,
        "items": views,
    }))
}

pub(crate) fn artifact_plan_module_view_v1(module: &ValidatedArtifactEntry) -> serde_json::Value {
    serde_json::json!({
        "package_root": &module.package,
        "artifact_manifest": {
            "artifact_name": &module.artifact_name,
            "role": &module.role,
            "fault_policy": &module.fault_policy,
            "wasm_path": &module.wasm_path,
            "cwasm_path": &module.cwasm_path,
            "target_artifact_path": &module.target_artifact_path,
            "target_artifact_sha256": &module.target_artifact_sha256,
            "code_payload_format": &module.code_payload_format,
            "cwasm_sha256": &module.cwasm_sha256,
            "abi_fingerprint": &module.abi_fingerprint,
            "manifest_binding_hash": &module.manifest_binding_hash,
        },
        "capability_manifest": &module.capabilities,
        "target_profile": {
            "hash_status": &module.hash_status,
            "signature_scheme": &module.signature_scheme,
            "signature_status": &module.signature_status,
            "signature_verified": module.signature_verified,
            "signer": &module.signer,
        },
        "resource_limits": {
            "max_memory_pages": module.resource_limits.max_memory_pages,
            "max_table_elements": module.resource_limits.max_table_elements,
            "max_hostcalls_per_activation": module.resource_limits.max_hostcalls_per_activation
        },
        "expected_exports": &module.expected_exports,
        "service_dependencies": &module.service_dependencies,
    })
}

pub(crate) fn artifact_manifest_module_rejection_view_v1(
    module: &artifact_manifest::ModuleArtifactManifest,
) -> serde_json::Value {
    serde_json::json!({
        "package_root": &module.package,
        "artifact_manifest": {
            "artifact_name": &module.artifact_name,
            "role": &module.role,
            "fault_policy": &module.fault_policy,
            "wasm_path": &module.wasm_path,
            "cwasm_path": &module.cwasm_path,
            "target_artifact_path": &module.target_artifact_path,
            "target_artifact_sha256": &module.target_artifact_sha256,
            "code_payload_format": &module.code_payload_format,
            "cwasm_sha256": &module.cwasm_sha256,
            "abi_fingerprint": &module.abi_fingerprint,
            "manifest_binding_hash": &module.signature.manifest_binding_hash,
        },
        "capability_manifest": &module.capabilities,
        "target_profile": {
            "hash_status": "rejected",
            "signature_scheme": &module.signature.scheme,
            "signature_status": "rejected",
            "signature_verified": false,
            "signer": &module.signature.signer,
        },
    })
}

pub(crate) fn artifact_plan_view_v1(
    manifest: &ArtifactBundleManifest,
    plan: Option<&ValidatedArtifactPlan>,
    last_error: Option<&str>,
) -> serde_json::Value {
    let mode = plan
        .and_then(|plan| RuntimeMode::parse(&plan.runtime_mode))
        .unwrap_or(RuntimeMode::Research);
    let package_roots =
        manifest.modules.iter().map(|module| module.package.clone()).collect::<Vec<_>>();
    let modules = plan
        .map(|plan| plan.modules.iter().map(artifact_plan_module_view_v1).collect::<Vec<_>>())
        .unwrap_or_else(|| {
            manifest
                .modules
                .iter()
                .map(artifact_manifest_module_rejection_view_v1)
                .collect::<Vec<_>>()
        });
    let module_count = plan.map_or(manifest.modules.len(), ValidatedArtifactPlan::module_count);
    let capability_count = plan.map_or_else(
        || manifest.modules.iter().map(|module| module.capabilities.len()).sum(),
        ValidatedArtifactPlan::capability_count,
    );
    let expected_export_count = plan.map_or_else(
        || manifest.modules.iter().map(|module| module.expected_exports.len()).sum(),
        ValidatedArtifactPlan::expected_export_count,
    );

    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "schema_version": OSCTL_JSON_SCHEMA_VERSION,
        "kind": "artifact-plan",
        "state": if last_error.is_some() { "rejected" } else { "accepted" },
        "accepted": last_error.is_none(),
        "artifact_profile": plan
            .map(|plan| plan.artifact_profile.as_str())
            .unwrap_or(manifest.artifact_profile.as_str()),
        "runtime_mode": plan
            .map(|plan| plan.runtime_mode.as_str())
            .unwrap_or(manifest.runtime_mode.as_str()),
        "mode_policy": {
            "event_log": mode.event_log_policy(),
            "dmw": mode.dmw_policy(),
            "fastpath_enabled": mode.fast_path_enabled(),
            "deterministic_boundary": mode.deterministic_boundary(),
            "capability_audit": mode.capability_audit_policy(),
            "debug_metadata": mode.debug_metadata_policy(),
            "nondeterminism": mode.nondeterminism_policy()
        },
        "contract_version": plan
            .map(|plan| plan.contract_version.as_str())
            .unwrap_or(manifest.contract.contract_version.as_str()),
        "supervisor_world": plan
            .map(|plan| plan.supervisor_world.as_str())
            .unwrap_or(manifest.contract.supervisor_world.as_str()),
        "target_arch": plan
            .map(|plan| plan.target_arch.as_str())
            .unwrap_or(manifest.target.arch.as_str()),
        "target_profile": {
            "artifact_profile": &manifest.artifact_profile,
            "arch": &manifest.target.arch,
            "machine_abi_version": &manifest.target.machine_abi_version,
            "supervisor_abi_version": &manifest.target.supervisor_abi_version,
            "wasm_feature_profile": &manifest.target.wasm_feature_profile,
            "memory64": manifest.target.memory64,
            "multi_memory": manifest.target.multi_memory,
            "dmw_layout": &manifest.target.dmw_layout,
            "linux_abi_profile": &manifest.target.linux_abi_profile,
            "artifact_signature_profile": &manifest.target.artifact_signature_profile,
            "network_contract_version": &manifest.target.network_contract_version,
        },
        "compiler": {
            "engine": plan
                .map(|plan| plan.compiler_engine.as_str())
                .unwrap_or(manifest.compiler.engine.as_str()),
            "execution_mode": plan
                .map(|plan| plan.compiler_execution_mode.as_str())
                .unwrap_or(manifest.compiler.execution_mode.as_str()),
            "artifact_format": plan
                .map(|plan| plan.artifact_format.as_str())
                .unwrap_or(manifest.compiler.artifact_format.as_str()),
            "target_artifact_format": plan
                .map(|plan| plan.target_artifact_format.as_str())
                .unwrap_or(manifest.compiler.target_artifact_format.as_str()),
            "runtime_executor_abi": plan
                .map(|plan| plan.runtime_executor_abi.as_str())
                .unwrap_or(manifest.compiler.runtime_executor_abi.as_str())
        },
        "package_roots": package_roots,
        "module_count": module_count,
        "capability_count": capability_count,
        "expected_export_count": expected_export_count,
        "modules": modules,
        "last_error": last_error
    })
}

pub(crate) fn canonical_view_kind(kind: &str) -> &'static str {
    match kind {
        "hart" => "hart",
        "task" => "task",
        "activation" | "runtime-activation" => "activation",
        "activation-context" | "context" => "activation-context",
        "saved-context" => "saved-context",
        "timer-interrupt" => "timer-interrupt",
        "ipi" | "ipi-event" => "ipi-event",
        "remote-preempt" => "remote-preempt",
        "remote-park" => "remote-park",
        "preemption" => "preemption",
        "scheduler-decision" => "scheduler-decision",
        "cross-hart-scheduler-decision" => "cross-hart-scheduler-decision",
        "activation-migration" => "activation-migration",
        "smp-safe-point" | "safepoint" => "smp-safe-point",
        "stop-the-world-rendezvous" | "stop-the-world" | "stw" => "stop-the-world-rendezvous",
        "smp-code-publish-barrier" | "code-publish-barrier" | "publish-barrier" => {
            "smp-code-publish-barrier"
        }
        "smp-cleanup-quiescence" | "cleanup-quiescence" => "smp-cleanup-quiescence",
        "smp-snapshot-barrier" | "snapshot-barrier" => "smp-snapshot-barrier",
        "smp-stress-run" | "smp-stress" => "smp-stress-run",
        "smp-scaling-benchmark" | "smp-scaling" => "smp-scaling-benchmark",
        "device" | "device-object" => "device",
        "queue" | "queue-object" => "queue",
        "descriptor" | "descriptor-object" => "descriptor",
        "dma-buffer" | "dma-buffer-object" => "dma-buffer",
        "mmio-region" | "mmio-region-object" => "mmio-region",
        "irq-line" | "irq-line-object" => "irq-line",
        "irq-event" => "irq-event",
        "device-capability" | "io-capability" => "device-capability",
        "driver-store-binding" | "driver-binding" => "driver-store-binding",
        "io-wait" | "io-wait-token" => "io-wait",
        "io-cleanup" => "io-cleanup",
        "io-fault" | "io-fault-injection" => "io-fault-injection",
        "io-validation" | "io-validation-report" | "io-validator" => "io-validation-report",
        "packet-device" | "packet-device-object" | "net-device" => "packet-device",
        "packet-buffer" | "packet-buffer-object" => "packet-buffer",
        "packet-queue" | "packet-queue-object" | "rx-queue" | "tx-queue" => "packet-queue",
        "packet-descriptor" | "packet-descriptor-object" => "packet-descriptor",
        "fake-net-backend" | "fake-net-backend-object" => "fake-net-backend",
        "virtio-net-backend" | "virtio-net-backend-object" => "virtio-net-backend",
        "network-rx-interrupt" | "rx-interrupt" => "network-rx-interrupt",
        "network-rx-wait-resolution" | "rx-wait-resolution" => "network-rx-wait-resolution",
        "network-tx-capability-gate" | "tx-capability-gate" => "network-tx-capability-gate",
        "network-tx-completion" | "tx-completion" => "network-tx-completion",
        "network-stack-adapter" | "smoltcp-adapter" => "network-stack-adapter",
        "socket-object" | "socket" => "socket-object",
        "endpoint-object" | "endpoint" => "endpoint-object",
        "socket-operation" | "socket-op" => "socket-operation",
        "socket-wait" | "socket-wait-token" => "socket-wait",
        "network-backpressure" | "backpressure" | "drop-policy" => "network-backpressure",
        "network-driver-cleanup" | "network-cleanup" => "network-driver-cleanup",
        "network-generation-audit" | "generation-audit" | "stale-generation-audit" => {
            "network-generation-audit"
        }
        "network-fault-injection" | "packet-loss" | "packet-error" => "network-fault-injection",
        "network-benchmark" | "network-throughput" | "network-latency" => "network-benchmark",
        "network-recovery-benchmark" | "network-recovery" => "network-recovery-benchmark",
        "block-device" | "block-device-object" | "block" => "block-device",
        "block-range" | "block-range-object" | "sector-range" => "block-range",
        "block-request" | "block-request-object" => "block-request",
        "block-completion" | "block-completion-object" => "block-completion",
        "block-wait" | "block-wait-token" => "block-wait",
        "fake-block-backend" | "fake-block-backend-object" => "fake-block-backend",
        "virtio-blk-backend" | "virtio-blk-backend-object" => "virtio-blk-backend",
        "block-read-path" | "block-read" => "block-read-path",
        "block-write-path" | "block-write" => "block-write-path",
        "block-request-queue" | "block-queue" => "block-request-queue",
        "block-dma-buffer" | "block-buffer" => "block-dma-buffer",
        "block-page-object" | "block-page" => "block-page-object",
        "buffer-cache-object" | "buffer-cache" | "fs-cache" => "buffer-cache-object",
        "file-object" | "file" => "file-object",
        "directory-object" | "directory" => "directory-object",
        "fat-adapter-object" | "fat-adapter" => "fat-adapter-object",
        "ext4-adapter-object" | "ext4-adapter" => "ext4-adapter-object",
        "file-handle-capability" | "file-handle" | "file-capability" => "file-handle-capability",
        "fs-wait" | "filesystem-wait" | "file-wait" => "fs-wait",
        "block-driver-cleanup" | "disk-driver-cleanup" | "disk-cleanup" => "block-driver-cleanup",
        "block-pending-io-policy" | "pending-block-io" | "pending-io-policy" => {
            "block-pending-io-policy"
        }
        "block-request-generation-audit"
        | "stale-block-request-generation"
        | "block-generation-audit" => "block-request-generation-audit",
        "block-benchmark" | "disk-benchmark" | "block-iops" => "block-benchmark",
        "block-recovery-benchmark" | "disk-recovery-benchmark" | "disk-recovery" => {
            "block-recovery-benchmark"
        }
        "target-feature-set" | "target-feature" | "target-feature-set-object" => {
            "target-feature-set"
        }
        "vector-state" | "vector" | "simd-vector-state" => "vector-state",
        "simd-fault-injection" | "simd-fault" => "simd-fault-injection",
        "simd-benchmark" | "simd-scalar-vector-benchmark" => "simd-benchmark",
        "simd-context-switch-benchmark" | "simd-context-switch" | "simd-switch-benchmark" => {
            "simd-context-switch-benchmark"
        }
        "framebuffer-object" | "framebuffer" | "fb" => "framebuffer-object",
        "display-object" | "display" | "display-mode" => "display-object",
        "display-capability" | "display-cap" => "display-capability",
        "framebuffer-window-lease" | "fb-window-lease" | "display-lease" => {
            "framebuffer-window-lease"
        }
        "framebuffer-mapping" | "fb-mapping" | "display-mapping" => "framebuffer-mapping",
        "framebuffer-write" | "fb-write" | "display-write" => "framebuffer-write",
        "framebuffer-flush-region" | "flush-region" | "display-flush" => "framebuffer-flush-region",
        "framebuffer-dirty-region" | "dirty-region" | "display-dirty" => "framebuffer-dirty-region",
        "display-event-log" | "display-log" => "display-event-log",
        "display-cleanup" => "display-cleanup",
        "display-snapshot-barrier" | "display-snapshot" => "display-snapshot-barrier",
        "display-panic-last-frame" | "panic-last-frame" => "display-panic-last-frame",
        "framebuffer-benchmark" | "fb-benchmark" | "display-benchmark" => "framebuffer-benchmark",
        "integrated-smp-preemption-cleanup"
        | "integrated-smp-cleanup"
        | "smp-preemption-cleanup" => "integrated-smp-preemption-cleanup",
        "integrated-smp-network-fault" | "smp-network-fault" | "integrated-network-fault" => {
            "integrated-smp-network-fault"
        }
        "integrated-disk-preempt-fault"
        | "disk-preempt-fault"
        | "integrated-block-preempt-fault" => "integrated-disk-preempt-fault",
        "integrated-simd-migration" | "simd-migration" | "integrated-vector-migration" => {
            "integrated-simd-migration"
        }
        "integrated-network-disk-io" | "network-disk-io" | "integrated-io-concurrency" => {
            "integrated-network-disk-io"
        }
        "integrated-display-scheduler-load"
        | "display-scheduler-load"
        | "integrated-display-load" => "integrated-display-scheduler-load",
        "integrated-snapshot-io-lease-barrier"
        | "snapshot-io-lease-barrier"
        | "snapshot-io-barrier" => "integrated-snapshot-io-lease-barrier",
        "integrated-code-publish-smp-workload"
        | "code-publish-smp-workload"
        | "integrated-code-publish-workload" => "integrated-code-publish-smp-workload",
        "integrated-display-panic" | "display-panic" | "panic-ring-extraction" => {
            "integrated-display-panic"
        }
        "integrated-osctl-trace-replay" | "osctl-trace-replay" | "full-osctl-trace-replay" => {
            "integrated-osctl-trace-replay"
        }
        "activation-resume" => "activation-resume",
        "activation-wait" => "activation-wait",
        "activation-cleanup" => "activation-cleanup",
        "preemption-latency" => "preemption-latency",
        "hart-event" | "hart-event-attribution" => "hart-event-attribution",
        "scheduler" => "scheduler",
        "runnable-queue" => "runnable-queue",
        "cap" | "capability" => "capability",
        "store" => "store",
        "wait" => "wait",
        "cleanup" => "cleanup",
        "command" => "command",
        _ => "unknown",
    }
}

pub(crate) fn select_view_by_id(
    views: Vec<serde_json::Value>,
    id: &str,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let parsed = id.parse::<u64>()?;
    views
        .into_iter()
        .find(|view| view.get("id").and_then(serde_json::Value::as_u64) == Some(parsed))
        .ok_or_else(|| format!("object id {id} not found").into())
}
