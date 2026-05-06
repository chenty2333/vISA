use super::*;

pub(crate) fn inspect_package_object_json(
    kind: &str,
    package: &MigrationPackageManifest,
    filter: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let (canonical_kind, total_count, items, summary) = match kind {
        "artifact" => (
            "artifact",
            package.semantic.target_artifact_count,
            package.semantic.target_artifacts.iter().map(artifact_view_v1).collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.target_artifact_roots.len() }),
        ),
        "code" => (
            "code",
            package.semantic.code_object_count,
            package.semantic.code_objects.iter().map(code_object_view_v1).collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.code_object_roots.len() }),
        ),
        "store" => (
            "store",
            package.semantic.store_record_count,
            package
                .semantic
                .store_records
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.target_store_record_roots.len() }),
        ),
        "activation" => (
            "activation",
            package.semantic.activation_record_count,
            package.semantic.activation_records.iter().map(activation_view_v1).collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.activation_record_roots.len() }),
        ),
        "cap" | "capability" => (
            "capability",
            if package.semantic.capability_records.is_empty() {
                package.logical_capabilities.len()
            } else {
                package.semantic.capability_record_count
            },
            if package.semantic.capability_records.is_empty() {
                package
                    .logical_capabilities
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                package
                    .semantic
                    .capability_records
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<Result<Vec<_>, _>>()?
            },
            serde_json::json!({
                "root_count": if package.semantic.capability_records.is_empty() {
                    package.semantic.roots.capability_roots.len()
                } else {
                    package.semantic.roots.target_capability_record_roots.len()
                }
            }),
        ),
        "wait" => (
            "wait",
            package.semantic.wait_token_count,
            package
                .semantic
                .roots
                .wait_roots
                .iter()
                .map(|root| serde_json::json!({ "kind": "wait", "root": root }))
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.wait_roots.len() }),
        ),
        "trap" => (
            "trap",
            package.semantic.trap_record_count,
            package.semantic.trap_records.iter().map(trap_view_v1).collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.trap_roots.len() }),
        ),
        "hostcall" => (
            "hostcall",
            package.semantic.hostcall_trace_count,
            package.semantic.hostcall_trace.iter().map(hostcall_trace_view_v1).collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.hostcall_trace_roots.len() }),
        ),
        "cleanup" => (
            "cleanup",
            package.semantic.cleanup_transaction_count,
            package.semantic.cleanup_transactions.iter().map(cleanup_view_v1).collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.cleanup_roots.len() }),
        ),
        "file-handle-capability" | "file-handle" => (
            "file-handle-capability",
            package.semantic.file_handle_capability_count,
            package
                .semantic
                .file_handle_capabilities
                .iter()
                .map(file_handle_capability_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.file_handle_capability_roots.len() }),
        ),
        "fs-wait" | "filesystem-wait" | "file-wait" => (
            "fs-wait",
            package.semantic.fs_wait_count,
            package.semantic.fs_waits.iter().map(fs_wait_view_v1).collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.fs_wait_roots.len() }),
        ),
        "block-driver-cleanup" | "disk-driver-cleanup" | "disk-cleanup" => (
            "block-driver-cleanup",
            package.semantic.block_driver_cleanup_count,
            package
                .semantic
                .block_driver_cleanups
                .iter()
                .map(block_driver_cleanup_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.block_driver_cleanup_roots.len() }),
        ),
        "block-pending-io-policy" | "pending-block-io" | "pending-io-policy" => (
            "block-pending-io-policy",
            package.semantic.block_pending_io_policy_count,
            package
                .semantic
                .block_pending_io_policies
                .iter()
                .map(block_pending_io_policy_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.block_pending_io_policy_roots.len() }),
        ),
        "block-request-generation-audit"
        | "stale-block-request-generation"
        | "block-generation-audit" => (
            "block-request-generation-audit",
            package.semantic.block_request_generation_audit_count,
            package
                .semantic
                .block_request_generation_audits
                .iter()
                .map(block_request_generation_audit_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.block_request_generation_audit_roots.len() }),
        ),
        "block-benchmark" | "disk-benchmark" | "block-iops" => (
            "block-benchmark",
            package.semantic.block_benchmark_count,
            package
                .semantic
                .block_benchmarks
                .iter()
                .map(block_benchmark_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.block_benchmark_roots.len() }),
        ),
        "block-recovery-benchmark" | "disk-recovery-benchmark" | "disk-recovery" => (
            "block-recovery-benchmark",
            package.semantic.block_recovery_benchmark_count,
            package
                .semantic
                .block_recovery_benchmarks
                .iter()
                .map(block_recovery_benchmark_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.block_recovery_benchmark_roots.len() }),
        ),
        "target-feature-set" | "target-feature" | "target-feature-set-object" => (
            "target-feature-set",
            package.semantic.target_feature_set_count,
            package
                .semantic
                .target_feature_sets
                .iter()
                .map(target_feature_set_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.target_feature_set_roots.len() }),
        ),
        "vector-state" | "vector" | "simd-vector-state" => (
            "vector-state",
            package.semantic.vector_state_count,
            package.semantic.vector_states.iter().map(vector_state_view_v1).collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.vector_state_roots.len() }),
        ),
        "simd-fault-injection" | "simd-fault" => (
            "simd-fault-injection",
            package.semantic.simd_fault_injection_count,
            package
                .semantic
                .simd_fault_injections
                .iter()
                .map(simd_fault_injection_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.simd_fault_injection_roots.len() }),
        ),
        "simd-benchmark" | "simd-scalar-vector-benchmark" => (
            "simd-benchmark",
            package.semantic.simd_benchmark_count,
            package.semantic.simd_benchmarks.iter().map(simd_benchmark_view_v1).collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.simd_benchmark_roots.len() }),
        ),
        "simd-context-switch-benchmark" | "simd-context-switch" | "simd-switch-benchmark" => (
            "simd-context-switch-benchmark",
            package.semantic.simd_context_switch_benchmark_count,
            package
                .semantic
                .simd_context_switch_benchmarks
                .iter()
                .map(simd_context_switch_benchmark_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .simd_context_switch_benchmark_roots
                    .len()
            }),
        ),
        "framebuffer-object" | "framebuffer" | "fb" => (
            "framebuffer-object",
            package.semantic.framebuffer_object_count,
            package
                .semantic
                .framebuffer_objects
                .iter()
                .map(framebuffer_object_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_object_roots.len()
            }),
        ),
        "display-object" | "display" | "display-mode" => (
            "display-object",
            package.semantic.display_object_count,
            package.semantic.display_objects.iter().map(display_object_view_v1).collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_object_roots.len()
            }),
        ),
        "display-capability" | "display-cap" => (
            "display-capability",
            package.semantic.display_capability_count,
            package
                .semantic
                .display_capabilities
                .iter()
                .map(display_capability_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_capability_roots.len()
            }),
        ),
        "framebuffer-window-lease" | "fb-window-lease" | "display-lease" => (
            "framebuffer-window-lease",
            package.semantic.framebuffer_window_lease_count,
            package
                .semantic
                .framebuffer_window_leases
                .iter()
                .map(framebuffer_window_lease_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_window_lease_roots.len()
            }),
        ),
        "framebuffer-mapping" | "fb-mapping" | "display-mapping" => (
            "framebuffer-mapping",
            package.semantic.framebuffer_mapping_count,
            package
                .semantic
                .framebuffer_mappings
                .iter()
                .map(framebuffer_mapping_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_mapping_roots.len()
            }),
        ),
        "framebuffer-write" | "fb-write" | "display-write" => (
            "framebuffer-write",
            package.semantic.framebuffer_write_count,
            package
                .semantic
                .framebuffer_writes
                .iter()
                .map(framebuffer_write_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_write_roots.len()
            }),
        ),
        "framebuffer-flush-region" | "flush-region" | "display-flush" => (
            "framebuffer-flush-region",
            package.semantic.framebuffer_flush_region_count,
            package
                .semantic
                .framebuffer_flush_regions
                .iter()
                .map(framebuffer_flush_region_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_flush_region_roots.len()
            }),
        ),
        "framebuffer-dirty-region" | "dirty-region" | "display-dirty" => (
            "framebuffer-dirty-region",
            package.semantic.framebuffer_dirty_region_count,
            package
                .semantic
                .framebuffer_dirty_regions
                .iter()
                .map(framebuffer_dirty_region_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_dirty_region_roots.len()
            }),
        ),
        "display-event-log" | "display-log" => (
            "display-event-log",
            package.semantic.display_event_log_count,
            package
                .semantic
                .display_event_logs
                .iter()
                .map(display_event_log_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_event_log_roots.len()
            }),
        ),
        "display-cleanup" => (
            "display-cleanup",
            package.semantic.display_cleanup_count,
            package
                .semantic
                .display_cleanups
                .iter()
                .map(display_cleanup_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_cleanup_roots.len()
            }),
        ),
        "display-snapshot-barrier" | "display-snapshot" => (
            "display-snapshot-barrier",
            package.semantic.display_snapshot_barrier_count,
            package
                .semantic
                .display_snapshot_barriers
                .iter()
                .map(display_snapshot_barrier_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_snapshot_barrier_roots.len()
            }),
        ),
        "display-panic-last-frame" | "panic-last-frame" => (
            "display-panic-last-frame",
            package.semantic.display_panic_last_frame_count,
            package
                .semantic
                .display_panic_last_frames
                .iter()
                .map(display_panic_last_frame_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_panic_last_frame_roots.len()
            }),
        ),
        "framebuffer-benchmark" | "fb-benchmark" | "display-benchmark" => (
            "framebuffer-benchmark",
            package.semantic.framebuffer_benchmark_count,
            package
                .semantic
                .framebuffer_benchmarks
                .iter()
                .map(framebuffer_benchmark_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_benchmark_roots.len()
            }),
        ),
        "integrated-smp-preemption-cleanup"
        | "integrated-smp-cleanup"
        | "smp-preemption-cleanup" => (
            "integrated-smp-preemption-cleanup",
            package.semantic.integrated_smp_preemption_cleanup_count,
            package
                .semantic
                .integrated_smp_preemption_cleanups
                .iter()
                .map(integrated_smp_preemption_cleanup_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_smp_preemption_cleanup_roots
                    .len()
            }),
        ),
        "integrated-smp-network-fault" | "smp-network-fault" | "integrated-network-fault" => (
            "integrated-smp-network-fault",
            package.semantic.integrated_smp_network_fault_count,
            package
                .semantic
                .integrated_smp_network_faults
                .iter()
                .map(integrated_smp_network_fault_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_smp_network_fault_roots
                    .len()
            }),
        ),
        "integrated-disk-preempt-fault"
        | "disk-preempt-fault"
        | "integrated-block-preempt-fault" => (
            "integrated-disk-preempt-fault",
            package.semantic.integrated_disk_preempt_fault_count,
            package
                .semantic
                .integrated_disk_preempt_faults
                .iter()
                .map(integrated_disk_preempt_fault_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_disk_preempt_fault_roots
                    .len()
            }),
        ),
        "integrated-simd-migration" | "simd-migration" | "integrated-vector-migration" => (
            "integrated-simd-migration",
            package.semantic.integrated_simd_migration_count,
            package
                .semantic
                .integrated_simd_migrations
                .iter()
                .map(integrated_simd_migration_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_simd_migration_roots
                    .len()
            }),
        ),
        "integrated-network-disk-io" | "network-disk-io" | "integrated-io-concurrency" => (
            "integrated-network-disk-io",
            package.semantic.integrated_network_disk_io_count,
            package
                .semantic
                .integrated_network_disk_ios
                .iter()
                .map(integrated_network_disk_io_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_network_disk_io_roots
                    .len()
            }),
        ),
        "integrated-display-scheduler-load"
        | "display-scheduler-load"
        | "integrated-display-load" => (
            "integrated-display-scheduler-load",
            package.semantic.integrated_display_scheduler_load_count,
            package
                .semantic
                .integrated_display_scheduler_loads
                .iter()
                .map(integrated_display_scheduler_load_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_display_scheduler_load_roots
                    .len()
            }),
        ),
        "integrated-snapshot-io-lease-barrier"
        | "snapshot-io-lease-barrier"
        | "snapshot-io-barrier" => (
            "integrated-snapshot-io-lease-barrier",
            package.semantic.integrated_snapshot_io_lease_barrier_count,
            package
                .semantic
                .integrated_snapshot_io_lease_barriers
                .iter()
                .map(integrated_snapshot_io_lease_barrier_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_snapshot_io_lease_barrier_roots
                    .len()
            }),
        ),
        "integrated-code-publish-smp-workload"
        | "code-publish-smp-workload"
        | "integrated-code-publish-workload" => (
            "integrated-code-publish-smp-workload",
            package.semantic.integrated_code_publish_smp_workload_count,
            package
                .semantic
                .integrated_code_publish_smp_workloads
                .iter()
                .map(integrated_code_publish_smp_workload_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_code_publish_smp_workload_roots
                    .len()
            }),
        ),
        "integrated-display-panic" | "display-panic" | "panic-ring-extraction" => (
            "integrated-display-panic",
            package.semantic.integrated_display_panic_count,
            package
                .semantic
                .integrated_display_panics
                .iter()
                .map(integrated_display_panic_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_display_panic_roots
                    .len()
            }),
        ),
        "integrated-osctl-trace-replay" | "osctl-trace-replay" | "full-osctl-trace-replay" => (
            "integrated-osctl-trace-replay",
            package.semantic.integrated_osctl_trace_replay_count,
            package
                .semantic
                .integrated_osctl_trace_replays
                .iter()
                .map(integrated_osctl_trace_replay_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_osctl_trace_replay_roots
                    .len()
            }),
        ),
        "command" => (
            "command",
            package.semantic.command_result_count,
            package.semantic.command_results.iter().map(command_result_view_v1).collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.command_result_roots.len() }),
        ),
        "contract" => (
            "contract",
            package.semantic.contract_violation_count,
            package
                .semantic
                .contract_violations
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "ok": package.semantic.contract_violation_count == 0 }),
        ),
        "memory-policy" => (
            "memory-policy",
            package.semantic.memory_policy_count,
            package
                .semantic
                .memory_policies
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.memory_policy_roots.len() }),
        ),
        "snapshot-validation" => (
            "snapshot-validation",
            package.semantic.snapshot_validation.violation_count,
            package
                .semantic
                .snapshot_validation
                .violations
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({
                "validator": &package.semantic.snapshot_validation.validator,
                "evidence_boundary": &package.semantic.snapshot_validation.evidence_boundary,
                "ok": package.semantic.snapshot_validation.ok,
                "root_count": package.semantic.roots.snapshot_validation_roots.len()
            }),
        ),
        "replay-validation" => (
            "replay-validation",
            package.semantic.replay_validation.violation_count,
            package
                .semantic
                .replay_validation
                .violations
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({
                "validator": &package.semantic.replay_validation.validator,
                "evidence_boundary": &package.semantic.replay_validation.evidence_boundary,
                "ok": package.semantic.replay_validation.ok,
                "root_count": package.semantic.roots.replay_validation_roots.len()
            }),
        ),
        "event" => (
            "event",
            package.semantic.roots.event_log_tail.len(),
            package
                .semantic
                .roots
                .event_log_tail
                .iter()
                .map(|event| serde_json::json!({ "kind": "event", "summary": event }))
                .collect::<Vec<_>>(),
            serde_json::json!({ "cursor": package.semantic.event_log_cursor }),
        ),
        "migration" => (
            "migration",
            package.semantic.migration_object_count,
            package
                .semantic
                .migration_objects
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.migration_object_roots.len() }),
        ),
        "tombstone" => (
            "tombstone",
            package.semantic.tombstone_count,
            package
                .semantic
                .tombstones
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.tombstone_roots.len() }),
        ),
        _ => return Err(format!("unknown inspect kind `{kind}`").into()),
    };
    let items = filter_json_items(items, filter)?;
    let value = serde_json::json!({
        "schema_version": OSCTL_JSON_SCHEMA_VERSION,
        "command": "inspect",
        "kind": canonical_kind,
        "source": "semantic-package",
        "package": package.package_id,
        "total_count": total_count,
        "count": items.len(),
        "filter": filter,
        "summary": summary,
        "items": items
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
