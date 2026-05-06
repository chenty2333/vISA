use super::*;

pub(crate) fn inspect_package_object(
    kind: &str,
    package: &MigrationPackageManifest,
    filter: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    match kind {
        "artifact" => {
            println!(
                "inspect artifact package={} count={}",
                package.package_id, package.semantic.target_artifact_count
            );
            for artifact in &package.semantic.target_artifacts {
                let line = format!(
                    "artifact id={} package={} name={} role={} kind={} profile={} artifact_hash={} abi={} binding={} code_hash={} exports={} hostcalls={} caps={}",
                    artifact.id,
                    artifact.package,
                    artifact.artifact_name,
                    artifact.role,
                    artifact.kind,
                    artifact.target_profile,
                    artifact.artifact_hash,
                    artifact.abi_fingerprint,
                    artifact.manifest_binding_hash,
                    artifact.code_hash,
                    artifact.exports.len(),
                    artifact.hostcalls.len(),
                    artifact.capabilities.len()
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.target_artifacts.is_empty() {
                print_roots_filtered(
                    "artifact-verification",
                    &package.semantic.roots.artifact_verification_roots,
                    filter,
                );
            }
        }
        "code" => {
            println!(
                "inspect code package={} count={}",
                package.package_id, package.semantic.code_object_count
            );
            for code in &package.semantic.code_objects {
                let store = code.bound_store.map_or_else(
                    || "none".to_owned(),
                    |store| {
                        format!(
                            "{store}@{}",
                            code.bound_store_generation
                                .map(|generation| generation.to_string())
                                .unwrap_or_else(|| "unknown".to_owned())
                        )
                    },
                );
                let table = display_option_u64(code.hostcall_table);
                let line = format!(
                    "code id={} artifact={} package={} state={} generation={} store={} hostcall_table={} text={:#x}+{}:{} rodata={:#x}+{}:{} hostcalls={}",
                    code.id,
                    code.artifact_id,
                    code.package,
                    code.state,
                    code.generation,
                    store,
                    table,
                    code.text_start,
                    code.text_len,
                    code.text_permission,
                    code.rodata_start,
                    code.rodata_len,
                    code.rodata_permission,
                    code.hostcalls.len()
                );
                print_if_matches(&line, filter);
            }
        }
        "store" => {
            println!(
                "inspect store package={} count={}",
                package.package_id, package.semantic.store_record_count
            );
            for store in &package.semantic.store_records {
                let resource = display_option_u64(store.resource);
                let line = format!(
                    "store id={} package={} artifact={} role={} state={} generation={} fault_policy={} fault_domain={} resource={} restart_count={}",
                    store.id,
                    store.package,
                    store.artifact,
                    store.role,
                    store.state,
                    store.generation,
                    store.fault_policy,
                    store.fault_domain,
                    resource,
                    store.restart_count
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.store_records.is_empty() {
                print_roots_filtered("store", &package.semantic.roots.store_roots, filter);
            }
            print_roots_filtered(
                "store-activation",
                &package.semantic.roots.store_activation_roots,
                filter,
            );
        }
        "activation" => {
            println!(
                "inspect activation package={} count={}",
                package.package_id, package.semantic.activation_record_count
            );
            for activation in &package.semantic.activation_records {
                let exit = display_option_u64(activation.exit_event);
                let wait = display_option_u64(activation.blocked_wait);
                let trap = display_option_u64(activation.trap);
                let ret = activation.return_tag.as_deref().unwrap_or("none");
                let line = format!(
                    "activation id={} store={} store_generation={} code={} code_generation={} artifact={} entry={} state={} generation={} start={} exit={} dmw={} wait={} trap={} return={}",
                    activation.id,
                    activation.store,
                    activation.store_generation,
                    activation.code_object,
                    activation.code_generation,
                    activation.artifact,
                    activation.entry,
                    activation.state,
                    activation.generation,
                    activation.start_event,
                    exit,
                    activation.active_dmw_leases,
                    wait,
                    trap,
                    ret
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.activation_records.is_empty() {
                print_roots_filtered(
                    "store-activation",
                    &package.semantic.roots.store_activation_roots,
                    filter,
                );
            }
        }
        "capability" | "cap" => {
            println!(
                "inspect capability package={} count={}",
                package.package_id, package.semantic.capability_record_count
            );
            for capability in &package.semantic.capability_records {
                let line = format!(
                    "cap id={} subject={} object={} class={} rights={} lifetime={} generation={} source={} owner_store={}@{} owner_task={} revoked={}",
                    capability.id,
                    capability.subject,
                    capability.object,
                    display_capability_class(&capability.class, &capability.object),
                    capability.rights.join("+"),
                    capability.lifetime,
                    capability.generation,
                    display_default(&capability.source, "unknown"),
                    display_option_u64(capability.owner_store),
                    display_option_u64(capability.owner_store_generation),
                    display_option_u64(capability.owner_task),
                    capability.revoked
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.capability_records.is_empty() {
                for capability in &package.logical_capabilities {
                    let line = format!(
                        "cap subject={} object={} class={} rights={} lifetime={} generation={} source={} owner_store={}@{} owner_task={} revoked={}",
                        capability.subject,
                        capability.object,
                        display_capability_class(&capability.class, &capability.object),
                        capability.rights.join("+"),
                        capability.lifetime,
                        capability.generation,
                        display_default(&capability.source, "unknown"),
                        display_option_u64(capability.owner_store),
                        display_option_u64(capability.owner_store_generation),
                        display_option_u64(capability.owner_task),
                        capability.revoked
                    );
                    print_if_matches(&line, filter);
                }
            }
        }
        "wait" => {
            println!(
                "inspect wait package={} count={}",
                package.package_id, package.semantic.wait_token_count
            );
            print_roots_filtered("wait", &package.semantic.roots.wait_roots, filter);
        }
        "trap" => {
            println!(
                "inspect trap package={} count={}",
                package.package_id, package.semantic.trap_record_count
            );
            for trap in &package.semantic.trap_records {
                let line = format!(
                    "trap id={} class={} store={}@{} activation={}@{} code={}@{} artifact={}@{} pc={} offset={} trap_kind={} hostcall={} policy={} effect={} detail={}",
                    trap.id,
                    trap.class,
                    display_option_u64(trap.store),
                    display_option_u64(trap.store_generation),
                    display_option_u64(trap.activation),
                    display_option_u64(trap.activation_generation),
                    display_option_u64(trap.code_object),
                    display_option_u64(trap.code_generation),
                    display_option_u64(trap.artifact),
                    display_option_u64(trap.artifact_generation),
                    display_option_u64(trap.target_pc),
                    display_option_u64(trap.offset),
                    trap.trap_kind.as_deref().unwrap_or("none"),
                    trap.hostcall.as_deref().unwrap_or("none"),
                    trap.fault_policy,
                    trap.effect,
                    trap.detail
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.trap_records.is_empty() {
                print_roots_filtered("trap", &package.semantic.roots.trap_roots, filter);
            }
        }
        "event" => {
            println!(
                "inspect event package={} cursor={} tail={}",
                package.package_id,
                package.semantic.event_log_cursor,
                package.semantic.roots.event_log_tail.len()
            );
            print_roots_filtered("event", &package.semantic.roots.event_log_tail, filter);
            print_roots_filtered("hostcall", &package.semantic.roots.hostcall_trace_roots, filter);
        }
        "hostcall" => {
            println!(
                "inspect hostcall package={} count={}",
                package.package_id, package.semantic.hostcall_trace_count
            );
            for trace in &package.semantic.hostcall_trace {
                let cap_args = trace
                    .cap_args
                    .iter()
                    .map(|cap| {
                        format!(
                            "{}:{}:{}:{}:{}",
                            cap.id,
                            cap.object,
                            cap.generation,
                            cap.rights_mask,
                            cap.rights.join("+")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let line = format!(
                    "hostcall abi={} frame_size={} seq={} caller_offset={} record_mode={} activation={} activation_generation={} store={} store_generation={} code={} code_generation={} artifact={} artifact_generation={} number={} name={} category={} subject={} object={} op={} cap_args=[{}] allowed={} result={} ret={} trap_out={} trap_generation_out={} wait_out={} wait_generation_out={}",
                    trace.abi_version,
                    trace.frame_size,
                    trace.hostcall_seq,
                    trace.caller_offset,
                    display_default(&trace.record_mode, "none"),
                    trace.activation,
                    trace.activation_generation,
                    trace.store,
                    trace.store_generation,
                    trace.code_object,
                    trace.code_generation,
                    trace.artifact,
                    trace.artifact_generation,
                    trace.hostcall_number,
                    trace.name,
                    trace.category,
                    trace.subject,
                    trace.object,
                    trace.operation,
                    cap_args,
                    trace.allowed,
                    trace.result,
                    display_default(&trace.ret_tag, "none"),
                    display_option_u64(trace.trap_out),
                    display_option_u64(trace.trap_generation_out),
                    display_option_u64(trace.wait_token_out),
                    display_option_u64(trace.wait_token_generation_out)
                );
                print_if_matches(&line, filter);
            }
        }
        "migration" => {
            println!(
                "inspect migration package={} count={}",
                package.package_id, package.semantic.migration_object_count
            );
            for object in &package.semantic.migration_objects {
                let line = format!(
                    "migration object={} class={} reason={}",
                    object.object, object.class, object.reason
                );
                print_if_matches(&line, filter);
            }
        }
        "tombstone" => {
            println!(
                "inspect tombstone package={} count={}",
                package.package_id, package.semantic.tombstone_count
            );
            for tombstone in &package.semantic.tombstones {
                let line = format!(
                    "tombstone kind={} id={} generation={} died_at={} reason={}",
                    tombstone.kind,
                    tombstone.id,
                    tombstone.generation,
                    tombstone.died_at,
                    tombstone.reason
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.tombstones.is_empty() {
                print_roots_filtered("tombstone", &package.semantic.roots.tombstone_roots, filter);
            }
        }
        "contract" => {
            println!(
                "inspect contract package={} violations={}",
                package.package_id, package.semantic.contract_violation_count
            );
            for violation in &package.semantic.contract_violations {
                let to = violation.to.as_ref().map_or_else(
                    || "none".to_owned(),
                    |to| format!("{}:{}@{}", to.kind, to.id, to.generation),
                );
                let line = format!(
                    "contract violation kind={} edge={} from={}:{}@{} to={} detail={}",
                    violation.kind,
                    violation.edge,
                    violation.from.kind,
                    violation.from.id,
                    violation.from.generation,
                    to,
                    violation.detail
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.contract_violations.is_empty() {
                print_roots_filtered(
                    "contract",
                    &package.semantic.roots.contract_violation_roots,
                    filter,
                );
            }
        }
        "cleanup" => {
            println!(
                "inspect cleanup package={} count={}",
                package.package_id, package.semantic.cleanup_transaction_count
            );
            for cleanup in &package.semantic.cleanup_transactions {
                let activation = display_option_u64(cleanup.activation);
                let code = display_option_u64(cleanup.code_object);
                let activation_generation = display_option_u64(cleanup.activation_generation);
                let code_generation = display_option_u64(cleanup.code_generation);
                let target_store_generation = if cleanup.target_store_generation == 0 {
                    cleanup.store_generation
                } else {
                    cleanup.target_store_generation
                };
                let result_store_generation = display_option_u64(cleanup.result_store_generation);
                let steps = cleanup
                    .steps
                    .iter()
                    .map(|step| format!("{}:{}:{}", step.step, step.state, step.detail))
                    .collect::<Vec<_>>()
                    .join("|");
                let line = format!(
                    "cleanup id={} target_store={}@{} result_store={}@{} activation={}@{} code={}@{} generation={} state={} reason={} released_dmw={} cancelled_waits={} revoked_caps={} dropped_resources={} unbound_code={} effect={} steps={}",
                    cleanup.id,
                    cleanup.store,
                    target_store_generation,
                    cleanup.store,
                    result_store_generation,
                    activation,
                    activation_generation,
                    code,
                    code_generation,
                    cleanup.generation,
                    cleanup.state,
                    cleanup.reason,
                    cleanup.released_dmw_leases,
                    cleanup.cancelled_waits,
                    cleanup.revoked_capabilities.len(),
                    cleanup.dropped_resources,
                    cleanup.unbound_code_object,
                    cleanup.effect,
                    steps
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.cleanup_transactions.is_empty() {
                print_roots_filtered("cleanup", &package.semantic.roots.cleanup_roots, filter);
            }
        }
        "block-driver-cleanup" | "disk-driver-cleanup" | "disk-cleanup" => {
            println!(
                "inspect block-driver-cleanup package={} count={}",
                package.package_id, package.semantic.block_driver_cleanup_count
            );
            for cleanup in &package.semantic.block_driver_cleanups {
                let line = format!(
                    "block-driver-cleanup id={} io_cleanup={}@{} driver_store={}@{} device={}@{} driver_binding={}@{} block_device={}@{} backend={}:{}@{} state={} generation={} cancelled_block_waits={} cancelled_wait_tokens={} released_dma_buffers={} revoked_device_capabilities={} reason={}",
                    cleanup.id,
                    cleanup.io_cleanup,
                    cleanup.io_cleanup_generation,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                    cleanup.device,
                    cleanup.device_generation,
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                    cleanup.block_device,
                    cleanup.block_device_generation,
                    cleanup.backend.kind,
                    cleanup.backend.id,
                    cleanup.backend.generation,
                    cleanup.state,
                    cleanup.generation,
                    cleanup.cancelled_block_waits.len(),
                    cleanup.cancelled_wait_tokens.len(),
                    cleanup.released_dma_buffers.len(),
                    cleanup.revoked_device_capabilities.len(),
                    cleanup.reason
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.block_driver_cleanups.is_empty() {
                print_roots_filtered(
                    "block-driver-cleanup",
                    &package.semantic.roots.block_driver_cleanup_roots,
                    filter,
                );
            }
        }
        "block-pending-io-policy" | "pending-block-io" | "pending-io-policy" => {
            println!(
                "inspect block-pending-io-policy package={} count={}",
                package.package_id, package.semantic.block_pending_io_policy_count
            );
            for policy in &package.semantic.block_pending_io_policies {
                let retry = policy
                    .retry_request
                    .zip(policy.retry_request_generation)
                    .map(|(id, generation)| format!("{id}@{generation}"))
                    .unwrap_or_else(|| "none".to_owned());
                let line = format!(
                    "block-pending-io-policy id={} block_wait={}@{} wait={}@{} block_request={}@{} retry_request={} block_device={}@{} block_range={}@{} action={} errno={} retry_attempt={} max_retries={} state={} generation={}",
                    policy.id,
                    policy.block_wait,
                    policy.block_wait_generation,
                    policy.wait,
                    policy.wait_generation,
                    policy.block_request,
                    policy.block_request_generation,
                    retry,
                    policy.block_device,
                    policy.block_device_generation,
                    policy.block_range,
                    policy.block_range_generation,
                    policy.action,
                    policy.errno,
                    policy.retry_attempt,
                    policy.max_retries,
                    policy.state,
                    policy.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.block_pending_io_policies.is_empty() {
                print_roots_filtered(
                    "block-pending-io-policy",
                    &package.semantic.roots.block_pending_io_policy_roots,
                    filter,
                );
            }
        }
        "block-request-generation-audit"
        | "stale-block-request-generation"
        | "block-generation-audit" => {
            println!(
                "inspect block-request-generation-audit package={} count={}",
                package.package_id, package.semantic.block_request_generation_audit_count
            );
            for audit in &package.semantic.block_request_generation_audits {
                let line = format!(
                    "block-request-generation-audit id={} block_device={}@{} block_range={}@{} block_request={}@{} backend={}:{}@{} dma_buffer={}:{}@{} rejected_completion_generation_probes={} rejected_wait_generation_probes={} rejected_dma_generation_probes={} rejected_queue_generation_probes={} state={} generation={}",
                    audit.id,
                    audit.block_device,
                    audit.block_device_generation,
                    audit.block_range,
                    audit.block_range_generation,
                    audit.block_request,
                    audit.block_request_generation,
                    audit.backend.kind,
                    audit.backend.id,
                    audit.backend.generation,
                    audit.dma_buffer.kind,
                    audit.dma_buffer.id,
                    audit.dma_buffer.generation,
                    audit.rejected_completion_generation_probes,
                    audit.rejected_wait_generation_probes,
                    audit.rejected_dma_generation_probes,
                    audit.rejected_queue_generation_probes,
                    audit.state,
                    audit.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.block_request_generation_audits.is_empty() {
                print_roots_filtered(
                    "block-request-generation-audit",
                    &package.semantic.roots.block_request_generation_audit_roots,
                    filter,
                );
            }
        }
        "block-benchmark" | "disk-benchmark" | "block-iops" => {
            println!(
                "inspect block-benchmark package={} count={}",
                package.package_id, package.semantic.block_benchmark_count
            );
            for benchmark in &package.semantic.block_benchmarks {
                let line = format!(
                    "block-benchmark id={} scenario={} backend={}:{}@{} block_device={}@{} block_range={}@{} read_path={}@{} write_path={}@{} request_queue={}@{} block_dma_buffer={}@{} sample_requests={} sample_bytes={} iops={} throughput_bytes_per_sec={} p50_latency_nanos={} p99_latency_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.backend.kind,
                    benchmark.backend.id,
                    benchmark.backend.generation,
                    benchmark.block_device,
                    benchmark.block_device_generation,
                    benchmark.block_range,
                    benchmark.block_range_generation,
                    benchmark.read_path,
                    benchmark.read_path_generation,
                    benchmark.write_path,
                    benchmark.write_path_generation,
                    benchmark.request_queue,
                    benchmark.request_queue_generation,
                    benchmark.block_dma_buffer,
                    benchmark.block_dma_buffer_generation,
                    benchmark.sample_requests,
                    benchmark.sample_bytes,
                    benchmark.iops,
                    benchmark.throughput_bytes_per_sec,
                    benchmark.p50_latency_nanos,
                    benchmark.p99_latency_nanos,
                    benchmark.state,
                    benchmark.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.block_benchmarks.is_empty() {
                print_roots_filtered(
                    "block-benchmark",
                    &package.semantic.roots.block_benchmark_roots,
                    filter,
                );
            }
        }
        "block-recovery-benchmark" | "disk-recovery-benchmark" | "disk-recovery" => {
            println!(
                "inspect block-recovery-benchmark package={} count={}",
                package.package_id, package.semantic.block_recovery_benchmark_count
            );
            for benchmark in &package.semantic.block_recovery_benchmarks {
                let line = format!(
                    "block-recovery-benchmark id={} scenario={} cleanup={}@{} io_cleanup={}@{} backend={}:{}@{} block_device={}@{} driver_store={}@{} device={}@{} driver_binding={}@{} recovery_start_event={} recovery_complete_event={} cancelled_block_waits={} cancelled_wait_tokens={} released_dma_buffers={} revoked_device_capabilities={} recovery_nanos={} budget_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.cleanup,
                    benchmark.cleanup_generation,
                    benchmark.io_cleanup,
                    benchmark.io_cleanup_generation,
                    benchmark.backend.kind,
                    benchmark.backend.id,
                    benchmark.backend.generation,
                    benchmark.block_device,
                    benchmark.block_device_generation,
                    benchmark.driver_store,
                    benchmark.driver_store_generation,
                    benchmark.device,
                    benchmark.device_generation,
                    benchmark.driver_binding,
                    benchmark.driver_binding_generation,
                    benchmark.recovery_start_event,
                    benchmark.recovery_complete_event,
                    benchmark.cancelled_block_waits,
                    benchmark.cancelled_wait_tokens,
                    benchmark.released_dma_buffers,
                    benchmark.revoked_device_capabilities,
                    benchmark.recovery_nanos,
                    benchmark.budget_nanos,
                    benchmark.state,
                    benchmark.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.block_recovery_benchmarks.is_empty() {
                print_roots_filtered(
                    "block-recovery-benchmark",
                    &package.semantic.roots.block_recovery_benchmark_roots,
                    filter,
                );
            }
        }
        "target-feature-set" | "target-feature" | "target-feature-set-object" => {
            println!(
                "inspect target-feature-set package={} count={}",
                package.package_id, package.semantic.target_feature_set_count
            );
            for feature in &package.semantic.target_feature_sets {
                let line = format!(
                    "target-feature-set id={} name={} source={} profile={} arch={} base_isa={} simd_abi={} simd_supported={} vector_register_count={} vector_register_bits={} scalar_fallback={} state={} generation={}",
                    feature.id,
                    feature.name,
                    feature.discovery_source,
                    feature.target_profile,
                    feature.target_arch,
                    feature.base_isa,
                    feature.simd_abi,
                    feature.simd_supported,
                    feature.vector_register_count,
                    feature.vector_register_bits,
                    feature.scalar_fallback,
                    feature.state,
                    feature.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.target_feature_sets.is_empty() {
                print_roots_filtered(
                    "target-feature-set",
                    &package.semantic.roots.target_feature_set_roots,
                    filter,
                );
            }
        }
        "vector-state" | "vector" | "simd-vector-state" => {
            println!(
                "inspect vector-state package={} count={}",
                package.package_id, package.semantic.vector_state_count
            );
            for vector_state in &package.semantic.vector_states {
                let line = format!(
                    "vector-state id={} activation={}@{} store={}@{} code_object={}@{} target_feature_set={}@{} simd_abi={} vector_register_count={} vector_register_bits={} register_bytes={} state={} generation={}",
                    vector_state.id,
                    vector_state.owner_activation.id,
                    vector_state.owner_activation.generation,
                    vector_state.owner_store.id,
                    vector_state.owner_store.generation,
                    vector_state.code_object.id,
                    vector_state.code_object.generation,
                    vector_state.target_feature_set.id,
                    vector_state.target_feature_set.generation,
                    vector_state.simd_abi,
                    vector_state.vector_register_count,
                    vector_state.vector_register_bits,
                    vector_state.register_bytes,
                    vector_state.state,
                    vector_state.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.vector_states.is_empty() {
                print_roots_filtered(
                    "vector-state",
                    &package.semantic.roots.vector_state_roots,
                    filter,
                );
            }
        }
        "simd-fault-injection" | "simd-fault" => {
            println!(
                "inspect simd-fault-injection package={} count={}",
                package.package_id, package.semantic.simd_fault_injection_count
            );
            for injection in &package.semantic.simd_fault_injections {
                let vector_state = injection
                    .vector_state
                    .as_ref()
                    .map(|reference| {
                        format!("{}:{}@{}", reference.kind, reference.id, reference.generation)
                    })
                    .unwrap_or_else(|| "none".to_owned());
                let line = format!(
                    "simd-fault-injection id={} activation={}@{} code_object={}@{} trap={}@{} target_feature_set={}@{} vector_state={} kind={} effect={} required_abi={} vector_register_count={} vector_register_bits={} injected_faults={} state={} generation={}",
                    injection.id,
                    injection.activation.id,
                    injection.activation.generation,
                    injection.code_object.id,
                    injection.code_object.generation,
                    injection.trap.id,
                    injection.trap.generation,
                    injection.target_feature_set.id,
                    injection.target_feature_set.generation,
                    vector_state,
                    injection.kind,
                    injection.effect,
                    injection.required_abi,
                    injection.vector_register_count,
                    injection.vector_register_bits,
                    injection.injected_faults,
                    injection.state,
                    injection.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.simd_fault_injections.is_empty() {
                print_roots_filtered(
                    "simd-fault-injection",
                    &package.semantic.roots.simd_fault_injection_roots,
                    filter,
                );
            }
        }
        "simd-benchmark" | "simd-scalar-vector-benchmark" => {
            println!(
                "inspect simd-benchmark package={} count={}",
                package.package_id, package.semantic.simd_benchmark_count
            );
            for benchmark in &package.semantic.simd_benchmarks {
                let line = format!(
                    "simd-benchmark id={} target_feature_set={}@{} scalar_code_object={}@{} vector_code_object={}@{} simd_abi={} vector_register_count={} vector_register_bits={} workload_units={} scalar_nanos={} vector_nanos={} speedup_milli={} context_overhead_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.target_feature_set.id,
                    benchmark.target_feature_set.generation,
                    benchmark.scalar_code_object.id,
                    benchmark.scalar_code_object.generation,
                    benchmark.vector_code_object.id,
                    benchmark.vector_code_object.generation,
                    benchmark.simd_abi,
                    benchmark.vector_register_count,
                    benchmark.vector_register_bits,
                    benchmark.workload_units,
                    benchmark.scalar_nanos,
                    benchmark.vector_nanos,
                    benchmark.speedup_milli,
                    benchmark.context_overhead_nanos,
                    benchmark.state,
                    benchmark.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.simd_benchmarks.is_empty() {
                print_roots_filtered(
                    "simd-benchmark",
                    &package.semantic.roots.simd_benchmark_roots,
                    filter,
                );
            }
        }
        "simd-context-switch-benchmark" | "simd-context-switch" | "simd-switch-benchmark" => {
            println!(
                "inspect simd-context-switch-benchmark package={} count={}",
                package.package_id, package.semantic.simd_context_switch_benchmark_count
            );
            for benchmark in &package.semantic.simd_context_switch_benchmarks {
                let line = format!(
                    "simd-context-switch-benchmark id={} preemption={}@{} activation_resume={}@{} saved_vector_state={}@{} restored_vector_state={}@{} target_feature_set={}@{} simd_abi={} vector_register_count={} vector_register_bits={} sample_count={} scalar_context_switch_nanos={} vector_context_switch_nanos={} overhead_nanos={} budget_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.preemption.id,
                    benchmark.preemption.generation,
                    benchmark.activation_resume.id,
                    benchmark.activation_resume.generation,
                    benchmark.saved_vector_state.id,
                    benchmark.saved_vector_state.generation,
                    benchmark.restored_vector_state.id,
                    benchmark.restored_vector_state.generation,
                    benchmark.target_feature_set.id,
                    benchmark.target_feature_set.generation,
                    benchmark.simd_abi,
                    benchmark.vector_register_count,
                    benchmark.vector_register_bits,
                    benchmark.sample_count,
                    benchmark.scalar_context_switch_nanos,
                    benchmark.vector_context_switch_nanos,
                    benchmark.overhead_nanos,
                    benchmark.budget_nanos,
                    benchmark.state,
                    benchmark.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.simd_context_switch_benchmarks.is_empty() {
                print_roots_filtered(
                    "simd-context-switch-benchmark",
                    &package.semantic.roots.simd_context_switch_benchmark_roots,
                    filter,
                );
            }
        }
        "command" => {
            println!(
                "inspect command package={} count={}",
                package.package_id, package.semantic.command_result_count
            );
            for result in &package.semantic.command_results {
                let line = format!(
                    "command id={} issuer={} name={} status={} events={} effects={} violations={}",
                    result.id,
                    result.issuer,
                    result.command,
                    result.status,
                    result.events.len(),
                    result.effects.len(),
                    result.violations.join("|")
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.command_results.is_empty() {
                print_roots_filtered(
                    "command",
                    &package.semantic.roots.command_result_roots,
                    filter,
                );
            }
        }
        "framebuffer-object" | "framebuffer" | "fb" => {
            println!(
                "inspect framebuffer-object package={} count={}",
                package.package_id, package.semantic.framebuffer_object_count
            );
            for framebuffer in &package.semantic.framebuffer_objects {
                let line = format!(
                    "framebuffer-object id={} name={} resource={}@{} width={} height={} stride_bytes={} pixel_format={} byte_len={} state={} generation={}",
                    framebuffer.id,
                    framebuffer.name,
                    framebuffer.resource,
                    framebuffer.resource_generation,
                    framebuffer.width,
                    framebuffer.height,
                    framebuffer.stride_bytes,
                    framebuffer.pixel_format,
                    framebuffer.byte_len,
                    framebuffer.state,
                    framebuffer.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_objects.is_empty() {
                print_roots_filtered(
                    "framebuffer-object",
                    &package.semantic.roots.framebuffer_object_roots,
                    filter,
                );
            }
        }
        "display-object" | "display" | "display-mode" => {
            println!(
                "inspect display-object package={} count={}",
                package.package_id, package.semantic.display_object_count
            );
            for display in &package.semantic.display_objects {
                let line = format!(
                    "display-object id={} name={} framebuffer={}@{} mode_name={} width={} height={} refresh_millihz={} state={} generation={}",
                    display.id,
                    display.name,
                    display.framebuffer,
                    display.framebuffer_generation,
                    display.mode_name,
                    display.width,
                    display.height,
                    display.refresh_millihz,
                    display.state,
                    display.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_objects.is_empty() {
                print_roots_filtered(
                    "display-object",
                    &package.semantic.roots.display_object_roots,
                    filter,
                );
            }
        }
        "display-capability" | "display-cap" => {
            println!(
                "inspect display-capability package={} count={}",
                package.package_id, package.semantic.display_capability_count
            );
            for capability in &package.semantic.display_capabilities {
                let line = format!(
                    "display-capability id={} owner_store={}@{} display={}@{} framebuffer={}@{} capability={}@{} handle_slot={} handle_generation={} operations={} state={} generation={}",
                    capability.id,
                    capability.owner_store,
                    capability.owner_store_generation,
                    capability.display,
                    capability.display_generation,
                    capability.framebuffer,
                    capability.framebuffer_generation,
                    capability.capability,
                    capability.capability_generation,
                    capability.handle_slot,
                    capability.handle_generation,
                    capability.operations.join("|"),
                    capability.state,
                    capability.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_capabilities.is_empty() {
                print_roots_filtered(
                    "display-capability",
                    &package.semantic.roots.display_capability_roots,
                    filter,
                );
            }
        }
        "framebuffer-window-lease" | "fb-window-lease" | "display-lease" => {
            println!(
                "inspect framebuffer-window-lease package={} count={}",
                package.package_id, package.semantic.framebuffer_window_lease_count
            );
            for lease in &package.semantic.framebuffer_window_leases {
                let line = format!(
                    "framebuffer-window-lease id={} owner_store={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} window={},{} {}x{} byte_range={}+{} access={} state={} generation={}",
                    lease.id,
                    lease.owner_store,
                    lease.owner_store_generation,
                    lease.display_capability,
                    lease.display_capability_generation,
                    lease.display,
                    lease.display_generation,
                    lease.framebuffer,
                    lease.framebuffer_generation,
                    lease.x,
                    lease.y,
                    lease.width,
                    lease.height,
                    lease.byte_offset,
                    lease.byte_len,
                    lease.access,
                    lease.state,
                    lease.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_window_leases.is_empty() {
                print_roots_filtered(
                    "framebuffer-window-lease",
                    &package.semantic.roots.framebuffer_window_lease_roots,
                    filter,
                );
            }
        }
        "framebuffer-mapping" | "fb-mapping" | "display-mapping" => {
            println!(
                "inspect framebuffer-mapping package={} count={}",
                package.package_id, package.semantic.framebuffer_mapping_count
            );
            for mapping in &package.semantic.framebuffer_mappings {
                let line = format!(
                    "framebuffer-mapping id={} owner_store={}@{} framebuffer_window_lease={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} map_handle_slot={} map_handle_generation={} window={},{} {}x{} byte_range={}+{} access={} mode={} state={} generation={}",
                    mapping.id,
                    mapping.owner_store,
                    mapping.owner_store_generation,
                    mapping.framebuffer_window_lease,
                    mapping.framebuffer_window_lease_generation,
                    mapping.display_capability,
                    mapping.display_capability_generation,
                    mapping.display,
                    mapping.display_generation,
                    mapping.framebuffer,
                    mapping.framebuffer_generation,
                    mapping.map_handle_slot,
                    mapping.map_handle_generation,
                    mapping.x,
                    mapping.y,
                    mapping.width,
                    mapping.height,
                    mapping.byte_offset,
                    mapping.byte_len,
                    mapping.access,
                    mapping.mode,
                    mapping.state,
                    mapping.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_mappings.is_empty() {
                print_roots_filtered(
                    "framebuffer-mapping",
                    &package.semantic.roots.framebuffer_mapping_roots,
                    filter,
                );
            }
        }
        "framebuffer-write" | "fb-write" | "display-write" => {
            println!(
                "inspect framebuffer-write package={} count={}",
                package.package_id, package.semantic.framebuffer_write_count
            );
            for write in &package.semantic.framebuffer_writes {
                let line = format!(
                    "framebuffer-write id={} owner_store={}@{} framebuffer_mapping={}@{} framebuffer_window_lease={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} map_handle_slot={} map_handle_generation={} region={},{} {}x{} byte_range={}+{} pixel_format={} payload_digest={} state={} generation={}",
                    write.id,
                    write.owner_store,
                    write.owner_store_generation,
                    write.framebuffer_mapping,
                    write.framebuffer_mapping_generation,
                    write.framebuffer_window_lease,
                    write.framebuffer_window_lease_generation,
                    write.display_capability,
                    write.display_capability_generation,
                    write.display,
                    write.display_generation,
                    write.framebuffer,
                    write.framebuffer_generation,
                    write.map_handle_slot,
                    write.map_handle_generation,
                    write.x,
                    write.y,
                    write.width,
                    write.height,
                    write.byte_offset,
                    write.byte_len,
                    write.pixel_format,
                    write.payload_digest,
                    write.state,
                    write.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_writes.is_empty() {
                print_roots_filtered(
                    "framebuffer-write",
                    &package.semantic.roots.framebuffer_write_roots,
                    filter,
                );
            }
        }
        "framebuffer-flush-region" | "flush-region" | "display-flush" => {
            println!(
                "inspect framebuffer-flush-region package={} count={}",
                package.package_id, package.semantic.framebuffer_flush_region_count
            );
            for flush in &package.semantic.framebuffer_flush_regions {
                let line = format!(
                    "framebuffer-flush-region id={} owner_store={}@{} framebuffer_write={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} region={},{} {}x{} byte_range={}+{} pixel_format={} payload_digest={} state={} generation={}",
                    flush.id,
                    flush.owner_store,
                    flush.owner_store_generation,
                    flush.framebuffer_write,
                    flush.framebuffer_write_generation,
                    flush.display_capability,
                    flush.display_capability_generation,
                    flush.display,
                    flush.display_generation,
                    flush.framebuffer,
                    flush.framebuffer_generation,
                    flush.x,
                    flush.y,
                    flush.width,
                    flush.height,
                    flush.byte_offset,
                    flush.byte_len,
                    flush.pixel_format,
                    flush.payload_digest,
                    flush.state,
                    flush.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_flush_regions.is_empty() {
                print_roots_filtered(
                    "framebuffer-flush-region",
                    &package.semantic.roots.framebuffer_flush_region_roots,
                    filter,
                );
            }
        }
        "framebuffer-dirty-region" | "dirty-region" | "display-dirty" => {
            println!(
                "inspect framebuffer-dirty-region package={} count={}",
                package.package_id, package.semantic.framebuffer_dirty_region_count
            );
            for dirty in &package.semantic.framebuffer_dirty_regions {
                let line = format!(
                    "framebuffer-dirty-region id={} owner_store={}@{} framebuffer_write={}@{} framebuffer_flush_region={}:{} display_capability={}@{} display={}@{} framebuffer={}@{} region={},{} {}x{} byte_range={}+{} pixel_format={} payload_digest={} dirty_at_event={} cleaned_at_event={} state={} generation={}",
                    dirty.id,
                    dirty.owner_store,
                    dirty.owner_store_generation,
                    dirty.framebuffer_write,
                    dirty.framebuffer_write_generation,
                    dirty
                        .framebuffer_flush_region
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    dirty
                        .framebuffer_flush_region_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    dirty.display_capability,
                    dirty.display_capability_generation,
                    dirty.display,
                    dirty.display_generation,
                    dirty.framebuffer,
                    dirty.framebuffer_generation,
                    dirty.x,
                    dirty.y,
                    dirty.width,
                    dirty.height,
                    dirty.byte_offset,
                    dirty.byte_len,
                    dirty.pixel_format,
                    dirty.payload_digest,
                    dirty.dirty_at_event,
                    dirty
                        .cleaned_at_event
                        .map(|event| event.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    dirty.state,
                    dirty.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_dirty_regions.is_empty() {
                print_roots_filtered(
                    "framebuffer-dirty-region",
                    &package.semantic.roots.framebuffer_dirty_region_roots,
                    filter,
                );
            }
        }
        "display-event-log" | "display-log" => {
            println!(
                "inspect display-event-log package={} count={}",
                package.package_id, package.semantic.display_event_log_count
            );
            for log in &package.semantic.display_event_logs {
                let line = format!(
                    "display-event-log id={} owner_store={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} framebuffer_dirty_region={}@{} events={}..{} event_count={} flush_count={} dirty_region_count={} state={} generation={}",
                    log.id,
                    log.owner_store,
                    log.owner_store_generation,
                    log.display_capability,
                    log.display_capability_generation,
                    log.display,
                    log.display_generation,
                    log.framebuffer,
                    log.framebuffer_generation,
                    log.framebuffer_dirty_region,
                    log.framebuffer_dirty_region_generation,
                    log.first_event,
                    log.last_event,
                    log.event_count,
                    log.flush_count,
                    log.dirty_region_count,
                    log.state,
                    log.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_event_logs.is_empty() {
                print_roots_filtered(
                    "display-event-log",
                    &package.semantic.roots.display_event_log_roots,
                    filter,
                );
            }
        }
        "display-cleanup" => {
            println!(
                "inspect display-cleanup package={} count={}",
                package.package_id, package.semantic.display_cleanup_count
            );
            for cleanup in &package.semantic.display_cleanups {
                let line = format!(
                    "display-cleanup id={} owner_store={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} unmapped_mappings={} released_leases={} revoked_display_capabilities={} state={} generation={}",
                    cleanup.id,
                    cleanup.owner_store,
                    cleanup.owner_store_generation,
                    cleanup.display_capability,
                    cleanup.display_capability_generation,
                    cleanup.display,
                    cleanup.display_generation,
                    cleanup.framebuffer,
                    cleanup.framebuffer_generation,
                    cleanup.unmapped_framebuffer_mappings.len(),
                    cleanup.released_framebuffer_window_leases.len(),
                    cleanup.revoked_display_capabilities.len(),
                    cleanup.state,
                    cleanup.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_cleanups.is_empty() {
                print_roots_filtered(
                    "display-cleanup",
                    &package.semantic.roots.display_cleanup_roots,
                    filter,
                );
            }
        }
        "display-snapshot-barrier" | "display-snapshot" => {
            println!(
                "inspect display-snapshot-barrier package={} count={}",
                package.package_id, package.semantic.display_snapshot_barrier_count
            );
            for barrier in &package.semantic.display_snapshot_barriers {
                let line = format!(
                    "display-snapshot-barrier id={} owner_store={}@{} display={}@{} framebuffer={}@{} cleanup={}:{} active_leases={} active_mappings={} dirty_regions={} snapshot_ok={} state={} generation={}",
                    barrier.id,
                    barrier.owner_store,
                    barrier.owner_store_generation,
                    barrier.display,
                    barrier.display_generation,
                    barrier.framebuffer,
                    barrier.framebuffer_generation,
                    barrier
                        .display_cleanup
                        .map(|cleanup| cleanup.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    barrier
                        .display_cleanup_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    barrier.active_framebuffer_window_lease_count,
                    barrier.active_framebuffer_mapping_count,
                    barrier.dirty_framebuffer_region_count,
                    barrier.snapshot_validation_ok,
                    barrier.state,
                    barrier.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_snapshot_barriers.is_empty() {
                print_roots_filtered(
                    "display-snapshot-barrier",
                    &package.semantic.roots.display_snapshot_barrier_roots,
                    filter,
                );
            }
        }
        "display-panic-last-frame" | "panic-last-frame" => {
            println!(
                "inspect display-panic-last-frame package={} count={}",
                package.package_id, package.semantic.display_panic_last_frame_count
            );
            for frame in &package.semantic.display_panic_last_frames {
                let line = format!(
                    "display-panic-last-frame id={} owner_store={}@{} display={}@{} framebuffer={}@{} barrier={}@{} display_event_log={}@{} framebuffer_write={}@{} framebuffer_flush_region={}@{} payload_digest={} summary_digest={} summary_record_bytes={} panic_epoch={} panic_cpu={} panic_reason_code={} raw_framebuffer_bytes_exported={} state={} generation={}",
                    frame.id,
                    frame.owner_store,
                    frame.owner_store_generation,
                    frame.display,
                    frame.display_generation,
                    frame.framebuffer,
                    frame.framebuffer_generation,
                    frame.display_snapshot_barrier,
                    frame.display_snapshot_barrier_generation,
                    frame.display_event_log,
                    frame.display_event_log_generation,
                    frame.framebuffer_write,
                    frame.framebuffer_write_generation,
                    frame.framebuffer_flush_region,
                    frame.framebuffer_flush_region_generation,
                    frame.payload_digest,
                    frame.summary_digest,
                    frame.summary_record_bytes,
                    frame.panic_epoch,
                    frame.panic_cpu,
                    frame.panic_reason_code,
                    frame.raw_framebuffer_bytes_exported,
                    frame.state,
                    frame.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_panic_last_frames.is_empty() {
                print_roots_filtered(
                    "display-panic-last-frame",
                    &package.semantic.roots.display_panic_last_frame_roots,
                    filter,
                );
            }
        }
        "framebuffer-benchmark" | "fb-benchmark" | "display-benchmark" => {
            println!(
                "inspect framebuffer-benchmark package={} count={}",
                package.package_id, package.semantic.framebuffer_benchmark_count
            );
            for benchmark in &package.semantic.framebuffer_benchmarks {
                let line = format!(
                    "framebuffer-benchmark id={} scenario={} owner_store={}@{} display={}@{} framebuffer={}@{} display_capability={}@{} framebuffer_write={}@{} framebuffer_flush_region={}@{} display_event_log={}@{} display_snapshot_barrier={}@{} sample_frames={} sample_bytes={} measured_nanos={} budget_nanos={} throughput_bytes_per_sec={} flushes_per_sec_milli={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.owner_store,
                    benchmark.owner_store_generation,
                    benchmark.display,
                    benchmark.display_generation,
                    benchmark.framebuffer,
                    benchmark.framebuffer_generation,
                    benchmark.display_capability,
                    benchmark.display_capability_generation,
                    benchmark.framebuffer_write,
                    benchmark.framebuffer_write_generation,
                    benchmark.framebuffer_flush_region,
                    benchmark.framebuffer_flush_region_generation,
                    benchmark.display_event_log,
                    benchmark.display_event_log_generation,
                    benchmark.display_snapshot_barrier,
                    benchmark.display_snapshot_barrier_generation,
                    benchmark.sample_frames,
                    benchmark.sample_bytes,
                    benchmark.measured_nanos,
                    benchmark.budget_nanos,
                    benchmark.throughput_bytes_per_sec,
                    benchmark.flushes_per_sec_milli,
                    benchmark.state,
                    benchmark.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_benchmarks.is_empty() {
                print_roots_filtered(
                    "framebuffer-benchmark",
                    &package.semantic.roots.framebuffer_benchmark_roots,
                    filter,
                );
            }
        }
        "integrated-smp-preemption-cleanup"
        | "integrated-smp-cleanup"
        | "smp-preemption-cleanup" => {
            println!(
                "inspect integrated-smp-preemption-cleanup package={} count={}",
                package.package_id, package.semantic.integrated_smp_preemption_cleanup_count
            );
            for record in &package.semantic.integrated_smp_preemption_cleanups {
                let line = format!(
                    "integrated-smp-preemption-cleanup id={} scenario={} stress_run={}@{} preemption={}@{} timer_interrupt={}@{} saved_context={}@{} remote_preempt={}@{} activation_cleanup={}@{} smp_cleanup_quiescence={}@{} cleanup_store={}@{}->{} cleanup_activation={}@{} harts={} invariants={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.stress_run,
                    record.stress_run_generation,
                    record.preemption,
                    record.preemption_generation,
                    record.timer_interrupt,
                    record.timer_interrupt_generation,
                    record.saved_context,
                    record.saved_context_generation,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                    record.activation_cleanup,
                    record.activation_cleanup_generation,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                    record.cleanup_store,
                    record.target_store_generation,
                    record.result_store_generation,
                    record.cleanup_activation,
                    record.cleanup_activation_generation_after,
                    record.hart_count,
                    record.invariant_checks,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.integrated_smp_preemption_cleanups.is_empty() {
                print_roots_filtered(
                    "integrated-smp-preemption-cleanup",
                    &package.semantic.roots.integrated_smp_preemption_cleanup_roots,
                    filter,
                );
            }
        }
        "integrated-smp-network-fault" | "smp-network-fault" | "integrated-network-fault" => {
            println!(
                "inspect integrated-smp-network-fault package={} count={}",
                package.package_id, package.semantic.integrated_smp_network_fault_count
            );
            for record in &package.semantic.integrated_smp_network_faults {
                let line = format!(
                    "integrated-smp-network-fault id={} scenario={} cleanup={}@{} stress_run={}@{} remote_preempt={}@{} smp_cleanup_quiescence={}@{} driver_store={}@{} packet_device={}@{} adapter={}@{} backend={}:{}@{} io_cleanup={}@{} harts={} cancelled_socket_waits={} cancelled_wait_tokens={} revoked_packet_capabilities={} invariants={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.network_driver_cleanup,
                    record.network_driver_cleanup_generation,
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                    record.driver_store,
                    record.driver_store_generation,
                    record.packet_device,
                    record.packet_device_generation,
                    record.adapter,
                    record.adapter_generation,
                    record.backend.kind,
                    record.backend.id,
                    record.backend.generation,
                    record.io_cleanup,
                    record.io_cleanup_generation,
                    record.hart_count,
                    record.cancelled_socket_wait_count,
                    record.cancelled_wait_token_count,
                    record.revoked_packet_capability_count,
                    record.invariant_checks,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.integrated_smp_network_faults.is_empty() {
                print_roots_filtered(
                    "integrated-smp-network-fault",
                    &package.semantic.roots.integrated_smp_network_fault_roots,
                    filter,
                );
            }
        }
        "integrated-disk-preempt-fault"
        | "disk-preempt-fault"
        | "integrated-block-preempt-fault" => {
            println!(
                "inspect integrated-disk-preempt-fault package={} count={}",
                package.package_id, package.semantic.integrated_disk_preempt_fault_count
            );
            for record in &package.semantic.integrated_disk_preempt_faults {
                let line = format!(
                    "integrated-disk-preempt-fault id={} scenario={} preemption={}@{} timer_interrupt={}@{} policy={}@{} block_wait={}@{} wait={}@{} block_request={}@{} retry_request={:?}@{:?} block_device={}@{} block_range={}@{} driver_store={:?}@{:?} action={} errno={} activation={}@{} invariants={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.preemption,
                    record.preemption_generation,
                    record.timer_interrupt,
                    record.timer_interrupt_generation,
                    record.block_pending_io_policy,
                    record.block_pending_io_policy_generation,
                    record.block_wait,
                    record.block_wait_generation,
                    record.wait,
                    record.wait_generation,
                    record.block_request,
                    record.block_request_generation,
                    record.retry_request,
                    record.retry_request_generation,
                    record.block_device,
                    record.block_device_generation,
                    record.block_range,
                    record.block_range_generation,
                    record.driver_store,
                    record.driver_store_generation,
                    record.action,
                    record.errno,
                    record.preempted_activation,
                    record.preempted_activation_generation_after,
                    record.invariant_checks,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.integrated_disk_preempt_faults.is_empty() {
                print_roots_filtered(
                    "integrated-disk-preempt-fault",
                    &package.semantic.roots.integrated_disk_preempt_fault_roots,
                    filter,
                );
            }
        }
        "integrated-simd-migration" | "simd-migration" | "integrated-vector-migration" => {
            println!(
                "inspect integrated-simd-migration package={} count={}",
                package.package_id, package.semantic.integrated_simd_migration_count
            );
            for record in &package.semantic.integrated_simd_migrations {
                let line = format!(
                    "integrated-simd-migration id={} scenario={} migration={}@{} target_feature_set={}@{} source_vector_state={}:{}@{} migrated_vector_state={}:{}@{} activation={}@{}->{} context={}@{} source_hart={}@{} target_hart={}@{} source_queue={}@{} target_queue={}@{} simd_abi={} vregs={} vbits={} invariants={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.activation_migration,
                    record.activation_migration_generation,
                    record.target_feature_set,
                    record.target_feature_set_generation,
                    record.source_vector_state.kind,
                    record.source_vector_state.id,
                    record.source_vector_state.generation,
                    record.migrated_vector_state.kind,
                    record.migrated_vector_state.id,
                    record.migrated_vector_state.generation,
                    record.activation,
                    record.activation_generation_before,
                    record.activation_generation_after,
                    record.context,
                    record.context_generation_after,
                    record.source_hart,
                    record.source_hart_generation,
                    record.target_hart,
                    record.target_hart_generation,
                    record.source_queue,
                    record.source_queue_generation,
                    record.target_queue,
                    record.target_queue_generation,
                    record.simd_abi,
                    record.vector_register_count,
                    record.vector_register_bits,
                    record.invariant_checks,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.integrated_simd_migrations.is_empty() {
                print_roots_filtered(
                    "integrated-simd-migration",
                    &package.semantic.roots.integrated_simd_migration_roots,
                    filter,
                );
            }
        }
        "integrated-network-disk-io" | "network-disk-io" | "integrated-io-concurrency" => {
            println!(
                "inspect integrated-network-disk-io package={} count={}",
                package.package_id, package.semantic.integrated_network_disk_io_count
            );
            for record in &package.semantic.integrated_network_disk_ios {
                let line = format!(
                    "integrated-network-disk-io id={} scenario={} network_benchmark={}@{} block_benchmark={}@{} network_owner_store={}@{} network_adapter={}@{} packet_device={}@{} socket={}@{} block_backend={}:{}@{} block_device={}@{} block_request_queue={}@{} block_dma_buffer={}@{} network_bytes={} block_bytes={} window_nanos={} combined_throughput={} max_p99_latency={} invariants={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.network_benchmark,
                    record.network_benchmark_generation,
                    record.block_benchmark,
                    record.block_benchmark_generation,
                    record.network_owner_store,
                    record.network_owner_store_generation,
                    record.network_adapter,
                    record.network_adapter_generation,
                    record.packet_device,
                    record.packet_device_generation,
                    record.socket,
                    record.socket_generation,
                    record.block_backend.kind,
                    record.block_backend.id,
                    record.block_backend.generation,
                    record.block_device,
                    record.block_device_generation,
                    record.block_request_queue,
                    record.block_request_queue_generation,
                    record.block_dma_buffer,
                    record.block_dma_buffer_generation,
                    record.network_sample_bytes,
                    record.block_sample_bytes,
                    record.concurrent_window_nanos,
                    record.combined_throughput_bytes_per_sec,
                    record.max_p99_latency_nanos,
                    record.invariant_checks,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.integrated_network_disk_ios.is_empty() {
                print_roots_filtered(
                    "integrated-network-disk-io",
                    &package.semantic.roots.integrated_network_disk_io_roots,
                    filter,
                );
            }
        }
        "integrated-display-scheduler-load"
        | "display-scheduler-load"
        | "integrated-display-load" => {
            println!(
                "inspect integrated-display-scheduler-load package={} count={}",
                package.package_id, package.semantic.integrated_display_scheduler_load_count
            );
            for record in &package.semantic.integrated_display_scheduler_loads {
                let line = format!(
                    "integrated-display-scheduler-load id={} scenario={} framebuffer_benchmark={}@{} scheduler_decision={}@{} owner_store={}@{} owner_task={}@{} queue={}@{} activation={}@{} display={}@{} framebuffer={}@{} display_capability={}@{} framebuffer_write={}@{} framebuffer_flush_region={}@{} display_event_log={}@{} sample_frames={} sample_bytes={} scheduler_load_units={} display_measured_nanos={} invariants={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.framebuffer_benchmark,
                    record.framebuffer_benchmark_generation,
                    record.scheduler_decision,
                    record.scheduler_decision_generation,
                    record.owner_store,
                    record.owner_store_generation,
                    record.owner_task,
                    record.owner_task_generation,
                    record.queue,
                    record.queue_generation,
                    record.selected_activation,
                    record.selected_activation_generation,
                    record.display,
                    record.display_generation,
                    record.framebuffer,
                    record.framebuffer_generation,
                    record.display_capability,
                    record.display_capability_generation,
                    record.framebuffer_write,
                    record.framebuffer_write_generation,
                    record.framebuffer_flush_region,
                    record.framebuffer_flush_region_generation,
                    record.display_event_log,
                    record.display_event_log_generation,
                    record.sample_frames,
                    record.sample_bytes,
                    record.scheduler_load_units,
                    record.display_measured_nanos,
                    record.invariant_checks,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.integrated_display_scheduler_loads.is_empty() {
                print_roots_filtered(
                    "integrated-display-scheduler-load",
                    &package.semantic.roots.integrated_display_scheduler_load_roots,
                    filter,
                );
            }
        }
        "integrated-snapshot-io-lease-barrier"
        | "snapshot-io-lease-barrier"
        | "snapshot-io-barrier" => {
            println!(
                "inspect integrated-snapshot-io-lease-barrier package={} count={}",
                package.package_id, package.semantic.integrated_snapshot_io_lease_barrier_count
            );
            for record in &package.semantic.integrated_snapshot_io_lease_barriers {
                let line = format!(
                    "integrated-snapshot-io-lease-barrier id={} scenario={} smp_snapshot_barrier={}@{} io_cleanup={}@{} display_snapshot_barrier={}@{} driver_store={}@{} device={}@{} display={}@{} framebuffer={}@{} released_dma_buffers={} released_mmio_regions={} released_irq_lines={} released_framebuffer_window_leases={} active_dmw_leases={} in_flight_dma={} active_framebuffer_window_leases={} invariants={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.smp_snapshot_barrier,
                    record.smp_snapshot_barrier_generation,
                    record.io_cleanup,
                    record.io_cleanup_generation,
                    record.display_snapshot_barrier,
                    record.display_snapshot_barrier_generation,
                    record.driver_store,
                    record.driver_store_generation,
                    record.device,
                    record.device_generation,
                    record.display,
                    record.display_generation,
                    record.framebuffer,
                    record.framebuffer_generation,
                    record.released_dma_buffers,
                    record.released_mmio_regions,
                    record.released_irq_lines,
                    record.released_framebuffer_window_leases,
                    record.active_dmw_lease_count,
                    record.in_flight_dma_count,
                    record.active_framebuffer_window_lease_count,
                    record.invariant_checks,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.integrated_snapshot_io_lease_barriers.is_empty() {
                print_roots_filtered(
                    "integrated-snapshot-io-lease-barrier",
                    &package.semantic.roots.integrated_snapshot_io_lease_barrier_roots,
                    filter,
                );
            }
        }
        "integrated-code-publish-smp-workload"
        | "code-publish-smp-workload"
        | "integrated-code-publish-workload" => {
            println!(
                "inspect integrated-code-publish-smp-workload package={} count={}",
                package.package_id, package.semantic.integrated_code_publish_smp_workload_count
            );
            for record in &package.semantic.integrated_code_publish_smp_workloads {
                let line = format!(
                    "integrated-code-publish-smp-workload id={} scenario={} stress_run={}@{} code_publish_barrier={}@{} rendezvous={}@{} safe_point={}@{} code_publish_epoch={}->{} harts={} iterations={} participant_count={} invariants={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                    record.smp_code_publish_barrier,
                    record.smp_code_publish_barrier_generation,
                    record.publish_rendezvous,
                    record.publish_rendezvous_generation,
                    record.publish_safe_point,
                    record.publish_safe_point_generation,
                    record.code_publish_epoch_before,
                    record.code_publish_epoch_after,
                    record.hart_count,
                    record.workload_iterations,
                    record.participant_count,
                    record.invariant_checks,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.integrated_code_publish_smp_workloads.is_empty() {
                print_roots_filtered(
                    "integrated-code-publish-smp-workload",
                    &package.semantic.roots.integrated_code_publish_smp_workload_roots,
                    filter,
                );
            }
        }
        "integrated-display-panic" | "display-panic" | "panic-ring-extraction" => {
            println!(
                "inspect integrated-display-panic package={} count={}",
                package.package_id, package.semantic.integrated_display_panic_count
            );
            for record in &package.semantic.integrated_display_panics {
                let line = format!(
                    "integrated-display-panic id={} scenario={} substrate_panic_event={} display_panic_last_frame={}@{} panic_ring_records={} lost={} jsonl_frames={} contract_panic_summary_records={} corrupt_records={} truncated_records={} raw_framebuffer_bytes_exported={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.substrate_panic_event,
                    record.display_panic_last_frame,
                    record.display_panic_last_frame_generation,
                    record.panic_ring_record_count,
                    record.panic_ring_lost_count,
                    record.jsonl_frame_count,
                    record.contract_panic_summary_records,
                    record.corrupt_record_count,
                    record.truncated_record_count,
                    record.raw_framebuffer_bytes_exported,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.integrated_display_panics.is_empty() {
                print_roots_filtered(
                    "integrated-display-panic",
                    &package.semantic.roots.integrated_display_panic_roots,
                    filter,
                );
            }
        }
        "integrated-osctl-trace-replay" | "osctl-trace-replay" | "full-osctl-trace-replay" => {
            println!(
                "inspect integrated-osctl-trace-replay package={} count={}",
                package.package_id, package.semantic.integrated_osctl_trace_replay_count
            );
            for record in &package.semantic.integrated_osctl_trace_replays {
                let line = format!(
                    "integrated-osctl-trace-replay id={} scenario={} replay_event_cursor={} integrated_scenarios={} replayed_roots={} stable_views={} historical_edges={} replay_fixtures={} contract_ok={} replay_ok={} graph_history_ok={} roots_match_counts={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.replay_event_cursor,
                    record.integrated_scenario_count,
                    record.replayed_root_count,
                    record.stable_view_count,
                    record.historical_edge_count,
                    record.replay_fixture_count,
                    record.contract_validation_ok,
                    record.replay_validation_ok,
                    record.graph_history_ok,
                    record.roots_match_counts,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.integrated_osctl_trace_replays.is_empty() {
                print_roots_filtered(
                    "integrated-osctl-trace-replay",
                    &package.semantic.roots.integrated_osctl_trace_replay_roots,
                    filter,
                );
            }
        }
        "memory-policy" => {
            println!(
                "inspect memory-policy package={} count={}",
                package.package_id, package.semantic.memory_policy_count
            );
            for policy in &package.semantic.memory_policies {
                let line = format!(
                    "memory-policy class={} owner={} perms={} migration={} snapshot={} cleanup={} alias_guest={} cross_pending={} executable={}",
                    policy.class,
                    policy.owner_kind,
                    policy.permissions,
                    policy.migration_policy,
                    policy.snapshot_policy,
                    policy.cleanup_policy,
                    policy.can_alias_guest_memory,
                    policy.can_cross_pending,
                    policy.can_be_executable
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.memory_policies.is_empty() {
                print_roots_filtered(
                    "memory-policy",
                    &package.semantic.roots.memory_policy_roots,
                    filter,
                );
            }
        }
        "snapshot-validation" => {
            print_boundary_validation(
                "snapshot-validation",
                package.package_id.as_str(),
                &package.semantic.snapshot_validation,
                &package.semantic.roots.snapshot_validation_roots,
                filter,
            );
        }
        "replay-validation" => {
            print_boundary_validation(
                "replay-validation",
                package.package_id.as_str(),
                &package.semantic.replay_validation,
                &package.semantic.roots.replay_validation_roots,
                filter,
            );
        }
        _ => return Err(format!("unknown inspect kind `{kind}`").into()),
    }
    Ok(())
}
