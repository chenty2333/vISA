use super::*;

pub(super) fn push_target_runtime_roots(
    roots: &mut SemanticRootSetManifest,
    semantic: &SemanticGraph,
    _capabilities: &[MigrationCapabilityManifest],
    target_v1: &TargetExecutorV1Report,
) {
    roots.target_artifact_roots = target_v1            .target_artifacts
            .iter()
            .map(|artifact| {
                format!(
                    "target-artifact id={} package={} artifact={} profile={} artifact_hash={} hash_status={} abi={} code_hash={} signature={} signature_status={} signature_verified={} signer={}",
                    artifact.id,
                    artifact.package,
                    artifact.artifact_name,
                    artifact.target_profile,
                    artifact.artifact_hash,
                    artifact.hash_status,
                    artifact.abi_fingerprint,
                    artifact.code_hash,
                    artifact.signature_scheme,
                    artifact.signature_status,
                    artifact.signature_verified,
                    artifact.signer
                )
            })
            .collect();
    roots.code_object_roots = target_v1
        .code_objects
        .iter()
        .map(|code| {
            let store = code
                .bound_store
                .map(|store| {
                    format!(
                        "{store}@{}",
                        code.bound_store_generation
                            .map(|generation| generation.to_string())
                            .unwrap_or_else(|| "unknown".to_owned())
                    )
                })
                .unwrap_or_else(|| "none".to_owned());
            format!(
                "code-object id={} artifact={} package={} state={} store={} generation={}",
                code.id, code.artifact_id, code.package, code.state, store, code.generation
            )
        })
        .collect();
    roots.activation_record_roots = target_v1            .activation_records
            .iter()
            .map(|activation| {
                let wait = activation
                    .blocked_wait
                    .map(|wait| wait.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                let trap = activation
                    .trap
                    .map(|trap| trap.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "activation id={} store={} store_generation={} code={} code_generation={} state={} entry={} wait={} trap={} dmw={}",
                    activation.id,
                    activation.store,
                    activation.store_generation,
                    activation.code_object,
                    activation.code_generation,
                    activation.state,
                    activation.entry,
                    wait,
                    trap,
                    activation.active_dmw_leases
                )
            })
            .collect();
    roots.trap_roots = target_v1
        .trap_records
        .iter()
        .map(|trap| {
            let store =
                trap.store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_owned());
            let activation = trap
                .activation
                .map(|activation| activation.to_string())
                .unwrap_or_else(|| "none".to_owned());
            let trap_kind = trap.trap_kind.as_deref().unwrap_or("none");
            let simd = trap
                .simd_attribution
                .as_ref()
                .map(|attribution| attribution.classification.clone())
                .unwrap_or_else(|| "none".to_owned());
            format!(
                "trap id={} class={} kind={} store={} activation={} simd={} effect={} detail={}",
                trap.id, trap.class, trap_kind, store, activation, simd, trap.effect, trap.detail
            )
        })
        .collect();
    roots.hostcall_trace_roots = target_v1            .hostcall_trace
            .iter()
            .map(|trace| {
                format!(
                    "hostcall abi={} frame_size={} seq={} caller_offset={} record_mode={} activation={} activation_generation={} store={} code={} artifact={}@{} number={} category={} subject={} object={} op={} cap_args={} allowed={} result={} ret={}",
                    trace.abi_version,
                    trace.frame_size,
                    trace.hostcall_seq,
                    trace.caller_offset,
                    trace.record_mode,
                    trace.activation,
                    trace.activation_generation,
                    trace.store,
                    trace.code_object,
                    trace.artifact,
                    trace.artifact_generation,
                    trace.hostcall_number,
                    trace.category,
                    trace.subject,
                    trace.object,
                    trace.operation,
                    trace.cap_args.len(),
                    trace.allowed,
                    trace.result,
                    trace.ret_tag
                )
            })
            .collect();
    roots.migration_object_roots = target_v1
        .migration_objects
        .iter()
        .map(|object| {
            format!(
                "migration-object object={} class={} reason={}",
                object.object, object.class, object.reason
            )
        })
        .collect();
    roots.tombstone_roots = target_v1
        .tombstones
        .iter()
        .map(|tombstone| {
            format!(
                "tombstone kind={} id={} generation={} died_at={} reason={}",
                tombstone.kind,
                tombstone.id,
                tombstone.generation,
                tombstone.died_at,
                tombstone.reason
            )
        })
        .collect();
    roots.contract_violation_roots = target_v1
        .contract_violations
        .iter()
        .map(|violation| {
            let to = violation.to.as_ref().map_or_else(
                || "none".to_owned(),
                |to| format!("{}:{}@{}", to.kind, to.id, to.generation),
            );
            format!(
                "contract-violation kind={} edge={} from={}:{}@{} to={} detail={}",
                violation.kind,
                violation.edge,
                violation.from.kind,
                violation.from.id,
                violation.from.generation,
                to,
                violation.detail
            )
        })
        .collect();
    roots.cleanup_roots = target_v1            .cleanup_transactions
            .iter()
            .map(|cleanup| {
                format!(
                    "cleanup id={} target_store={}@{} result_store_generation={} activation={} code={} generation={} state={} reason={} released_dmw={} cancelled_waits={} revoked_caps={} dropped_resources={} unbound_code={} effect={} steps={}",
                    cleanup.id,
                    cleanup.store,
                    cleanup.store_generation,
                    cleanup
                        .result_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .activation
                        .zip(cleanup.activation_generation)
                        .map(|(activation, generation)| format!("{activation}@{generation}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .code_object
                        .zip(cleanup.code_generation)
                        .map(|(code, generation)| format!("{code}@{generation}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup.generation,
                    cleanup.state,
                    cleanup.reason,
                    cleanup.released_dmw_leases,
                    cleanup.cancelled_waits,
                    cleanup.revoked_capabilities.len(),
                    cleanup.dropped_resources,
                    cleanup.unbound_code_object,
                    cleanup.effect,
                    cleanup
                        .steps
                        .iter()
                        .map(|step| format!("{}:{}", step.step, step.state))
                        .collect::<Vec<_>>()
                        .join("|")
                )
            })
            .collect();
    roots.memory_policy_roots = target_v1            .memory_policies
            .iter()
            .map(|policy| {
                format!(
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
                )
            })
            .collect();
    roots.snapshot_validation_roots = validation_roots(&target_v1.snapshot_validation);
    roots.replay_validation_roots = validation_roots(&target_v1.replay_validation);
    roots.substrate_event_roots = target_v1
        .substrate_events
        .iter()
        .map(|event| {
            format!(
                "substrate-event:{}:{}:{} requester={}",
                event.event_kind,
                event.authority,
                event.operation,
                event.requester.as_deref().unwrap_or("none")
            )
        })
        .collect();
    roots.command_result_roots = target_v1
        .command_results
        .iter()
        .map(|result| {
            format!(
                "command-result:{}:{}:{} issuer={}",
                result.id, result.command, result.status, result.issuer
            )
        })
        .collect();
    roots.interface_event_roots = target_v1
        .interface_events
        .iter()
        .map(|event| {
            format!(
                "interface-event:{}:{}:{} requester={}",
                event.interface_kind,
                event.interface,
                event.operation,
                event.requester.as_deref().unwrap_or("none")
            )
        })
        .collect();
    roots.event_log_tail = semantic
        .event_log_tail(16)
        .iter()
        .map(|event| event.summary())
        .chain(target_v1.target_event_tail.iter().cloned())
        .collect();
}
