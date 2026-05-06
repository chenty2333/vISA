use super::*;

pub(super) fn push_lifecycle_core_roots(
    roots: &mut SemanticRootSetManifest,
    semantic: &SemanticGraph,
    capabilities: &[MigrationCapabilityManifest],
    target_v1: &TargetExecutorV1Report,
) {
    roots.activation_resume_roots = semantic            .activation_resumes()
            .iter()
            .map(|resume| {
                format!(
                    "activation-resume id={} decision={}@{} activation={}@{}->{} vector_status={} saved_vector_state={} restored_vector_state={} state={} generation={}",
                    resume.id,
                    resume.scheduler_decision,
                    resume.scheduler_decision_generation,
                    resume.activation,
                    resume.activation_generation_before,
                    resume.activation_generation_after,
                    resume.vector_status.as_str(),
                    resume
                        .saved_vector_state
                        .map(|state| state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    resume
                        .restored_vector_state
                        .map(|state| state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    resume.state.as_str(),
                    resume.generation
                )
            })
            .collect();
    roots.activation_wait_roots = semantic
        .activation_waits()
        .iter()
        .map(|activation_wait| {
            format!(
                "activation-wait id={} activation={}@{}->{} wait={}@{} state={} generation={}",
                activation_wait.id,
                activation_wait.activation,
                activation_wait.activation_generation_before,
                activation_wait.activation_generation_after_block,
                activation_wait.wait,
                activation_wait.wait_generation,
                activation_wait.state.as_str(),
                activation_wait.generation
            )
        })
        .collect();
    roots.activation_cleanup_roots = semantic            .activation_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "activation-cleanup id={} store={}@{}->{} activation={}@{}->{} wait={}@{} state={} generation={}",
                    cleanup.id,
                    cleanup.store,
                    cleanup.target_store_generation,
                    cleanup.result_store_generation,
                    cleanup.activation,
                    cleanup.activation_generation_before,
                    cleanup.activation_generation_after,
                    cleanup
                        .wait
                        .map(|wait| wait.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .wait_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup.state.as_str(),
                    cleanup.generation
                )
            })
            .collect();
    roots.preemption_latency_roots = semantic            .preemption_latency_samples()
            .iter()
            .map(|sample| {
                format!(
                    "preemption-latency id={} timer={}@{} preemption={}@{} decision={}@{} resume={}@{} events={} measured_nanos={} budget_nanos={} state={} generation={}",
                    sample.id,
                    sample.timer_interrupt,
                    sample.timer_interrupt_generation,
                    sample.preemption,
                    sample.preemption_generation,
                    sample.scheduler_decision,
                    sample.scheduler_decision_generation,
                    sample.activation_resume,
                    sample.activation_resume_generation,
                    sample.interrupt_to_resume_events,
                    sample.measured_nanos,
                    sample.budget_nanos,
                    sample.state.as_str(),
                    sample.generation
                )
            })
            .collect();
    roots.hart_event_attribution_roots = semantic            .hart_event_attributions()
            .iter()
            .map(|attribution| {
                format!(
                    "hart-event-attribution id={} hart={}@{} hardware_id={} event={} kind={} generation={}",
                    attribution.id,
                    attribution.hart,
                    attribution.hart_generation,
                    attribution.hardware_hart,
                    attribution.event,
                    attribution.event_kind,
                    attribution.generation
                )
            })
            .collect();
    roots.resource_roots = semantic
        .resources()
        .iter()
        .map(|resource| {
            format!(
                "resource id={} kind={} generation={} live={}",
                resource.id,
                resource.kind.as_str(),
                resource.generation,
                resource.live
            )
        })
        .collect();
    roots.authority_roots = semantic
        .authority_bindings()
        .iter()
        .map(|authority| {
            format!(
                "authority:{}:{}:{}:gen{}:{}",
                authority.id,
                authority.subject,
                authority.object,
                authority.generation,
                authority.state.as_str()
            )
        })
        .collect();
    roots.wait_roots = target_v1
        .wait_records
        .iter()
        .map(|wait| {
            format!("wait id={} state={} generation={}", wait.id, wait.state, wait.generation)
        })
        .chain(semantic.wait_records().iter().map(|wait| {
            format!(
                "wait id={} state={} generation={}",
                wait.id,
                wait.state.as_str(),
                wait.generation
            )
        }))
        .collect();
    roots.store_roots = semantic
        .stores()
        .iter()
        .map(|store| {
            format!(
                "store id={} package={} state={} generation={}",
                store.id,
                store.package,
                store.state.as_str(),
                store.generation
            )
        })
        .collect();
    roots.capability_roots = capabilities
        .iter()
        .map(|capability| {
            format!(
                "cap:{}:{}:{}:{}:gen{}:{}",
                capability.subject,
                capability.class,
                capability.object,
                capability.rights.join("+"),
                capability.generation,
                capability.source
            )
        })
        .collect();
    roots.target_store_record_roots = target_v1
        .store_records
        .iter()
        .map(|store| {
            format!(
                "target-store id={} package={} artifact={} state={} generation={} fault_domain={}",
                store.id,
                store.package,
                store.artifact,
                store.state,
                store.generation,
                store.fault_domain
            )
        })
        .collect();
    roots.target_capability_record_roots = target_v1            .capability_records
            .iter()
            .map(|capability| {
                format!(
                    "target-capability id={} subject={} object={} class={} rights={} generation={} owner_store={}@{} revoked={} source={}",
                    capability.id,
                    capability.subject,
                    capability.object,
                    capability.class,
                    capability.rights.join("+"),
                    capability.generation,
                    capability
                        .owner_store
                        .map(|store| store.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    capability
                        .owner_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    capability.revoked,
                    capability.source
                )
            })
            .collect();
    roots.fast_path_roots = semantic
        .fast_path_plans()
        .iter()
        .map(|plan| format!("fastpath:{}:gen{}:valid{}", plan.id, plan.generation, plan.valid))
        .collect();
    roots.boundary_roots =
        semantic.boundaries().iter().map(|boundary| boundary.summary()).collect();
    roots.artifact_verification_roots =
        semantic.artifact_verifications().iter().map(|artifact| artifact.summary()).collect();
    roots.store_activation_roots =
        semantic.store_activations().iter().map(|activation| activation.summary()).collect();
    roots.executor_transition_roots =
        semantic.store_executor_transition_tail(semantic.store_executor_transition_count());
}
