use semantic_core::{CapabilityId, Generation};
use visa_runtime::{
    VisaRuntimeEvidenceSnapshot, VisaSubstrateAuthorityExtractionEvidence,
    VisaSubstrateUnsupportedEvidence,
};

use super::super::super::*;

pub(crate) fn wait_record_manifest(wait: &semantic_core::WaitRecord) -> WaitRecordManifest {
    WaitRecordManifest {
        id: wait.id,
        owner_task: wait.owner_task.map(u64::from),
        owner_task_generation: wait.owner_task_generation,
        owner_store: wait.owner_store,
        owner_store_generation: wait.owner_store_generation,
        kind: wait.kind.as_str().to_owned(),
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        blockers: wait.blockers.iter().copied().map(contract_object_ref_manifest).collect(),
        deadline: wait.deadline,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        restart_policy: wait.restart_policy.as_str().to_owned(),
        saved_context: wait.saved_context.clone(),
    }
}

pub(crate) fn capability_record_manifest(
    capability: &CapabilityRecord,
) -> CapabilityRecordManifest {
    CapabilityRecordManifest {
        id: capability.id,
        subject: capability.subject.clone(),
        object: capability.object.clone(),
        object_ref: capability.object_ref.map(authority_object_ref_manifest),
        rights: capability.operations.as_slice().to_vec(),
        lifetime: capability.lifetime.clone(),
        class: capability.class.as_str().to_owned(),
        owner_store: capability.owner_store,
        owner_store_generation: capability.owner_store_generation,
        owner_task: capability.owner_task.map(u64::from),
        source: capability.source.clone(),
        generation: capability.generation,
        parent: capability.parent,
        manifest_decl: capability.manifest_decl,
        debug_object_label: capability.debug_object_label.clone(),
        revoked: capability.revoked,
    }
}

pub(crate) fn activation_record_manifest(
    activation: &semantic_core::target_executor::ActivationRecord,
) -> ActivationRecordManifest {
    ActivationRecordManifest {
        id: activation.id,
        store: activation.store,
        store_generation: activation.store_generation,
        code_object: activation.code_object,
        code_generation: activation.code_generation,
        artifact: activation.artifact,
        entry: activation.entry.summary(),
        generation: activation.generation,
        state: activation.state.as_str().to_owned(),
        start_event: activation.start_event,
        exit_event: activation.exit_event,
        active_dmw_leases: activation.active_dmw_leases,
        blocked_wait: activation.blocked_wait,
        trap: activation.trap,
        return_tag: activation.return_tag.map(|tag| tag.as_str().to_owned()),
    }
}

pub(crate) fn trap_record_manifest(
    trap: &semantic_core::target_executor::TargetTrapRecord,
) -> TrapRecordManifest {
    TrapRecordManifest {
        id: trap.id,
        generation: trap.generation,
        class: trap.class.as_str().to_owned(),
        store: trap.store,
        store_generation: trap.store_generation,
        activation: trap.activation,
        activation_generation: trap.activation_generation,
        code_object: trap.code_object,
        code_generation: trap.code_generation,
        artifact: trap.artifact,
        artifact_generation: trap.artifact_generation,
        offset: trap.offset,
        target_pc: trap.target_pc,
        trap_kind: trap.trap_kind.clone(),
        function_index: trap.function_index,
        wasm_offset: trap.wasm_offset,
        debug_symbol: trap.debug_symbol,
        classification_status: trap.classification_status.clone(),
        attribution_status: trap.attribution_status.clone(),
        simd_attribution: trap.simd_attribution.as_ref().map(|attribution| {
            SimdTrapAttributionManifest {
                classification: attribution.classification.as_str().to_owned(),
                required_abi: attribution.required_abi.clone(),
                min_vector_register_count: attribution.min_vector_register_count,
                min_vector_register_bits: attribution.min_vector_register_bits,
                target_feature_set: attribution
                    .target_feature_set
                    .map(contract_object_ref_manifest),
                code_requirement_status: attribution.code_requirement_status.as_str().to_owned(),
                note: attribution.note.clone(),
            }
        }),
        hostcall: trap.hostcall.clone(),
        fault_policy: trap.fault_policy.clone(),
        effect: trap.effect.summary(),
        detail: trap.detail.clone(),
    }
}

pub(crate) fn hostcall_trace_manifest(trace: &HostcallTraceRecord) -> HostcallTraceManifest {
    HostcallTraceManifest {
        id: trace.id,
        generation: trace.generation,
        abi_version: trace.abi_version.clone(),
        frame_size: trace.frame_size,
        flags: trace.flags,
        activation: trace.activation,
        activation_generation: trace.activation_generation,
        store: trace.store,
        store_generation: trace.store_generation,
        code_object: trace.code_object,
        code_generation: trace.code_generation,
        artifact: trace.artifact,
        artifact_generation: trace.artifact_generation,
        hostcall_number: trace.hostcall_number,
        hostcall_seq: trace.hostcall_seq,
        caller_offset: trace.caller_offset,
        name: trace.name.clone(),
        category: trace.category.as_str().to_owned(),
        subject: trace.subject.clone(),
        subject_source: trace.subject_source.clone(),
        object: trace.object.clone(),
        operation: trace.operation.clone(),
        args: trace.args,
        cap_args: trace.cap_args.iter().map(cap_arg_manifest).collect(),
        record_mode: trace.record_mode.as_str().to_owned(),
        allowed: trace.allowed,
        gate_status: trace.gate_status.clone(),
        result: trace.result.clone(),
        denial_reason: trace.denial_reason.clone(),
        ret_tag: trace.ret_tag.as_str().to_owned(),
        ret0: trace.ret0,
        ret1: trace.ret1,
        trap_out: trace.trap_out,
        trap_generation_out: trace.trap_generation_out,
        wait_token_out: trace.wait_token_out,
        wait_token_generation_out: trace.wait_token_generation_out,
    }
}

pub(crate) fn cap_arg_manifest(arg: &CapabilityHandleArg) -> CapabilityHandleArgManifest {
    CapabilityHandleArgManifest {
        id: arg.id,
        object: arg.object.clone(),
        generation: arg.generation,
        owner_store: arg.owner_store,
        owner_store_generation: arg.owner_store_generation,
        handle_slot: arg.handle_slot,
        handle_generation: arg.handle_generation,
        handle_tag: arg.handle_tag,
        rights_mask: arg.rights_mask,
        rights: arg.rights.clone(),
    }
}

pub(crate) fn substrate_event_manifests(events: &[EventRecord]) -> Vec<SubstrateEventManifest> {
    events.iter().filter_map(substrate_event_manifest).collect()
}

pub fn runtime_evidence_substrate_event_manifests(
    evidence: &VisaRuntimeEvidenceSnapshot,
) -> Vec<SubstrateEventManifest> {
    let mut events = Vec::with_capacity(
        evidence.authority_extractions.len() + evidence.unsupported_substrate_events.len(),
    );
    events.extend(evidence.authority_extractions.iter().map(runtime_authority_extraction_manifest));
    events.extend(
        evidence.unsupported_substrate_events.iter().map(runtime_unsupported_substrate_manifest),
    );
    events.sort_by_key(|event| (event.epoch, event.id));
    events
}

fn runtime_authority_extraction_manifest(
    extraction: &VisaSubstrateAuthorityExtractionEvidence,
) -> SubstrateEventManifest {
    let requester_label = extraction.requester.as_deref().unwrap_or("unknown");
    SubstrateEventManifest {
        id: extraction.event_id,
        epoch: extraction.event_epoch,
        event_kind: "authority-extracted".to_owned(),
        authority: extraction.authority.clone(),
        operation: extraction.operation.clone(),
        requester: extraction.requester.clone(),
        artifact: extraction.artifact_id,
        store: extraction.store_id,
        capability: substrate_capability_manifest(
            extraction.capability_id,
            extraction.capability_generation,
        ),
        explanation: format!(
            "{requester_label} extracted {}::{} authority from substrate",
            extraction.authority, extraction.operation
        ),
    }
}

fn runtime_unsupported_substrate_manifest(
    unsupported: &VisaSubstrateUnsupportedEvidence,
) -> SubstrateEventManifest {
    let requester_label = unsupported.requester.as_deref().unwrap_or("unknown");
    SubstrateEventManifest {
        id: unsupported.event_id,
        epoch: unsupported.event_epoch,
        event_kind: "unsupported".to_owned(),
        authority: unsupported.authority.clone(),
        operation: unsupported.operation.clone(),
        requester: unsupported.requester.clone(),
        artifact: unsupported.artifact_id,
        store: unsupported.store_id,
        capability: None,
        explanation: format!(
            "{requester_label} observed {}::{} as unsupported",
            unsupported.authority, unsupported.operation
        ),
    }
}

pub(crate) fn substrate_event_manifest(event: &EventRecord) -> Option<SubstrateEventManifest> {
    match &event.kind {
        EventKind::SubstrateAuthorityExtracted {
            authority,
            operation,
            requester,
            artifact,
            store,
            capability,
            capability_generation,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            let capability_manifest =
                substrate_capability_manifest(*capability, *capability_generation);
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "authority-extracted".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: capability_manifest,
                explanation: format!(
                    "{requester_label} extracted {authority}::{operation} authority from substrate"
                ),
            })
        }
        EventKind::SubstrateUnsupported { authority, operation, requester, artifact, store } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "unsupported".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: None,
                explanation: format!(
                    "{requester_label} observed {authority}::{operation} as unsupported"
                ),
            })
        }
        EventKind::SubstrateCapabilityDenied {
            authority,
            operation,
            requester,
            artifact,
            store,
            capability,
            capability_generation,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            let capability_manifest =
                substrate_capability_manifest(*capability, *capability_generation);
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "capability-denied".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: capability_manifest,
                explanation: format!(
                    "{requester_label} was denied {authority}::{operation} by capability gate"
                ),
            })
        }
        EventKind::SubstratePanic {
            authority,
            operation,
            requester,
            artifact,
            store,
            panic_epoch,
            panic_cpu,
            panic_reason_code,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "panic".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: None,
                explanation: format!(
                    "{requester_label} reported substrate panic epoch={panic_epoch} cpu={panic_cpu} reason={panic_reason_code}"
                ),
            })
        }
        _ => None,
    }
}

fn substrate_capability_manifest(
    capability: Option<CapabilityId>,
    capability_generation: Option<Generation>,
) -> Option<CapabilityHandleArgManifest> {
    match (capability, capability_generation) {
        (Some(id), Some(generation)) => Some(CapabilityHandleArgManifest {
            id,
            object: "substrate-capability".to_owned(),
            generation,
            owner_store: None,
            owner_store_generation: None,
            handle_slot: 0,
            handle_generation: 0,
            handle_tag: 0,
            rights_mask: 0,
            rights: Vec::new(),
        }),
        _ => None,
    }
}

pub(crate) fn command_result_manifest(result: &CommandResult) -> CommandResultManifest {
    CommandResultManifest {
        id: result.command_id,
        issuer: result.issuer.clone(),
        command: result.command.to_owned(),
        status: result.status.as_str().to_owned(),
        events: result.events.clone(),
        effects: result
            .effects
            .iter()
            .map(|effect| CommandEffectManifest {
                kind: effect.kind.clone(),
                target: effect.target.map(contract_object_ref_manifest),
            })
            .collect(),
        violations: result.violations.clone(),
    }
}

pub(crate) fn interface_event_manifests(events: &[EventRecord]) -> Vec<InterfaceEventManifest> {
    events.iter().filter_map(interface_event_manifest).collect()
}

pub(crate) fn interface_event_manifest(event: &EventRecord) -> Option<InterfaceEventManifest> {
    match &event.kind {
        EventKind::InterfaceUnsupported {
            interface_kind,
            interface,
            operation,
            requester,
            artifact,
            store,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(InterfaceEventManifest {
                id: event.id,
                epoch: event.epoch,
                interface_kind: interface_kind.clone(),
                interface: interface.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                explanation: format!(
                    "{requester_label} observed {interface_kind} {interface}::{operation} as unsupported"
                ),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod runtime_evidence_tests {
    use super::*;

    #[test]
    fn runtime_evidence_projects_substrate_event_manifests_in_event_order() {
        let evidence = VisaRuntimeEvidenceSnapshot {
            contract_graph: semantic_core::ContractGraphSnapshot::default(),
            event_log_cursor: 11,
            runtime_events: Vec::new(),
            authority_extractions: vec![VisaSubstrateAuthorityExtractionEvidence {
                event_id: 9,
                event_epoch: 4,
                authority: "DmaAuthority".to_owned(),
                operation: "dma_alloc".to_owned(),
                requester: Some("native-visa".to_owned()),
                artifact_id: Some(29),
                store_id: Some(1),
                capability_id: Some(7),
                capability_generation: Some(3),
            }],
            unsupported_substrate_events: vec![VisaSubstrateUnsupportedEvidence {
                event_id: 8,
                event_epoch: 3,
                authority: "ConsoleAuthority".to_owned(),
                operation: "console_write".to_owned(),
                requester: Some("native-visa".to_owned()),
                artifact_id: Some(29),
                store_id: Some(1),
            }],
        };

        let manifests = runtime_evidence_substrate_event_manifests(&evidence);

        assert_eq!(manifests.len(), 2);
        assert_eq!(manifests[0].event_kind, "unsupported");
        assert_eq!(manifests[0].id, 8);
        assert_eq!(manifests[0].epoch, 3);
        assert_eq!(manifests[0].requester.as_deref(), Some("native-visa"));
        assert!(manifests[0].capability.is_none());
        assert_eq!(manifests[1].event_kind, "authority-extracted");
        assert_eq!(manifests[1].id, 9);
        assert_eq!(manifests[1].epoch, 4);
        assert_eq!(manifests[1].authority, "DmaAuthority");
        assert_eq!(manifests[1].operation, "dma_alloc");
        assert_eq!(manifests[1].artifact, Some(29));
        assert_eq!(manifests[1].store, Some(1));
        assert_eq!(manifests[1].capability.as_ref().map(|cap| cap.id), Some(7));
        assert_eq!(manifests[1].capability.as_ref().map(|cap| cap.generation), Some(3));
    }
}

pub(crate) fn migration_object_manifest(record: &MigrationObjectRecord) -> MigrationObjectManifest {
    MigrationObjectManifest {
        object: record.object.clone(),
        class: record.class.as_str().to_owned(),
        reason: record.reason.clone(),
    }
}

pub(crate) fn tombstone_manifest(record: &TombstoneRecord) -> TombstoneManifest {
    TombstoneManifest {
        kind: record.kind.as_str().to_owned(),
        id: record.id,
        generation: record.generation,
        died_at: record.died_at,
        reason: record.reason.clone(),
    }
}

pub(crate) fn contract_object_ref_manifest(
    reference: ContractObjectRef,
) -> ContractObjectRefManifest {
    ContractObjectRefManifest {
        kind: reference.kind.as_str().to_owned(),
        id: reference.id,
        generation: reference.generation,
    }
}

pub(crate) fn optional_generation_ref(id: Option<u64>, generation: Option<u64>) -> String {
    match (id, generation) {
        (Some(id), Some(generation)) => format!("{id}@{generation}"),
        _ => "none".to_owned(),
    }
}

pub(crate) fn authority_object_ref_manifest(
    reference: AuthorityObjectRef,
) -> AuthorityObjectRefManifest {
    match reference {
        AuthorityObjectRef::Internal { class, object } => AuthorityObjectRefManifest {
            scope: "internal".to_owned(),
            class: class.as_str().to_owned(),
            object: contract_object_ref_manifest(object),
        },
        AuthorityObjectRef::External { class, object } => AuthorityObjectRefManifest {
            scope: "external".to_owned(),
            class: class.as_str().to_owned(),
            object: contract_object_ref_manifest(object),
        },
    }
}

pub(crate) fn contract_violation_manifest(
    violation: &ContractViolation,
) -> ContractViolationManifest {
    ContractViolationManifest {
        kind: violation.kind.as_str().to_owned(),
        edge: violation.edge.clone(),
        from: contract_object_ref_manifest(violation.from),
        to: violation.to.map(contract_object_ref_manifest),
        detail: violation.detail.clone(),
    }
}

pub(crate) fn cleanup_transaction_manifest(
    cleanup: &semantic_core::target_executor::FaultCleanupTransaction,
) -> CleanupTransactionManifest {
    CleanupTransactionManifest {
        id: cleanup.id,
        store: cleanup.store,
        store_generation: cleanup.store_generation,
        target_store_generation: cleanup.store_generation,
        result_store_generation: cleanup.result_store_generation,
        activation: cleanup.activation,
        activation_generation: cleanup.activation_generation,
        code_object: cleanup.code_object,
        code_generation: cleanup.code_generation,
        generation: cleanup.generation,
        started_at: cleanup.started_at,
        finished_at: cleanup.finished_at,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        released_dmw_leases: cleanup.released_dmw_leases,
        cancelled_waits: cleanup.cancelled_waits,
        revoked_capabilities: cleanup.revoked_capabilities.clone(),
        revoked_capability_refs: cleanup
            .revoked_capability_refs
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        dropped_resources: cleanup.dropped_resources,
        unbound_code_object: cleanup.unbound_code_object,
        state_digest: cleanup.state_digest.clone(),
        effect: cleanup.effect.summary(),
        steps: cleanup
            .steps
            .iter()
            .map(|step| CleanupStepManifest {
                step: step.step.as_str().to_owned(),
                state: step.state.as_str().to_owned(),
                detail: step.detail.clone(),
                target: step.target.map(contract_object_ref_manifest),
                observed_generation: step.observed_generation,
                error: step.error.clone(),
                idempotency_key: step.idempotency_key.clone(),
                event_seq: step.event_seq,
            })
            .collect(),
        effects: cleanup
            .effects
            .iter()
            .map(|effect| CleanupEffectManifest {
                kind: effect.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(effect.target),
                expected_generation: effect.expected_generation,
                status: effect.status.as_str().to_owned(),
                event_seq: effect.event_seq,
            })
            .collect(),
    }
}

pub(crate) fn memory_policy_manifest(policy: &MemoryClassPolicy) -> MemoryClassPolicyManifest {
    MemoryClassPolicyManifest {
        class: policy.class.as_str().to_owned(),
        owner_kind: policy.owner_kind.as_str().to_owned(),
        permissions: policy.permissions.summary(),
        migration_policy: policy.migratable.as_str().to_owned(),
        snapshot_policy: policy.snapshot_policy.as_str().to_owned(),
        cleanup_policy: policy.cleanup_policy.as_str().to_owned(),
        can_alias_guest_memory: policy.can_alias_guest_memory,
        can_cross_pending: policy.can_cross_pending,
        can_be_executable: policy.can_be_executable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substrate_authority_extracted_projects_to_manifest() {
        let event = EventRecord {
            id: 7,
            epoch: 11,
            source: "substrate".to_owned(),
            causal_parent: None,
            kind: EventKind::SubstrateAuthorityExtracted {
                authority: "ConsoleAuthority".to_owned(),
                operation: "console_write".to_owned(),
                requester: Some("wasi-app".to_owned()),
                artifact: Some(9),
                store: Some(1),
                capability: Some(3),
                capability_generation: Some(2),
            },
        };

        let manifest = substrate_event_manifest(&event).expect("project extracted authority");

        assert_eq!(manifest.event_kind, "authority-extracted");
        assert_eq!(manifest.authority, "ConsoleAuthority");
        assert_eq!(manifest.operation, "console_write");
        assert_eq!(manifest.requester.as_deref(), Some("wasi-app"));
        assert_eq!(manifest.artifact, Some(9));
        assert_eq!(manifest.store, Some(1));
        let capability = manifest.capability.expect("capability projection");
        assert_eq!(capability.id, 3);
        assert_eq!(capability.generation, 2);
        assert!(manifest.explanation.contains("extracted ConsoleAuthority::console_write"));
    }
}
