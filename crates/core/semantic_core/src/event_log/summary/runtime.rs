use alloc::{
    format,
    string::{String, ToString},
};

use super::super::{super::*, kind::EventKind};

pub(super) fn summary(kind: &EventKind) -> Option<String> {
    let summary = match kind {
        EventKind::RuntimeActivationResumed {
            resume,
            decision,
            decision_generation,
            activation,
            from_generation,
            to_generation,
            queue,
            queue_generation,
            generation,
        } => format!(
            "RuntimeActivationResumed resume={resume} decision={decision}@{decision_generation} activation={activation}@{from_generation}->{to_generation} queue={queue}@{queue_generation} generation={generation}"
        ),
        EventKind::PreemptionLatencySampleRecorded {
            sample,
            timer_interrupt,
            timer_interrupt_generation,
            preemption,
            preemption_generation,
            scheduler_decision,
            scheduler_decision_generation,
            activation_resume,
            activation_resume_generation,
            measured_nanos,
            budget_nanos,
            generation,
        } => format!(
            "PreemptionLatencySampleRecorded sample={sample} timer={timer_interrupt}@{timer_interrupt_generation} preemption={preemption}@{preemption_generation} decision={scheduler_decision}@{scheduler_decision_generation} resume={activation_resume}@{activation_resume_generation} measured_nanos={measured_nanos} budget_nanos={budget_nanos} generation={generation}"
        ),
        EventKind::RuntimeActivationWaitBlocked {
            activation_wait,
            activation,
            from_generation,
            to_generation,
            wait,
            wait_generation,
            generation,
        } => format!(
            "RuntimeActivationWaitBlocked activation_wait={activation_wait} activation={activation}@{from_generation}->{to_generation} wait={wait}@{wait_generation} generation={generation}"
        ),
        EventKind::RuntimeActivationWaitCancelled {
            activation_wait,
            activation,
            from_generation,
            to_generation,
            wait,
            wait_generation,
            reason,
            generation,
        } => format!(
            "RuntimeActivationWaitCancelled activation_wait={activation_wait} activation={activation}@{from_generation}->{to_generation} wait={wait}@{wait_generation} reason={} generation={generation}",
            reason.as_str()
        ),
        EventKind::RuntimeActivationCleanupStarted {
            cleanup,
            store,
            store_generation,
            activation,
            activation_generation,
            generation,
        } => format!(
            "RuntimeActivationCleanupStarted cleanup={cleanup} store={store}@{store_generation} activation={activation}@{activation_generation} generation={generation}"
        ),
        EventKind::RuntimeActivationCleanupCompleted {
            cleanup,
            store,
            target_store_generation,
            result_store_generation,
            activation,
            activation_generation_before,
            activation_generation_after,
            generation,
        } => format!(
            "RuntimeActivationCleanupCompleted cleanup={cleanup} store={store}@{target_store_generation}->{result_store_generation} activation={activation}@{activation_generation_before}->{activation_generation_after} generation={generation}"
        ),
        EventKind::ResourceCreated { resource, kind, generation } => format!(
            "ResourceCreated resource={resource} kind={} generation={generation}",
            kind.as_str()
        ),
        EventKind::ResourceClosed { resource, generation } => {
            format!("ResourceClosed resource={resource} generation={generation}")
        }
        EventKind::ResourceHandleValidated { resource, generation } => {
            format!("ResourceHandleValidated resource={resource} generation={generation}")
        }
        EventKind::ResourceHandleRejected { resource, expected, actual, reason } => match actual {
            Some(actual) => format!(
                "ResourceHandleRejected resource={resource} expected={expected} actual={actual} reason={}",
                reason.as_str()
            ),
            None => format!(
                "ResourceHandleRejected resource={resource} expected={expected} actual=missing reason={}",
                reason.as_str()
            ),
        },
        EventKind::AuthorityBound { authority, resource, kind, subject, object, generation } => {
            format!(
                "AuthorityBound authority={authority} resource={resource} kind={} subject={subject} object={object} generation={generation}",
                kind.as_str()
            )
        }
        EventKind::AuthorityReleased { authority, resource, generation, reason } => format!(
            "AuthorityReleased authority={authority} resource={resource} generation={generation} reason={reason}"
        ),
        EventKind::AuthorityRevoked { authority, resource, generation, reason } => format!(
            "AuthorityRevoked authority={authority} resource={resource} generation={generation} reason={reason}"
        ),
        EventKind::BoundaryPublished {
            boundary,
            name,
            kind,
            status,
            evidence,
            backend,
            blocked_by,
            generation,
        } => {
            let blocked_by = blocked_by.as_deref().unwrap_or("none");
            format!(
                "BoundaryPublished boundary={boundary} name={name} kind={} status={} evidence={} backend={backend} blocked={blocked_by} generation={generation}",
                kind.as_str(),
                status.as_str(),
                evidence.as_str()
            )
        }
        EventKind::ArtifactVerificationRecorded {
            artifact,
            package,
            artifact_name,
            state,
            manifest_binding_hash,
            blocked_by,
            generation,
        } => {
            let blocked_by = blocked_by.as_deref().unwrap_or("none");
            format!(
                "ArtifactVerificationRecorded artifact={artifact} package={package} name={artifact_name} state={} binding={manifest_binding_hash} blocked={blocked_by} generation={generation}",
                state.as_str()
            )
        }
        EventKind::WaitCreated { wait, task, kind, generation } => format!(
            "WaitCreated wait={wait} task={task} kind={} generation={generation}",
            kind.as_str()
        ),
        EventKind::WaitPending { wait, generation } => {
            format!("WaitPending wait={wait} generation={generation}")
        }
        EventKind::WaitResolved { wait, reason } => {
            format!("WaitResolved wait={wait} reason={reason}")
        }
        EventKind::WaitConsumed { wait } => {
            format!("WaitConsumed wait={wait}")
        }
        EventKind::WaitCancelled { wait, errno, reason } => {
            format!("WaitCancelled wait={wait} errno={errno} reason={}", reason.as_str())
        }
        EventKind::WaitInterrupted { wait, reason } => {
            format!("WaitInterrupted wait={wait} reason={}", reason.as_str())
        }
        EventKind::WaitRestarted { wait, class } => {
            format!("WaitRestarted wait={wait} class={class}")
        }
        EventKind::WaitTokenValidated { wait, generation } => {
            format!("WaitTokenValidated wait={wait} generation={generation}")
        }
        EventKind::WaitTokenRejected { wait, expected, actual, reason } => match actual {
            Some(actual) => format!(
                "WaitTokenRejected wait={wait} expected={expected} actual={actual} reason={}",
                reason.as_str()
            ),
            None => format!(
                "WaitTokenRejected wait={wait} expected={expected} actual=missing reason={}",
                reason.as_str()
            ),
        },
        EventKind::CapabilityGranted { cap } => format!("CapabilityGranted cap={cap}"),
        EventKind::CapabilityRevoked { cap } => format!("CapabilityRevoked cap={cap}"),
        EventKind::CapabilityUsed { cap, subject, object, operation, generation } => format!(
            "CapabilityUsed cap={cap} subject={subject} object={object} op={operation} generation={generation}"
        ),
        EventKind::CapabilityDenied { subject, object, operation, reason } => format!(
            "CapabilityDenied subject={subject} object={object} op={operation} reason={}",
            reason.as_str()
        ),
        EventKind::CapabilityGenerationMismatch {
            subject,
            object,
            operation,
            expected,
            actual,
        } => match actual {
            Some(actual) => format!(
                "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual={actual}"
            ),
            None => format!(
                "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual=missing"
            ),
        },
        EventKind::HostcallEntered { label, class, subject, object, operation } => format!(
            "HostcallEntered label={label} class={} subject={subject} object={object} op={operation}",
            class.as_str()
        ),
        EventKind::SubstrateAuthorityExtracted {
            authority,
            operation,
            requester,
            artifact,
            store,
            capability,
            capability_generation,
        } => {
            let requester = requester.as_deref().unwrap_or("none");
            let artifact =
                artifact.map(|artifact| artifact.to_string()).unwrap_or_else(|| "none".to_string());
            let store = store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
            let capability = capability
                .map(|capability| capability.to_string())
                .unwrap_or_else(|| "none".to_string());
            let generation = capability_generation
                .map(|generation| generation.to_string())
                .unwrap_or_else(|| "none".to_string());
            format!(
                "SubstrateAuthorityExtracted authority={authority} op={operation} requester={requester} artifact={artifact} store={store} capability={capability} generation={generation}"
            )
        }
        EventKind::SubstrateUnsupported { authority, operation, requester, artifact, store } => {
            let requester = requester.as_deref().unwrap_or("none");
            let artifact =
                artifact.map(|artifact| artifact.to_string()).unwrap_or_else(|| "none".to_string());
            let store = store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
            format!(
                "SubstrateUnsupported authority={authority} op={operation} requester={requester} artifact={artifact} store={store}"
            )
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
            let requester = requester.as_deref().unwrap_or("none");
            let artifact =
                artifact.map(|artifact| artifact.to_string()).unwrap_or_else(|| "none".to_string());
            let store = store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
            let capability = capability
                .map(|capability| capability.to_string())
                .unwrap_or_else(|| "none".to_string());
            let generation = capability_generation
                .map(|generation| generation.to_string())
                .unwrap_or_else(|| "none".to_string());
            format!(
                "SubstrateCapabilityDenied authority={authority} op={operation} requester={requester} artifact={artifact} store={store} capability={capability} generation={generation}"
            )
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
            let requester = requester.as_deref().unwrap_or("none");
            let artifact =
                artifact.map(|artifact| artifact.to_string()).unwrap_or_else(|| "none".to_string());
            let store = store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
            format!(
                "SubstratePanic authority={authority} op={operation} requester={requester} artifact={artifact} store={store} panic_epoch={panic_epoch} panic_cpu={panic_cpu} panic_reason_code={panic_reason_code}"
            )
        }
        EventKind::InterfaceUnsupported {
            interface_kind,
            interface,
            operation,
            requester,
            artifact,
            store,
        } => {
            let requester = requester.as_deref().unwrap_or("none");
            let artifact =
                artifact.map(|artifact| artifact.to_string()).unwrap_or_else(|| "none".to_string());
            let store = store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
            format!(
                "InterfaceUnsupported kind={interface_kind} interface={interface} op={operation} requester={requester} artifact={artifact} store={store}"
            )
        }
        EventKind::FaultDomainRegistered { domain } => {
            format!("FaultDomainRegistered domain={domain}")
        }
        EventKind::FaultDomainStateChanged { domain, from, to, generation } => format!(
            "FaultDomainStateChanged domain={domain} {}->{} generation={generation}",
            from.as_str(),
            to.as_str()
        ),
        EventKind::FaultClassified { trap, class, store, task, detail } => {
            let store = store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
            let task = task.map(|task| task.to_string()).unwrap_or_else(|| "none".to_string());
            format!(
                "FaultClassified trap={} class={} store={store} task={task} detail={detail}",
                trap.as_str(),
                class.as_str()
            )
        }
        EventKind::DriverTrap { domain, trap, detail } => match domain {
            Some(domain) => {
                format!("DriverTrap domain={domain} trap={} detail={detail}", trap.as_str())
            }
            None => format!("DriverTrap trap={} detail={detail}", trap.as_str()),
        },
        EventKind::FaultDomainRestarted { domain } => {
            format!("FaultDomainRestarted domain={domain}")
        }
        EventKind::StoreRegistered { store, domain, resource, generation } => format!(
            "StoreRegistered store={store} domain={domain} resource={resource} generation={generation}"
        ),
        EventKind::StoreStateChanged { store, from, to, generation } => format!(
            "StoreStateChanged store={store} {}->{} generation={generation}",
            from.as_str(),
            to.as_str()
        ),
        EventKind::StoreExecutorTransition {
            store,
            from,
            to,
            blocked_by,
            hostcall_table,
            trap_surface,
        } => {
            let blocked_by = blocked_by.as_deref().unwrap_or("none");
            format!(
                "StoreExecutorTransition store={store} {from}->{to} blocked={blocked_by} hostcalls={hostcall_table} traps={trap_surface}"
            )
        }
        EventKind::StoreActivationRecorded {
            activation,
            store,
            package,
            code_publish_state,
            memory_layout_state,
            hostcall_table_state,
            trap_surface_state,
            entrypoint_state,
            blocked_by,
            generation,
        } => {
            let blocked_by = blocked_by.as_deref().unwrap_or("none");
            format!(
                "StoreActivationRecorded activation={activation} store={store} package={package} code={} memory={} hostcalls={} traps={} entry={} blocked={blocked_by} generation={generation}",
                code_publish_state.as_str(),
                memory_layout_state.as_str(),
                hostcall_table_state.as_str(),
                trap_surface_state.as_str(),
                entrypoint_state.as_str()
            )
        }
        EventKind::StoreActivationHandleValidated { store, generation } => {
            format!("StoreActivationHandleValidated store={store} generation={generation}")
        }
        EventKind::StoreActivationHandleRejected { store, expected, actual, reason } => {
            match actual {
                Some(actual) => format!(
                    "StoreActivationHandleRejected store={store} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "StoreActivationHandleRejected store={store} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            }
        }
        EventKind::StoreTrap { store, trap, detail } => {
            format!("StoreTrap store={store} trap={} detail={detail}", trap.as_str())
        }
        EventKind::StoreDropped { store, generation, resource } => match resource {
            Some(resource) => {
                format!("StoreDropped store={store} generation={generation} resource={resource}")
            }
            None => format!("StoreDropped store={store} generation={generation}"),
        },
        EventKind::StoreRebound { store, generation, resource } => {
            format!("StoreRebound store={store} generation={generation} resource={resource}")
        }
        EventKind::WindowLeaseCreated { lease, generation } => {
            format!("WindowLeaseCreated lease={lease} generation={generation}")
        }
        EventKind::WindowLeaseDestroyed { lease, generation } => {
            format!("WindowLeaseDestroyed lease={lease} generation={generation}")
        }
        EventKind::SnapshotBarrierEnter { barrier } => {
            format!("SnapshotBarrierEnter barrier={barrier}")
        }
        EventKind::SnapshotBarrierExit { barrier } => {
            format!("SnapshotBarrierExit barrier={barrier}")
        }
        EventKind::FastPathPlanInstalled { plan } => {
            format!("FastPathPlanInstalled plan={plan}")
        }
        EventKind::FastPathPlanInvalidated { plan } => {
            format!("FastPathPlanInvalidated plan={plan}")
        }
        EventKind::TransactionBegan { transaction, store, task, label } => {
            let store = store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
            let task = task.map(|task| task.to_string()).unwrap_or_else(|| "none".to_string());
            format!(
                "TransactionBegan transaction={transaction} store={store} task={task} label={label}"
            )
        }
        EventKind::TransactionCommitted { transaction, generation } => {
            format!("TransactionCommitted transaction={transaction} generation={generation}")
        }
        EventKind::TransactionRolledBack { transaction, reason, generation } => {
            format!(
                "TransactionRolledBack transaction={transaction} reason={reason} generation={generation}"
            )
        }
        EventKind::CleanupStepApplied { cleanup, step, target, observed_generation } => {
            format!(
                "CleanupStepApplied cleanup={cleanup} step={step} target={target} observed_generation={observed_generation}"
            )
        }
        EventKind::FailureEffect { effect } => {
            format!("FailureEffect {}", effect.summary())
        }
        EventKind::ProcessCreated { pid, parent_pid } => {
            format!("ProcessCreated pid={pid} parent={parent_pid:?}")
        }
        EventKind::ProcessStateChanged { pid, old_state, new_state } => {
            format!("ProcessStateChanged pid={pid} {old_state}->{new_state}")
        }
        EventKind::ProcessGroupChanged { pid, old_pgid, new_pgid } => {
            format!("ProcessGroupChanged pid={pid} pgid={old_pgid}->{new_pgid}")
        }
        EventKind::ProcessSessionChanged { pid, old_sid, new_sid, old_pgid, new_pgid } => format!(
            "ProcessSessionChanged pid={pid} sid={old_sid}->{new_sid} pgid={old_pgid}->{new_pgid}"
        ),
        EventKind::ThreadCreated { tid, task_id } => {
            format!("ThreadCreated tid={tid} task={task_id}")
        }
        EventKind::ThreadClearChildTidChanged { tid, clear_child_tid } => {
            format!("ThreadClearChildTidChanged tid={tid} clear_child_tid={clear_child_tid:?}")
        }
        EventKind::ThreadRobustListChanged { tid, head, len } => {
            format!("ThreadRobustListChanged tid={tid} head={head:?} len={len}")
        }
        EventKind::ThreadGroupCreated { tgid } => {
            format!("ThreadGroupCreated tgid={tgid}")
        }
        EventKind::FdTableCreated { shared } => {
            format!("FdTableCreated shared={shared}")
        }
        EventKind::CredentialCreated { uid, gid } => {
            format!("CredentialCreated uid={uid} gid={gid}")
        }
        EventKind::CredentialTransition { from_id } => {
            format!("CredentialTransition from_id={from_id}")
        }
        _ => return None,
    };
    Some(summary)
}
