use alloc::{boxed::Box, format, string::ToString};

use super::*;

pub(super) fn apply_lifecycle_command(
    graph: &mut SemanticGraph,
    command: SemanticCommand,
) -> ApplyDispatch {
    let applied = match command {
        SemanticCommand::ResumeActivation {
            resume,
            scheduler_decision,
            scheduler_decision_generation,
            activation,
            activation_generation,
            note,
        } => graph.resume_activation_with_id(
            resume,
            scheduler_decision,
            scheduler_decision_generation,
            activation,
            activation_generation,
            &note,
        ),
        SemanticCommand::RecordPreemptionLatencySample {
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
            note,
        } => graph.record_preemption_latency_sample_with_id(
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
            &note,
        ),
        SemanticCommand::BlockActivationOnWait {
            activation_wait,
            activation,
            activation_generation,
            wait,
            kind,
            blockers,
            deadline,
            restart_policy,
            note,
        } => graph.block_activation_on_wait_with_id(
            activation_wait,
            activation,
            activation_generation,
            wait,
            kind,
            blockers,
            deadline,
            restart_policy,
            &note,
        ),
        SemanticCommand::CancelActivationWait {
            activation_wait,
            activation_wait_generation,
            wait_generation,
            errno,
            reason,
            note,
        } => graph.cancel_activation_wait(
            activation_wait,
            activation_wait_generation,
            wait_generation,
            errno,
            reason,
            &note,
        ),
        SemanticCommand::CleanupActivationForStoreFault {
            cleanup,
            store,
            store_generation,
            activation,
            activation_generation,
            wait,
            wait_generation,
            reason,
            note,
        } => graph.cleanup_activation_for_store_fault_with_id(
            cleanup,
            store,
            store_generation,
            activation,
            activation_generation,
            wait,
            wait_generation,
            &reason,
            &note,
        ),
        SemanticCommand::GrantCapability {
            subject,
            debug_object_label,
            object_ref,
            operations,
            lifetime,
            owner_store,
            owner_store_generation,
            owner_task,
            source,
            manifest_decl,
        } => {
            let operations = operations.iter().map(String::as_str).collect::<Vec<_>>();
            let cap = graph.domains.capability.capabilities.grant_with_authority_ref(
                &subject,
                &debug_object_label,
                object_ref,
                &operations,
                &lifetime,
                owner_store,
                owner_store_generation,
                owner_task,
                &source,
                manifest_decl,
            );
            let Ok(cap) = cap else {
                return ApplyDispatch::Applied(false);
            };
            graph.event_log.push("command", EventKind::CapabilityGranted { cap });
            true
        }
        SemanticCommand::RevokeCapability { cap } => {
            let changed = graph.domains.capability.capabilities.revoke(cap);
            if changed {
                graph.event_log.push("command", EventKind::CapabilityRevoked { cap });
            }
            changed
        }
        SemanticCommand::CreateWait {
            wait,
            owner_task,
            owner_store,
            owner_store_generation,
            kind,
            generation,
            blockers,
            deadline,
            restart_policy,
            saved_context,
        } => {
            graph.record_wait_created_with_details(
                wait,
                owner_task,
                owner_store,
                owner_store_generation,
                kind,
                generation,
                blockers,
                deadline,
                restart_policy,
                saved_context,
            );
            true
        }
        SemanticCommand::ResolveWait { wait, reason } => {
            graph.record_wait_resolved(wait, &reason);
            true
        }
        SemanticCommand::CancelWait { wait, errno, reason } => {
            graph.record_wait_cancelled_with_reason(wait, errno, reason);
            true
        }
        SemanticCommand::RecordTrap { store, task, trap, detail } => {
            graph.event_log.push(
                "command",
                EventKind::FaultClassified { trap, class: trap.fault_class(), store, task, detail },
            );
            true
        }
        SemanticCommand::BeginCleanup { cleanup, store, generation, reason } => {
            graph.domains.lifecycle.next_transaction_id =
                graph.domains.lifecycle.next_transaction_id.max(cleanup + 1);
            graph.domains.lifecycle.transactions.push(SemanticTransactionRecord {
                id: cleanup,
                label: format!("cleanup:{reason}"),
                store: Some(store),
                task: None,
                state: TransactionState::Begun,
                generation,
            });
            graph.event_log.push(
                "command",
                EventKind::TransactionBegan {
                    transaction: cleanup,
                    store: Some(store),
                    task: None,
                    label: format!("cleanup:{reason}"),
                },
            );
            true
        }
        SemanticCommand::ApplyCleanupStep { cleanup, step, target, observed_generation } => {
            graph.event_log.push(
                "command",
                EventKind::CleanupStepApplied {
                    cleanup,
                    step: step.as_str().to_string(),
                    target: target.summary(),
                    observed_generation,
                },
            );
            true
        }
        SemanticCommand::CommitCleanup { cleanup } => {
            let before = graph.event_count();
            graph.commit_transaction(cleanup);
            graph.event_count() != before
        }
        other => return ApplyDispatch::Next(Box::new(other)),
    };
    ApplyDispatch::Applied(applied)
}
