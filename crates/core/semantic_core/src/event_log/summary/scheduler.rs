use alloc::{
    format,
    string::{String, ToString},
};

use super::super::{super::*, kind::EventKind};

pub(super) fn summary(kind: &EventKind) -> Option<String> {
    let summary = match kind {
        EventKind::HartRegistered { hart, hardware_id, label, boot, generation } => format!(
            "HartRegistered hart={hart} hardware_id={hardware_id} label={label} boot={boot} generation={generation}"
        ),
        EventKind::HartStateChanged { hart, from, to, reason, generation } => format!(
            "HartStateChanged hart={hart} from={} to={} reason={reason} generation={generation}",
            from.as_str(),
            to.as_str()
        ),
        EventKind::HartCurrentActivationBound {
            hart,
            from,
            activation,
            activation_generation,
            generation,
        } => format!(
            "HartCurrentActivationBound hart={hart} from={} activation={activation}@{activation_generation} generation={generation}",
            from.as_str()
        ),
        EventKind::HartCurrentActivationCleared {
            hart,
            activation,
            activation_generation,
            reason,
            generation,
        } => format!(
            "HartCurrentActivationCleared hart={hart} activation={activation}@{activation_generation} reason={reason} generation={generation}"
        ),
        EventKind::TaskCreated { task, frontend } => {
            format!("TaskCreated task={task} frontend={}", frontend.as_str())
        }
        EventKind::TaskStateChanged { task, from, to } => {
            format!("TaskStateChanged task={task} {}->{}", from.as_str(), to.as_str())
        }
        EventKind::RuntimeActivationCreated { activation, task, generation } => format!(
            "RuntimeActivationCreated activation={activation} task={task} generation={generation}"
        ),
        EventKind::RuntimeActivationStateChanged { activation, from, to, generation } => format!(
            "RuntimeActivationStateChanged activation={activation} {}->{} generation={generation}",
            from.as_str(),
            to.as_str()
        ),
        EventKind::RunnableQueueCreated { queue, label, generation } => {
            format!("RunnableQueueCreated queue={queue} label={label} generation={generation}")
        }
        EventKind::RunnableQueueOwnerBound { queue, hart, hart_generation, generation, note } => {
            format!(
                "RunnableQueueOwnerBound queue={queue} hart={hart}@{hart_generation} generation={generation} note={note}"
            )
        }
        EventKind::RunnableQueued { queue, activation, activation_generation } => {
            format!("RunnableQueued queue={queue} activation={activation}@{activation_generation}")
        }
        EventKind::RunnableDequeued { queue, activation, activation_generation } => format!(
            "RunnableDequeued queue={queue} activation={activation}@{activation_generation}"
        ),
        EventKind::ActivationContextCreated {
            context,
            activation,
            activation_generation,
            generation,
        } => format!(
            "ActivationContextCreated context={context} activation={activation}@{activation_generation} generation={generation}"
        ),
        EventKind::ActivationContextVectorStateUpdated {
            context,
            context_generation_before,
            context_generation_after,
            vector_state,
            vector_status,
            generation,
        } => format!(
            "ActivationContextVectorStateUpdated context={context}@{context_generation_before}->{context_generation_after} vector_state={} vector_status={} generation={generation}",
            vector_state.map(ContractObjectRef::summary).unwrap_or_else(|| "none".to_string()),
            vector_status.as_str()
        ),
        EventKind::LazyVectorStateEnabled {
            context,
            context_generation_before,
            context_generation_after,
            vector_state,
            generation,
        } => format!(
            "LazyVectorStateEnabled context={context}@{context_generation_before}->{context_generation_after} vector_state={} vector_status=dirty generation={generation}",
            vector_state.summary()
        ),
        EventKind::SavedContextCaptured {
            saved_context,
            context,
            context_generation,
            activation,
            activation_generation,
            reason,
            generation,
        } => format!(
            "SavedContextCaptured saved_context={saved_context} context={context}@{context_generation} activation={activation}@{activation_generation} reason={} generation={generation}",
            reason.as_str()
        ),
        EventKind::DirtyVectorStateSavedOnPreempt {
            saved_context,
            saved_context_generation,
            context,
            context_generation_before,
            context_generation_after,
            preemption,
            preemption_generation,
            vector_state,
            generation,
        } => format!(
            "DirtyVectorStateSavedOnPreempt saved_context={saved_context}@{saved_context_generation} context={context}@{context_generation_before}->{context_generation_after} preemption={preemption}@{preemption_generation} vector_state={} vector_status=clean generation={generation}",
            vector_state.summary()
        ),
        EventKind::VectorStateRestoredOnResume {
            resume,
            resume_generation,
            context,
            context_generation,
            saved_context,
            saved_context_generation,
            saved_vector_state,
            restored_vector_state,
            generation,
        } => format!(
            "VectorStateRestoredOnResume resume={resume}@{resume_generation} context={context}@{context_generation} saved_context={saved_context}@{saved_context_generation} saved_vector_state={} restored_vector_state={} vector_status=clean generation={generation}",
            saved_vector_state.summary(),
            restored_vector_state.summary()
        ),
        EventKind::VectorStateReleasedOnResume {
            resume,
            resume_generation,
            vector_state,
            restored_vector_state,
            generation,
        } => format!(
            "VectorStateReleasedOnResume resume={resume}@{resume_generation} vector_state={} restored_vector_state={} vector_status=dropped generation={generation}",
            vector_state.summary(),
            restored_vector_state.summary()
        ),
        EventKind::TimerInterruptRecorded {
            interrupt,
            timer_epoch,
            hart,
            hart_generation,
            hardware_hart,
            target_activation,
            target_activation_generation,
            generation,
        } => format!(
            "TimerInterruptRecorded interrupt={interrupt} epoch={timer_epoch} hart={hart}@{hart_generation} hardware_id={hardware_hart} target={}@{} generation={generation}",
            target_activation
                .map(|activation| activation.to_string())
                .unwrap_or_else(|| "none".to_string()),
            target_activation_generation
                .map(|generation| generation.to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
        EventKind::IpiEventRecorded {
            ipi,
            source_hart,
            source_hart_generation,
            target_hart,
            target_hart_generation,
            kind,
            generation,
        } => format!(
            "IpiEventRecorded ipi={ipi} kind={} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation} generation={generation}",
            kind.as_str()
        ),
        EventKind::RemoteActivationPreempted {
            remote_preempt,
            ipi,
            ipi_generation,
            source_hart,
            source_hart_generation,
            target_hart,
            target_hart_generation_before,
            target_hart_generation_after,
            activation,
            from_generation,
            to_generation,
            queue,
            queue_generation,
            generation,
        } => format!(
            "RemoteActivationPreempted remote_preempt={remote_preempt} ipi={ipi}@{ipi_generation} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation_before}->{target_hart_generation_after} activation={activation}@{from_generation}->{to_generation} queue={queue}@{queue_generation} generation={generation}"
        ),
        EventKind::RemoteHartParked {
            remote_park,
            ipi,
            ipi_generation,
            source_hart,
            source_hart_generation,
            target_hart,
            target_hart_generation_before,
            target_hart_generation_after,
            reason,
            generation,
        } => format!(
            "RemoteHartParked remote_park={remote_park} ipi={ipi}@{ipi_generation} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation_before}->{target_hart_generation_after} reason={reason} generation={generation}"
        ),
        EventKind::RuntimeActivationPreempted {
            preemption,
            activation,
            from_generation,
            to_generation,
            timer_interrupt,
            timer_interrupt_generation,
            queue,
            queue_generation,
            generation,
        } => format!(
            "RuntimeActivationPreempted preemption={preemption} activation={activation}@{from_generation}->{to_generation} timer={timer_interrupt}@{timer_interrupt_generation} queue={queue}@{queue_generation} generation={generation}",
        ),
        EventKind::SchedulerDecisionRecorded {
            decision,
            queue,
            queue_generation,
            activation,
            activation_generation,
            generation,
        } => format!(
            "SchedulerDecisionRecorded decision={decision} queue={queue}@{queue_generation} activation={activation}@{activation_generation} generation={generation}"
        ),
        EventKind::CrossHartSchedulerDecisionRecorded {
            cross_decision,
            scheduler_decision,
            scheduler_decision_generation,
            deciding_hart,
            deciding_hart_generation,
            target_hart,
            target_hart_generation,
            queue,
            queue_generation,
            activation,
            activation_generation,
            generation,
        } => format!(
            "CrossHartSchedulerDecisionRecorded cross_decision={cross_decision} decision={scheduler_decision}@{scheduler_decision_generation} deciding_hart={deciding_hart}@{deciding_hart_generation} target_hart={target_hart}@{target_hart_generation} queue={queue}@{queue_generation} activation={activation}@{activation_generation} generation={generation}"
        ),
        EventKind::ActivationMigrated {
            migration,
            activation,
            from_generation,
            to_generation,
            source_hart,
            source_hart_generation,
            target_hart,
            target_hart_generation,
            source_queue,
            source_queue_generation,
            target_queue,
            target_queue_generation,
            generation,
        } => format!(
            "ActivationMigrated migration={migration} activation={activation}@{from_generation}->{to_generation} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation} source_queue={source_queue}@{source_queue_generation} target_queue={target_queue}@{target_queue_generation} generation={generation}"
        ),
        EventKind::VectorStateMigratedAcrossHart {
            migration,
            migration_generation,
            context,
            context_generation,
            source_vector_state,
            migrated_vector_state,
            generation,
        } => format!(
            "VectorStateMigratedAcrossHart migration={migration}@{migration_generation} context={context}@{context_generation} source_vector_state={} migrated_vector_state={} vector_status=clean generation={generation}",
            source_vector_state.summary(),
            migrated_vector_state.summary()
        ),
        EventKind::SmpSafePointRecorded {
            safe_point,
            coordinator_hart,
            coordinator_hart_generation,
            participant_count,
            generation,
        } => format!(
            "SmpSafePointRecorded safe_point={safe_point} coordinator_hart={coordinator_hart}@{coordinator_hart_generation} participants={participant_count} generation={generation}"
        ),
        EventKind::StopTheWorldRendezvousCompleted {
            rendezvous,
            epoch,
            safe_point,
            safe_point_generation,
            coordinator_hart,
            coordinator_hart_generation,
            participant_count,
            generation,
        } => format!(
            "StopTheWorldRendezvousCompleted rendezvous={rendezvous} epoch={epoch} safe_point={safe_point}@{safe_point_generation} coordinator_hart={coordinator_hart}@{coordinator_hart_generation} participants={participant_count} generation={generation}"
        ),
        EventKind::SmpCodePublishBarrierValidated {
            barrier,
            rendezvous,
            rendezvous_generation,
            code_publish_epoch_before,
            code_publish_epoch_after,
            participant_count,
            generation,
        } => format!(
            "SmpCodePublishBarrierValidated barrier={barrier} rendezvous={rendezvous}@{rendezvous_generation} code_publish_epoch={code_publish_epoch_before}->{code_publish_epoch_after} participants={participant_count} generation={generation}"
        ),
        EventKind::SmpCleanupQuiescenceValidated {
            quiescence,
            cleanup,
            cleanup_generation,
            store,
            target_store_generation,
            result_store_generation,
            rendezvous,
            rendezvous_generation,
            participant_count,
            generation,
        } => format!(
            "SmpCleanupQuiescenceValidated quiescence={quiescence} cleanup={cleanup}@{cleanup_generation} store={store}@{target_store_generation}->{result_store_generation} rendezvous={rendezvous}@{rendezvous_generation} participants={participant_count} generation={generation}"
        ),
        EventKind::SmpSnapshotBarrierValidated {
            barrier,
            rendezvous,
            rendezvous_generation,
            event_log_cursor,
            participant_count,
            generation,
        } => format!(
            "SmpSnapshotBarrierValidated barrier={barrier} rendezvous={rendezvous}@{rendezvous_generation} cursor={event_log_cursor} participants={participant_count} generation={generation}"
        ),
        EventKind::SmpStressRunRecorded {
            run,
            scenario,
            iterations,
            hart_count,
            safe_point_count,
            rendezvous_count,
            property_failures,
            generation,
        } => format!(
            "SmpStressRunRecorded run={run} scenario={scenario} iterations={iterations} harts={hart_count} safe_points={safe_point_count} rendezvous={rendezvous_count} property_failures={property_failures} generation={generation}"
        ),
        EventKind::SmpScalingBenchmarkRecorded {
            benchmark,
            stress_run,
            stress_run_generation,
            hart_count,
            workload_units,
            measured_smp_nanos,
            budget_nanos,
            speedup_milli,
            efficiency_milli,
            generation,
        } => format!(
            "SmpScalingBenchmarkRecorded benchmark={benchmark} stress_run={stress_run}@{stress_run_generation} harts={hart_count} workload_units={workload_units} measured_nanos={measured_smp_nanos} budget_nanos={budget_nanos} speedup_milli={speedup_milli} efficiency_milli={efficiency_milli} generation={generation}"
        ),
        _ => return None,
    };
    Some(summary)
}
