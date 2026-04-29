use alloc::{
    format,
    string::{String, ToString},
};

use super::{super::*, kind::EventKind};

impl EventKind {
    pub fn summary(&self) -> String {
        match self {
            Self::HartRegistered { hart, hardware_id, label, boot, generation } => format!(
                "HartRegistered hart={hart} hardware_id={hardware_id} label={label} boot={boot} generation={generation}"
            ),
            Self::HartStateChanged { hart, from, to, reason, generation } => format!(
                "HartStateChanged hart={hart} from={} to={} reason={reason} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::HartCurrentActivationBound {
                hart,
                from,
                activation,
                activation_generation,
                generation,
            } => format!(
                "HartCurrentActivationBound hart={hart} from={} activation={activation}@{activation_generation} generation={generation}",
                from.as_str()
            ),
            Self::HartCurrentActivationCleared {
                hart,
                activation,
                activation_generation,
                reason,
                generation,
            } => format!(
                "HartCurrentActivationCleared hart={hart} activation={activation}@{activation_generation} reason={reason} generation={generation}"
            ),
            Self::TaskCreated { task, frontend } => {
                format!("TaskCreated task={task} frontend={}", frontend.as_str())
            }
            Self::TaskStateChanged { task, from, to } => {
                format!("TaskStateChanged task={task} {}->{}", from.as_str(), to.as_str())
            }
            Self::RuntimeActivationCreated { activation, task, generation } => format!(
                "RuntimeActivationCreated activation={activation} task={task} generation={generation}"
            ),
            Self::RuntimeActivationStateChanged { activation, from, to, generation } => format!(
                "RuntimeActivationStateChanged activation={activation} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::RunnableQueueCreated { queue, label, generation } => {
                format!("RunnableQueueCreated queue={queue} label={label} generation={generation}")
            }
            Self::RunnableQueueOwnerBound { queue, hart, hart_generation, generation, note } => {
                format!(
                    "RunnableQueueOwnerBound queue={queue} hart={hart}@{hart_generation} generation={generation} note={note}"
                )
            }
            Self::RunnableQueued { queue, activation, activation_generation } => format!(
                "RunnableQueued queue={queue} activation={activation}@{activation_generation}"
            ),
            Self::RunnableDequeued { queue, activation, activation_generation } => format!(
                "RunnableDequeued queue={queue} activation={activation}@{activation_generation}"
            ),
            Self::ActivationContextCreated {
                context,
                activation,
                activation_generation,
                generation,
            } => format!(
                "ActivationContextCreated context={context} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::ActivationContextVectorStateUpdated {
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
            Self::LazyVectorStateEnabled {
                context,
                context_generation_before,
                context_generation_after,
                vector_state,
                generation,
            } => format!(
                "LazyVectorStateEnabled context={context}@{context_generation_before}->{context_generation_after} vector_state={} vector_status=dirty generation={generation}",
                vector_state.summary()
            ),
            Self::SavedContextCaptured {
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
            Self::DirtyVectorStateSavedOnPreempt {
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
            Self::VectorStateRestoredOnResume {
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
            Self::VectorStateReleasedOnResume {
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
            Self::TimerInterruptRecorded {
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
            Self::IpiEventRecorded {
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
            Self::RemoteActivationPreempted {
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
            Self::RemoteHartParked {
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
            Self::RuntimeActivationPreempted {
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
            Self::SchedulerDecisionRecorded {
                decision,
                queue,
                queue_generation,
                activation,
                activation_generation,
                generation,
            } => format!(
                "SchedulerDecisionRecorded decision={decision} queue={queue}@{queue_generation} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::CrossHartSchedulerDecisionRecorded {
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
            Self::ActivationMigrated {
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
            Self::VectorStateMigratedAcrossHart {
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
            Self::SmpSafePointRecorded {
                safe_point,
                coordinator_hart,
                coordinator_hart_generation,
                participant_count,
                generation,
            } => format!(
                "SmpSafePointRecorded safe_point={safe_point} coordinator_hart={coordinator_hart}@{coordinator_hart_generation} participants={participant_count} generation={generation}"
            ),
            Self::StopTheWorldRendezvousCompleted {
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
            Self::SmpCodePublishBarrierValidated {
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
            Self::SmpCleanupQuiescenceValidated {
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
            Self::SmpSnapshotBarrierValidated {
                barrier,
                rendezvous,
                rendezvous_generation,
                event_log_cursor,
                participant_count,
                generation,
            } => format!(
                "SmpSnapshotBarrierValidated barrier={barrier} rendezvous={rendezvous}@{rendezvous_generation} cursor={event_log_cursor} participants={participant_count} generation={generation}"
            ),
            Self::SmpStressRunRecorded {
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
            Self::SmpScalingBenchmarkRecorded {
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
            Self::IntegratedSmpPreemptionCleanupRecorded {
                scenario,
                integrated,
                stress_run,
                stress_run_generation,
                preemption,
                preemption_generation,
                remote_preempt,
                remote_preempt_generation,
                activation_cleanup,
                activation_cleanup_generation,
                smp_cleanup_quiescence,
                smp_cleanup_quiescence_generation,
                cleanup_store,
                target_store_generation,
                result_store_generation,
                hart_count,
                invariant_checks,
                generation,
            } => format!(
                "IntegratedSmpPreemptionCleanupRecorded integrated={integrated} scenario={scenario} stress_run={stress_run}@{stress_run_generation} preemption={preemption}@{preemption_generation} remote_preempt={remote_preempt}@{remote_preempt_generation} activation_cleanup={activation_cleanup}@{activation_cleanup_generation} smp_cleanup_quiescence={smp_cleanup_quiescence}@{smp_cleanup_quiescence_generation} cleanup_store={cleanup_store}@{target_store_generation}->{result_store_generation} harts={hart_count} invariant_checks={invariant_checks} generation={generation}"
            ),
            Self::IntegratedSmpNetworkFaultRecorded {
                scenario,
                integrated,
                network_driver_cleanup,
                network_driver_cleanup_generation,
                smp_stress_run,
                smp_stress_run_generation,
                remote_preempt,
                remote_preempt_generation,
                smp_cleanup_quiescence,
                smp_cleanup_quiescence_generation,
                driver_store,
                driver_store_generation,
                packet_device,
                packet_device_generation,
                hart_count,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                invariant_checks,
                generation,
            } => format!(
                "IntegratedSmpNetworkFaultRecorded integrated={integrated} scenario={scenario} cleanup={network_driver_cleanup}@{network_driver_cleanup_generation} stress_run={smp_stress_run}@{smp_stress_run_generation} remote_preempt={remote_preempt}@{remote_preempt_generation} smp_cleanup_quiescence={smp_cleanup_quiescence}@{smp_cleanup_quiescence_generation} driver_store={driver_store}@{driver_store_generation} packet_device={packet_device}@{packet_device_generation} harts={hart_count} cancelled_socket_waits={cancelled_socket_waits} revoked_packet_capabilities={revoked_packet_capabilities} invariant_checks={invariant_checks} generation={generation}"
            ),
            Self::IntegratedDiskPreemptFaultRecorded {
                scenario,
                integrated,
                preemption,
                preemption_generation,
                timer_interrupt,
                timer_interrupt_generation,
                block_pending_io_policy,
                block_pending_io_policy_generation,
                block_wait,
                block_wait_generation,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
                block_device,
                block_device_generation,
                action,
                errno,
                preempted_activation,
                preempted_activation_generation_after,
                invariant_checks,
                generation,
            } => format!(
                "IntegratedDiskPreemptFaultRecorded integrated={integrated} scenario={scenario} preemption={preemption}@{preemption_generation} timer_interrupt={timer_interrupt}@{timer_interrupt_generation} policy={block_pending_io_policy}@{block_pending_io_policy_generation} block_wait={block_wait}@{block_wait_generation} wait={wait}@{wait_generation} block_request={block_request}@{block_request_generation} block_device={block_device}@{block_device_generation} action={} errno={errno} activation={preempted_activation}@{preempted_activation_generation_after} invariant_checks={invariant_checks} generation={generation}",
                action.as_str()
            ),
            Self::IntegratedSimdMigrationRecorded {
                scenario,
                integrated,
                activation_migration,
                activation_migration_generation,
                target_feature_set,
                target_feature_set_generation,
                source_vector_state,
                migrated_vector_state,
                activation,
                activation_generation_before,
                activation_generation_after,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                simd_abi,
                invariant_checks,
                generation,
            } => format!(
                "IntegratedSimdMigrationRecorded integrated={integrated} scenario={scenario} migration={activation_migration}@{activation_migration_generation} target_feature_set={target_feature_set}@{target_feature_set_generation} source_vector_state={} migrated_vector_state={} activation={activation}@{activation_generation_before}->{activation_generation_after} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation} simd_abi={simd_abi} invariant_checks={invariant_checks} generation={generation}",
                source_vector_state.summary(),
                migrated_vector_state.summary()
            ),
            Self::IntegratedNetworkDiskIoRecorded {
                scenario,
                integrated,
                network_benchmark,
                network_benchmark_generation,
                block_benchmark,
                block_benchmark_generation,
                network_owner_store,
                network_owner_store_generation,
                packet_device,
                packet_device_generation,
                block_device,
                block_device_generation,
                network_sample_bytes,
                block_sample_bytes,
                concurrent_window_nanos,
                combined_throughput_bytes_per_sec,
                max_p99_latency_nanos,
                invariant_checks,
                generation,
            } => format!(
                "IntegratedNetworkDiskIoRecorded integrated={integrated} scenario={scenario} network_benchmark={network_benchmark}@{network_benchmark_generation} block_benchmark={block_benchmark}@{block_benchmark_generation} network_owner_store={network_owner_store}@{network_owner_store_generation} packet_device={packet_device}@{packet_device_generation} block_device={block_device}@{block_device_generation} network_bytes={network_sample_bytes} block_bytes={block_sample_bytes} window_nanos={concurrent_window_nanos} combined_throughput={combined_throughput_bytes_per_sec} max_p99_latency={max_p99_latency_nanos} invariant_checks={invariant_checks} generation={generation}"
            ),
            Self::IntegratedDisplaySchedulerLoadRecorded {
                scenario,
                integrated,
                framebuffer_benchmark,
                framebuffer_benchmark_generation,
                scheduler_decision,
                scheduler_decision_generation,
                owner_store,
                owner_store_generation,
                queue,
                queue_generation,
                selected_activation,
                selected_activation_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                sample_frames,
                sample_bytes,
                scheduler_load_units,
                display_measured_nanos,
                invariant_checks,
                generation,
            } => format!(
                "IntegratedDisplaySchedulerLoadRecorded integrated={integrated} scenario={scenario} framebuffer_benchmark={framebuffer_benchmark}@{framebuffer_benchmark_generation} scheduler_decision={scheduler_decision}@{scheduler_decision_generation} owner_store={owner_store}@{owner_store_generation} queue={queue}@{queue_generation} activation={selected_activation}@{selected_activation_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} sample_frames={sample_frames} sample_bytes={sample_bytes} scheduler_load_units={scheduler_load_units} display_measured_nanos={display_measured_nanos} invariant_checks={invariant_checks} generation={generation}"
            ),
            Self::IntegratedSnapshotIoLeaseBarrierRecorded {
                scenario,
                integrated,
                smp_snapshot_barrier,
                smp_snapshot_barrier_generation,
                io_cleanup,
                io_cleanup_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                released_dma_buffers,
                released_mmio_regions,
                released_irq_lines,
                released_framebuffer_window_leases,
                active_dmw_lease_count,
                in_flight_dma_count,
                active_framebuffer_window_lease_count,
                invariant_checks,
                generation,
            } => format!(
                "IntegratedSnapshotIoLeaseBarrierRecorded integrated={integrated} scenario={scenario} smp_snapshot_barrier={smp_snapshot_barrier}@{smp_snapshot_barrier_generation} io_cleanup={io_cleanup}@{io_cleanup_generation} display_snapshot_barrier={display_snapshot_barrier}@{display_snapshot_barrier_generation} released_dma_buffers={released_dma_buffers} released_mmio_regions={released_mmio_regions} released_irq_lines={released_irq_lines} released_framebuffer_window_leases={released_framebuffer_window_leases} active_dmw_leases={active_dmw_lease_count} in_flight_dma={in_flight_dma_count} active_framebuffer_window_leases={active_framebuffer_window_lease_count} invariant_checks={invariant_checks} generation={generation}"
            ),
            Self::IntegratedCodePublishSmpWorkloadRecorded {
                scenario,
                integrated,
                smp_stress_run,
                smp_stress_run_generation,
                smp_code_publish_barrier,
                smp_code_publish_barrier_generation,
                publish_rendezvous,
                publish_rendezvous_generation,
                publish_safe_point,
                publish_safe_point_generation,
                code_publish_epoch_before,
                code_publish_epoch_after,
                hart_count,
                workload_iterations,
                invariant_checks,
                generation,
            } => format!(
                "IntegratedCodePublishSmpWorkloadRecorded integrated={integrated} scenario={scenario} stress_run={smp_stress_run}@{smp_stress_run_generation} code_publish_barrier={smp_code_publish_barrier}@{smp_code_publish_barrier_generation} rendezvous={publish_rendezvous}@{publish_rendezvous_generation} safe_point={publish_safe_point}@{publish_safe_point_generation} code_publish_epoch={code_publish_epoch_before}->{code_publish_epoch_after} harts={hart_count} iterations={workload_iterations} invariant_checks={invariant_checks} generation={generation}"
            ),
            Self::IntegratedDisplayPanicRecorded {
                scenario,
                integrated,
                substrate_panic_event,
                display_panic_last_frame,
                display_panic_last_frame_generation,
                panic_ring_record_count,
                panic_ring_lost_count,
                jsonl_frame_count,
                contract_panic_summary_records,
                last_frame_summary_records,
                corrupt_record_count,
                truncated_record_count,
                invariant_checks,
                generation,
            } => format!(
                "IntegratedDisplayPanicRecorded integrated={integrated} scenario={scenario} substrate_panic_event={substrate_panic_event} display_panic_last_frame={display_panic_last_frame}@{display_panic_last_frame_generation} panic_ring_records={panic_ring_record_count} lost={panic_ring_lost_count} jsonl_frames={jsonl_frame_count} contract_panic_summary_records={contract_panic_summary_records} last_frame_summary_records={last_frame_summary_records} corrupt_records={corrupt_record_count} truncated_records={truncated_record_count} invariant_checks={invariant_checks} generation={generation}"
            ),
            Self::IntegratedOsctlTraceReplayRecorded {
                scenario,
                integrated,
                replay_event_cursor,
                integrated_scenario_count,
                replayed_root_count,
                stable_view_count,
                historical_edge_count,
                replay_fixture_count,
                contract_validation_ok,
                replay_validation_ok,
                graph_history_ok,
                roots_match_counts,
                invariant_checks,
                generation,
            } => format!(
                "IntegratedOsctlTraceReplayRecorded integrated={integrated} scenario={scenario} replay_event_cursor={replay_event_cursor} integrated_scenarios={integrated_scenario_count} replayed_roots={replayed_root_count} stable_views={stable_view_count} historical_edges={historical_edge_count} replay_fixtures={replay_fixture_count} contract_validation_ok={contract_validation_ok} replay_validation_ok={replay_validation_ok} graph_history_ok={graph_history_ok} roots_match_counts={roots_match_counts} invariant_checks={invariant_checks} generation={generation}"
            ),
            Self::DeviceObjectRecorded {
                device,
                resource,
                resource_generation,
                class,
                backend,
                generation,
            } => format!(
                "DeviceObjectRecorded device={device} resource={resource}@{resource_generation} class={class} backend={backend} generation={generation}"
            ),
            Self::QueueObjectRecorded {
                queue,
                device,
                device_generation,
                role,
                queue_index,
                depth,
                generation,
            } => format!(
                "QueueObjectRecorded queue={queue} device={device}@{device_generation} role={} index={queue_index} depth={depth} generation={generation}",
                role.as_str()
            ),
            Self::DescriptorObjectRecorded {
                descriptor,
                queue,
                queue_generation,
                slot,
                access,
                length,
                generation,
            } => format!(
                "DescriptorObjectRecorded descriptor={descriptor} queue={queue}@{queue_generation} slot={slot} access={} length={length} generation={generation}",
                access.as_str()
            ),
            Self::DmaBufferObjectRecorded {
                dma_buffer,
                descriptor,
                descriptor_generation,
                resource,
                resource_generation,
                access,
                length,
                generation,
            } => format!(
                "DmaBufferObjectRecorded dma_buffer={dma_buffer} descriptor={descriptor}@{descriptor_generation} resource={resource}@{resource_generation} access={} length={length} generation={generation}",
                access.as_str()
            ),
            Self::MmioRegionObjectRecorded {
                mmio_region,
                device,
                device_generation,
                resource,
                resource_generation,
                region_index,
                offset,
                length,
                access,
                generation,
            } => format!(
                "MmioRegionObjectRecorded mmio_region={mmio_region} device={device}@{device_generation} resource={resource}@{resource_generation} index={region_index} offset={offset} length={length} access={} generation={generation}",
                access.as_str()
            ),
            Self::IrqLineObjectRecorded {
                irq_line,
                device,
                device_generation,
                resource,
                resource_generation,
                irq_number,
                trigger,
                polarity,
                generation,
            } => format!(
                "IrqLineObjectRecorded irq_line={irq_line} device={device}@{device_generation} resource={resource}@{resource_generation} irq_number={irq_number} trigger={} polarity={} generation={generation}",
                trigger.as_str(),
                polarity.as_str()
            ),
            Self::IrqEventRecorded {
                irq_event,
                irq_line,
                irq_line_generation,
                device,
                device_generation,
                driver_store,
                driver_store_generation,
                irq_number,
                sequence,
                generation,
            } => format!(
                "IrqEventRecorded irq_event={irq_event} irq_line={irq_line}@{irq_line_generation} device={device}@{device_generation} driver_store={driver_store}@{driver_store_generation} irq_number={irq_number} sequence={sequence} generation={generation}"
            ),
            Self::DeviceCapabilityRecorded {
                device_capability,
                driver_store,
                driver_store_generation,
                target,
                class,
                operation,
                capability,
                capability_generation,
                handle_slot,
                handle_generation,
                generation,
            } => format!(
                "DeviceCapabilityRecorded device_capability={device_capability} driver_store={driver_store}@{driver_store_generation} target={} class={} operation={operation} capability={capability}@{capability_generation} handle_slot={handle_slot} handle_generation={handle_generation} generation={generation}",
                target.summary(),
                class.as_str()
            ),
            Self::DriverStoreBound {
                binding,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                device_capability,
                device_capability_generation,
                capability,
                capability_generation,
                generation,
            } => format!(
                "DriverStoreBound binding={binding} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} device_capability={device_capability}@{device_capability_generation} capability={capability}@{capability_generation} generation={generation}"
            ),
            Self::IoWaitCreated {
                io_wait,
                wait,
                wait_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                blocker,
                generation,
            } => format!(
                "IoWaitCreated io_wait={io_wait} wait={wait}@{wait_generation} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} blocker={} generation={generation}",
                blocker.summary()
            ),
            Self::IoWaitResolved {
                io_wait,
                wait,
                wait_generation,
                irq_event,
                irq_event_generation,
                generation,
            } => format!(
                "IoWaitResolved io_wait={io_wait} wait={wait}@{wait_generation} irq_event={irq_event}@{irq_event_generation} generation={generation}"
            ),
            Self::IoWaitCancelled { io_wait, wait, wait_generation, reason, generation } => {
                format!(
                    "IoWaitCancelled io_wait={io_wait} wait={wait}@{wait_generation} reason={} generation={generation}",
                    reason.as_str()
                )
            }
            Self::IoCleanupStarted {
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                generation,
            } => format!(
                "IoCleanupStarted cleanup={cleanup} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} generation={generation}"
            ),
            Self::IoCleanupCompleted {
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                cancelled_io_waits,
                revoked_device_capabilities,
                released_dma_buffers,
                released_mmio_regions,
                released_irq_lines,
                generation,
            } => format!(
                "IoCleanupCompleted cleanup={cleanup} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} cancelled_io_waits={cancelled_io_waits} revoked_device_capabilities={revoked_device_capabilities} released_dma_buffers={released_dma_buffers} released_mmio_regions={released_mmio_regions} released_irq_lines={released_irq_lines} generation={generation}"
            ),
            Self::IoFaultInjected {
                fault,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                target,
                cleanup,
                cleanup_generation,
                kind,
                generation,
            } => format!(
                "IoFaultInjected fault={fault} kind={} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} target={} cleanup={cleanup}@{cleanup_generation} generation={generation}",
                kind.as_str(),
                target.summary()
            ),
            Self::IoValidationReportRecorded {
                report,
                ok,
                violation_count,
                device_count,
                dma_buffer_count,
                irq_event_count,
                cleanup_count,
                fault_injection_count,
                generation,
            } => format!(
                "IoValidationReportRecorded report={report} ok={ok} violations={violation_count} devices={device_count} dma_buffers={dma_buffer_count} irq_events={irq_event_count} cleanups={cleanup_count} fault_injections={fault_injection_count} generation={generation}"
            ),
            Self::PacketDeviceObjectRecorded {
                packet_device,
                device,
                device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                frame_format_version,
                max_payload_len,
                generation,
            } => format!(
                "PacketDeviceObjectRecorded packet_device={packet_device} device={device}@{device_generation} mtu={mtu} rx_queue_depth={rx_queue_depth} tx_queue_depth={tx_queue_depth} frame_format_version={frame_format_version} max_payload_len={max_payload_len} generation={generation}"
            ),
            Self::BlockDeviceObjectRecorded {
                block_device,
                device,
                device_generation,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                generation,
            } => format!(
                "BlockDeviceObjectRecorded block_device={block_device} device={device}@{device_generation} sector_size={sector_size} sector_count={sector_count} read_only={read_only} max_transfer_sectors={max_transfer_sectors} generation={generation}"
            ),
            Self::BlockRangeObjectRecorded {
                block_range,
                block_device,
                block_device_generation,
                start_sector,
                sector_count,
                byte_offset,
                byte_len,
                generation,
            } => format!(
                "BlockRangeObjectRecorded block_range={block_range} block_device={block_device}@{block_device_generation} start_sector={start_sector} sector_count={sector_count} byte_offset={byte_offset} byte_len={byte_len} generation={generation}"
            ),
            Self::BlockRequestObjectRecorded {
                block_request,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                operation,
                sequence,
                byte_len,
                generation,
            } => format!(
                "BlockRequestObjectRecorded block_request={block_request} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} operation={} sequence={sequence} byte_len={byte_len} generation={generation}",
                operation.as_str()
            ),
            Self::BlockCompletionObjectRecorded {
                block_completion,
                block_request,
                block_request_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                sequence,
                completed_bytes,
                status,
                generation,
            } => format!(
                "BlockCompletionObjectRecorded block_completion={block_completion} block_request={block_request}@{block_request_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} sequence={sequence} completed_bytes={completed_bytes} status={} generation={generation}",
                status.as_str()
            ),
            Self::BlockWaitCreated {
                block_wait,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                operation,
                sequence,
                byte_len,
                generation,
            } => format!(
                "BlockWaitCreated block_wait={block_wait} wait={wait}@{wait_generation} block_request={block_request}@{block_request_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} operation={} sequence={sequence} byte_len={byte_len} generation={generation}",
                operation.as_str()
            ),
            Self::BlockWaitResolved {
                block_wait,
                wait,
                wait_generation,
                block_completion,
                block_completion_generation,
                generation,
            } => format!(
                "BlockWaitResolved block_wait={block_wait} wait={wait}@{wait_generation} block_completion={block_completion}@{block_completion_generation} generation={generation}"
            ),
            Self::BlockWaitCancelled { block_wait, wait, wait_generation, reason, generation } => {
                format!(
                    "BlockWaitCancelled block_wait={block_wait} wait={wait}@{wait_generation} reason={} generation={generation}",
                    reason.as_str()
                )
            }
            Self::BlockPendingIoPolicyApplied {
                policy,
                block_wait,
                block_wait_generation,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
                retry_request,
                retry_request_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                action,
                errno,
                retry_attempt,
                max_retries,
                generation,
            } => format!(
                "BlockPendingIoPolicyApplied policy={policy} block_wait={block_wait}@{block_wait_generation} wait={wait}@{wait_generation} block_request={block_request}@{block_request_generation} retry_request={} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} action={} errno={errno} retry_attempt={retry_attempt} max_retries={max_retries} generation={generation}",
                retry_request
                    .zip(*retry_request_generation)
                    .map(|(id, generation)| format!("{id}@{generation}"))
                    .unwrap_or_else(|| "none".to_string()),
                action.as_str()
            ),
            Self::BlockRequestGenerationAuditRecorded {
                audit,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                block_request,
                block_request_generation,
                backend,
                dma_buffer,
                rejected_completion_generation_probes,
                rejected_wait_generation_probes,
                rejected_dma_generation_probes,
                rejected_queue_generation_probes,
                generation,
            } => format!(
                "BlockRequestGenerationAuditRecorded audit={audit} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} block_request={block_request}@{block_request_generation} backend={}:{}@{} dma_buffer={}:{}@{} rejected_completion_generation_probes={rejected_completion_generation_probes} rejected_wait_generation_probes={rejected_wait_generation_probes} rejected_dma_generation_probes={rejected_dma_generation_probes} rejected_queue_generation_probes={rejected_queue_generation_probes} generation={generation}",
                backend.kind.as_str(),
                backend.id,
                backend.generation,
                dma_buffer.kind.as_str(),
                dma_buffer.id,
                dma_buffer.generation
            ),
            Self::BlockBenchmarkRecorded {
                benchmark,
                backend,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                read_path,
                read_path_generation,
                write_path,
                write_path_generation,
                request_queue,
                request_queue_generation,
                block_dma_buffer,
                block_dma_buffer_generation,
                sample_requests,
                sample_bytes,
                read_completed_requests,
                write_completed_requests,
                queue_completed_requests,
                measured_nanos,
                budget_nanos,
                iops,
                throughput_bytes_per_sec,
                p50_latency_nanos,
                p99_latency_nanos,
                generation,
            } => format!(
                "BlockBenchmarkRecorded benchmark={benchmark} backend={}:{}@{} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} read_path={read_path}@{read_path_generation} write_path={write_path}@{write_path_generation} request_queue={request_queue}@{request_queue_generation} block_dma_buffer={block_dma_buffer}@{block_dma_buffer_generation} sample_requests={sample_requests} sample_bytes={sample_bytes} read_completed_requests={read_completed_requests} write_completed_requests={write_completed_requests} queue_completed_requests={queue_completed_requests} measured_nanos={measured_nanos} budget_nanos={budget_nanos} iops={iops} throughput_bytes_per_sec={throughput_bytes_per_sec} p50_latency_nanos={p50_latency_nanos} p99_latency_nanos={p99_latency_nanos} generation={generation}",
                backend.kind.as_str(),
                backend.id,
                backend.generation
            ),
            Self::BlockRecoveryBenchmarkRecorded {
                benchmark,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                backend,
                block_device,
                block_device_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_block_waits,
                cancelled_wait_tokens,
                released_dma_buffers,
                revoked_device_capabilities,
                recovery_nanos,
                budget_nanos,
                generation,
            } => format!(
                "BlockRecoveryBenchmarkRecorded benchmark={benchmark} cleanup={cleanup}@{cleanup_generation} io_cleanup={io_cleanup}@{io_cleanup_generation} backend={}:{}@{} block_device={block_device}@{block_device_generation} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} recovery_start_event={recovery_start_event} recovery_complete_event={recovery_complete_event} cancelled_block_waits={cancelled_block_waits} cancelled_wait_tokens={cancelled_wait_tokens} released_dma_buffers={released_dma_buffers} revoked_device_capabilities={revoked_device_capabilities} recovery_nanos={recovery_nanos} budget_nanos={budget_nanos} generation={generation}",
                backend.kind.as_str(),
                backend.id,
                backend.generation
            ),
            Self::TargetFeatureSetDiscovered {
                feature_set,
                target_profile,
                target_arch,
                base_isa,
                simd_abi,
                simd_supported,
                vector_register_count,
                vector_register_bits,
                scalar_fallback,
                generation,
            } => format!(
                "TargetFeatureSetDiscovered feature_set={feature_set} target_profile={target_profile} target_arch={target_arch} base_isa={base_isa} simd_abi={simd_abi} simd_supported={simd_supported} vector_register_count={vector_register_count} vector_register_bits={vector_register_bits} scalar_fallback={scalar_fallback} generation={generation}"
            ),
            Self::VectorStateRecorded {
                vector_state,
                owner_activation,
                owner_store,
                code_object,
                target_feature_set,
                simd_abi,
                vector_register_count,
                vector_register_bits,
                register_bytes,
                state,
                generation,
            } => format!(
                "VectorStateRecorded vector_state={vector_state} activation={}:{}@{} store={}:{}@{} code_object={}:{}@{} target_feature_set={}:{}@{} simd_abi={simd_abi} vector_register_count={vector_register_count} vector_register_bits={vector_register_bits} register_bytes={register_bytes} state={} generation={generation}",
                owner_activation.kind.as_str(),
                owner_activation.id,
                owner_activation.generation,
                owner_store.kind.as_str(),
                owner_store.id,
                owner_store.generation,
                code_object.kind.as_str(),
                code_object.id,
                code_object.generation,
                target_feature_set.kind.as_str(),
                target_feature_set.id,
                target_feature_set.generation,
                state.as_str()
            ),
            Self::SimdFaultInjectionRecorded {
                injection,
                activation,
                code_object,
                trap,
                target_feature_set,
                vector_state,
                kind,
                effect,
                generation,
            } => format!(
                "SimdFaultInjectionRecorded injection={injection} activation={} code_object={} trap={} target_feature_set={} vector_state={} kind={} effect={} generation={generation}",
                activation.summary(),
                code_object.summary(),
                trap.summary(),
                target_feature_set.summary(),
                vector_state.map(|record| record.summary()).unwrap_or_else(|| "none".to_string()),
                kind.as_str(),
                effect.as_str()
            ),
            Self::SimdBenchmarkRecorded {
                benchmark,
                target_feature_set,
                scalar_code_object,
                vector_code_object,
                simd_abi,
                vector_register_count,
                vector_register_bits,
                workload_units,
                scalar_nanos,
                vector_nanos,
                speedup_milli,
                context_overhead_nanos,
                generation,
            } => format!(
                "SimdBenchmarkRecorded benchmark={benchmark} target_feature_set={} scalar_code_object={} vector_code_object={} simd_abi={simd_abi} vector_register_count={vector_register_count} vector_register_bits={vector_register_bits} workload_units={workload_units} scalar_nanos={scalar_nanos} vector_nanos={vector_nanos} speedup_milli={speedup_milli} context_overhead_nanos={context_overhead_nanos} generation={generation}",
                target_feature_set.summary(),
                scalar_code_object.summary(),
                vector_code_object.summary()
            ),
            Self::SimdContextSwitchBenchmarkRecorded {
                benchmark,
                preemption,
                activation_resume,
                saved_vector_state,
                restored_vector_state,
                target_feature_set,
                simd_abi,
                vector_register_count,
                vector_register_bits,
                sample_count,
                scalar_context_switch_nanos,
                vector_context_switch_nanos,
                overhead_nanos,
                budget_nanos,
                generation,
            } => format!(
                "SimdContextSwitchBenchmarkRecorded benchmark={benchmark} preemption={} activation_resume={} saved_vector_state={} restored_vector_state={} target_feature_set={} simd_abi={simd_abi} vector_register_count={vector_register_count} vector_register_bits={vector_register_bits} sample_count={sample_count} scalar_context_switch_nanos={scalar_context_switch_nanos} vector_context_switch_nanos={vector_context_switch_nanos} overhead_nanos={overhead_nanos} budget_nanos={budget_nanos} generation={generation}",
                preemption.summary(),
                activation_resume.summary(),
                saved_vector_state.summary(),
                restored_vector_state.summary(),
                target_feature_set.summary()
            ),
            Self::FramebufferObjectRecorded {
                framebuffer,
                resource,
                resource_generation,
                width,
                height,
                stride_bytes,
                pixel_format,
                byte_len,
                generation,
            } => format!(
                "FramebufferObjectRecorded framebuffer={framebuffer} resource={resource}@{resource_generation} width={width} height={height} stride_bytes={stride_bytes} pixel_format={pixel_format} byte_len={byte_len} generation={generation}"
            ),
            Self::DisplayObjectRecorded {
                display,
                framebuffer,
                framebuffer_generation,
                mode_name,
                width,
                height,
                refresh_millihz,
                generation,
            } => format!(
                "DisplayObjectRecorded display={display} framebuffer={framebuffer}@{framebuffer_generation} mode_name={mode_name} width={width} height={height} refresh_millihz={refresh_millihz} generation={generation}"
            ),
            Self::DisplayCapabilityRecorded {
                display_capability,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                capability,
                capability_generation,
                handle_slot,
                handle_generation,
                handle_tag,
                operations,
                state,
                generation,
            } => format!(
                "DisplayCapabilityRecorded display_capability={display_capability} owner_store={owner_store}@{owner_store_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} capability={capability}@{capability_generation} handle_slot={handle_slot} handle_generation={handle_generation} handle_tag={handle_tag} operations={} state={} generation={generation}",
                operations.join("|"),
                state.as_str()
            ),
            Self::FramebufferWindowLeaseRecorded {
                framebuffer_window_lease,
                owner_store,
                owner_store_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                access,
                state,
                generation,
            } => format!(
                "FramebufferWindowLeaseRecorded framebuffer_window_lease={framebuffer_window_lease} owner_store={owner_store}@{owner_store_generation} display_capability={display_capability}@{display_capability_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} window={x},{y} {width}x{height} byte_range={byte_offset}+{byte_len} access={access} state={} generation={generation}",
                state.as_str()
            ),
            Self::FramebufferMappingRecorded {
                framebuffer_mapping,
                owner_store,
                owner_store_generation,
                framebuffer_window_lease,
                framebuffer_window_lease_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                map_handle_slot,
                map_handle_generation,
                map_handle_tag,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                access,
                mode,
                state,
                generation,
            } => format!(
                "FramebufferMappingRecorded framebuffer_mapping={framebuffer_mapping} owner_store={owner_store}@{owner_store_generation} framebuffer_window_lease={framebuffer_window_lease}@{framebuffer_window_lease_generation} display_capability={display_capability}@{display_capability_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} map_handle_slot={map_handle_slot} map_handle_generation={map_handle_generation} map_handle_tag={map_handle_tag} window={x},{y} {width}x{height} byte_range={byte_offset}+{byte_len} access={access} mode={mode} state={} generation={generation}",
                state.as_str()
            ),
            Self::FramebufferWriteRecorded {
                framebuffer_write,
                owner_store,
                owner_store_generation,
                framebuffer_mapping,
                framebuffer_mapping_generation,
                framebuffer_window_lease,
                framebuffer_window_lease_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                map_handle_slot,
                map_handle_generation,
                map_handle_tag,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                pixel_format,
                payload_digest,
                state,
                generation,
            } => format!(
                "FramebufferWriteRecorded framebuffer_write={framebuffer_write} owner_store={owner_store}@{owner_store_generation} framebuffer_mapping={framebuffer_mapping}@{framebuffer_mapping_generation} framebuffer_window_lease={framebuffer_window_lease}@{framebuffer_window_lease_generation} display_capability={display_capability}@{display_capability_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} map_handle_slot={map_handle_slot} map_handle_generation={map_handle_generation} map_handle_tag={map_handle_tag} region={x},{y} {width}x{height} byte_range={byte_offset}+{byte_len} pixel_format={pixel_format} payload_digest={payload_digest} state={} generation={generation}",
                state.as_str()
            ),
            Self::FramebufferFlushRegionRecorded {
                framebuffer_flush_region,
                owner_store,
                owner_store_generation,
                framebuffer_write,
                framebuffer_write_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                pixel_format,
                payload_digest,
                state,
                generation,
            } => format!(
                "FramebufferFlushRegionRecorded framebuffer_flush_region={framebuffer_flush_region} owner_store={owner_store}@{owner_store_generation} framebuffer_write={framebuffer_write}@{framebuffer_write_generation} display_capability={display_capability}@{display_capability_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} region={x},{y} {width}x{height} byte_range={byte_offset}+{byte_len} pixel_format={pixel_format} payload_digest={payload_digest} state={} generation={generation}",
                state.as_str()
            ),
            Self::FramebufferDirtyRegionTracked {
                framebuffer_dirty_region,
                owner_store,
                owner_store_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                pixel_format,
                payload_digest,
                state,
                generation,
            } => format!(
                "FramebufferDirtyRegionTracked framebuffer_dirty_region={framebuffer_dirty_region} owner_store={owner_store}@{owner_store_generation} framebuffer_write={framebuffer_write}@{framebuffer_write_generation} framebuffer_flush_region={}:{} display_capability={display_capability}@{display_capability_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} region={x},{y} {width}x{height} byte_range={byte_offset}+{byte_len} pixel_format={pixel_format} payload_digest={payload_digest} state={} generation={generation}",
                framebuffer_flush_region
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                framebuffer_flush_region_generation
                    .map(|generation| generation.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                state.as_str()
            ),
            Self::DisplayEventLogRecorded {
                display_event_log,
                owner_store,
                owner_store_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                framebuffer_dirty_region,
                framebuffer_dirty_region_generation,
                first_event,
                last_event,
                event_count,
                flush_count,
                dirty_region_count,
                state,
                generation,
            } => format!(
                "DisplayEventLogRecorded display_event_log={display_event_log} owner_store={owner_store}@{owner_store_generation} display_capability={display_capability}@{display_capability_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} framebuffer_dirty_region={framebuffer_dirty_region}@{framebuffer_dirty_region_generation} events={first_event}..{last_event} event_count={event_count} flush_count={flush_count} dirty_region_count={dirty_region_count} state={} generation={generation}",
                state.as_str()
            ),
            Self::DisplayCleanupStarted {
                cleanup,
                owner_store,
                owner_store_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                generation,
            } => format!(
                "DisplayCleanupStarted cleanup={cleanup} owner_store={owner_store}@{owner_store_generation} display_capability={display_capability}@{display_capability_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} generation={generation}"
            ),
            Self::DisplayCleanupCompleted {
                cleanup,
                owner_store,
                owner_store_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                unmapped_framebuffer_mappings,
                released_framebuffer_window_leases,
                revoked_display_capabilities,
                generation,
            } => format!(
                "DisplayCleanupCompleted cleanup={cleanup} owner_store={owner_store}@{owner_store_generation} display_capability={display_capability}@{display_capability_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} unmapped_framebuffer_mappings={unmapped_framebuffer_mappings} released_framebuffer_window_leases={released_framebuffer_window_leases} revoked_display_capabilities={revoked_display_capabilities} generation={generation}"
            ),
            Self::DisplaySnapshotBarrierValidated {
                barrier,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                display_cleanup,
                display_cleanup_generation,
                active_framebuffer_window_lease_count,
                active_framebuffer_mapping_count,
                dirty_framebuffer_region_count,
                generation,
            } => format!(
                "DisplaySnapshotBarrierValidated barrier={barrier} owner_store={owner_store}@{owner_store_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} display_cleanup={}:{} active_framebuffer_window_leases={active_framebuffer_window_lease_count} active_framebuffer_mappings={active_framebuffer_mapping_count} dirty_framebuffer_regions={dirty_framebuffer_region_count} generation={generation}",
                display_cleanup.map(|id| id.to_string()).unwrap_or_else(|| "none".to_string()),
                display_cleanup_generation
                    .map(|generation| generation.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
            Self::DisplayPanicLastFrameRecorded {
                panic_last_frame,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                display_event_log,
                display_event_log_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                payload_digest,
                summary_digest,
                summary_record_bytes,
                panic_epoch,
                panic_cpu,
                panic_reason_code,
                raw_framebuffer_bytes_exported,
                generation,
            } => format!(
                "DisplayPanicLastFrameRecorded panic_last_frame={panic_last_frame} owner_store={owner_store}@{owner_store_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} barrier={display_snapshot_barrier}@{display_snapshot_barrier_generation} display_event_log={display_event_log}@{display_event_log_generation} framebuffer_write={framebuffer_write}@{framebuffer_write_generation} framebuffer_flush_region={framebuffer_flush_region}@{framebuffer_flush_region_generation} payload_digest={payload_digest} summary_digest={summary_digest} summary_record_bytes={summary_record_bytes} panic_epoch={panic_epoch} panic_cpu={panic_cpu} panic_reason_code={panic_reason_code} raw_framebuffer_bytes_exported={raw_framebuffer_bytes_exported} generation={generation}"
            ),
            Self::FramebufferBenchmarkRecorded {
                benchmark,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                display_capability,
                display_capability_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                display_event_log,
                display_event_log_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                sample_frames,
                sample_bytes,
                frame_area_pixels,
                write_nanos,
                flush_nanos,
                measured_nanos,
                budget_nanos,
                throughput_bytes_per_sec,
                flushes_per_sec_milli,
                p50_latency_nanos,
                p99_latency_nanos,
                generation,
            } => format!(
                "FramebufferBenchmarkRecorded benchmark={benchmark} owner_store={owner_store}@{owner_store_generation} display={display}@{display_generation} framebuffer={framebuffer}@{framebuffer_generation} display_capability={display_capability}@{display_capability_generation} framebuffer_write={framebuffer_write}@{framebuffer_write_generation} framebuffer_flush_region={framebuffer_flush_region}@{framebuffer_flush_region_generation} display_event_log={display_event_log}@{display_event_log_generation} display_snapshot_barrier={display_snapshot_barrier}@{display_snapshot_barrier_generation} sample_frames={sample_frames} sample_bytes={sample_bytes} frame_area_pixels={frame_area_pixels} write_nanos={write_nanos} flush_nanos={flush_nanos} measured_nanos={measured_nanos} budget_nanos={budget_nanos} throughput_bytes_per_sec={throughput_bytes_per_sec} flushes_per_sec_milli={flushes_per_sec_milli} p50_latency_nanos={p50_latency_nanos} p99_latency_nanos={p99_latency_nanos} generation={generation}"
            ),
            Self::FakeBlockBackendObjectBound {
                fake_block_backend,
                block_device,
                block_device_generation,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                deterministic_seed,
                generation,
            } => format!(
                "FakeBlockBackendObjectBound fake_block_backend={fake_block_backend} block_device={block_device}@{block_device_generation} sector_size={sector_size} sector_count={sector_count} read_only={read_only} max_transfer_sectors={max_transfer_sectors} deterministic_seed={deterministic_seed} generation={generation}"
            ),
            Self::VirtioBlkBackendSkeletonBound {
                virtio_blk_backend,
                block_device,
                block_device_generation,
                driver_binding,
                driver_binding_generation,
                device,
                device_generation,
                queue_size,
                request_queue_index,
                negotiated_features,
                generation,
            } => format!(
                "VirtioBlkBackendSkeletonBound virtio_blk_backend={virtio_blk_backend} block_device={block_device}@{block_device_generation} driver_binding={driver_binding}@{driver_binding_generation} device={device}@{device_generation} queue_size={queue_size} request_queue_index={request_queue_index} negotiated_features={negotiated_features} generation={generation}"
            ),
            Self::BlockReadPathRecorded {
                read_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                sequence,
                completed_bytes,
                data_digest,
                generation,
            } => format!(
                "BlockReadPathRecorded read_path={read_path} backend={} block_request={block_request}@{block_request_generation} block_completion={block_completion}@{block_completion_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} sequence={sequence} completed_bytes={completed_bytes} data_digest={data_digest} generation={generation}",
                backend.summary()
            ),
            Self::BlockWritePathRecorded {
                write_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                sequence,
                completed_bytes,
                payload_digest,
                generation,
            } => format!(
                "BlockWritePathRecorded write_path={write_path} backend={} block_request={block_request}@{block_request_generation} block_completion={block_completion}@{block_completion_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} sequence={sequence} completed_bytes={completed_bytes} payload_digest={payload_digest} generation={generation}",
                backend.summary()
            ),
            Self::BlockRequestQueueRecorded {
                queue,
                backend,
                block_device,
                block_device_generation,
                depth,
                request_count,
                pending_count,
                completed_count,
                first_sequence,
                last_sequence,
                generation,
            } => format!(
                "BlockRequestQueueRecorded queue={queue} backend={} block_device={block_device}@{block_device_generation} depth={depth} request_count={request_count} pending_count={pending_count} completed_count={completed_count} first_sequence={first_sequence} last_sequence={last_sequence} generation={generation}",
                backend.summary()
            ),
            Self::BlockDmaBufferBound {
                block_dma_buffer,
                backend,
                block_request,
                block_request_generation,
                dma_buffer,
                dma_buffer_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                descriptor,
                descriptor_generation,
                queue,
                queue_generation,
                operation,
                access,
                byte_len,
                buffer_len,
                buffer_digest,
                generation,
            } => format!(
                "BlockDmaBufferBound block_dma_buffer={block_dma_buffer} backend={} block_request={block_request}@{block_request_generation} dma_buffer={dma_buffer}@{dma_buffer_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} descriptor={descriptor}@{descriptor_generation} queue={queue}@{queue_generation} operation={} access={} byte_len={byte_len} buffer_len={buffer_len} buffer_digest={buffer_digest} generation={generation}",
                backend.summary(),
                operation.as_str(),
                access.as_str()
            ),
            Self::BlockPageObjectIntegrated {
                block_page_object,
                block_dma_buffer,
                block_dma_buffer_generation,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                dma_buffer,
                dma_buffer_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                aspace,
                vma_region,
                page,
                page_dirty_generation,
                page_offset,
                byte_len,
                operation,
                generation,
            } => format!(
                "BlockPageObjectIntegrated block_page_object={block_page_object} block_dma_buffer={block_dma_buffer}@{block_dma_buffer_generation} block_request={block_request}@{block_request_generation} block_completion={block_completion}@{block_completion_generation} dma_buffer={dma_buffer}@{dma_buffer_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} aspace={} vma_region={} page={} page_dirty_generation={page_dirty_generation} page_offset={page_offset} byte_len={byte_len} operation={} generation={generation}",
                aspace.summary(),
                vma_region.summary(),
                page.summary(),
                operation.as_str()
            ),
            Self::BufferCacheObjectRecorded {
                buffer_cache_object,
                block_page_object,
                block_page_object_generation,
                block_dma_buffer,
                block_dma_buffer_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                aspace,
                vma_region,
                page,
                page_dirty_generation,
                page_offset,
                block_offset,
                byte_len,
                operation,
                cache_state,
                coherency_epoch,
                generation,
            } => format!(
                "BufferCacheObjectRecorded buffer_cache_object={buffer_cache_object} block_page_object={block_page_object}@{block_page_object_generation} block_dma_buffer={block_dma_buffer}@{block_dma_buffer_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} aspace={} vma_region={} page={} page_dirty_generation={page_dirty_generation} page_offset={page_offset} block_offset={block_offset} byte_len={byte_len} operation={} cache_state={} coherency_epoch={coherency_epoch} generation={generation}",
                aspace.summary(),
                vma_region.summary(),
                page.summary(),
                operation.as_str(),
                cache_state.as_str()
            ),
            Self::FileObjectRecorded {
                file_object,
                buffer_cache_object,
                buffer_cache_object_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                page,
                page_dirty_generation,
                namespace,
                file_key,
                path,
                file_offset,
                byte_len,
                file_size,
                content_digest,
                cache_state,
                state,
                generation,
            } => format!(
                "FileObjectRecorded file_object={file_object} buffer_cache_object={buffer_cache_object}@{buffer_cache_object_generation} block_device={block_device}@{block_device_generation} block_range={block_range}@{block_range_generation} page={} page_dirty_generation={page_dirty_generation} namespace={namespace} file_key={file_key} path={path} file_offset={file_offset} byte_len={byte_len} file_size={file_size} content_digest={content_digest} cache_state={} state={} generation={generation}",
                page.summary(),
                cache_state.as_str(),
                state.as_str()
            ),
            Self::DirectoryObjectRecorded {
                directory_object,
                file_object,
                file_object_generation,
                namespace,
                directory_key,
                directory_path,
                entry_name,
                child_file_key,
                child_path,
                entry_kind,
                file_size,
                content_digest,
                state,
                generation,
            } => format!(
                "DirectoryObjectRecorded directory_object={directory_object} file_object={file_object}@{file_object_generation} namespace={namespace} directory_key={directory_key} directory_path={directory_path} entry_name={entry_name} child_file_key={child_file_key} child_path={child_path} entry_kind={} file_size={file_size} content_digest={content_digest} state={} generation={generation}",
                entry_kind.as_str(),
                state.as_str()
            ),
            Self::FatAdapterObjectRecorded {
                fat_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation,
                version,
                profile,
                volume_label,
                image_bytes,
                adapter_path,
                semantic_path,
                bytes_written,
                bytes_read,
                write_digest,
                read_digest,
                file_content_digest,
                state,
                generation,
            } => format!(
                "FatAdapterObjectRecorded fat_adapter_object={fat_adapter_object} directory_object={directory_object}@{directory_object_generation} file_object={file_object}@{file_object_generation} block_device={block_device}@{block_device_generation} implementation={implementation} version={version} profile={profile} volume_label={volume_label} image_bytes={image_bytes} adapter_path={adapter_path} semantic_path={semantic_path} bytes_written={bytes_written} bytes_read={bytes_read} write_digest={write_digest} read_digest={read_digest} file_content_digest={file_content_digest} state={} generation={generation}",
                state.as_str()
            ),
            Self::Ext4AdapterObjectRecorded {
                ext4_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation,
                version,
                profile,
                volume_label,
                image_bytes,
                adapter_path,
                semantic_path,
                bytes_read,
                read_digest,
                file_content_digest,
                directory_entries,
                read_only_enforced,
                state,
                generation,
            } => format!(
                "Ext4AdapterObjectRecorded ext4_adapter_object={ext4_adapter_object} directory_object={directory_object}@{directory_object_generation} file_object={file_object}@{file_object_generation} block_device={block_device}@{block_device_generation} implementation={implementation} version={version} profile={profile} volume_label={volume_label} image_bytes={image_bytes} adapter_path={adapter_path} semantic_path={semantic_path} bytes_read={bytes_read} read_digest={read_digest} file_content_digest={file_content_digest} directory_entries={directory_entries} read_only_enforced={read_only_enforced} state={} generation={generation}",
                state.as_str()
            ),
            Self::FileHandleCapabilityRecorded {
                file_handle_capability,
                owner_store,
                owner_store_generation,
                file_object,
                file_object_generation,
                directory_object,
                directory_object_generation,
                capability,
                capability_generation,
                handle_slot,
                handle_generation,
                handle_tag,
                operation,
                file_offset,
                byte_len,
                content_digest,
                state,
                generation,
            } => format!(
                "FileHandleCapabilityRecorded file_handle_capability={file_handle_capability} owner_store={owner_store}@{owner_store_generation} file_object={file_object}@{file_object_generation} directory_object={directory_object}@{directory_object_generation} capability={capability}@{capability_generation} handle_slot={handle_slot} handle_generation={handle_generation} handle_tag={handle_tag} operation={operation} file_offset={file_offset} byte_len={byte_len} content_digest={content_digest} state={} generation={generation}",
                state.as_str()
            ),
            Self::FsWaitCreated {
                fs_wait,
                wait,
                wait_generation,
                owner_store,
                owner_store_generation,
                file_object,
                file_object_generation,
                directory_object,
                directory_object_generation,
                file_handle_capability,
                file_handle_capability_generation,
                operation,
                blocker,
                sequence,
                byte_len,
                generation,
            } => format!(
                "FsWaitCreated fs_wait={fs_wait} wait={wait}@{wait_generation} owner_store={owner_store}@{owner_store_generation} file_object={file_object}@{file_object_generation} directory_object={directory_object}@{directory_object_generation} file_handle_capability={file_handle_capability}@{file_handle_capability_generation} operation={operation} blocker={} sequence={sequence} byte_len={byte_len} generation={generation}",
                blocker.summary()
            ),
            Self::FsWaitResolved { fs_wait, wait, wait_generation, generation } => format!(
                "FsWaitResolved fs_wait={fs_wait} wait={wait}@{wait_generation} generation={generation}"
            ),
            Self::FsWaitCancelled { fs_wait, wait, wait_generation, reason, generation } => {
                format!(
                    "FsWaitCancelled fs_wait={fs_wait} wait={wait}@{wait_generation} reason={} generation={generation}",
                    reason.as_str()
                )
            }
            Self::PacketBufferObjectRecorded {
                packet_buffer,
                packet_device,
                packet_device_generation,
                direction,
                frame_format_version,
                capacity,
                payload_len,
                sequence,
                state,
                generation,
            } => format!(
                "PacketBufferObjectRecorded packet_buffer={packet_buffer} packet_device={packet_device}@{packet_device_generation} direction={} frame_format_version={frame_format_version} capacity={capacity} payload_len={payload_len} sequence={sequence} state={} generation={generation}",
                direction.as_str(),
                state.as_str()
            ),
            Self::PacketQueueObjectRecorded {
                packet_queue,
                packet_device,
                packet_device_generation,
                role,
                queue_index,
                depth,
                generation,
            } => format!(
                "PacketQueueObjectRecorded packet_queue={packet_queue} packet_device={packet_device}@{packet_device_generation} role={} queue_index={queue_index} depth={depth} generation={generation}",
                role.as_str()
            ),
            Self::PacketDescriptorObjectRecorded {
                packet_descriptor,
                packet_queue,
                packet_queue_generation,
                packet_buffer,
                packet_buffer_generation,
                slot,
                length,
                generation,
            } => format!(
                "PacketDescriptorObjectRecorded packet_descriptor={packet_descriptor} packet_queue={packet_queue}@{packet_queue_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} slot={slot} length={length} generation={generation}"
            ),
            Self::FakeNetBackendObjectBound {
                fake_net_backend,
                packet_device,
                packet_device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                frame_format_version,
                max_payload_len,
                deterministic_seed,
                generation,
            } => format!(
                "FakeNetBackendObjectBound fake_net_backend={fake_net_backend} packet_device={packet_device}@{packet_device_generation} mtu={mtu} rx_queue_depth={rx_queue_depth} tx_queue_depth={tx_queue_depth} frame_format_version={frame_format_version} max_payload_len={max_payload_len} deterministic_seed={deterministic_seed} generation={generation}"
            ),
            Self::VirtioNetBackendSkeletonBound {
                virtio_net_backend,
                packet_device,
                packet_device_generation,
                driver_binding,
                driver_binding_generation,
                device,
                device_generation,
                queue_size,
                rx_queue_index,
                tx_queue_index,
                negotiated_features,
                generation,
            } => format!(
                "VirtioNetBackendSkeletonBound virtio_net_backend={virtio_net_backend} packet_device={packet_device}@{packet_device_generation} driver_binding={driver_binding}@{driver_binding_generation} device={device}@{device_generation} queue_size={queue_size} rx_queue_index={rx_queue_index} tx_queue_index={tx_queue_index} negotiated_features={negotiated_features} generation={generation}"
            ),
            Self::NetworkRxInterruptRecorded {
                rx_interrupt,
                virtio_net_backend,
                virtio_net_backend_generation,
                irq_event,
                irq_event_generation,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                ready_descriptors,
                sequence,
                generation,
            } => format!(
                "NetworkRxInterruptRecorded rx_interrupt={rx_interrupt} virtio_net_backend={virtio_net_backend}@{virtio_net_backend_generation} irq_event={irq_event}@{irq_event_generation} packet_device={packet_device}@{packet_device_generation} rx_queue={rx_queue}@{rx_queue_generation} ready_descriptors={ready_descriptors} sequence={sequence} generation={generation}"
            ),
            Self::NetworkRxWaitResolved {
                resolution,
                io_wait,
                io_wait_generation,
                wait,
                wait_generation,
                rx_interrupt,
                rx_interrupt_generation,
                rx_queue,
                rx_queue_generation,
                ready_descriptors,
                generation,
            } => format!(
                "NetworkRxWaitResolved resolution={resolution} io_wait={io_wait}@{io_wait_generation} wait={wait}@{wait_generation} rx_interrupt={rx_interrupt}@{rx_interrupt_generation} rx_queue={rx_queue}@{rx_queue_generation} ready_descriptors={ready_descriptors} generation={generation}"
            ),
            Self::NetworkTxCapabilityGateRecorded {
                tx_gate,
                driver_store,
                driver_store_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                device_capability,
                device_capability_generation,
                capability,
                capability_generation,
                handle_slot,
                handle_generation,
                handle_tag,
                byte_len,
                sequence,
                generation,
            } => format!(
                "NetworkTxCapabilityGateRecorded tx_gate={tx_gate} driver_store={driver_store}@{driver_store_generation} packet_device={packet_device}@{packet_device_generation} tx_queue={tx_queue}@{tx_queue_generation} packet_descriptor={packet_descriptor}@{packet_descriptor_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} device_capability={device_capability}@{device_capability_generation} capability={capability}@{capability_generation} handle_slot={handle_slot} handle_generation={handle_generation} handle_tag={handle_tag} byte_len={byte_len} sequence={sequence} generation={generation}"
            ),
            Self::NetworkTxCompleted {
                completion,
                tx_gate,
                tx_gate_generation,
                backend,
                driver_store,
                driver_store_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                byte_len,
                sequence,
                completion_sequence,
                generation,
            } => format!(
                "NetworkTxCompleted completion={completion} tx_gate={tx_gate}@{tx_gate_generation} backend={} driver_store={driver_store}@{driver_store_generation} packet_device={packet_device}@{packet_device_generation} tx_queue={tx_queue}@{tx_queue_generation} packet_descriptor={packet_descriptor}@{packet_descriptor_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} byte_len={byte_len} sequence={sequence} completion_sequence={completion_sequence} generation={generation}",
                backend.summary()
            ),
            Self::NetworkStackAdapterBound {
                adapter,
                implementation,
                implementation_version,
                profile,
                medium,
                backend,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                tx_queue,
                tx_queue_generation,
                mac,
                ipv4_addr,
                ipv4_prefix_len,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                max_payload_len,
                socket_capacity,
                generation,
            } => format!(
                "NetworkStackAdapterBound adapter={adapter} implementation={implementation} version={implementation_version} profile={profile} medium={medium} backend={} packet_device={packet_device}@{packet_device_generation} rx_queue={rx_queue}@{rx_queue_generation} tx_queue={tx_queue}@{tx_queue_generation} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ipv4={}.{}.{}.{}/{} mtu={mtu} rx_queue_depth={rx_queue_depth} tx_queue_depth={tx_queue_depth} max_payload_len={max_payload_len} socket_capacity={socket_capacity} generation={generation}",
                backend.summary(),
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5],
                ipv4_addr[0],
                ipv4_addr[1],
                ipv4_addr[2],
                ipv4_addr[3],
                ipv4_prefix_len
            ),
            Self::SocketObjectCreated {
                socket,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                domain,
                socket_type,
                protocol,
                canonical_protocol,
                family,
                transport,
                generation,
            } => format!(
                "SocketObjectCreated socket={socket} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} domain={domain} type={socket_type} protocol={protocol} canonical_protocol={canonical_protocol} family={family} transport={transport} generation={generation}"
            ),
            Self::EndpointObjectCreated {
                endpoint,
                socket,
                socket_generation,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                family,
                transport,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                generation,
            } => format!(
                "EndpointObjectCreated endpoint={endpoint} socket={socket}@{socket_generation} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} family={family} transport={transport} local={}.{}.{}.{}:{local_port} remote={}.{}.{}.{}:{remote_port} generation={generation}",
                local_addr[0],
                local_addr[1],
                local_addr[2],
                local_addr[3],
                remote_addr[0],
                remote_addr[1],
                remote_addr[2],
                remote_addr[3]
            ),
            Self::SocketOperationRecorded {
                operation_id,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                operation,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                backlog,
                byte_len,
                sequence,
                generation,
            } => format!(
                "SocketOperationRecorded operation_id={operation_id} operation={} endpoint={endpoint}@{endpoint_generation} socket={socket}@{socket_generation} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} local={}.{}.{}.{}:{local_port} remote={}.{}.{}.{}:{remote_port} backlog={backlog} byte_len={byte_len} sequence={sequence} generation={generation}",
                operation.as_str(),
                local_addr[0],
                local_addr[1],
                local_addr[2],
                local_addr[3],
                remote_addr[0],
                remote_addr[1],
                remote_addr[2],
                remote_addr[3]
            ),
            Self::SocketWaitCreated {
                socket_wait,
                wait,
                wait_generation,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                wait_kind,
                blocker,
                generation,
            } => format!(
                "SocketWaitCreated socket_wait={socket_wait} wait={wait}@{wait_generation} endpoint={endpoint}@{endpoint_generation} socket={socket}@{socket_generation} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} kind={} blocker={}:{}@{} generation={generation}",
                wait_kind.as_str(),
                blocker.kind.as_str(),
                blocker.id,
                blocker.generation
            ),
            Self::SocketWaitResolved {
                socket_wait,
                wait,
                wait_generation,
                ready_sequence,
                byte_len,
                generation,
            } => format!(
                "SocketWaitResolved socket_wait={socket_wait} wait={wait}@{wait_generation} ready_sequence={ready_sequence} byte_len={byte_len} generation={generation}"
            ),
            Self::SocketWaitCancelled {
                socket_wait,
                wait,
                wait_generation,
                reason,
                generation,
            } => format!(
                "SocketWaitCancelled socket_wait={socket_wait} wait={wait}@{wait_generation} reason={} generation={generation}",
                reason.as_str()
            ),
            Self::NetworkBackpressureRecorded {
                backpressure,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                owner_store,
                owner_store_generation,
                direction,
                reason,
                action,
                queue_depth,
                queue_limit,
                dropped_packets,
                dropped_bytes,
                sequence,
                generation,
            } => {
                let endpoint_summary = endpoint.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", endpoint_generation.unwrap_or(0)),
                );
                let socket_summary = socket.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", socket_generation.unwrap_or(0)),
                );
                let owner_store_summary = owner_store.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", owner_store_generation.unwrap_or(0)),
                );
                format!(
                    "NetworkBackpressureRecorded backpressure={backpressure} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} packet_queue={packet_queue}@{packet_queue_generation} endpoint={endpoint_summary} socket={socket_summary} owner_store={owner_store_summary} direction={} reason={} action={} queue_depth={queue_depth} queue_limit={queue_limit} dropped_packets={dropped_packets} dropped_bytes={dropped_bytes} sequence={sequence} generation={generation}",
                    direction.as_str(),
                    reason.as_str(),
                    action.as_str()
                )
            }
            Self::NetworkDriverCleanupStarted {
                cleanup,
                io_cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                packet_device,
                packet_device_generation,
                adapter,
                adapter_generation,
                backend,
                generation,
            } => format!(
                "NetworkDriverCleanupStarted cleanup={cleanup} io_cleanup={io_cleanup} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} packet_device={packet_device}@{packet_device_generation} adapter={adapter}@{adapter_generation} backend={}:{}@{} generation={generation}",
                backend.kind.as_str(),
                backend.id,
                backend.generation
            ),
            Self::NetworkDriverCleanupCompleted {
                cleanup,
                io_cleanup,
                io_cleanup_generation,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                generation,
            } => format!(
                "NetworkDriverCleanupCompleted cleanup={cleanup} io_cleanup={io_cleanup}@{io_cleanup_generation} cancelled_socket_waits={cancelled_socket_waits} revoked_packet_capabilities={revoked_packet_capabilities} generation={generation}"
            ),
            Self::BlockDriverCleanupStarted {
                cleanup,
                io_cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                block_device,
                block_device_generation,
                backend,
                generation,
            } => format!(
                "BlockDriverCleanupStarted cleanup={cleanup} io_cleanup={io_cleanup} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} block_device={block_device}@{block_device_generation} backend={}:{}@{} generation={generation}",
                backend.kind.as_str(),
                backend.id,
                backend.generation
            ),
            Self::BlockDriverCleanupCompleted {
                cleanup,
                io_cleanup,
                io_cleanup_generation,
                cancelled_block_waits,
                released_dma_buffers,
                revoked_device_capabilities,
                generation,
            } => format!(
                "BlockDriverCleanupCompleted cleanup={cleanup} io_cleanup={io_cleanup}@{io_cleanup_generation} cancelled_block_waits={cancelled_block_waits} released_dma_buffers={released_dma_buffers} revoked_device_capabilities={revoked_device_capabilities} generation={generation}"
            ),
            Self::NetworkGenerationAuditRecorded {
                audit,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                dma_buffer,
                device_capability,
                rejected_packet_generation_probes,
                rejected_dma_generation_probes,
                generation,
            } => format!(
                "NetworkGenerationAuditRecorded audit={audit} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} packet_queue={packet_queue}@{packet_queue_generation} packet_descriptor={packet_descriptor}@{packet_descriptor_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} dma_buffer={}:{}@{} device_capability={}:{}@{} rejected_packet_generation_probes={rejected_packet_generation_probes} rejected_dma_generation_probes={rejected_dma_generation_probes} generation={generation}",
                dma_buffer.kind.as_str(),
                dma_buffer.id,
                dma_buffer.generation,
                device_capability.kind.as_str(),
                device_capability.id,
                device_capability.generation
            ),
            Self::NetworkFaultInjectionRecorded {
                injection,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                owner_store,
                owner_store_generation,
                direction,
                kind,
                effect,
                injected_packets,
                dropped_packets,
                error_packets,
                error_code,
                sequence,
                generation,
            } => {
                let descriptor_summary = packet_descriptor.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", packet_descriptor_generation.unwrap_or(0)),
                );
                let buffer_summary = packet_buffer.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", packet_buffer_generation.unwrap_or(0)),
                );
                let endpoint_summary = endpoint.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", endpoint_generation.unwrap_or(0)),
                );
                let socket_summary = socket.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", socket_generation.unwrap_or(0)),
                );
                let owner_store_summary = owner_store.map_or_else(
                    || "none".to_string(),
                    |id| format!("{id}@{}", owner_store_generation.unwrap_or(0)),
                );
                format!(
                    "NetworkFaultInjectionRecorded injection={injection} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} packet_queue={packet_queue}@{packet_queue_generation} packet_descriptor={descriptor_summary} packet_buffer={buffer_summary} endpoint={endpoint_summary} socket={socket_summary} owner_store={owner_store_summary} direction={} kind={} effect={} injected_packets={injected_packets} dropped_packets={dropped_packets} error_packets={error_packets} error_code={error_code} sequence={sequence} generation={generation}",
                    direction.as_str(),
                    kind.as_str(),
                    effect.as_str()
                )
            }
            Self::NetworkBenchmarkRecorded {
                benchmark,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                tx_completion,
                tx_completion_generation,
                rx_wait_resolution,
                rx_wait_resolution_generation,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                owner_store,
                owner_store_generation,
                sample_packets,
                sample_bytes,
                tx_completed_packets,
                rx_resolved_packets,
                dropped_packets,
                measured_nanos,
                budget_nanos,
                throughput_bytes_per_sec,
                p50_latency_nanos,
                p99_latency_nanos,
                generation,
            } => format!(
                "NetworkBenchmarkRecorded benchmark={benchmark} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} tx_completion={tx_completion}@{tx_completion_generation} rx_wait_resolution={rx_wait_resolution}@{rx_wait_resolution_generation} endpoint={endpoint}@{endpoint_generation} socket={socket}@{socket_generation} owner_store={owner_store}@{owner_store_generation} sample_packets={sample_packets} sample_bytes={sample_bytes} tx_completed_packets={tx_completed_packets} rx_resolved_packets={rx_resolved_packets} dropped_packets={dropped_packets} measured_nanos={measured_nanos} budget_nanos={budget_nanos} throughput_bytes_per_sec={throughput_bytes_per_sec} p50_latency_nanos={p50_latency_nanos} p99_latency_nanos={p99_latency_nanos} generation={generation}",
            ),
            Self::NetworkRecoveryBenchmarkRecorded {
                benchmark,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                driver_store,
                driver_store_generation,
                fault_injection,
                fault_injection_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                recovery_nanos,
                budget_nanos,
                generation,
            } => {
                let fault_injection_summary = match (*fault_injection, *fault_injection_generation)
                {
                    (Some(injection), Some(injection_generation)) => {
                        format!("{injection}@{injection_generation}")
                    }
                    _ => "none".to_string(),
                };
                format!(
                    "NetworkRecoveryBenchmarkRecorded benchmark={benchmark} cleanup={cleanup}@{cleanup_generation} io_cleanup={io_cleanup}@{io_cleanup_generation} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} driver_store={driver_store}@{driver_store_generation} fault_injection={fault_injection_summary} recovery_start_event={recovery_start_event} recovery_complete_event={recovery_complete_event} cancelled_socket_waits={cancelled_socket_waits} revoked_packet_capabilities={revoked_packet_capabilities} recovery_nanos={recovery_nanos} budget_nanos={budget_nanos} generation={generation}"
                )
            }
            Self::RuntimeActivationResumed {
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
            Self::PreemptionLatencySampleRecorded {
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
            Self::RuntimeActivationWaitBlocked {
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
            Self::RuntimeActivationWaitCancelled {
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
            Self::RuntimeActivationCleanupStarted {
                cleanup,
                store,
                store_generation,
                activation,
                activation_generation,
                generation,
            } => format!(
                "RuntimeActivationCleanupStarted cleanup={cleanup} store={store}@{store_generation} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::RuntimeActivationCleanupCompleted {
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
            Self::ResourceCreated { resource, kind, generation } => format!(
                "ResourceCreated resource={resource} kind={} generation={generation}",
                kind.as_str()
            ),
            Self::ResourceClosed { resource, generation } => {
                format!("ResourceClosed resource={resource} generation={generation}")
            }
            Self::ResourceHandleValidated { resource, generation } => {
                format!("ResourceHandleValidated resource={resource} generation={generation}")
            }
            Self::ResourceHandleRejected { resource, expected, actual, reason } => match actual {
                Some(actual) => format!(
                    "ResourceHandleRejected resource={resource} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "ResourceHandleRejected resource={resource} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::AuthorityBound { authority, resource, kind, subject, object, generation } => {
                format!(
                    "AuthorityBound authority={authority} resource={resource} kind={} subject={subject} object={object} generation={generation}",
                    kind.as_str()
                )
            }
            Self::AuthorityReleased { authority, resource, generation, reason } => format!(
                "AuthorityReleased authority={authority} resource={resource} generation={generation} reason={reason}"
            ),
            Self::AuthorityRevoked { authority, resource, generation, reason } => format!(
                "AuthorityRevoked authority={authority} resource={resource} generation={generation} reason={reason}"
            ),
            Self::BoundaryPublished {
                boundary,
                name,
                kind,
                status,
                backend,
                blocked_by,
                generation,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "BoundaryPublished boundary={boundary} name={name} kind={} status={} backend={backend} blocked={blocked_by} generation={generation}",
                    kind.as_str(),
                    status.as_str()
                )
            }
            Self::ArtifactVerificationRecorded {
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
            Self::WaitCreated { wait, task, kind, generation } => format!(
                "WaitCreated wait={wait} task={task} kind={} generation={generation}",
                kind.as_str()
            ),
            Self::WaitPending { wait, generation } => {
                format!("WaitPending wait={wait} generation={generation}")
            }
            Self::WaitResolved { wait, reason } => {
                format!("WaitResolved wait={wait} reason={reason}")
            }
            Self::WaitConsumed { wait } => {
                format!("WaitConsumed wait={wait}")
            }
            Self::WaitCancelled { wait, errno, reason } => {
                format!("WaitCancelled wait={wait} errno={errno} reason={}", reason.as_str())
            }
            Self::WaitInterrupted { wait, reason } => {
                format!("WaitInterrupted wait={wait} reason={}", reason.as_str())
            }
            Self::WaitRestarted { wait, class } => {
                format!("WaitRestarted wait={wait} class={class}")
            }
            Self::WaitTokenValidated { wait, generation } => {
                format!("WaitTokenValidated wait={wait} generation={generation}")
            }
            Self::WaitTokenRejected { wait, expected, actual, reason } => match actual {
                Some(actual) => format!(
                    "WaitTokenRejected wait={wait} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "WaitTokenRejected wait={wait} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::CapabilityGranted { cap } => format!("CapabilityGranted cap={cap}"),
            Self::CapabilityRevoked { cap } => format!("CapabilityRevoked cap={cap}"),
            Self::CapabilityUsed { cap, subject, object, operation, generation } => format!(
                "CapabilityUsed cap={cap} subject={subject} object={object} op={operation} generation={generation}"
            ),
            Self::CapabilityDenied { subject, object, operation, reason } => format!(
                "CapabilityDenied subject={subject} object={object} op={operation} reason={}",
                reason.as_str()
            ),
            Self::CapabilityGenerationMismatch { subject, object, operation, expected, actual } => {
                match actual {
                    Some(actual) => format!(
                        "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual={actual}"
                    ),
                    None => format!(
                        "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual=missing"
                    ),
                }
            }
            Self::HostcallEntered { label, class, subject, object, operation } => format!(
                "HostcallEntered label={label} class={} subject={subject} object={object} op={operation}",
                class.as_str()
            ),
            Self::SubstrateUnsupported { authority, operation, requester, artifact, store } => {
                let requester = requester.as_deref().unwrap_or("none");
                let artifact = artifact
                    .map(|artifact| artifact.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let store =
                    store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
                format!(
                    "SubstrateUnsupported authority={authority} op={operation} requester={requester} artifact={artifact} store={store}"
                )
            }
            Self::SubstrateCapabilityDenied {
                authority,
                operation,
                requester,
                artifact,
                store,
                capability,
                capability_generation,
            } => {
                let requester = requester.as_deref().unwrap_or("none");
                let artifact = artifact
                    .map(|artifact| artifact.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let store =
                    store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
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
            Self::SubstratePanic {
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
                let artifact = artifact
                    .map(|artifact| artifact.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let store =
                    store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
                format!(
                    "SubstratePanic authority={authority} op={operation} requester={requester} artifact={artifact} store={store} panic_epoch={panic_epoch} panic_cpu={panic_cpu} panic_reason_code={panic_reason_code}"
                )
            }
            Self::InterfaceUnsupported {
                interface_kind,
                interface,
                operation,
                requester,
                artifact,
                store,
            } => {
                let requester = requester.as_deref().unwrap_or("none");
                let artifact = artifact
                    .map(|artifact| artifact.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let store =
                    store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
                format!(
                    "InterfaceUnsupported kind={interface_kind} interface={interface} op={operation} requester={requester} artifact={artifact} store={store}"
                )
            }
            Self::FaultDomainRegistered { domain } => {
                format!("FaultDomainRegistered domain={domain}")
            }
            Self::FaultDomainStateChanged { domain, from, to, generation } => format!(
                "FaultDomainStateChanged domain={domain} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::FaultClassified { trap, class, store, task, detail } => {
                let store =
                    store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
                let task = task.map(|task| task.to_string()).unwrap_or_else(|| "none".to_string());
                format!(
                    "FaultClassified trap={} class={} store={store} task={task} detail={detail}",
                    trap.as_str(),
                    class.as_str()
                )
            }
            Self::DriverTrap { domain, trap, detail } => match domain {
                Some(domain) => {
                    format!("DriverTrap domain={domain} trap={} detail={detail}", trap.as_str())
                }
                None => format!("DriverTrap trap={} detail={detail}", trap.as_str()),
            },
            Self::PacketReceived { interface, socket, ready_key, len } => {
                let socket =
                    socket.map(|socket| socket.to_string()).unwrap_or_else(|| "none".to_string());
                format!(
                    "PacketReceived interface={interface} socket={socket} ready_key=0x{ready_key:x} len={len}"
                )
            }
            Self::PacketTransmitted { interface, socket, ready_key, len } => {
                let socket =
                    socket.map(|socket| socket.to_string()).unwrap_or_else(|| "none".to_string());
                format!(
                    "PacketTransmitted interface={interface} socket={socket} ready_key=0x{ready_key:x} len={len}"
                )
            }
            Self::NetInterfaceStateChanged { interface, up } => {
                let state = if *up { "up" } else { "down" };
                format!("NetInterfaceStateChanged interface={interface} state={state}")
            }
            Self::SocketStateChanged { socket, state } => {
                format!("SocketStateChanged socket={socket} state={state}")
            }
            Self::DeviceIrqDelivered { irq, device, cause } => {
                format!("DeviceIrqDelivered irq={irq} device={device} cause={cause}")
            }
            Self::DriverCompletion { device, operation } => {
                format!("DriverCompletion device={device} operation={operation}")
            }
            Self::DmaSubmitted { buffer, device, len } => {
                format!("DmaSubmitted buffer={buffer} device={device} len={len}")
            }
            Self::DmaCompleted { buffer, device, len } => {
                format!("DmaCompleted buffer={buffer} device={device} len={len}")
            }
            Self::FaultDomainRestarted { domain } => {
                format!("FaultDomainRestarted domain={domain}")
            }
            Self::StoreRegistered { store, domain, resource, generation } => format!(
                "StoreRegistered store={store} domain={domain} resource={resource} generation={generation}"
            ),
            Self::StoreStateChanged { store, from, to, generation } => format!(
                "StoreStateChanged store={store} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::StoreExecutorTransition {
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
            Self::StoreActivationRecorded {
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
            Self::StoreActivationHandleValidated { store, generation } => {
                format!("StoreActivationHandleValidated store={store} generation={generation}")
            }
            Self::StoreActivationHandleRejected { store, expected, actual, reason } => match actual
            {
                Some(actual) => format!(
                    "StoreActivationHandleRejected store={store} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "StoreActivationHandleRejected store={store} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::StoreTrap { store, trap, detail } => {
                format!("StoreTrap store={store} trap={} detail={detail}", trap.as_str())
            }
            Self::StoreDropped { store, generation, resource } => match resource {
                Some(resource) => format!(
                    "StoreDropped store={store} generation={generation} resource={resource}"
                ),
                None => format!("StoreDropped store={store} generation={generation}"),
            },
            Self::StoreRebound { store, generation, resource } => {
                format!("StoreRebound store={store} generation={generation} resource={resource}")
            }
            Self::WindowLeaseCreated { lease, generation } => {
                format!("WindowLeaseCreated lease={lease} generation={generation}")
            }
            Self::WindowLeaseDestroyed { lease, generation } => {
                format!("WindowLeaseDestroyed lease={lease} generation={generation}")
            }
            Self::SnapshotBarrierEnter { barrier } => {
                format!("SnapshotBarrierEnter barrier={barrier}")
            }
            Self::SnapshotBarrierExit { barrier } => {
                format!("SnapshotBarrierExit barrier={barrier}")
            }
            Self::FastPathPlanInstalled { plan } => {
                format!("FastPathPlanInstalled plan={plan}")
            }
            Self::FastPathPlanInvalidated { plan } => {
                format!("FastPathPlanInvalidated plan={plan}")
            }
            Self::TransactionBegan { transaction, store, task, label } => {
                let store =
                    store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
                let task = task.map(|task| task.to_string()).unwrap_or_else(|| "none".to_string());
                format!(
                    "TransactionBegan transaction={transaction} store={store} task={task} label={label}"
                )
            }
            Self::TransactionCommitted { transaction, generation } => {
                format!("TransactionCommitted transaction={transaction} generation={generation}")
            }
            Self::TransactionRolledBack { transaction, reason, generation } => {
                format!(
                    "TransactionRolledBack transaction={transaction} reason={reason} generation={generation}"
                )
            }
            Self::CleanupStepApplied { cleanup, step, target, observed_generation } => {
                format!(
                    "CleanupStepApplied cleanup={cleanup} step={step} target={target} observed_generation={observed_generation}"
                )
            }
            Self::FailureEffect { effect } => {
                format!("FailureEffect {}", effect.summary())
            }
        }
    }
}
