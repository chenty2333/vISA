use super::*;

pub(crate) fn record_block_runtime_b21_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let driver_store =
        semantic.store_id("b4.block.driver").ok_or("block runtime b21 driver store is missing")?;
    let driver_store_generation = semantic
        .store_handle(driver_store)
        .map(|handle| handle.generation)
        .ok_or("block runtime b21 driver store generation is missing")?;
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 1);
    let dma_buffer = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 20_060, 1);

    let stale_completion = semantic.apply_envelope(CommandEnvelope::new(
        320,
        "target-executor-b21",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_126,
            block_request: 20_111,
            block_request_generation: 2,
            sequence: 1000,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b21-reject-stale-completion-request-generation".to_owned(),
        },
    ));
    if stale_completion.status != CommandStatus::Rejected
        || !stale_completion
            .violations
            .iter()
            .any(|violation| violation.contains("block request generation"))
    {
        return Err(format!(
            "block runtime b21 stale completion command {} ({}) was not rejected: status={} violations={:?}",
            stale_completion.command_id,
            stale_completion.command,
            stale_completion.status.as_str(),
            stale_completion.violations
        )
        .into());
    }

    let create_stale_wait = semantic.apply_envelope(CommandEnvelope::new(
        321,
        "target-executor-b21",
        SemanticCommand::CreateWait {
            wait: 20_127,
            owner_task: None,
            owner_store: Some(driver_store),
            owner_store_generation: Some(driver_store_generation),
            kind: SemanticWaitKind::DriverCompletion,
            generation: 1,
            blockers: vec![ContractObjectRef::new(
                ContractObjectKind::BlockRequestObject,
                20_111,
                2,
            )],
            deadline: None,
            restart_policy: RestartPolicy::InternalOnly,
            saved_context: Some("b21-stale-request-wait-probe".to_owned()),
        },
    ));
    if create_stale_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b21 create stale wait command {} ({}) failed: status={} violations={:?}",
            create_stale_wait.command_id,
            create_stale_wait.command,
            create_stale_wait.status.as_str(),
            create_stale_wait.violations
        )
        .into());
    }

    let stale_block_wait = semantic.apply_envelope(CommandEnvelope::new(
        322,
        "target-executor-b21",
        SemanticCommand::RecordBlockWait {
            block_wait: 20_128,
            wait: 20_127,
            wait_generation: 1,
            block_request: 20_111,
            block_request_generation: 2,
            note: "b21-reject-stale-block-wait-request-generation".to_owned(),
        },
    ));
    if stale_block_wait.status != CommandStatus::Rejected
        || !stale_block_wait
            .violations
            .iter()
            .any(|violation| violation.contains("request generation"))
    {
        return Err(format!(
            "block runtime b21 stale block wait command {} ({}) was not rejected: status={} violations={:?}",
            stale_block_wait.command_id,
            stale_block_wait.command,
            stale_block_wait.status.as_str(),
            stale_block_wait.violations
        )
        .into());
    }

    let cancel_probe_wait = semantic.apply_envelope(CommandEnvelope::new(
        323,
        "target-executor-b21",
        SemanticCommand::CancelWait {
            wait: 20_127,
            errno: 125,
            reason: WaitCancelReason::GenerationMismatch,
        },
    ));
    if cancel_probe_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b21 cancel stale wait command {} ({}) failed: status={} violations={:?}",
            cancel_probe_wait.command_id,
            cancel_probe_wait.command,
            cancel_probe_wait.status.as_str(),
            cancel_probe_wait.violations
        )
        .into());
    }

    let stale_dma = semantic.apply_envelope(CommandEnvelope::new(
        324,
        "target-executor-b21",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 20_129,
            backend,
            block_request: 20_111,
            block_request_generation: 2,
            dma_buffer: 20_060,
            dma_buffer_generation: 1,
            buffer_digest: 1,
            note: "b21-reject-stale-dma-request-generation".to_owned(),
        },
    ));
    if stale_dma.status != CommandStatus::Rejected
        || !stale_dma.violations.iter().any(|violation| violation.contains("request generation"))
    {
        return Err(format!(
            "block runtime b21 stale dma command {} ({}) was not rejected: status={} violations={:?}",
            stale_dma.command_id,
            stale_dma.command,
            stale_dma.status.as_str(),
            stale_dma.violations
        )
        .into());
    }

    let stale_queue = semantic.apply_envelope(CommandEnvelope::new(
        325,
        "target-executor-b21",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_130,
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            depth: 4,
            entries: vec![BlockRequestQueueEntryRef::pending(20_111, 2)],
            note: "b21-reject-stale-queue-request-generation".to_owned(),
        },
    ));
    if stale_queue.status != CommandStatus::Rejected
        || !stale_queue.violations.iter().any(|violation| violation.contains("request generation"))
    {
        return Err(format!(
            "block runtime b21 stale queue command {} ({}) was not rejected: status={} violations={:?}",
            stale_queue.command_id,
            stale_queue.command,
            stale_queue.status.as_str(),
            stale_queue.violations
        )
        .into());
    }

    let audit = semantic.apply_envelope(CommandEnvelope::new(
        326,
        "target-executor-b21",
        SemanticCommand::RecordBlockRequestGenerationAudit {
            audit: 20_131,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            block_request: 20_111,
            block_request_generation: 1,
            backend,
            dma_buffer,
            rejected_completion_generation_probes: 1,
            rejected_wait_generation_probes: 1,
            rejected_dma_generation_probes: 1,
            rejected_queue_generation_probes: 1,
            note: "b21-record-stale-block-request-generation-audit".to_owned(),
        },
    ));
    if audit.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b21 audit command {} ({}) failed: status={} violations={:?}",
            audit.command_id,
            audit.command,
            audit.status.as_str(),
            audit.violations
        )
        .into());
    }
    if semantic.block_request_generation_audit_count() != 1 {
        return Err(format!(
            "block runtime b21 expected 1 generation audit, got {}",
            semantic.block_request_generation_audit_count()
        )
        .into());
    }
    if !semantic.block_request_generation_audits().iter().any(|audit| {
        audit.id == 20_131
            && audit.block_request == 20_111
            && audit.block_request_generation == 1
            && audit.rejected_completion_generation_probes == 1
            && audit.rejected_wait_generation_probes == 1
            && audit.rejected_dma_generation_probes == 1
            && audit.rejected_queue_generation_probes == 1
    }) {
        return Err("block runtime b21 generation audit evidence is missing".into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b22_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 1);
    let benchmark = semantic.apply_envelope(CommandEnvelope::new(
        327,
        "target-executor-b22",
        SemanticCommand::RecordBlockBenchmark {
            benchmark: 20_132,
            scenario: "fake-block-read-write-iops-latency-v1".to_owned(),
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            read_path: 20_039,
            read_path_generation: 1,
            write_path: 20_048,
            write_path_generation: 1,
            request_queue: 20_053,
            request_queue_generation: 1,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 1,
            sample_requests: 2,
            sample_bytes: 8192,
            read_completed_requests: 1,
            write_completed_requests: 1,
            queue_completed_requests: 2,
            measured_nanos: 40_000,
            budget_nanos: 80_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 35_000,
            note: "b22-record-disk-iops-latency-benchmark".to_owned(),
        },
    ));
    if benchmark.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b22 benchmark command {} ({}) failed: status={} violations={:?}",
            benchmark.command_id,
            benchmark.command,
            benchmark.status.as_str(),
            benchmark.violations
        )
        .into());
    }

    let stale_read_path = semantic.apply_envelope(CommandEnvelope::new(
        328,
        "target-executor-b22",
        SemanticCommand::RecordBlockBenchmark {
            benchmark: 20_133,
            scenario: "stale read path generation cannot benchmark".to_owned(),
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            read_path: 20_039,
            read_path_generation: 2,
            write_path: 20_048,
            write_path_generation: 1,
            request_queue: 20_053,
            request_queue_generation: 1,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 1,
            sample_requests: 2,
            sample_bytes: 8192,
            read_completed_requests: 1,
            write_completed_requests: 1,
            queue_completed_requests: 2,
            measured_nanos: 40_000,
            budget_nanos: 80_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 35_000,
            note: "b22-reject-stale-read-path-generation".to_owned(),
        },
    ));
    if stale_read_path.status != CommandStatus::Rejected
        || !stale_read_path
            .violations
            .iter()
            .any(|violation| violation.contains("read path generation"))
    {
        return Err(format!(
            "block runtime b22 stale read path command {} ({}) was not rejected: status={} violations={:?}",
            stale_read_path.command_id,
            stale_read_path.command,
            stale_read_path.status.as_str(),
            stale_read_path.violations
        )
        .into());
    }

    let over_budget = semantic.apply_envelope(CommandEnvelope::new(
        329,
        "target-executor-b22",
        SemanticCommand::RecordBlockBenchmark {
            benchmark: 20_134,
            scenario: "latency budget violation cannot benchmark".to_owned(),
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            read_path: 20_039,
            read_path_generation: 1,
            write_path: 20_048,
            write_path_generation: 1,
            request_queue: 20_053,
            request_queue_generation: 1,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 1,
            sample_requests: 2,
            sample_bytes: 8192,
            read_completed_requests: 1,
            write_completed_requests: 1,
            queue_completed_requests: 2,
            measured_nanos: 90_000,
            budget_nanos: 80_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 35_000,
            note: "b22-reject-disk-benchmark-over-budget".to_owned(),
        },
    ));
    if over_budget.status != CommandStatus::Rejected
        || !over_budget.violations.iter().any(|violation| violation.contains("latency budget"))
    {
        return Err(format!(
            "block runtime b22 over-budget command {} ({}) was not rejected: status={} violations={:?}",
            over_budget.command_id,
            over_budget.command,
            over_budget.status.as_str(),
            over_budget.violations
        )
        .into());
    }

    let record = semantic
        .block_benchmarks()
        .iter()
        .find(|record| record.id == 20_132 && record.generation == 1)
        .ok_or("block runtime b22 benchmark evidence is missing")?;
    if record.iops != 50_000 || record.throughput_bytes_per_sec != 204_800_000 {
        return Err(format!(
            "block runtime b22 benchmark metrics drifted: iops={} throughput={}",
            record.iops, record.throughput_bytes_per_sec
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b23_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let cleanup = semantic
        .block_driver_cleanups()
        .iter()
        .find(|record| record.id == 20_107 && record.generation == 1)
        .cloned()
        .ok_or("block driver cleanup 20107@1 is missing for b23 evidence")?;
    let cleanup_complete_event = cleanup
        .completed_at_event
        .ok_or("block driver cleanup completion event is missing for b23 evidence")?;
    let cancelled_block_waits = cleanup.cancelled_block_waits.len() as u32;
    let cancelled_wait_tokens = cleanup.cancelled_wait_tokens.len() as u32;
    let released_dma_buffers = cleanup.released_dma_buffers.len() as u32;
    let revoked_device_capabilities = cleanup.revoked_device_capabilities.len() as u32;

    let benchmark = semantic.apply_envelope(CommandEnvelope::new(
        330,
        "target-executor-b23",
        SemanticCommand::RecordBlockRecoveryBenchmark {
            benchmark: 20_135,
            scenario: "host-validation-disk-driver-recovery".to_owned(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup_complete_event,
            cancelled_block_waits,
            cancelled_wait_tokens,
            released_dma_buffers,
            revoked_device_capabilities,
            recovery_nanos: 70_000,
            budget_nanos: 150_000,
            note: "b23-record-host-validation-disk-recovery-benchmark".to_owned(),
        },
    ));
    if benchmark.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b23 recovery benchmark command {} ({}) failed: status={} violations={:?}",
            benchmark.command_id,
            benchmark.command,
            benchmark.status.as_str(),
            benchmark.violations
        )
        .into());
    }

    let stale_cleanup = semantic.apply_envelope(CommandEnvelope::new(
        331,
        "target-executor-b23",
        SemanticCommand::RecordBlockRecoveryBenchmark {
            benchmark: 20_136,
            scenario: "stale cleanup generation cannot record disk recovery benchmark".to_owned(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation.saturating_add(1),
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup_complete_event,
            cancelled_block_waits,
            cancelled_wait_tokens,
            released_dma_buffers,
            revoked_device_capabilities,
            recovery_nanos: 70_000,
            budget_nanos: 150_000,
            note: "b23-reject-stale-cleanup-generation".to_owned(),
        },
    ));
    if stale_cleanup.status != CommandStatus::Rejected
        || !stale_cleanup
            .violations
            .iter()
            .any(|violation| violation.contains("cleanup generation"))
    {
        return Err(format!(
            "block runtime b23 stale cleanup command {} ({}) was not rejected: status={} violations={:?}",
            stale_cleanup.command_id,
            stale_cleanup.command,
            stale_cleanup.status.as_str(),
            stale_cleanup.violations
        )
        .into());
    }

    let budget_overrun = semantic.apply_envelope(CommandEnvelope::new(
        332,
        "target-executor-b23",
        SemanticCommand::RecordBlockRecoveryBenchmark {
            benchmark: 20_136,
            scenario: "disk recovery budget overrun cannot record benchmark".to_owned(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup_complete_event,
            cancelled_block_waits,
            cancelled_wait_tokens,
            released_dma_buffers,
            revoked_device_capabilities,
            recovery_nanos: 160_000,
            budget_nanos: 150_000,
            note: "b23-reject-disk-recovery-budget-overrun".to_owned(),
        },
    ));
    if budget_overrun.status != CommandStatus::Rejected
        || !budget_overrun.violations.iter().any(|violation| violation.contains("recovery budget"))
    {
        return Err(format!(
            "block runtime b23 budget command {} ({}) was not rejected: status={} violations={:?}",
            budget_overrun.command_id,
            budget_overrun.command,
            budget_overrun.status.as_str(),
            budget_overrun.violations
        )
        .into());
    }

    Ok(())
}
