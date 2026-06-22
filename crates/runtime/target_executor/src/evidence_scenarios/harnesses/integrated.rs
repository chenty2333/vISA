use super::super::super::*;

pub(crate) fn run_integrated_smp_preemption_cleanup_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_001,
        "integrated-runtime-x0",
        SemanticCommand::RecordIntegratedSmpPreemptionCleanup {
            integrated: 26_001,
            scenario: "x0-smp-preemption-cleanup".to_owned(),
            stress_run: 9501,
            stress_run_generation: 1,
            preemption: 9001,
            preemption_generation: 1,
            timer_interrupt: 9001,
            timer_interrupt_generation: 1,
            saved_context: 9002,
            saved_context_generation: 2,
            remote_preempt: 9001,
            remote_preempt_generation: 1,
            activation_cleanup: 9001,
            activation_cleanup_generation: 1,
            smp_cleanup_quiescence: 9301,
            smp_cleanup_quiescence_generation: 1,
            invariant_checks: 7,
            note: "x0 records integrated SMP preemption and cleanup closure".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x0 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_smp_network_fault_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_002,
        "integrated-runtime-x1",
        SemanticCommand::RecordIntegratedSmpNetworkFault {
            integrated: 26_101,
            scenario: "x1-smp-network-driver-fault".to_owned(),
            network_driver_cleanup: 10051,
            network_driver_cleanup_generation: 1,
            smp_stress_run: 9501,
            smp_stress_run_generation: 1,
            remote_preempt: 9001,
            remote_preempt_generation: 1,
            smp_cleanup_quiescence: 9301,
            smp_cleanup_quiescence_generation: 1,
            invariant_checks: 7,
            note: "x1 records network driver cleanup under SMP stress and quiescence evidence"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x1 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_disk_preempt_fault_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_003,
        "integrated-runtime-x2",
        SemanticCommand::RecordIntegratedDiskPreemptFault {
            integrated: 26_201,
            scenario: "x2-disk-pending-io-fault-under-preemption".to_owned(),
            preemption: 9_070,
            preemption_generation: 1,
            block_pending_io_policy: 20_124,
            block_pending_io_policy_generation: 1,
            invariant_checks: 6,
            note: "x2 records block pending EIO policy under timer preemption evidence".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x2 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_simd_migration_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_004,
        "integrated-runtime-x3",
        SemanticCommand::RecordIntegratedSimdMigration {
            integrated: 26_301,
            scenario: "x3-simd-task-migration-across-harts".to_owned(),
            activation_migration: 9_080,
            activation_migration_generation: 1,
            invariant_checks: 6,
            note: "x3 records clean SIMD vector state rehome across hart migration evidence"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x3 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_network_disk_io_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_005,
        "integrated-runtime-x4",
        SemanticCommand::RecordIntegratedNetworkDiskIo {
            integrated: 26_401,
            scenario: "x4-network-disk-concurrent-io".to_owned(),
            network_benchmark: 10_067,
            network_benchmark_generation: 1,
            block_benchmark: 20_132,
            block_benchmark_generation: 1,
            invariant_checks: 6,
            note: "x4 records network and disk concurrent IO semantic evidence".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x4 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_display_scheduler_load_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_006,
        "integrated-runtime-x5",
        SemanticCommand::RecordIntegratedDisplaySchedulerLoad {
            integrated: 26_501,
            scenario: "x5-display-update-during-scheduler-load".to_owned(),
            framebuffer_benchmark: 25_101,
            framebuffer_benchmark_generation: 1,
            scheduler_decision: 9_001,
            scheduler_decision_generation: 1,
            invariant_checks: 6,
            note: "x5 records display update evidence under scheduler decision load".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x5 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_snapshot_io_lease_barrier_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_007,
        "integrated-runtime-x6",
        SemanticCommand::RecordIntegratedSnapshotIoLeaseBarrier {
            integrated: 26_601,
            scenario: "x6-snapshot-barrier-blocks-active-io-leases".to_owned(),
            smp_snapshot_barrier: 9_401,
            smp_snapshot_barrier_generation: 1,
            io_cleanup: 9_967,
            io_cleanup_generation: 1,
            display_snapshot_barrier: 24_001,
            display_snapshot_barrier_generation: 1,
            invariant_checks: 7,
            note: "x6 records snapshot barrier closure after IO and display leases are cleaned"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x6 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_code_publish_smp_workload_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_008,
        "integrated-runtime-x7",
        SemanticCommand::RecordIntegratedCodePublishSmpWorkload {
            integrated: 26_701,
            scenario: "x7-code-publish-while-smp-workload-active".to_owned(),
            smp_stress_run: 9_501,
            smp_stress_run_generation: 1,
            smp_code_publish_barrier: 9_201,
            smp_code_publish_barrier_generation: 1,
            invariant_checks: 7,
            note: "x7 records semantic code publish barrier during SMP workload evidence"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x7 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_display_panic_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let substrate_panic_event = semantic.record_substrate_panic(
        "unknown",
        "PanicRing",
        "extract-after-substrate-panic",
        Some("substrate.panic".to_owned()),
        None,
        None,
        1,
        0,
        1,
    );
    let mut ring = PanicRingV1::new();
    ring.push_record(
        PanicRecordKindV1::PanicRecord,
        br#"{"panic_epoch":1,"panic_cpu":0,"reason_code":1}"#,
    )
    .map_err(|err| format!("push panic record: {err:?}"))?;
    ring.push_record(
        PanicRecordKindV1::LastHostcallFrameSummary,
        br#"{"hostcall":"none","status":"substrate-panic"}"#,
    )
    .map_err(|err| format!("push hostcall summary record: {err:?}"))?;
    ring.push_record(
        PanicRecordKindV1::ContractPanicSummary,
        br#"{"display_panic_last_frame":"display-panic-last-frame:25001@1","raw_framebuffer_bytes_exported":false}"#,
    )
    .map_err(|err| format!("push contract panic summary record: {err:?}"))?;
    let mut out = [0u8; 8192];
    let len = ring.dump_jsonl(&mut out).map_err(|err| format!("dump panic ring jsonl: {err:?}"))?;
    let jsonl = std::str::from_utf8(&out[..len])?;
    let jsonl_frame_count = jsonl.lines().count() as u32;
    let contract_panic_summary_records =
        jsonl.matches("\"schema\":\"contract-panic-summary-v1\"").count() as u32;
    let corrupt_record_count =
        jsonl.matches("\"schema\":\"panic-ring-corrupt-record-v1\"").count() as u32;
    let truncated_record_count =
        jsonl.matches("\"schema\":\"truncated-panic-record-v1\"").count() as u32;

    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_009,
        "integrated-runtime-x8",
        SemanticCommand::RecordIntegratedDisplayPanic {
            integrated: 26_801,
            scenario: "x8-panic-ring-extraction-after-substrate-panic".to_owned(),
            substrate_panic_event,
            display_panic_last_frame: 25_001,
            display_panic_last_frame_generation: 1,
            panic_ring_bytes: PANIC_RING_SIZE as u32,
            panic_record_max_bytes: PANIC_RECORD_MAX_LEN as u32,
            panic_ring_oldest_seq: ring.header().oldest_seq,
            panic_ring_newest_seq: ring.header().write_seq,
            panic_ring_record_count: ring.header().record_count,
            panic_ring_lost_count: ring.header().lost_count,
            jsonl_frame_count,
            contract_panic_summary_records,
            last_frame_summary_records: contract_panic_summary_records,
            corrupt_record_count,
            truncated_record_count,
            invariant_checks: 8,
            note: "x8 records panic-ring extraction after substrate panic without raw framebuffer bytes"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x8 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_osctl_trace_replay_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_010,
        "integrated-runtime-x9",
        SemanticCommand::RecordIntegratedOsctlTraceReplay {
            integrated: 26_901,
            scenario: "x9-full-osctl-trace-replay".to_owned(),
            integrated_smp_preemption_cleanup: 26_001,
            integrated_smp_preemption_cleanup_generation: 1,
            integrated_smp_network_fault: 26_101,
            integrated_smp_network_fault_generation: 1,
            integrated_disk_preempt_fault: 26_201,
            integrated_disk_preempt_fault_generation: 1,
            integrated_simd_migration: 26_301,
            integrated_simd_migration_generation: 1,
            integrated_network_disk_io: 26_401,
            integrated_network_disk_io_generation: 1,
            integrated_display_scheduler_load: 26_501,
            integrated_display_scheduler_load_generation: 1,
            integrated_snapshot_io_lease_barrier: 26_601,
            integrated_snapshot_io_lease_barrier_generation: 1,
            integrated_code_publish_smp_workload: 26_701,
            integrated_code_publish_smp_workload_generation: 1,
            integrated_display_panic: 26_801,
            integrated_display_panic_generation: 1,
            replay_event_cursor: semantic.event_log().cursor(),
            stable_view_count: 9,
            historical_edge_count: 9,
            replayed_root_count: 9,
            integrated_scenario_count: 9,
            replay_fixture_count: 9,
            invariant_checks: 9,
            note: "x9 records full osctl trace replay closure across integrated scenarios"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x9 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}
