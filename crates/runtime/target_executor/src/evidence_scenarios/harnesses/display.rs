use super::super::super::*;

pub(crate) fn run_framebuffer_object_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let framebuffer_resource =
        semantic.register_resource(ResourceKind::Framebuffer, None, "framebuffer:fb0");
    let framebuffer_resource_generation = semantic
        .resource_handle(framebuffer_resource)
        .ok_or("display runtime g0 framebuffer resource missing after registration")?
        .generation;

    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_020,
        "display-runtime-g0",
        SemanticCommand::RecordFramebufferObject {
            framebuffer: 23_001,
            name: "fb0".to_owned(),
            resource: framebuffer_resource,
            resource_generation: framebuffer_resource_generation,
            width: 800,
            height: 600,
            stride_bytes: 3200,
            pixel_format: "xrgb8888".to_owned(),
            byte_len: 1_920_000,
            note: "g0 records semantic framebuffer object without display write authority"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g0 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_object_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let framebuffer = semantic
        .framebuffer_objects()
        .iter()
        .find(|record| record.id == 23_001)
        .map(|record| record.object_ref())
        .ok_or("display runtime g1 requires g0 framebuffer evidence")?;

    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_021,
        "display-runtime-g1",
        SemanticCommand::RecordDisplayObject {
            display: 23_101,
            name: "display0".to_owned(),
            framebuffer: framebuffer.id,
            framebuffer_generation: framebuffer.generation,
            mode_name: "800x600@60".to_owned(),
            width: 800,
            height: 600,
            refresh_millihz: 60_000,
            note: "g1 records semantic display object bound to framebuffer generation".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g1 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_capability_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let owner_store = semantic_store_id(semantic, "wasm_app")?;
    let owner_store_generation = semantic
        .store_handle(owner_store)
        .ok_or("display runtime g2 owner store missing after lookup")?
        .generation;
    let display = semantic
        .display_objects()
        .iter()
        .find(|record| record.id == 23_101)
        .map(|record| record.object_ref())
        .ok_or("display runtime g2 requires g1 display object evidence")?;
    let display_record = semantic
        .display_objects()
        .iter()
        .find(|record| record.id == display.id && record.generation == display.generation)
        .ok_or("display runtime g2 display generation missing")?;
    let display_name = display_record.name.clone();
    let framebuffer = display_record.framebuffer;
    let framebuffer_generation = display_record.framebuffer_generation;

    let capability = semantic.grant_capability_with_authority_ref(
        "wasm_app",
        "display.display0",
        AuthorityObjectRef::internal(CapabilityClass::Display, display),
        &["flush", "lease"],
        "store",
        "display-runtime-g2",
        true,
    );
    let capability_record = semantic
        .capabilities()
        .record(capability)
        .ok_or("display runtime g2 capability missing after grant")?
        .clone();
    let handle = capability_record
        .store_local_handle(vec!["flush".to_owned(), "lease".to_owned()])
        .ok_or("display runtime g2 capability is not store-local")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_022,
        "display-runtime-g2",
        SemanticCommand::RecordDisplayCapability {
            display_capability: 23_201,
            owner_store,
            owner_store_generation,
            display: display.id,
            display_generation: display.generation,
            capability: capability_record.id,
            capability_generation: capability_record.generation,
            handle,
            operations: vec!["flush".to_owned(), "lease".to_owned()],
            note: format!(
                "g2 records display capability for {} backed by framebuffer {}@{}",
                display_name, framebuffer, framebuffer_generation
            ),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g2 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_window_lease_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let display_capability = semantic
        .display_capabilities()
        .iter()
        .find(|record| record.id == 23_201)
        .cloned()
        .ok_or("display runtime g3 requires g2 display capability evidence")?;
    let display = semantic
        .display_objects()
        .iter()
        .find(|record| {
            record.id == display_capability.display
                && record.generation == display_capability.display_generation
        })
        .cloned()
        .ok_or("display runtime g3 display generation missing")?;
    let framebuffer = semantic
        .framebuffer_objects()
        .iter()
        .find(|record| {
            record.id == display_capability.framebuffer
                && record.generation == display_capability.framebuffer_generation
        })
        .cloned()
        .ok_or("display runtime g3 framebuffer generation missing")?;

    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_023,
        "display-runtime-g3",
        SemanticCommand::RecordFramebufferWindowLease {
            framebuffer_window_lease: 23_301,
            owner_store: display_capability.owner_store,
            owner_store_generation: display_capability.owner_store_generation,
            display_capability: display_capability.id,
            display_capability_generation: display_capability.generation,
            display: display.id,
            display_generation: display.generation,
            framebuffer: framebuffer.id,
            framebuffer_generation: framebuffer.generation,
            x: 0,
            y: 0,
            width: display.width,
            height: display.height,
            byte_offset: 0,
            byte_len: framebuffer.byte_len,
            access: "write".to_owned(),
            note: "g3 records framebuffer write-window lease without pixel writes or flush"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g3 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_mapping_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let lease = semantic
        .framebuffer_window_leases()
        .iter()
        .find(|record| record.id == 23_301)
        .cloned()
        .ok_or("display runtime g4 requires g3 framebuffer window lease evidence")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_024,
        "display-runtime-g4",
        SemanticCommand::RecordFramebufferMapping {
            framebuffer_mapping: 23_401,
            owner_store: lease.owner_store,
            owner_store_generation: lease.owner_store_generation,
            framebuffer_window_lease: lease.id,
            framebuffer_window_lease_generation: lease.generation,
            map_handle_slot: 3,
            map_handle_generation: 1,
            map_handle_tag: 0x4d41505f4642,
            x: lease.x,
            y: lease.y,
            width: lease.width,
            height: lease.height,
            byte_offset: lease.byte_offset,
            byte_len: lease.byte_len,
            access: lease.access.clone(),
            mode: "handle-mode".to_owned(),
            note:
                "g4 maps framebuffer through semantic handle-mode lease without raw pointer mapping"
                    .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g4 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_write_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let mapping = semantic
        .framebuffer_mappings()
        .iter()
        .find(|record| record.id == 23_401)
        .cloned()
        .ok_or("display runtime g5 requires g4 framebuffer mapping evidence")?;
    let byte_len = 800 * 4;
    let payload_digest = SemanticGraph::expected_framebuffer_write_payload_digest_v1(
        mapping.id,
        mapping.generation,
        mapping.framebuffer,
        mapping.framebuffer_generation,
        0,
        0,
        800,
        1,
        0,
        byte_len,
    );
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_025,
        "display-runtime-g5",
        SemanticCommand::RecordFramebufferWrite {
            framebuffer_write: 23_501,
            owner_store: mapping.owner_store,
            owner_store_generation: mapping.owner_store_generation,
            framebuffer_mapping: mapping.id,
            framebuffer_mapping_generation: mapping.generation,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len,
            payload_digest,
            note: "g5 records semantic pixel write evidence through handle-mode mapping".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g5 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_flush_region_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let write = semantic
        .framebuffer_writes()
        .iter()
        .find(|record| record.id == 23_501)
        .cloned()
        .ok_or("display runtime g6 requires g5 framebuffer write evidence")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_026,
        "display-runtime-g6",
        SemanticCommand::RecordFramebufferFlushRegion {
            framebuffer_flush_region: 23_601,
            owner_store: write.owner_store,
            owner_store_generation: write.owner_store_generation,
            framebuffer_write: write.id,
            framebuffer_write_generation: write.generation,
            x: write.x,
            y: write.y,
            width: write.width,
            height: write.height,
            byte_offset: write.byte_offset,
            byte_len: write.byte_len,
            payload_digest: write.payload_digest,
            note: "g6 records semantic flush region evidence without real present".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g6 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_dirty_region_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let flush = semantic
        .framebuffer_flush_regions()
        .iter()
        .find(|record| record.id == 23_601)
        .cloned()
        .ok_or("display runtime g7 requires g6 framebuffer flush region evidence")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_027,
        "display-runtime-g7",
        SemanticCommand::RecordFramebufferDirtyRegion {
            framebuffer_dirty_region: 23_701,
            owner_store: flush.owner_store,
            owner_store_generation: flush.owner_store_generation,
            framebuffer_write: flush.framebuffer_write,
            framebuffer_write_generation: flush.framebuffer_write_generation,
            framebuffer_flush_region: Some(flush.id),
            framebuffer_flush_region_generation: Some(flush.generation),
            state: semantic_core::FramebufferDirtyRegionState::Clean,
            x: flush.x,
            y: flush.y,
            width: flush.width,
            height: flush.height,
            byte_offset: flush.byte_offset,
            byte_len: flush.byte_len,
            payload_digest: flush.payload_digest,
            note: "g7 records dirty region tracking and clean state after semantic flush"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g7 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_event_log_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let dirty = semantic
        .framebuffer_dirty_regions()
        .iter()
        .find(|record| record.id == 23_701)
        .cloned()
        .ok_or("display runtime g8 requires g7 framebuffer dirty region evidence")?;
    let first_event = semantic
        .framebuffer_objects()
        .iter()
        .find(|record| record.id == dirty.framebuffer)
        .map(|record| record.recorded_at_event)
        .ok_or("display runtime g8 requires g0 framebuffer object evidence")?;
    let last_event = dirty.recorded_at_event;
    let event_count = semantic
        .event_log()
        .events()
        .iter()
        .filter(|event| {
            event.source == "display" && event.id >= first_event && event.id <= last_event
        })
        .count() as u64;
    let flush_count = semantic
        .event_log()
        .events()
        .iter()
        .filter(|event| {
            event.source == "display"
                && event.id >= first_event
                && event.id <= last_event
                && matches!(
                    event.kind,
                    semantic_core::EventKind::FramebufferFlushRegionRecorded { .. }
                )
        })
        .count() as u64;
    let dirty_region_count = semantic
        .event_log()
        .events()
        .iter()
        .filter(|event| {
            event.source == "display"
                && event.id >= first_event
                && event.id <= last_event
                && matches!(
                    event.kind,
                    semantic_core::EventKind::FramebufferDirtyRegionTracked { .. }
                )
        })
        .count() as u64;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_028,
        "display-runtime-g8",
        SemanticCommand::RecordDisplayEventLog {
            display_event_log: 23_801,
            owner_store: dirty.owner_store,
            owner_store_generation: dirty.owner_store_generation,
            framebuffer_dirty_region: dirty.id,
            framebuffer_dirty_region_generation: dirty.generation,
            first_event,
            last_event,
            event_count,
            flush_count,
            dirty_region_count,
            note: "g8 records display event-log summary for semantic display evidence".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g8 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_cleanup_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let display_capability = semantic
        .display_capabilities()
        .iter()
        .find(|record| record.id == 23_201)
        .cloned()
        .ok_or("display runtime g9 requires g2 display capability evidence")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_029,
        "display-runtime-g9",
        SemanticCommand::CleanupDisplay {
            cleanup: 23_901,
            owner_store: display_capability.owner_store,
            owner_store_generation: display_capability.owner_store_generation,
            display_capability: display_capability.id,
            display_capability_generation: display_capability.generation,
            display: display_capability.display,
            display_generation: display_capability.display_generation,
            framebuffer: display_capability.framebuffer,
            framebuffer_generation: display_capability.framebuffer_generation,
            reason: "display-window-cleanup".to_owned(),
            note: "g9 releases framebuffer mapping and lease before revoking display capability"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g9 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_snapshot_barrier_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let cleanup = semantic
        .display_cleanups()
        .iter()
        .find(|record| record.id == 23_901)
        .cloned()
        .ok_or("display runtime g10 requires g9 display cleanup evidence")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_030,
        "display-runtime-g10",
        SemanticCommand::ValidateDisplaySnapshotBarrier {
            barrier: 24_001,
            owner_store: cleanup.owner_store,
            owner_store_generation: cleanup.owner_store_generation,
            display: cleanup.display,
            display_generation: cleanup.display_generation,
            framebuffer: cleanup.framebuffer,
            framebuffer_generation: cleanup.framebuffer_generation,
            display_cleanup: Some(cleanup.id),
            display_cleanup_generation: Some(cleanup.generation),
            reason: "display-snapshot-barrier".to_owned(),
            note:
                "g10 validates snapshot barrier after display cleanup released leases and mappings"
                    .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g10 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_panic_last_frame_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let barrier = semantic
        .display_snapshot_barriers()
        .iter()
        .find(|record| record.id == 24_001)
        .cloned()
        .ok_or("display runtime g11 requires g10 display snapshot barrier evidence")?;
    let event_log = semantic
        .display_event_logs()
        .iter()
        .find(|record| record.id == 23_801)
        .cloned()
        .ok_or("display runtime g11 requires g8 display event-log evidence")?;
    let write = semantic
        .framebuffer_writes()
        .iter()
        .find(|record| record.id == 23_501)
        .cloned()
        .ok_or("display runtime g11 requires g5 framebuffer write evidence")?;
    let flush = semantic
        .framebuffer_flush_regions()
        .iter()
        .find(|record| record.id == 23_601)
        .cloned()
        .ok_or("display runtime g11 requires g6 framebuffer flush evidence")?;
    let panic_epoch = 1;
    let summary_digest = SemanticGraph::expected_display_panic_last_frame_summary_digest_v1(
        barrier.owner_store,
        barrier.owner_store_generation,
        barrier.display,
        barrier.display_generation,
        barrier.framebuffer,
        barrier.framebuffer_generation,
        barrier.id,
        barrier.generation,
        event_log.id,
        event_log.generation,
        write.id,
        write.generation,
        flush.id,
        flush.generation,
        flush.payload_digest,
        panic_epoch,
        0,
        1,
    );
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_031,
        "display-runtime-g11",
        SemanticCommand::RecordDisplayPanicLastFrame {
            panic_last_frame: 25_001,
            owner_store: barrier.owner_store,
            owner_store_generation: barrier.owner_store_generation,
            display_snapshot_barrier: barrier.id,
            display_snapshot_barrier_generation: barrier.generation,
            display_event_log: event_log.id,
            display_event_log_generation: event_log.generation,
            framebuffer_write: write.id,
            framebuffer_write_generation: write.generation,
            framebuffer_flush_region: flush.id,
            framebuffer_flush_region_generation: flush.generation,
            payload_digest: flush.payload_digest,
            summary_digest,
            summary_record_bytes: 512,
            panic_epoch,
            panic_record_kind: "contract-panic-summary-v1".to_owned(),
            raw_framebuffer_bytes_exported: false,
            note: "g11 records panic-safe last framebuffer summary without raw bytes".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g11 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_benchmark_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let barrier = semantic
        .display_snapshot_barriers()
        .iter()
        .find(|record| record.id == 24_001)
        .cloned()
        .ok_or("display runtime g12 requires g10 display snapshot barrier evidence")?;
    let event_log = semantic
        .display_event_logs()
        .iter()
        .find(|record| record.id == 23_801)
        .cloned()
        .ok_or("display runtime g12 requires g8 display event-log evidence")?;
    let write = semantic
        .framebuffer_writes()
        .iter()
        .find(|record| record.id == 23_501)
        .cloned()
        .ok_or("display runtime g12 requires g5 framebuffer write evidence")?;
    let flush = semantic
        .framebuffer_flush_regions()
        .iter()
        .find(|record| record.id == 23_601)
        .cloned()
        .ok_or("display runtime g12 requires g6 framebuffer flush evidence")?;
    let sample_frames = 1;
    let sample_bytes = flush.byte_len;
    let frame_area_pixels = u64::from(flush.width) * u64::from(flush.height);
    let write_nanos = 40_000;
    let flush_nanos = 60_000;
    let measured_nanos = write_nanos + flush_nanos;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_032,
        "display-runtime-g12",
        SemanticCommand::RecordFramebufferBenchmark {
            benchmark: 25_101,
            scenario: "display-g12-single-flush".to_owned(),
            owner_store: barrier.owner_store,
            owner_store_generation: barrier.owner_store_generation,
            display_capability: write.display_capability,
            display_capability_generation: write.display_capability_generation,
            framebuffer_write: write.id,
            framebuffer_write_generation: write.generation,
            framebuffer_flush_region: flush.id,
            framebuffer_flush_region_generation: flush.generation,
            display_event_log: event_log.id,
            display_event_log_generation: event_log.generation,
            display_snapshot_barrier: barrier.id,
            display_snapshot_barrier_generation: barrier.generation,
            sample_frames,
            sample_bytes,
            frame_area_pixels,
            write_nanos,
            flush_nanos,
            measured_nanos,
            budget_nanos: 200_000,
            p50_latency_nanos: measured_nanos,
            p99_latency_nanos: measured_nanos,
            note: "g12 records semantic framebuffer write/flush benchmark evidence".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g12 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}
