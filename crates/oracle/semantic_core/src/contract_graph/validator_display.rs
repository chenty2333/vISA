use alloc::vec::Vec;

use super::*;

impl ContractGraphValidator {
    pub(super) fn validate_framebuffer_objects(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for framebuffer in &snapshot.framebuffer_objects {
            let from = framebuffer.object_ref();
            if framebuffer.id == 0
                || framebuffer.generation == 0
                || framebuffer.resource == 0
                || framebuffer.resource_generation == 0
                || framebuffer.name.is_empty()
                || framebuffer.width == 0
                || framebuffer.height == 0
                || framebuffer.stride_bytes == 0
                || framebuffer.pixel_format.is_empty()
                || framebuffer.byte_len == 0
                || framebuffer.state != FramebufferObjectState::Registered
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-object->contract",
                    from,
                    None,
                    "framebuffer object requires nonzero identity, backing resource, geometry, pixel format, and registered state",
                ));
                continue;
            }

            let bytes_per_pixel = match framebuffer.pixel_format.as_str() {
                "xrgb8888" | "argb8888" | "rgba8888" | "bgra8888" => 4,
                "rgb565" => 2,
                _ => {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "framebuffer-object->pixel-format",
                        from,
                        None,
                        "framebuffer object uses an unsupported pixel format",
                    ));
                    continue;
                }
            };
            if framebuffer.stride_bytes < framebuffer.width.saturating_mul(bytes_per_pixel)
                || framebuffer.byte_len
                    < u64::from(framebuffer.stride_bytes)
                        .saturating_mul(u64::from(framebuffer.height))
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-object->geometry",
                    from,
                    None,
                    "framebuffer object stride/byte length do not cover visible geometry",
                ));
            }
        }
    }

    pub(super) fn validate_display_objects(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for display in &snapshot.display_objects {
            let from = display.object_ref();
            if display.id == 0
                || display.generation == 0
                || display.framebuffer == 0
                || display.framebuffer_generation == 0
                || display.name.is_empty()
                || display.mode_name.is_empty()
                || display.width == 0
                || display.height == 0
                || display.refresh_millihz == 0
                || display.state != DisplayObjectState::Registered
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-object->contract",
                    from,
                    None,
                    "display object requires nonzero identity, framebuffer generation, mode, refresh, and registered state",
                ));
                continue;
            }

            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-object->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                display.framebuffer,
                display.framebuffer_generation,
                ContractEdgeMode::Live,
            );

            if let Some(framebuffer) = snapshot.framebuffer_objects.iter().find(|framebuffer| {
                framebuffer.id == display.framebuffer
                    && framebuffer.generation == display.framebuffer_generation
            }) {
                if framebuffer.state != FramebufferObjectState::Registered
                    || display.width > framebuffer.width
                    || display.height > framebuffer.height
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "display-object->framebuffer-geometry",
                        from,
                        Some(framebuffer.object_ref()),
                        "display object mode must fit its registered framebuffer generation",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_display_capabilities(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for capability in &snapshot.display_capabilities {
            let from = capability.object_ref();
            if capability.id == 0
                || capability.generation == 0
                || capability.owner_store_generation == 0
                || capability.display_generation == 0
                || capability.framebuffer_generation == 0
                || capability.capability_generation == 0
                || capability.operations.is_empty()
                || capability.operations.iter().any(|operation| operation.is_empty())
                || (capability.state != DisplayCapabilityState::Active
                    && capability.state != DisplayCapabilityState::Revoked)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-capability->contract",
                    from,
                    None,
                    "display capability requires nonzero owner, display, framebuffer, capability, operations, and known state",
                ));
                continue;
            }
            let active = capability.state == DisplayCapabilityState::Active;
            let edge_mode =
                if active { ContractEdgeMode::Live } else { ContractEdgeMode::Historical };
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-capability->owner-store",
                ContractObjectKind::Store,
                capability.owner_store,
                capability.owner_store_generation,
                edge_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-capability->display-object",
                ContractObjectKind::DisplayObject,
                capability.display,
                capability.display_generation,
                edge_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-capability->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                capability.framebuffer,
                capability.framebuffer_generation,
                edge_mode,
            );
            if active {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "display-capability->capability",
                    ContractObjectKind::Capability,
                    capability.capability,
                    capability.capability_generation,
                    ContractEdgeMode::Live,
                );
            } else if !snapshot.capabilities.iter().any(|record| {
                record.id == capability.capability
                    && record.revoked
                    && record.generation > capability.capability_generation
            }) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "display-capability->revoked-capability",
                    from,
                    None,
                    "revoked display capability must point to an advanced revoked capability generation",
                ));
            }

            if let Some(display) = snapshot.display_objects.iter().find(|display| {
                display.id == capability.display
                    && display.generation == capability.display_generation
            }) {
                if display.framebuffer != capability.framebuffer
                    || display.framebuffer_generation != capability.framebuffer_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-capability->display-framebuffer",
                        from,
                        Some(display.object_ref()),
                        "display capability framebuffer edge does not match display object generation",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_framebuffer_window_leases(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for lease in &snapshot.framebuffer_window_leases {
            let from = lease.object_ref();
            if lease.id == 0
                || lease.generation == 0
                || lease.owner_store_generation == 0
                || lease.display_capability_generation == 0
                || lease.display_generation == 0
                || lease.framebuffer_generation == 0
                || lease.width == 0
                || lease.height == 0
                || lease.byte_len == 0
                || lease.access.is_empty()
                || (lease.state != FramebufferWindowLeaseState::Active
                    && lease.state != FramebufferWindowLeaseState::Released)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-window-lease->contract",
                    from,
                    None,
                    "framebuffer window lease requires nonzero exact refs, window, byte range, access, and known state",
                ));
                continue;
            }
            let active = lease.state == FramebufferWindowLeaseState::Active;
            let owner_mode =
                if active { ContractEdgeMode::Live } else { ContractEdgeMode::Historical };
            let capability_mode =
                if active { ContractEdgeMode::Live } else { ContractEdgeMode::CleanupEffect };
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->owner-store",
                ContractObjectKind::Store,
                lease.owner_store,
                lease.owner_store_generation,
                owner_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->display-capability",
                ContractObjectKind::DisplayCapability,
                lease.display_capability,
                lease.display_capability_generation,
                capability_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->display-object",
                ContractObjectKind::DisplayObject,
                lease.display,
                lease.display_generation,
                owner_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                lease.framebuffer,
                lease.framebuffer_generation,
                owner_mode,
            );

            let display_capability = snapshot.display_capabilities.iter().find(|capability| {
                capability.id == lease.display_capability
                    && capability.generation == lease.display_capability_generation
            });
            if let Some(capability) = display_capability {
                if capability.owner_store != lease.owner_store
                    || capability.owner_store_generation != lease.owner_store_generation
                    || capability.display != lease.display
                    || capability.display_generation != lease.display_generation
                    || capability.framebuffer != lease.framebuffer
                    || capability.framebuffer_generation != lease.framebuffer_generation
                    || !capability.operations.iter().any(|operation| operation == "lease")
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-window-lease->display-capability-binding",
                        from,
                        Some(capability.object_ref()),
                        "framebuffer window lease does not match display capability authority binding",
                    ));
                }
            }
            if let Some(display) = snapshot.display_objects.iter().find(|display| {
                display.id == lease.display && display.generation == lease.display_generation
            }) {
                if display.framebuffer != lease.framebuffer
                    || display.framebuffer_generation != lease.framebuffer_generation
                    || lease.x.checked_add(lease.width).is_none_or(|right| right > display.width)
                    || lease
                        .y
                        .checked_add(lease.height)
                        .is_none_or(|bottom| bottom > display.height)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "framebuffer-window-lease->display-window",
                        from,
                        Some(display.object_ref()),
                        "framebuffer window lease window is outside display mode or framebuffer binding",
                    ));
                }
            }
            if let Some(framebuffer) = snapshot.framebuffer_objects.iter().find(|framebuffer| {
                framebuffer.id == lease.framebuffer
                    && framebuffer.generation == lease.framebuffer_generation
            }) {
                let bytes_per_pixel = match framebuffer.pixel_format.as_str() {
                    "xrgb8888" | "argb8888" | "rgba8888" | "bgra8888" => Some(4_u64),
                    "rgb565" => Some(2_u64),
                    _ => None,
                };
                let byte_window = bytes_per_pixel.and_then(|bytes_per_pixel| {
                    let row_bytes = u64::from(lease.width).checked_mul(bytes_per_pixel)?;
                    let expected_byte_offset = u64::from(lease.y)
                        .checked_mul(u64::from(framebuffer.stride_bytes))
                        .and_then(|base| {
                            u64::from(lease.x)
                                .checked_mul(bytes_per_pixel)
                                .and_then(|x_bytes| base.checked_add(x_bytes))
                        })?;
                    let min_window_bytes = u64::from(lease.height.saturating_sub(1))
                        .checked_mul(u64::from(framebuffer.stride_bytes))
                        .and_then(|rows| rows.checked_add(row_bytes))?;
                    Some((expected_byte_offset, min_window_bytes))
                });
                if byte_window.is_none_or(|(expected_byte_offset, min_window_bytes)| {
                    lease.byte_offset != expected_byte_offset || lease.byte_len < min_window_bytes
                }) || lease
                    .byte_offset
                    .checked_add(lease.byte_len)
                    .is_none_or(|end| end > framebuffer.byte_len)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "framebuffer-window-lease->byte-window",
                        from,
                        Some(framebuffer.object_ref()),
                        "framebuffer window lease byte window does not match framebuffer geometry or exceeds framebuffer object",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_framebuffer_mappings(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for mapping in &snapshot.framebuffer_mappings {
            let from = mapping.object_ref();
            if mapping.id == 0
                || mapping.generation == 0
                || mapping.owner_store_generation == 0
                || mapping.framebuffer_window_lease_generation == 0
                || mapping.map_handle_slot == 0
                || mapping.map_handle_generation == 0
                || mapping.map_handle_tag == 0
                || mapping.width == 0
                || mapping.height == 0
                || mapping.byte_len == 0
                || mapping.mode != "handle-mode"
                || (mapping.access != "write" && mapping.access != "read")
                || (mapping.state != FramebufferMappingState::Active
                    && mapping.state != FramebufferMappingState::Unmapped)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-mapping->contract",
                    from,
                    None,
                    "framebuffer mapping requires exact refs, handle-mode state, handle identity, and byte window",
                ));
                continue;
            }
            let active = mapping.state == FramebufferMappingState::Active;
            let owner_mode =
                if active { ContractEdgeMode::Live } else { ContractEdgeMode::Historical };
            let cleanup_mode =
                if active { ContractEdgeMode::Live } else { ContractEdgeMode::CleanupEffect };
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->owner-store",
                ContractObjectKind::Store,
                mapping.owner_store,
                mapping.owner_store_generation,
                owner_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->framebuffer-window-lease",
                ContractObjectKind::FramebufferWindowLease,
                mapping.framebuffer_window_lease,
                mapping.framebuffer_window_lease_generation,
                cleanup_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->display-capability",
                ContractObjectKind::DisplayCapability,
                mapping.display_capability,
                mapping.display_capability_generation,
                cleanup_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->display-object",
                ContractObjectKind::DisplayObject,
                mapping.display,
                mapping.display_generation,
                owner_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                mapping.framebuffer,
                mapping.framebuffer_generation,
                owner_mode,
            );
            if let Some(lease) = snapshot.framebuffer_window_leases.iter().find(|lease| {
                lease.id == mapping.framebuffer_window_lease
                    && lease.generation == mapping.framebuffer_window_lease_generation
            }) {
                if lease.owner_store != mapping.owner_store
                    || lease.owner_store_generation != mapping.owner_store_generation
                    || lease.display_capability != mapping.display_capability
                    || lease.display_capability_generation != mapping.display_capability_generation
                    || lease.display != mapping.display
                    || lease.display_generation != mapping.display_generation
                    || lease.framebuffer != mapping.framebuffer
                    || lease.framebuffer_generation != mapping.framebuffer_generation
                    || lease.x != mapping.x
                    || lease.y != mapping.y
                    || lease.width != mapping.width
                    || lease.height != mapping.height
                    || lease.byte_offset != mapping.byte_offset
                    || lease.byte_len != mapping.byte_len
                    || lease.access != mapping.access
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-mapping->lease-binding",
                        from,
                        Some(lease.object_ref()),
                        "framebuffer mapping does not match the active framebuffer window lease",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_framebuffer_writes(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for write in &snapshot.framebuffer_writes {
            let from = write.object_ref();
            if write.id == 0
                || write.generation == 0
                || write.owner_store_generation == 0
                || write.framebuffer_mapping_generation == 0
                || write.map_handle_slot == 0
                || write.map_handle_generation == 0
                || write.map_handle_tag == 0
                || write.width == 0
                || write.height == 0
                || write.byte_len == 0
                || write.pixel_format.is_empty()
                || write.payload_digest == 0
                || write.state != FramebufferWriteState::Applied
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-write->contract",
                    from,
                    None,
                    "framebuffer write requires exact refs, applied state, handle identity, payload digest, and byte window",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->owner-store",
                ContractObjectKind::Store,
                write.owner_store,
                write.owner_store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->framebuffer-mapping",
                ContractObjectKind::FramebufferMapping,
                write.framebuffer_mapping,
                write.framebuffer_mapping_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->framebuffer-window-lease",
                ContractObjectKind::FramebufferWindowLease,
                write.framebuffer_window_lease,
                write.framebuffer_window_lease_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->display-capability",
                ContractObjectKind::DisplayCapability,
                write.display_capability,
                write.display_capability_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->display-object",
                ContractObjectKind::DisplayObject,
                write.display,
                write.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                write.framebuffer,
                write.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            if let Some(mapping) = snapshot.framebuffer_mappings.iter().find(|mapping| {
                mapping.id == write.framebuffer_mapping
                    && mapping.generation == write.framebuffer_mapping_generation
            }) {
                let region_mismatch = write.x < mapping.x
                    || write.y < mapping.y
                    || write
                        .x
                        .checked_add(write.width)
                        .zip(mapping.x.checked_add(mapping.width))
                        .is_none_or(|(write_right, mapping_right)| write_right > mapping_right)
                    || write
                        .y
                        .checked_add(write.height)
                        .zip(mapping.y.checked_add(mapping.height))
                        .is_none_or(|(write_bottom, mapping_bottom)| write_bottom > mapping_bottom);
                let byte_mismatch = write.byte_offset < mapping.byte_offset
                    || write
                        .byte_offset
                        .checked_add(write.byte_len)
                        .zip(mapping.byte_offset.checked_add(mapping.byte_len))
                        .is_none_or(|(write_end, mapping_end)| write_end > mapping_end);
                if mapping.owner_store != write.owner_store
                    || mapping.owner_store_generation != write.owner_store_generation
                    || mapping.framebuffer_window_lease != write.framebuffer_window_lease
                    || mapping.framebuffer_window_lease_generation
                        != write.framebuffer_window_lease_generation
                    || mapping.display_capability != write.display_capability
                    || mapping.display_capability_generation != write.display_capability_generation
                    || mapping.display != write.display
                    || mapping.display_generation != write.display_generation
                    || mapping.framebuffer != write.framebuffer
                    || mapping.framebuffer_generation != write.framebuffer_generation
                    || mapping.map_handle_slot != write.map_handle_slot
                    || mapping.map_handle_generation != write.map_handle_generation
                    || mapping.map_handle_tag != write.map_handle_tag
                    || mapping.access != "write"
                    || mapping.mode != "handle-mode"
                    || region_mismatch
                    || byte_mismatch
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-write->mapping-binding",
                        from,
                        Some(mapping.object_ref()),
                        "framebuffer write does not match the mapped framebuffer lease authority",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_framebuffer_flush_regions(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for flush in &snapshot.framebuffer_flush_regions {
            let from = flush.object_ref();
            if flush.id == 0
                || flush.generation == 0
                || flush.owner_store_generation == 0
                || flush.framebuffer_write_generation == 0
                || flush.width == 0
                || flush.height == 0
                || flush.byte_len == 0
                || flush.pixel_format.is_empty()
                || flush.payload_digest == 0
                || flush.state != FramebufferFlushRegionState::Applied
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-flush-region->contract",
                    from,
                    None,
                    "framebuffer flush region requires exact refs, applied state, payload digest, and byte window",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-flush-region->owner-store",
                ContractObjectKind::Store,
                flush.owner_store,
                flush.owner_store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-flush-region->framebuffer-write",
                ContractObjectKind::FramebufferWrite,
                flush.framebuffer_write,
                flush.framebuffer_write_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-flush-region->display-capability",
                ContractObjectKind::DisplayCapability,
                flush.display_capability,
                flush.display_capability_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-flush-region->display-object",
                ContractObjectKind::DisplayObject,
                flush.display,
                flush.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-flush-region->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                flush.framebuffer,
                flush.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            if let Some(write) = snapshot.framebuffer_writes.iter().find(|write| {
                write.id == flush.framebuffer_write
                    && write.generation == flush.framebuffer_write_generation
            }) {
                if write.owner_store != flush.owner_store
                    || write.owner_store_generation != flush.owner_store_generation
                    || write.display_capability != flush.display_capability
                    || write.display_capability_generation != flush.display_capability_generation
                    || write.display != flush.display
                    || write.display_generation != flush.display_generation
                    || write.framebuffer != flush.framebuffer
                    || write.framebuffer_generation != flush.framebuffer_generation
                    || write.x != flush.x
                    || write.y != flush.y
                    || write.width != flush.width
                    || write.height != flush.height
                    || write.byte_offset != flush.byte_offset
                    || write.byte_len != flush.byte_len
                    || write.pixel_format != flush.pixel_format
                    || write.payload_digest != flush.payload_digest
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-flush-region->write-binding",
                        from,
                        Some(write.object_ref()),
                        "framebuffer flush region does not match the written framebuffer region",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_framebuffer_dirty_regions(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for dirty in &snapshot.framebuffer_dirty_regions {
            let from = dirty.object_ref();
            let state_valid = matches!(
                dirty.state,
                FramebufferDirtyRegionState::Dirty | FramebufferDirtyRegionState::Clean
            );
            let clean_has_flush = dirty.framebuffer_flush_region.is_some()
                && dirty.framebuffer_flush_region_generation.unwrap_or(0) != 0
                && dirty.cleaned_at_event.unwrap_or(0) != 0;
            let dirty_has_no_flush = dirty.framebuffer_flush_region.is_none()
                && dirty.framebuffer_flush_region_generation.is_none()
                && dirty.cleaned_at_event.is_none();
            if dirty.id == 0
                || dirty.generation == 0
                || dirty.owner_store_generation == 0
                || dirty.framebuffer_write_generation == 0
                || dirty.width == 0
                || dirty.height == 0
                || dirty.byte_len == 0
                || dirty.pixel_format.is_empty()
                || dirty.payload_digest == 0
                || !state_valid
                || (dirty.state == FramebufferDirtyRegionState::Clean && !clean_has_flush)
                || (dirty.state == FramebufferDirtyRegionState::Dirty && !dirty_has_no_flush)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-dirty-region->contract",
                    from,
                    None,
                    "framebuffer dirty region requires exact refs, state-consistent flush refs, payload digest, and byte window",
                ));
                continue;
            }
            let owner_edge_mode = if dirty.state == FramebufferDirtyRegionState::Dirty {
                ContractEdgeMode::Live
            } else {
                ContractEdgeMode::Historical
            };
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-dirty-region->owner-store",
                ContractObjectKind::Store,
                dirty.owner_store,
                dirty.owner_store_generation,
                owner_edge_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-dirty-region->framebuffer-write",
                ContractObjectKind::FramebufferWrite,
                dirty.framebuffer_write,
                dirty.framebuffer_write_generation,
                ContractEdgeMode::Historical,
            );
            if let (Some(flush), Some(generation)) =
                (dirty.framebuffer_flush_region, dirty.framebuffer_flush_region_generation)
            {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "framebuffer-dirty-region->framebuffer-flush-region",
                    ContractObjectKind::FramebufferFlushRegion,
                    flush,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-dirty-region->display-capability",
                ContractObjectKind::DisplayCapability,
                dirty.display_capability,
                dirty.display_capability_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-dirty-region->display-object",
                ContractObjectKind::DisplayObject,
                dirty.display,
                dirty.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-dirty-region->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                dirty.framebuffer,
                dirty.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            if let Some(write) = snapshot.framebuffer_writes.iter().find(|write| {
                write.id == dirty.framebuffer_write
                    && write.generation == dirty.framebuffer_write_generation
            }) {
                if write.owner_store != dirty.owner_store
                    || write.owner_store_generation != dirty.owner_store_generation
                    || write.display_capability != dirty.display_capability
                    || write.display_capability_generation != dirty.display_capability_generation
                    || write.display != dirty.display
                    || write.display_generation != dirty.display_generation
                    || write.framebuffer != dirty.framebuffer
                    || write.framebuffer_generation != dirty.framebuffer_generation
                    || write.x != dirty.x
                    || write.y != dirty.y
                    || write.width != dirty.width
                    || write.height != dirty.height
                    || write.byte_offset != dirty.byte_offset
                    || write.byte_len != dirty.byte_len
                    || write.pixel_format != dirty.pixel_format
                    || write.payload_digest != dirty.payload_digest
                    || write.recorded_at_event != dirty.dirty_at_event
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-dirty-region->write-binding",
                        from,
                        Some(write.object_ref()),
                        "framebuffer dirty region does not match the written framebuffer region",
                    ));
                }
            }
            if let (Some(flush_id), Some(flush_generation)) =
                (dirty.framebuffer_flush_region, dirty.framebuffer_flush_region_generation)
                && let Some(flush) = snapshot
                    .framebuffer_flush_regions
                    .iter()
                    .find(|flush| flush.id == flush_id && flush.generation == flush_generation)
                && (flush.owner_store != dirty.owner_store
                    || flush.owner_store_generation != dirty.owner_store_generation
                    || flush.framebuffer_write != dirty.framebuffer_write
                    || flush.framebuffer_write_generation != dirty.framebuffer_write_generation
                    || flush.display_capability != dirty.display_capability
                    || flush.display_capability_generation != dirty.display_capability_generation
                    || flush.display != dirty.display
                    || flush.display_generation != dirty.display_generation
                    || flush.framebuffer != dirty.framebuffer
                    || flush.framebuffer_generation != dirty.framebuffer_generation
                    || flush.x != dirty.x
                    || flush.y != dirty.y
                    || flush.width != dirty.width
                    || flush.height != dirty.height
                    || flush.byte_offset != dirty.byte_offset
                    || flush.byte_len != dirty.byte_len
                    || flush.pixel_format != dirty.pixel_format
                    || flush.payload_digest != dirty.payload_digest
                    || Some(flush.recorded_at_event) != dirty.cleaned_at_event)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "framebuffer-dirty-region->flush-binding",
                    from,
                    Some(flush.object_ref()),
                    "clean framebuffer dirty region does not match the clearing flush region",
                ));
            }
        }
    }

    pub(super) fn validate_display_event_logs(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for log in &snapshot.display_event_logs {
            let from = log.object_ref();
            if log.id == 0
                || log.generation == 0
                || log.owner_store_generation == 0
                || log.framebuffer_dirty_region_generation == 0
                || log.first_event == 0
                || log.last_event < log.first_event
                || log.event_count == 0
                || log.state != DisplayEventLogState::Recorded
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-event-log->contract",
                    from,
                    None,
                    "display event log requires exact refs, recorded state, and nonempty event window",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-event-log->owner-store",
                ContractObjectKind::Store,
                log.owner_store,
                log.owner_store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-event-log->framebuffer-dirty-region",
                ContractObjectKind::FramebufferDirtyRegion,
                log.framebuffer_dirty_region,
                log.framebuffer_dirty_region_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-event-log->display-capability",
                ContractObjectKind::DisplayCapability,
                log.display_capability,
                log.display_capability_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-event-log->display-object",
                ContractObjectKind::DisplayObject,
                log.display,
                log.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-event-log->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                log.framebuffer,
                log.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            if let Some(dirty) = snapshot.framebuffer_dirty_regions.iter().find(|dirty| {
                dirty.id == log.framebuffer_dirty_region
                    && dirty.generation == log.framebuffer_dirty_region_generation
            }) {
                if dirty.owner_store != log.owner_store
                    || dirty.owner_store_generation != log.owner_store_generation
                    || dirty.display_capability != log.display_capability
                    || dirty.display_capability_generation != log.display_capability_generation
                    || dirty.display != log.display
                    || dirty.display_generation != log.display_generation
                    || dirty.framebuffer != log.framebuffer
                    || dirty.framebuffer_generation != log.framebuffer_generation
                    || dirty.dirty_at_event < log.first_event
                    || dirty.recorded_at_event > log.last_event
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-event-log->dirty-region-binding",
                        from,
                        Some(dirty.object_ref()),
                        "display event log window or refs do not match the dirty region lifecycle",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_display_cleanups(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for cleanup in &snapshot.display_cleanups {
            let from = cleanup.object_ref();
            if cleanup.id == 0
                || cleanup.generation == 0
                || cleanup.owner_store_generation == 0
                || cleanup.display_capability_generation == 0
                || cleanup.display_generation == 0
                || cleanup.framebuffer_generation == 0
                || cleanup.reason.is_empty()
                || cleanup.state != DisplayCleanupState::Completed
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-cleanup->contract",
                    from,
                    None,
                    "display cleanup requires exact refs, completed state, and reason",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-cleanup->owner-store",
                ContractObjectKind::Store,
                cleanup.owner_store,
                cleanup.owner_store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-cleanup->display-capability",
                ContractObjectKind::DisplayCapability,
                cleanup.display_capability,
                cleanup.display_capability_generation,
                ContractEdgeMode::CleanupEffect,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-cleanup->display-object",
                ContractObjectKind::DisplayObject,
                cleanup.display,
                cleanup.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-cleanup->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                cleanup.framebuffer,
                cleanup.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            for mapping in &cleanup.unmapped_framebuffer_mappings {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "display-cleanup->unmapped-framebuffer-mapping",
                    ContractObjectKind::FramebufferMapping,
                    mapping.id,
                    mapping.generation,
                    ContractEdgeMode::CleanupEffect,
                );
                if let Some(record) = snapshot.framebuffer_mappings.iter().find(|record| {
                    record.id == mapping.id && record.generation == mapping.generation
                }) {
                    if record.state != FramebufferMappingState::Unmapped
                        || record.owner_store != cleanup.owner_store
                        || record.owner_store_generation != cleanup.owner_store_generation
                        || record.display_capability != cleanup.display_capability
                        || record.display_capability_generation
                            != cleanup.display_capability_generation
                    {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "display-cleanup->mapping-effect",
                            from,
                            Some(record.object_ref()),
                            "display cleanup mapping effect does not match the cleanup target",
                        ));
                    }
                }
            }
            for lease in &cleanup.released_framebuffer_window_leases {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "display-cleanup->released-framebuffer-window-lease",
                    ContractObjectKind::FramebufferWindowLease,
                    lease.id,
                    lease.generation,
                    ContractEdgeMode::CleanupEffect,
                );
                if let Some(record) = snapshot
                    .framebuffer_window_leases
                    .iter()
                    .find(|record| record.id == lease.id && record.generation == lease.generation)
                {
                    if record.state != FramebufferWindowLeaseState::Released
                        || record.owner_store != cleanup.owner_store
                        || record.owner_store_generation != cleanup.owner_store_generation
                        || record.display_capability != cleanup.display_capability
                        || record.display_capability_generation
                            != cleanup.display_capability_generation
                    {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "display-cleanup->lease-effect",
                            from,
                            Some(record.object_ref()),
                            "display cleanup lease effect does not match the cleanup target",
                        ));
                    }
                }
            }
            for display_capability in &cleanup.revoked_display_capabilities {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "display-cleanup->revoked-display-capability",
                    ContractObjectKind::DisplayCapability,
                    display_capability.id,
                    display_capability.generation,
                    ContractEdgeMode::CleanupEffect,
                );
                if let Some(record) = snapshot.display_capabilities.iter().find(|record| {
                    record.id == display_capability.id
                        && record.generation == display_capability.generation
                }) {
                    if record.state != DisplayCapabilityState::Revoked
                        || record.owner_store != cleanup.owner_store
                        || record.owner_store_generation != cleanup.owner_store_generation
                    {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "display-cleanup->display-capability-effect",
                            from,
                            Some(record.object_ref()),
                            "display cleanup display-capability effect does not match the cleanup target",
                        ));
                    }
                }
            }
            for capability in &cleanup.revoked_capabilities {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "display-cleanup->revoked-capability",
                    ContractObjectKind::Capability,
                    capability.id,
                    capability.generation,
                    ContractEdgeMode::CleanupEffect,
                );
            }
        }
    }

    pub(super) fn validate_display_snapshot_barriers(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for barrier in &snapshot.display_snapshot_barriers {
            let from = barrier.object_ref();
            if barrier.id == 0
                || barrier.generation == 0
                || barrier.owner_store_generation == 0
                || barrier.display_generation == 0
                || barrier.framebuffer_generation == 0
                || barrier.reason.is_empty()
                || !barrier.snapshot_validation_ok
                || barrier.state != DisplaySnapshotBarrierState::Validated
                || barrier.active_framebuffer_window_lease_count != 0
                || barrier.active_framebuffer_mapping_count != 0
                || barrier.dirty_framebuffer_region_count != 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-snapshot-barrier->contract",
                    from,
                    None,
                    "display snapshot barrier requires exact refs and quiescent display state",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-snapshot-barrier->owner-store",
                ContractObjectKind::Store,
                barrier.owner_store,
                barrier.owner_store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-snapshot-barrier->display-object",
                ContractObjectKind::DisplayObject,
                barrier.display,
                barrier.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-snapshot-barrier->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                barrier.framebuffer,
                barrier.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            match (barrier.display_cleanup, barrier.display_cleanup_generation) {
                (Some(cleanup), Some(generation)) => {
                    Self::check_generation_edge(
                        snapshot,
                        violations,
                        from,
                        "display-snapshot-barrier->display-cleanup",
                        ContractObjectKind::DisplayCleanup,
                        cleanup,
                        generation,
                        ContractEdgeMode::Historical,
                    );
                    if let Some(cleanup_record) = snapshot
                        .display_cleanups
                        .iter()
                        .find(|record| record.id == cleanup && record.generation == generation)
                    {
                        if cleanup_record.owner_store != barrier.owner_store
                            || cleanup_record.owner_store_generation
                                != barrier.owner_store_generation
                            || cleanup_record.display != barrier.display
                            || cleanup_record.display_generation != barrier.display_generation
                            || cleanup_record.framebuffer != barrier.framebuffer
                            || cleanup_record.framebuffer_generation
                                != barrier.framebuffer_generation
                            || cleanup_record.state != DisplayCleanupState::Completed
                        {
                            violations.push(ContractViolation::new(
                                ContractViolationKind::GenerationMismatch,
                                "display-snapshot-barrier->cleanup-binding",
                                from,
                                Some(cleanup_record.object_ref()),
                                "display snapshot barrier cleanup does not match the barrier target",
                            ));
                        }
                    }
                }
                (None, None) => {}
                _ => violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "display-snapshot-barrier->cleanup-ref",
                    from,
                    None,
                    "display snapshot barrier cleanup ref must be exact or absent",
                )),
            }
        }
    }

    pub(super) fn validate_display_panic_last_frames(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for frame in &snapshot.display_panic_last_frames {
            let from = frame.object_ref();
            if frame.id == 0
                || frame.generation == 0
                || frame.owner_store_generation == 0
                || frame.display_generation == 0
                || frame.framebuffer_generation == 0
                || frame.display_snapshot_barrier_generation == 0
                || frame.display_event_log_generation == 0
                || frame.framebuffer_write_generation == 0
                || frame.framebuffer_flush_region_generation == 0
                || frame.payload_digest == 0
                || frame.summary_digest == 0
                || frame.summary_record_bytes == 0
                || frame.summary_record_bytes > 4096
                || frame.panic_epoch == 0
                || frame.panic_record_kind != "contract-panic-summary-v1"
                || frame.raw_framebuffer_bytes_exported
                || frame.state != DisplayPanicLastFrameState::Recorded
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-panic-last-frame->contract",
                    from,
                    None,
                    "display panic last-frame summary requires exact refs and no raw framebuffer bytes",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "display-panic-last-frame->owner-store",
                    ContractObjectKind::Store,
                    frame.owner_store,
                    frame.owner_store_generation,
                ),
                (
                    "display-panic-last-frame->display-object",
                    ContractObjectKind::DisplayObject,
                    frame.display,
                    frame.display_generation,
                ),
                (
                    "display-panic-last-frame->framebuffer-object",
                    ContractObjectKind::FramebufferObject,
                    frame.framebuffer,
                    frame.framebuffer_generation,
                ),
                (
                    "display-panic-last-frame->snapshot-barrier",
                    ContractObjectKind::DisplaySnapshotBarrier,
                    frame.display_snapshot_barrier,
                    frame.display_snapshot_barrier_generation,
                ),
                (
                    "display-panic-last-frame->display-event-log",
                    ContractObjectKind::DisplayEventLog,
                    frame.display_event_log,
                    frame.display_event_log_generation,
                ),
                (
                    "display-panic-last-frame->framebuffer-write",
                    ContractObjectKind::FramebufferWrite,
                    frame.framebuffer_write,
                    frame.framebuffer_write_generation,
                ),
                (
                    "display-panic-last-frame->framebuffer-flush-region",
                    ContractObjectKind::FramebufferFlushRegion,
                    frame.framebuffer_flush_region,
                    frame.framebuffer_flush_region_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(barrier) = snapshot.display_snapshot_barriers.iter().find(|barrier| {
                barrier.id == frame.display_snapshot_barrier
                    && barrier.generation == frame.display_snapshot_barrier_generation
            }) {
                if barrier.owner_store != frame.owner_store
                    || barrier.owner_store_generation != frame.owner_store_generation
                    || barrier.display != frame.display
                    || barrier.display_generation != frame.display_generation
                    || barrier.framebuffer != frame.framebuffer
                    || barrier.framebuffer_generation != frame.framebuffer_generation
                    || barrier.state != DisplaySnapshotBarrierState::Validated
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-panic-last-frame->snapshot-barrier-binding",
                        from,
                        Some(barrier.object_ref()),
                        "display panic last-frame barrier does not match frame target",
                    ));
                }
            }
            if let Some(event_log) = snapshot.display_event_logs.iter().find(|event_log| {
                event_log.id == frame.display_event_log
                    && event_log.generation == frame.display_event_log_generation
            }) {
                if event_log.owner_store != frame.owner_store
                    || event_log.owner_store_generation != frame.owner_store_generation
                    || event_log.display != frame.display
                    || event_log.display_generation != frame.display_generation
                    || event_log.framebuffer != frame.framebuffer
                    || event_log.framebuffer_generation != frame.framebuffer_generation
                    || event_log.flush_count == 0
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-panic-last-frame->event-log-binding",
                        from,
                        Some(event_log.object_ref()),
                        "display panic last-frame event log does not match frame target",
                    ));
                }
            }
            if let Some(write) = snapshot.framebuffer_writes.iter().find(|write| {
                write.id == frame.framebuffer_write
                    && write.generation == frame.framebuffer_write_generation
            }) {
                if write.owner_store != frame.owner_store
                    || write.owner_store_generation != frame.owner_store_generation
                    || write.display != frame.display
                    || write.display_generation != frame.display_generation
                    || write.framebuffer != frame.framebuffer
                    || write.framebuffer_generation != frame.framebuffer_generation
                    || write.x != frame.x
                    || write.y != frame.y
                    || write.width != frame.width
                    || write.height != frame.height
                    || write.byte_offset != frame.byte_offset
                    || write.byte_len != frame.byte_len
                    || write.pixel_format != frame.pixel_format
                    || write.payload_digest != frame.payload_digest
                    || write.state != FramebufferWriteState::Applied
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-panic-last-frame->write-binding",
                        from,
                        Some(write.object_ref()),
                        "display panic last-frame write does not match frame target",
                    ));
                }
            }
            if let Some(flush) = snapshot.framebuffer_flush_regions.iter().find(|flush| {
                flush.id == frame.framebuffer_flush_region
                    && flush.generation == frame.framebuffer_flush_region_generation
            }) {
                if flush.owner_store != frame.owner_store
                    || flush.owner_store_generation != frame.owner_store_generation
                    || flush.framebuffer_write != frame.framebuffer_write
                    || flush.framebuffer_write_generation != frame.framebuffer_write_generation
                    || flush.display != frame.display
                    || flush.display_generation != frame.display_generation
                    || flush.framebuffer != frame.framebuffer
                    || flush.framebuffer_generation != frame.framebuffer_generation
                    || flush.x != frame.x
                    || flush.y != frame.y
                    || flush.width != frame.width
                    || flush.height != frame.height
                    || flush.byte_offset != frame.byte_offset
                    || flush.byte_len != frame.byte_len
                    || flush.pixel_format != frame.pixel_format
                    || flush.payload_digest != frame.payload_digest
                    || flush.state != FramebufferFlushRegionState::Applied
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-panic-last-frame->flush-binding",
                        from,
                        Some(flush.object_ref()),
                        "display panic last-frame flush does not match frame target",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_framebuffer_benchmarks(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for benchmark in &snapshot.framebuffer_benchmarks {
            let from = benchmark.object_ref();
            if benchmark.id == 0
                || benchmark.generation == 0
                || benchmark.scenario.is_empty()
                || benchmark.owner_store_generation == 0
                || benchmark.display_generation == 0
                || benchmark.framebuffer_generation == 0
                || benchmark.display_capability_generation == 0
                || benchmark.framebuffer_write_generation == 0
                || benchmark.framebuffer_flush_region_generation == 0
                || benchmark.display_event_log_generation == 0
                || benchmark.display_snapshot_barrier_generation == 0
                || benchmark.sample_frames == 0
                || benchmark.sample_bytes == 0
                || benchmark.frame_area_pixels == 0
                || benchmark.write_nanos == 0
                || benchmark.flush_nanos == 0
                || benchmark.write_nanos.checked_add(benchmark.flush_nanos)
                    != Some(benchmark.measured_nanos)
                || benchmark.measured_nanos == 0
                || benchmark.budget_nanos == 0
                || benchmark.measured_nanos > benchmark.budget_nanos
                || benchmark.p50_latency_nanos == 0
                || benchmark.p99_latency_nanos < benchmark.p50_latency_nanos
                || benchmark.p99_latency_nanos > benchmark.measured_nanos
                || benchmark.state != FramebufferBenchmarkState::Recorded
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-benchmark->contract",
                    from,
                    None,
                    "framebuffer benchmark requires exact refs, bounded timing, and recorded state",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "framebuffer-benchmark->owner-store",
                    ContractObjectKind::Store,
                    benchmark.owner_store,
                    benchmark.owner_store_generation,
                ),
                (
                    "framebuffer-benchmark->display-object",
                    ContractObjectKind::DisplayObject,
                    benchmark.display,
                    benchmark.display_generation,
                ),
                (
                    "framebuffer-benchmark->framebuffer-object",
                    ContractObjectKind::FramebufferObject,
                    benchmark.framebuffer,
                    benchmark.framebuffer_generation,
                ),
                (
                    "framebuffer-benchmark->display-capability",
                    ContractObjectKind::DisplayCapability,
                    benchmark.display_capability,
                    benchmark.display_capability_generation,
                ),
                (
                    "framebuffer-benchmark->framebuffer-write",
                    ContractObjectKind::FramebufferWrite,
                    benchmark.framebuffer_write,
                    benchmark.framebuffer_write_generation,
                ),
                (
                    "framebuffer-benchmark->framebuffer-flush-region",
                    ContractObjectKind::FramebufferFlushRegion,
                    benchmark.framebuffer_flush_region,
                    benchmark.framebuffer_flush_region_generation,
                ),
                (
                    "framebuffer-benchmark->display-event-log",
                    ContractObjectKind::DisplayEventLog,
                    benchmark.display_event_log,
                    benchmark.display_event_log_generation,
                ),
                (
                    "framebuffer-benchmark->display-snapshot-barrier",
                    ContractObjectKind::DisplaySnapshotBarrier,
                    benchmark.display_snapshot_barrier,
                    benchmark.display_snapshot_barrier_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            let expected_throughput = SemanticGraph::derive_framebuffer_throughput_bytes_per_sec(
                benchmark.sample_bytes,
                benchmark.measured_nanos,
            );
            let expected_flushes = SemanticGraph::derive_framebuffer_flushes_per_sec_milli(
                benchmark.sample_frames,
                benchmark.measured_nanos,
            );
            if expected_throughput != Some(benchmark.throughput_bytes_per_sec)
                || expected_flushes != Some(benchmark.flushes_per_sec_milli)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-benchmark->metrics",
                    from,
                    None,
                    "framebuffer benchmark derived metrics do not match samples and timing",
                ));
            }
            if let Some(write) = snapshot.framebuffer_writes.iter().find(|write| {
                write.id == benchmark.framebuffer_write
                    && write.generation == benchmark.framebuffer_write_generation
            }) {
                if write.owner_store != benchmark.owner_store
                    || write.owner_store_generation != benchmark.owner_store_generation
                    || write.display_capability != benchmark.display_capability
                    || write.display_capability_generation
                        != benchmark.display_capability_generation
                    || write.display != benchmark.display
                    || write.display_generation != benchmark.display_generation
                    || write.framebuffer != benchmark.framebuffer
                    || write.framebuffer_generation != benchmark.framebuffer_generation
                    || write.state != FramebufferWriteState::Applied
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-benchmark->write-binding",
                        from,
                        Some(write.object_ref()),
                        "framebuffer benchmark write does not match display target",
                    ));
                }
            }
            if let Some(flush) = snapshot.framebuffer_flush_regions.iter().find(|flush| {
                flush.id == benchmark.framebuffer_flush_region
                    && flush.generation == benchmark.framebuffer_flush_region_generation
            }) {
                if flush.owner_store != benchmark.owner_store
                    || flush.owner_store_generation != benchmark.owner_store_generation
                    || flush.framebuffer_write != benchmark.framebuffer_write
                    || flush.framebuffer_write_generation != benchmark.framebuffer_write_generation
                    || flush.display_capability != benchmark.display_capability
                    || flush.display_capability_generation
                        != benchmark.display_capability_generation
                    || flush.display != benchmark.display
                    || flush.display_generation != benchmark.display_generation
                    || flush.framebuffer != benchmark.framebuffer
                    || flush.framebuffer_generation != benchmark.framebuffer_generation
                    || flush.byte_len.checked_mul(u64::from(benchmark.sample_frames))
                        != Some(benchmark.sample_bytes)
                    || u64::from(flush.width).checked_mul(u64::from(flush.height))
                        != Some(benchmark.frame_area_pixels)
                    || flush.state != FramebufferFlushRegionState::Applied
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-benchmark->flush-binding",
                        from,
                        Some(flush.object_ref()),
                        "framebuffer benchmark flush does not match sampled frame",
                    ));
                }
            }
            if let Some(event_log) = snapshot.display_event_logs.iter().find(|event_log| {
                event_log.id == benchmark.display_event_log
                    && event_log.generation == benchmark.display_event_log_generation
            }) {
                if event_log.owner_store != benchmark.owner_store
                    || event_log.owner_store_generation != benchmark.owner_store_generation
                    || event_log.display_capability != benchmark.display_capability
                    || event_log.display_capability_generation
                        != benchmark.display_capability_generation
                    || event_log.display != benchmark.display
                    || event_log.display_generation != benchmark.display_generation
                    || event_log.framebuffer != benchmark.framebuffer
                    || event_log.framebuffer_generation != benchmark.framebuffer_generation
                    || event_log.flush_count < u64::from(benchmark.sample_frames)
                    || event_log.state != DisplayEventLogState::Recorded
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-benchmark->event-log-binding",
                        from,
                        Some(event_log.object_ref()),
                        "framebuffer benchmark event log does not cover the sampled flush",
                    ));
                }
            }
            if let Some(barrier) = snapshot.display_snapshot_barriers.iter().find(|barrier| {
                barrier.id == benchmark.display_snapshot_barrier
                    && barrier.generation == benchmark.display_snapshot_barrier_generation
            }) {
                if barrier.owner_store != benchmark.owner_store
                    || barrier.owner_store_generation != benchmark.owner_store_generation
                    || barrier.display != benchmark.display
                    || barrier.display_generation != benchmark.display_generation
                    || barrier.framebuffer != benchmark.framebuffer
                    || barrier.framebuffer_generation != benchmark.framebuffer_generation
                    || barrier.active_framebuffer_window_lease_count != 0
                    || barrier.active_framebuffer_mapping_count != 0
                    || barrier.dirty_framebuffer_region_count != 0
                    || barrier.state != DisplaySnapshotBarrierState::Validated
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-benchmark->snapshot-barrier-binding",
                        from,
                        Some(barrier.object_ref()),
                        "framebuffer benchmark snapshot barrier is not quiescent for the display target",
                    ));
                }
            }
        }
    }
}
