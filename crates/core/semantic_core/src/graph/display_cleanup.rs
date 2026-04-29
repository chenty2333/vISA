use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_display_cleanup(
        &self,
        cleanup: DisplayCleanupId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display_capability: DisplayCapabilityId,
        display_capability_generation: Generation,
        display: DisplayObjectId,
        display_generation: Generation,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
        reason: &str,
    ) -> Result<(), &'static str> {
        if cleanup == 0 {
            return Err("display cleanup id=0 is invalid");
        }
        if owner_store_generation == 0
            || display_capability_generation == 0
            || display_generation == 0
            || framebuffer_generation == 0
            || reason.is_empty()
        {
            return Err("display cleanup requires exact refs and reason");
        }
        if self.display_cleanups.iter().any(|record| {
            record.id == cleanup
                && (record.owner_store != owner_store
                    || record.owner_store_generation != owner_store_generation
                    || record.display_capability != display_capability
                    || record.display_capability_generation != display_capability_generation
                    || record.display != display
                    || record.display_generation != display_generation
                    || record.framebuffer != framebuffer
                    || record.framebuffer_generation != framebuffer_generation)
        }) {
            return Err("display cleanup id is already used for a different target");
        }
        if self.display_cleanups.iter().any(|record| {
            record.owner_store == owner_store
                && record.owner_store_generation == owner_store_generation
                && record.display_capability == display_capability
                && record.display_capability_generation == display_capability_generation
                && record.display == display
                && record.display_generation == display_generation
                && record.framebuffer == framebuffer
                && record.framebuffer_generation == framebuffer_generation
                && record.state == DisplayCleanupState::Completed
        }) {
            return Ok(());
        }
        let Some(store_record) = self
            .stores
            .iter()
            .find(|store| store.id == owner_store && store.generation == owner_store_generation)
        else {
            return Err("display cleanup owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("display cleanup owner store is dead");
        }
        let Some(display_capability_record) = self.display_capabilities.iter().find(|record| {
            record.id == display_capability
                && record.generation == display_capability_generation
                && record.state == DisplayCapabilityState::Active
        }) else {
            return Err("display cleanup active display capability generation is missing");
        };
        if display_capability_record.owner_store != owner_store
            || display_capability_record.owner_store_generation != owner_store_generation
            || display_capability_record.display != display
            || display_capability_record.display_generation != display_generation
            || display_capability_record.framebuffer != framebuffer
            || display_capability_record.framebuffer_generation != framebuffer_generation
        {
            return Err("display cleanup display capability binding mismatch");
        }
        let Some(capability_record) =
            self.domains.capability.capabilities.record(display_capability_record.capability)
        else {
            return Err("display cleanup capability ledger record is missing");
        };
        if capability_record.generation != display_capability_record.capability_generation
            || capability_record.revoked
            || capability_record.owner_store != Some(owner_store)
            || capability_record.owner_store_generation != Some(owner_store_generation)
        {
            return Err("display cleanup capability ledger binding mismatch");
        }
        if !self.display_objects.iter().any(|record| {
            record.id == display
                && record.generation == display_generation
                && record.framebuffer == framebuffer
                && record.framebuffer_generation == framebuffer_generation
                && record.state == DisplayObjectState::Registered
        }) {
            return Err("display cleanup display generation is missing");
        }
        if !self.framebuffer_objects.iter().any(|record| {
            record.id == framebuffer
                && record.generation == framebuffer_generation
                && record.state == FramebufferObjectState::Registered
        }) {
            return Err("display cleanup framebuffer generation is missing");
        }
        if self.check_invariants().is_err() {
            return Err("display cleanup requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cleanup_display_for_store_with_id(
        &mut self,
        cleanup: DisplayCleanupId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display_capability: DisplayCapabilityId,
        display_capability_generation: Generation,
        display: DisplayObjectId,
        display_generation: Generation,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_display_cleanup(
                cleanup,
                owner_store,
                owner_store_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                reason,
            )
            .is_err()
        {
            return false;
        }
        if self.display_cleanups.iter().any(|record| {
            record.id == cleanup
                && record.owner_store == owner_store
                && record.owner_store_generation == owner_store_generation
                && record.display_capability == display_capability
                && record.display_capability_generation == display_capability_generation
                && record.display == display
                && record.display_generation == display_generation
                && record.framebuffer == framebuffer
                && record.framebuffer_generation == framebuffer_generation
                && record.state == DisplayCleanupState::Completed
        }) {
            return true;
        }

        let generation = 1;
        self.next_display_cleanup_id = self.next_display_cleanup_id.max(cleanup + 1);
        let started_at_event = self.event_log.push(
            "display",
            EventKind::DisplayCleanupStarted {
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
            },
        );

        let store_ref =
            ContractObjectRef::new(ContractObjectKind::Store, owner_store, owner_store_generation);
        let display_capability_ref = ContractObjectRef::new(
            ContractObjectKind::DisplayCapability,
            display_capability,
            display_capability_generation,
        );
        let mapping_targets = self
            .framebuffer_mappings
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                record.owner_store == owner_store
                    && record.owner_store_generation == owner_store_generation
                    && record.display_capability == display_capability
                    && record.display_capability_generation == display_capability_generation
                    && record.display == display
                    && record.display_generation == display_generation
                    && record.framebuffer == framebuffer
                    && record.framebuffer_generation == framebuffer_generation
                    && record.state == FramebufferMappingState::Active
            })
            .map(|(index, record)| (index, record.object_ref()))
            .collect::<Vec<_>>();
        let mut unmapped_framebuffer_mappings = Vec::new();
        for (index, object) in mapping_targets {
            self.framebuffer_mappings[index].state = FramebufferMappingState::Unmapped;
            unmapped_framebuffer_mappings.push(object);
        }
        let unmap_event = self.event_log.cursor();

        let lease_targets = self
            .framebuffer_window_leases
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                record.owner_store == owner_store
                    && record.owner_store_generation == owner_store_generation
                    && record.display_capability == display_capability
                    && record.display_capability_generation == display_capability_generation
                    && record.display == display
                    && record.display_generation == display_generation
                    && record.framebuffer == framebuffer
                    && record.framebuffer_generation == framebuffer_generation
                    && record.state == FramebufferWindowLeaseState::Active
            })
            .map(|(index, record)| (index, record.object_ref()))
            .collect::<Vec<_>>();
        let mut released_framebuffer_window_leases = Vec::new();
        for (index, object) in lease_targets {
            self.framebuffer_window_leases[index].state = FramebufferWindowLeaseState::Released;
            released_framebuffer_window_leases.push(object);
        }
        let release_event = self.event_log.cursor();

        let mut revoked_display_capabilities = Vec::new();
        let mut revoked_capabilities = Vec::new();
        if let Some(index) = self.display_capabilities.iter().position(|record| {
            record.id == display_capability
                && record.generation == display_capability_generation
                && record.state == DisplayCapabilityState::Active
        }) {
            let capability = self.display_capabilities[index].capability;
            let capability_generation = self.display_capabilities[index].capability_generation;
            if self
                .domains
                .capability
                .capabilities
                .revoke_generation(capability, capability_generation)
            {
                self.event_log.push("capability", EventKind::CapabilityRevoked { cap: capability });
                let revoked_generation = self
                    .domains
                    .capability
                    .capabilities
                    .record(capability)
                    .map(|record| record.generation)
                    .unwrap_or(capability_generation);
                self.display_capabilities[index].state = DisplayCapabilityState::Revoked;
                revoked_display_capabilities.push(display_capability_ref);
                revoked_capabilities.push(ContractObjectRef::new(
                    ContractObjectKind::Capability,
                    capability,
                    revoked_generation,
                ));
            }
        }
        let revoke_event = self.event_log.cursor();

        let steps = Vec::from([
            DisplayCleanupStepRecord {
                kind: DisplayCleanupStepKind::UnmapFramebufferMappings,
                target: display_capability_ref,
                observed_generation: display_capability_generation,
                status: if unmapped_framebuffer_mappings.is_empty() {
                    DisplayCleanupStepStatus::SkippedNotPresent
                } else {
                    DisplayCleanupStepStatus::Done
                },
                event: Some(unmap_event),
            },
            DisplayCleanupStepRecord {
                kind: DisplayCleanupStepKind::ReleaseFramebufferWindowLeases,
                target: display_capability_ref,
                observed_generation: display_capability_generation,
                status: if released_framebuffer_window_leases.is_empty() {
                    DisplayCleanupStepStatus::SkippedNotPresent
                } else {
                    DisplayCleanupStepStatus::Done
                },
                event: Some(release_event),
            },
            DisplayCleanupStepRecord {
                kind: DisplayCleanupStepKind::RevokeDisplayCapabilities,
                target: store_ref,
                observed_generation: owner_store_generation,
                status: if revoked_display_capabilities.is_empty() {
                    DisplayCleanupStepStatus::SkippedNotPresent
                } else {
                    DisplayCleanupStepStatus::Done
                },
                event: Some(revoke_event),
            },
        ]);

        let completed_at_event = self.event_log.push(
            "display",
            EventKind::DisplayCleanupCompleted {
                cleanup,
                owner_store,
                owner_store_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                unmapped_framebuffer_mappings: unmapped_framebuffer_mappings.len(),
                released_framebuffer_window_leases: released_framebuffer_window_leases.len(),
                revoked_display_capabilities: revoked_display_capabilities.len(),
                generation,
            },
        );

        self.display_cleanups.push(DisplayCleanupRecord {
            id: cleanup,
            owner_store,
            owner_store_generation,
            display_capability,
            display_capability_generation,
            display,
            display_generation,
            framebuffer,
            framebuffer_generation,
            generation,
            state: DisplayCleanupState::Completed,
            reason: reason.to_string(),
            started_at_event,
            completed_at_event,
            unmapped_framebuffer_mappings,
            released_framebuffer_window_leases,
            revoked_display_capabilities,
            revoked_capabilities,
            steps,
            note: note.to_string(),
        });
        self.check_invariants().is_ok()
    }

    pub fn display_cleanups(&self) -> &[DisplayCleanupRecord] {
        &self.display_cleanups
    }

    pub fn display_cleanup_count(&self) -> usize {
        self.display_cleanups.len()
    }

    pub fn check_display_cleanup_invariants(&self) -> Result<(), SemanticInvariantError> {
        for cleanup in &self.display_cleanups {
            if cleanup.id == 0
                || cleanup.generation == 0
                || cleanup.owner_store_generation == 0
                || cleanup.display_capability_generation == 0
                || cleanup.display_generation == 0
                || cleanup.framebuffer_generation == 0
                || cleanup.reason.is_empty()
                || cleanup.state != DisplayCleanupState::Completed
            {
                return Err(SemanticInvariantError::DisplayCleanupInvalid { cleanup: cleanup.id });
            }
            if !self.stores.iter().any(|store| {
                store.id == cleanup.owner_store
                    && store.generation == cleanup.owner_store_generation
            }) {
                return Err(SemanticInvariantError::DisplayCleanupMissingStore {
                    cleanup: cleanup.id,
                    store: cleanup.owner_store,
                });
            }
            let Some(display_capability) = self.display_capabilities.iter().find(|record| {
                record.id == cleanup.display_capability
                    && record.generation == cleanup.display_capability_generation
            }) else {
                return Err(SemanticInvariantError::DisplayCleanupMissingDisplayCapability {
                    cleanup: cleanup.id,
                    display_capability: cleanup.display_capability,
                });
            };
            if display_capability.state != DisplayCapabilityState::Revoked
                || display_capability.owner_store != cleanup.owner_store
                || display_capability.owner_store_generation != cleanup.owner_store_generation
                || display_capability.display != cleanup.display
                || display_capability.display_generation != cleanup.display_generation
                || display_capability.framebuffer != cleanup.framebuffer
                || display_capability.framebuffer_generation != cleanup.framebuffer_generation
            {
                return Err(SemanticInvariantError::DisplayCleanupInvalid { cleanup: cleanup.id });
            }
            for mapping in &cleanup.unmapped_framebuffer_mappings {
                if !self.framebuffer_mappings.iter().any(|record| {
                    record.id == mapping.id
                        && record.generation == mapping.generation
                        && record.state == FramebufferMappingState::Unmapped
                }) {
                    return Err(SemanticInvariantError::DisplayCleanupMissingEffectTarget {
                        cleanup: cleanup.id,
                        target: *mapping,
                    });
                }
            }
            for lease in &cleanup.released_framebuffer_window_leases {
                if !self.framebuffer_window_leases.iter().any(|record| {
                    record.id == lease.id
                        && record.generation == lease.generation
                        && record.state == FramebufferWindowLeaseState::Released
                }) {
                    return Err(SemanticInvariantError::DisplayCleanupMissingEffectTarget {
                        cleanup: cleanup.id,
                        target: *lease,
                    });
                }
            }
            for display_capability in &cleanup.revoked_display_capabilities {
                if !self.display_capabilities.iter().any(|record| {
                    record.id == display_capability.id
                        && record.generation == display_capability.generation
                        && record.state == DisplayCapabilityState::Revoked
                }) {
                    return Err(SemanticInvariantError::DisplayCleanupMissingEffectTarget {
                        cleanup: cleanup.id,
                        target: *display_capability,
                    });
                }
            }
            for capability in &cleanup.revoked_capabilities {
                let Some(record) = self.domains.capability.capabilities.record(capability.id)
                else {
                    return Err(SemanticInvariantError::DisplayCleanupMissingEffectTarget {
                        cleanup: cleanup.id,
                        target: *capability,
                    });
                };
                if !record.revoked || record.generation != capability.generation {
                    return Err(SemanticInvariantError::DisplayCleanupInvalid {
                        cleanup: cleanup.id,
                    });
                }
            }
            let expected_steps = [
                (
                    DisplayCleanupStepKind::UnmapFramebufferMappings,
                    ContractObjectKind::DisplayCapability,
                    cleanup.display_capability,
                    cleanup.display_capability_generation,
                    cleanup.unmapped_framebuffer_mappings.is_empty(),
                ),
                (
                    DisplayCleanupStepKind::ReleaseFramebufferWindowLeases,
                    ContractObjectKind::DisplayCapability,
                    cleanup.display_capability,
                    cleanup.display_capability_generation,
                    cleanup.released_framebuffer_window_leases.is_empty(),
                ),
                (
                    DisplayCleanupStepKind::RevokeDisplayCapabilities,
                    ContractObjectKind::Store,
                    cleanup.owner_store,
                    cleanup.owner_store_generation,
                    cleanup.revoked_display_capabilities.is_empty(),
                ),
            ];
            if cleanup.steps.len() != expected_steps.len() {
                return Err(SemanticInvariantError::DisplayCleanupInvalid { cleanup: cleanup.id });
            }
            for (step, (kind, target_kind, target_id, target_generation, empty_effect)) in
                cleanup.steps.iter().zip(expected_steps)
            {
                let expected_status = if empty_effect {
                    DisplayCleanupStepStatus::SkippedNotPresent
                } else {
                    DisplayCleanupStepStatus::Done
                };
                if step.kind != kind
                    || step.target.kind != target_kind
                    || step.target.id != target_id
                    || step.target.generation != target_generation
                    || step.observed_generation != target_generation
                    || step.status != expected_status
                    || step.event.unwrap_or(0) == 0
                {
                    return Err(SemanticInvariantError::DisplayCleanupInvalid {
                        cleanup: cleanup.id,
                    });
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == cleanup.started_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DisplayCleanupStarted {
                            cleanup: event_cleanup,
                            owner_store,
                            owner_store_generation,
                            display_capability,
                            display_capability_generation,
                            display,
                            display_generation,
                            framebuffer,
                            framebuffer_generation,
                            generation,
                        } if *event_cleanup == cleanup.id
                            && *owner_store == cleanup.owner_store
                            && *owner_store_generation == cleanup.owner_store_generation
                            && *display_capability == cleanup.display_capability
                            && *display_capability_generation
                                == cleanup.display_capability_generation
                            && *display == cleanup.display
                            && *display_generation == cleanup.display_generation
                            && *framebuffer == cleanup.framebuffer
                            && *framebuffer_generation == cleanup.framebuffer_generation
                            && *generation == cleanup.generation
                    )
            }) || !self.event_log.events.iter().any(|event| {
                event.id == cleanup.completed_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DisplayCleanupCompleted {
                            cleanup: event_cleanup,
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
                        } if *event_cleanup == cleanup.id
                            && *owner_store == cleanup.owner_store
                            && *owner_store_generation == cleanup.owner_store_generation
                            && *display_capability == cleanup.display_capability
                            && *display_capability_generation
                                == cleanup.display_capability_generation
                            && *display == cleanup.display
                            && *display_generation == cleanup.display_generation
                            && *framebuffer == cleanup.framebuffer
                            && *framebuffer_generation == cleanup.framebuffer_generation
                            && *unmapped_framebuffer_mappings
                                == cleanup.unmapped_framebuffer_mappings.len()
                            && *released_framebuffer_window_leases
                                == cleanup.released_framebuffer_window_leases.len()
                            && *revoked_display_capabilities
                                == cleanup.revoked_display_capabilities.len()
                            && *generation == cleanup.generation
                    )
            }) {
                return Err(SemanticInvariantError::DisplayCleanupMissingEvent {
                    cleanup: cleanup.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_display_cleanup_mapping_effect_for_test(
        &mut self,
        cleanup: DisplayCleanupId,
        mapping_generation: Generation,
    ) {
        if let Some(record) = self.display_cleanups.iter_mut().find(|record| record.id == cleanup)
            && let Some(mapping) = record.unmapped_framebuffer_mappings.first_mut()
        {
            mapping.generation = mapping_generation;
        }
    }
}
