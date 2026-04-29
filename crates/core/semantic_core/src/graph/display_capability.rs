use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_display_capability(
        &self,
        display_capability: DisplayCapabilityId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display: DisplayObjectId,
        display_generation: Generation,
        capability: CapabilityId,
        capability_generation: Generation,
        handle: &CapabilityHandle,
        operations: &[String],
    ) -> Result<(), &'static str> {
        if display_capability == 0 {
            return Err("display capability id=0 is invalid");
        }
        if self.display_capabilities.iter().any(|record| record.id == display_capability) {
            return Err("display capability already exists");
        }
        if owner_store_generation == 0
            || display_generation == 0
            || capability_generation == 0
            || operations.is_empty()
            || operations.iter().any(|operation| operation.is_empty())
        {
            return Err("display capability identity values must be nonzero");
        }
        if !operations.iter().all(|operation| {
            matches!(operation.as_str(), "flush" | "present" | "lease" | "inspect")
        }) {
            return Err("display capability operation is unsupported");
        }
        let Some(store_record) = self
            .stores
            .iter()
            .find(|store| store.id == owner_store && store.generation == owner_store_generation)
        else {
            return Err("display capability owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("display capability owner store is dead");
        }
        let Some(display_record) = self.display_objects.iter().find(|record| {
            record.id == display
                && record.generation == display_generation
                && record.state == DisplayObjectState::Registered
        }) else {
            return Err("display capability display generation is missing");
        };
        if !self.framebuffer_objects.iter().any(|framebuffer| {
            framebuffer.id == display_record.framebuffer
                && framebuffer.generation == display_record.framebuffer_generation
                && framebuffer.state == FramebufferObjectState::Registered
        }) {
            return Err("display capability framebuffer generation is missing");
        }
        if handle.owner_store != owner_store
            || handle.owner_store_generation != owner_store_generation
            || handle.class_hint != CapabilityClass::Display
        {
            return Err("display capability handle mismatch");
        }
        if !operations.iter().all(|operation| handle.rights_hint.contains(operation)) {
            return Err("display capability handle rights are insufficient");
        }
        let authority =
            AuthorityObjectRef::internal(CapabilityClass::Display, display_record.object_ref());
        let capability_record = self
            .capabilities
            .check_authority(&store_record.package, authority, &operations[0], Some(handle))
            .map_err(|_| "display capability handle is not authorized")?;
        if capability_record.id != capability
            || capability_record.generation != capability_generation
            || capability_record.owner_store != Some(owner_store)
            || capability_record.owner_store_generation != Some(owner_store_generation)
            || !operations.iter().all(|operation| capability_record.operations.contains(operation))
            || !capability_record.manifest_decl
        {
            return Err("display capability attribution mismatch");
        }
        if self.display_capabilities.iter().any(|record| {
            record.owner_store == owner_store
                && record.owner_store_generation == owner_store_generation
                && record.display == display
                && record.display_generation == display_generation
                && record.state == DisplayCapabilityState::Active
        }) {
            return Err("display capability already active for display generation");
        }
        if self.check_invariants().is_err() {
            return Err("display capability requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_display_capability_with_id(
        &mut self,
        display_capability: DisplayCapabilityId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display: DisplayObjectId,
        display_generation: Generation,
        capability: CapabilityId,
        capability_generation: Generation,
        handle: CapabilityHandle,
        operations: Vec<String>,
        note: &str,
    ) -> bool {
        if self
            .validate_display_capability(
                display_capability,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                capability,
                capability_generation,
                &handle,
                &operations,
            )
            .is_err()
        {
            return false;
        }
        let Some(display_record) = self
            .display_objects
            .iter()
            .find(|record| record.id == display && record.generation == display_generation)
        else {
            return false;
        };
        let generation = 1;
        self.next_display_capability_id =
            self.next_display_capability_id.max(display_capability.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::DisplayCapabilityRecorded {
                display_capability,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                framebuffer: display_record.framebuffer,
                framebuffer_generation: display_record.framebuffer_generation,
                capability,
                capability_generation,
                handle_slot: handle.slot,
                handle_generation: handle.generation,
                handle_tag: handle.tag,
                operations: operations.clone(),
                state: DisplayCapabilityState::Active,
                generation,
            },
        );
        self.display_capabilities.push(DisplayCapabilityRecord {
            id: display_capability,
            owner_store,
            owner_store_generation,
            display,
            display_generation,
            framebuffer: display_record.framebuffer,
            framebuffer_generation: display_record.framebuffer_generation,
            capability,
            capability_generation,
            handle_slot: handle.slot,
            handle_generation: handle.generation,
            handle_tag: handle.tag,
            operations,
            generation,
            state: DisplayCapabilityState::Active,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn display_capabilities(&self) -> &[DisplayCapabilityRecord] {
        &self.display_capabilities
    }

    pub fn display_capability_count(&self) -> usize {
        self.display_capabilities.len()
    }

    pub fn check_display_capability_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.display_capabilities {
            let Some(store_record) = self.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::DisplayCapabilityMissingStore {
                    display_capability: record.id,
                    store: record.owner_store,
                });
            };
            let Some(display_record) = self.display_objects.iter().find(|display| {
                display.id == record.display && display.generation == record.display_generation
            }) else {
                return Err(SemanticInvariantError::DisplayCapabilityMissingDisplay {
                    display_capability: record.id,
                    display: record.display,
                });
            };
            let Some(framebuffer_record) = self.framebuffer_objects.iter().find(|framebuffer| {
                framebuffer.id == record.framebuffer
                    && framebuffer.generation == record.framebuffer_generation
            }) else {
                return Err(SemanticInvariantError::DisplayCapabilityMissingFramebuffer {
                    display_capability: record.id,
                    framebuffer: record.framebuffer,
                });
            };
            let Some(capability_record) = self.capabilities.record(record.capability) else {
                return Err(SemanticInvariantError::DisplayCapabilityMissingCapability {
                    display_capability: record.id,
                    capability: record.capability,
                });
            };
            let authority =
                AuthorityObjectRef::internal(CapabilityClass::Display, display_record.object_ref());
            let active = record.state == DisplayCapabilityState::Active;
            let revoked = record.state == DisplayCapabilityState::Revoked;
            if record.id == 0
                || record.generation == 0
                || record.owner_store_generation == 0
                || record.display_generation == 0
                || record.framebuffer_generation == 0
                || record.capability_generation == 0
                || record.operations.is_empty()
                || record.operations.iter().any(|operation| operation.is_empty())
                || (!active && !revoked)
                || (active && store_record.state == StoreState::Dead)
                || display_record.state != DisplayObjectState::Registered
                || framebuffer_record.state != FramebufferObjectState::Registered
                || display_record.framebuffer != record.framebuffer
                || display_record.framebuffer_generation != record.framebuffer_generation
                || capability_record.subject != store_record.package
                || capability_record.class != CapabilityClass::Display
                || capability_record.object_ref != Some(authority)
                || capability_record.owner_store != Some(record.owner_store)
                || capability_record.owner_store_generation != Some(record.owner_store_generation)
                || (active && capability_record.generation != record.capability_generation)
                || (revoked && capability_record.generation <= record.capability_generation)
                || capability_record.handle_slot != record.handle_slot
                || (active && capability_record.handle_generation != record.handle_generation)
                || (active && capability_record.handle_tag != record.handle_tag)
                || (active && capability_record.revoked)
                || (revoked && !capability_record.revoked)
                || !capability_record.manifest_decl
                || !record
                    .operations
                    .iter()
                    .all(|operation| capability_record.operations.contains(operation))
            {
                return Err(SemanticInvariantError::DisplayCapabilityInvalid {
                    display_capability: record.id,
                });
            }
            if let Some(duplicate) = self.display_capabilities.iter().find(|other| {
                other.id != record.id
                    && other.owner_store == record.owner_store
                    && other.owner_store_generation == record.owner_store_generation
                    && other.display == record.display
                    && other.display_generation == record.display_generation
                    && other.state == DisplayCapabilityState::Active
            }) {
                return Err(SemanticInvariantError::DisplayCapabilityDuplicateGrant {
                    display_capability: duplicate.id,
                    display: record.display,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DisplayCapabilityRecorded {
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
                        } if *display_capability == record.id
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *display == record.display
                            && *display_generation == record.display_generation
                            && *framebuffer == record.framebuffer
                            && *framebuffer_generation == record.framebuffer_generation
                            && *capability == record.capability
                            && *capability_generation == record.capability_generation
                            && *handle_slot == record.handle_slot
                            && *handle_generation == record.handle_generation
                            && *handle_tag == record.handle_tag
                            && operations == &record.operations
                            && *state == DisplayCapabilityState::Active
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::DisplayCapabilityMissingEvent {
                    display_capability: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_display_capability_generation_for_test(
        &mut self,
        display_capability: DisplayCapabilityId,
        capability_generation: Generation,
    ) {
        if let Some(record) =
            self.display_capabilities.iter_mut().find(|record| record.id == display_capability)
        {
            record.capability_generation = capability_generation;
        }
    }
}
