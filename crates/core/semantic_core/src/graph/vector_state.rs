use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_vector_state(
        &self,
        vector_state: VectorStateId,
        owner_activation: ContractObjectRef,
        owner_store: ContractObjectRef,
        code_object: ContractObjectRef,
        target_feature_set: ContractObjectRef,
        simd_abi: &str,
        vector_register_count: u16,
        vector_register_bits: u16,
        register_bytes: u32,
        state: VectorStateState,
    ) -> Result<(), &'static str> {
        if vector_state == 0 {
            return Err("vector state id=0 is invalid");
        }
        if vector_state == u64::MAX {
            return Err("vector state id cannot advance generation cursor");
        }
        if self.vector_states.iter().any(|record| record.id == vector_state) {
            return Err("vector state already exists");
        }
        if owner_activation.kind != ContractObjectKind::Activation
            || owner_activation.id == 0
            || owner_activation.generation == 0
        {
            return Err("vector state owner activation must be an exact activation ref");
        }
        if owner_store.kind != ContractObjectKind::Store
            || owner_store.id == 0
            || owner_store.generation == 0
        {
            return Err("vector state owner store must be an exact store ref");
        }
        if code_object.kind != ContractObjectKind::CodeObject
            || code_object.id == 0
            || code_object.generation == 0
        {
            return Err("vector state code object must be an exact code object ref");
        }
        if target_feature_set.kind != ContractObjectKind::TargetFeatureSet
            || target_feature_set.id == 0
            || target_feature_set.generation == 0
        {
            return Err("vector state target feature set must be an exact target feature ref");
        }
        if simd_abi.is_empty() || vector_register_count == 0 || vector_register_bits == 0 {
            return Err("vector state requires a SIMD ABI and vector register shape");
        }
        if !vector_register_bits.is_multiple_of(8) {
            return Err("vector state register bits must be byte aligned");
        }
        let expected_bytes =
            u32::from(vector_register_count) * (u32::from(vector_register_bits) / 8);
        if register_bytes != expected_bytes {
            return Err("vector state byte footprint does not match vector shape");
        }

        let Some(feature) = self.target_feature_sets.iter().find(|feature| {
            feature.id == target_feature_set.id
                && feature.generation == target_feature_set.generation
        }) else {
            return Err("vector state references missing target feature set");
        };
        if feature.simd_abi != simd_abi {
            return Err("vector state SIMD ABI does not match target feature set");
        }
        match state {
            VectorStateState::Reserved => {
                if !feature.simd_supported {
                    return Err("reserved vector state requires supported SIMD target feature set");
                }
                if feature.vector_register_count < vector_register_count
                    || feature.vector_register_bits < vector_register_bits
                {
                    return Err("reserved vector state exceeds target vector shape");
                }
            }
            VectorStateState::Unavailable => {
                if feature.simd_supported || feature.unsupported_reason.is_empty() {
                    return Err(
                        "unavailable vector state requires unsupported SIMD target feature set",
                    );
                }
            }
            VectorStateState::Dropped => {}
        }
        if self.check_invariants().is_err() {
            return Err("vector state record requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_vector_state_with_id(
        &mut self,
        vector_state: VectorStateId,
        owner_activation: ContractObjectRef,
        owner_store: ContractObjectRef,
        code_object: ContractObjectRef,
        target_feature_set: ContractObjectRef,
        simd_abi: &str,
        vector_register_count: u16,
        vector_register_bits: u16,
        register_bytes: u32,
        state: VectorStateState,
        note: &str,
    ) -> bool {
        if self
            .validate_vector_state(
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
            )
            .is_err()
        {
            return false;
        }

        let generation = 1;
        self.next_vector_state_id = self.next_vector_state_id.max(vector_state.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "target",
            EventKind::VectorStateRecorded {
                vector_state,
                owner_activation,
                owner_store,
                code_object,
                target_feature_set,
                simd_abi: simd_abi.to_string(),
                vector_register_count,
                vector_register_bits,
                register_bytes,
                state,
                generation,
            },
        );
        self.vector_states.push(VectorStateRecord {
            id: vector_state,
            owner_activation,
            owner_store,
            code_object,
            target_feature_set,
            simd_abi: simd_abi.to_string(),
            vector_register_count,
            vector_register_bits,
            register_bytes,
            generation,
            state,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn vector_states(&self) -> &[VectorStateRecord] {
        &self.vector_states
    }

    pub fn vector_state_count(&self) -> usize {
        self.vector_states.len()
    }

    pub fn check_vector_state_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.vector_states {
            if record.id == 0
                || record.generation == 0
                || record.simd_abi.is_empty()
                || record.vector_register_count == 0
                || record.vector_register_bits == 0
                || !record.vector_register_bits.is_multiple_of(8)
                || record.register_bytes
                    != u32::from(record.vector_register_count)
                        * (u32::from(record.vector_register_bits) / 8)
                || record.recorded_at_event == 0
            {
                return Err(SemanticInvariantError::VectorStateInvalid { vector_state: record.id });
            }
            let feature = self.target_feature_sets.iter().find(|feature| {
                feature.id == record.target_feature_set.id
                    && feature.generation == record.target_feature_set.generation
            });
            let Some(feature) = feature else {
                return Err(SemanticInvariantError::VectorStateMissingTargetFeatureSet {
                    vector_state: record.id,
                    target_feature_set: record.target_feature_set,
                });
            };
            if record.target_feature_set.kind != ContractObjectKind::TargetFeatureSet
                || record.owner_activation.kind != ContractObjectKind::Activation
                || record.owner_store.kind != ContractObjectKind::Store
                || record.code_object.kind != ContractObjectKind::CodeObject
                || feature.simd_abi != record.simd_abi
            {
                return Err(SemanticInvariantError::VectorStateInvalid { vector_state: record.id });
            }
            match record.state {
                VectorStateState::Reserved => {
                    if !feature.simd_supported
                        || feature.vector_register_count < record.vector_register_count
                        || feature.vector_register_bits < record.vector_register_bits
                    {
                        return Err(SemanticInvariantError::VectorStateInvalid {
                            vector_state: record.id,
                        });
                    }
                }
                VectorStateState::Unavailable => {
                    if feature.simd_supported || feature.unsupported_reason.is_empty() {
                        return Err(SemanticInvariantError::VectorStateInvalid {
                            vector_state: record.id,
                        });
                    }
                }
                VectorStateState::Dropped => {}
            }
            let has_state_event = self.event_log.events.iter().any(|event| {
                if event.id != record.recorded_at_event {
                    return false;
                }
                let recorded_event_matches = matches!(
                    &event.kind,
                    EventKind::VectorStateRecorded {
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
                    } if *vector_state == record.id
                        && *owner_activation == record.owner_activation
                        && *owner_store == record.owner_store
                        && *code_object == record.code_object
                        && *target_feature_set == record.target_feature_set
                        && simd_abi == &record.simd_abi
                        && *vector_register_count == record.vector_register_count
                        && *vector_register_bits == record.vector_register_bits
                        && *register_bytes == record.register_bytes
                        && *state == record.state
                        && *generation == record.generation
                );
                let resume_release_event_matches = matches!(
                    &event.kind,
                    EventKind::VectorStateReleasedOnResume {
                        vector_state,
                        generation,
                        ..
                    } if record.state == VectorStateState::Dropped
                        && *vector_state == record.object_ref()
                        && *generation == 1
                );
                let migration_release_event_matches = matches!(
                    &event.kind,
                    EventKind::VectorStateMigratedAcrossHart {
                        source_vector_state,
                        generation,
                        ..
                    } if record.state == VectorStateState::Dropped
                        && *source_vector_state == record.object_ref()
                        && *generation == 1
                );
                recorded_event_matches
                    || resume_release_event_matches
                    || migration_release_event_matches
            });
            if !has_state_event {
                return Err(SemanticInvariantError::VectorStateMissingEvent {
                    vector_state: record.id,
                    event: record.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_vector_state_owner_activation_generation_for_test(
        &mut self,
        vector_state: VectorStateId,
        generation: Generation,
    ) {
        if let Some(record) = self.vector_states.iter_mut().find(|record| record.id == vector_state)
        {
            record.owner_activation.generation = generation;
        }
    }
}
