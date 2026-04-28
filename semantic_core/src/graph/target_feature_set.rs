use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_target_feature_set(
        &self,
        feature_set: TargetFeatureSetId,
        name: &str,
        discovery_source: &str,
        target_profile: &str,
        target_arch: &str,
        base_isa: &str,
        simd_abi: &str,
        simd_supported: bool,
        vector_register_count: u16,
        vector_register_bits: u16,
        scalar_fallback: bool,
        unsupported_reason: &str,
    ) -> Result<(), &'static str> {
        if feature_set == 0 {
            return Err("target feature set id=0 is invalid");
        }
        if feature_set == u64::MAX {
            return Err("target feature set id cannot advance generation cursor");
        }
        if self
            .target_feature_sets
            .iter()
            .any(|record| record.id == feature_set)
        {
            return Err("target feature set already exists");
        }
        if name.is_empty()
            || discovery_source.is_empty()
            || target_profile.is_empty()
            || target_arch.is_empty()
            || base_isa.is_empty()
            || simd_abi.is_empty()
        {
            return Err("target feature set identity fields must be nonempty");
        }
        if simd_supported {
            if vector_register_count == 0 || vector_register_bits == 0 {
                return Err("supported SIMD discovery requires vector register shape");
            }
            if !unsupported_reason.is_empty() {
                return Err("supported SIMD discovery cannot carry an unsupported reason");
            }
        } else {
            if vector_register_count != 0 || vector_register_bits != 0 {
                return Err("unsupported SIMD discovery cannot expose vector registers");
            }
            if !scalar_fallback {
                return Err("unsupported SIMD discovery requires scalar fallback");
            }
            if unsupported_reason.is_empty() {
                return Err("unsupported SIMD discovery requires a reason");
            }
        }
        if self.check_invariants().is_err() {
            return Err("target feature set discovery requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_target_feature_set_with_id(
        &mut self,
        feature_set: TargetFeatureSetId,
        name: &str,
        discovery_source: &str,
        target_profile: &str,
        target_arch: &str,
        base_isa: &str,
        simd_abi: &str,
        simd_supported: bool,
        vector_register_count: u16,
        vector_register_bits: u16,
        scalar_fallback: bool,
        unsupported_reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_target_feature_set(
                feature_set,
                name,
                discovery_source,
                target_profile,
                target_arch,
                base_isa,
                simd_abi,
                simd_supported,
                vector_register_count,
                vector_register_bits,
                scalar_fallback,
                unsupported_reason,
            )
            .is_err()
        {
            return false;
        }

        let generation = 1;
        self.next_target_feature_set_id = self
            .next_target_feature_set_id
            .max(feature_set.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "target",
            EventKind::TargetFeatureSetDiscovered {
                feature_set,
                target_profile: target_profile.to_string(),
                target_arch: target_arch.to_string(),
                base_isa: base_isa.to_string(),
                simd_abi: simd_abi.to_string(),
                simd_supported,
                vector_register_count,
                vector_register_bits,
                scalar_fallback,
                generation,
            },
        );
        self.target_feature_sets.push(TargetFeatureSetRecord {
            id: feature_set,
            name: name.to_string(),
            discovery_source: discovery_source.to_string(),
            target_profile: target_profile.to_string(),
            target_arch: target_arch.to_string(),
            base_isa: base_isa.to_string(),
            simd_abi: simd_abi.to_string(),
            simd_supported,
            vector_register_count,
            vector_register_bits,
            scalar_fallback,
            unsupported_reason: unsupported_reason.to_string(),
            generation,
            state: TargetFeatureSetState::Discovered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn target_feature_sets(&self) -> &[TargetFeatureSetRecord] {
        &self.target_feature_sets
    }

    pub fn target_feature_set_count(&self) -> usize {
        self.target_feature_sets.len()
    }

    pub fn check_target_feature_set_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.target_feature_sets {
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.discovery_source.is_empty()
                || record.target_profile.is_empty()
                || record.target_arch.is_empty()
                || record.base_isa.is_empty()
                || record.simd_abi.is_empty()
                || record.state != TargetFeatureSetState::Discovered
                || record.recorded_at_event == 0
            {
                return Err(SemanticInvariantError::TargetFeatureSetInvalid {
                    feature_set: record.id,
                });
            }
            if record.simd_supported {
                if record.vector_register_count == 0
                    || record.vector_register_bits == 0
                    || !record.unsupported_reason.is_empty()
                {
                    return Err(SemanticInvariantError::TargetFeatureSetInvalid {
                        feature_set: record.id,
                    });
                }
            } else if record.vector_register_count != 0
                || record.vector_register_bits != 0
                || !record.scalar_fallback
                || record.unsupported_reason.is_empty()
            {
                return Err(SemanticInvariantError::TargetFeatureSetInvalid {
                    feature_set: record.id,
                });
            }

            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::TargetFeatureSetDiscovered {
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
                        } if *feature_set == record.id
                            && target_profile == &record.target_profile
                            && target_arch == &record.target_arch
                            && base_isa == &record.base_isa
                            && simd_abi == &record.simd_abi
                            && *simd_supported == record.simd_supported
                            && *vector_register_count == record.vector_register_count
                            && *vector_register_bits == record.vector_register_bits
                            && *scalar_fallback == record.scalar_fallback
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::TargetFeatureSetMissingEvent {
                    feature_set: record.id,
                    event: record.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_target_feature_set_vector_shape_for_test(
        &mut self,
        feature_set: TargetFeatureSetId,
        vector_register_bits: u16,
    ) {
        if let Some(record) = self
            .target_feature_sets
            .iter_mut()
            .find(|record| record.id == feature_set)
        {
            record.vector_register_bits = vector_register_bits;
        }
    }
}
