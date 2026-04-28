use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_simd_fault_injection(
        &self,
        injection: SimdFaultInjectionId,
        activation: ContractObjectRef,
        code_object: ContractObjectRef,
        trap: ContractObjectRef,
        target_feature_set: ContractObjectRef,
        vector_state: Option<ContractObjectRef>,
        kind: SimdFaultInjectionKind,
        effect: SimdFaultInjectionEffect,
        required_abi: &str,
        vector_register_count: u16,
        vector_register_bits: u16,
        injected_faults: u32,
    ) -> Result<(), &'static str> {
        if injection == 0 {
            return Err("SIMD fault injection id=0 is invalid");
        }
        if self
            .simd_fault_injections
            .iter()
            .any(|record| record.id == injection)
        {
            return Err("SIMD fault injection already exists");
        }
        if activation.kind != ContractObjectKind::Activation
            || code_object.kind != ContractObjectKind::CodeObject
            || trap.kind != ContractObjectKind::Trap
            || target_feature_set.kind != ContractObjectKind::TargetFeatureSet
            || activation.generation == 0
            || code_object.generation == 0
            || trap.generation == 0
            || target_feature_set.generation == 0
        {
            return Err("SIMD fault injection requires exact activation/code/trap/feature refs");
        }
        if let Some(vector_state) = vector_state {
            if vector_state.kind != ContractObjectKind::VectorState || vector_state.generation == 0
            {
                return Err("SIMD fault injection vector state ref is invalid");
            }
        }
        if required_abi.is_empty()
            || vector_register_count == 0
            || vector_register_bits == 0
            || vector_register_bits % 8 != 0
            || injected_faults == 0
        {
            return Err("SIMD fault injection requires ABI, vector shape, and fault count");
        }
        match kind {
            SimdFaultInjectionKind::UnsupportedFeature => {
                if vector_state.is_some() {
                    return Err(
                        "unsupported SIMD fault injection must record a trap without live vector state",
                    );
                }
            }
            SimdFaultInjectionKind::IllegalInstruction => {
                if effect != SimdFaultInjectionEffect::ActivationTrapped {
                    return Err("SIMD illegal instruction injection must trap the activation");
                }
            }
        }
        let Some(feature) = self.target_feature_sets.iter().find(|record| {
            record.id == target_feature_set.id && record.generation == target_feature_set.generation
        }) else {
            return Err("SIMD fault injection target feature set is missing");
        };
        if feature.simd_abi != required_abi {
            return Err(
                "SIMD fault injection feature set does not satisfy the requested vector shape",
            );
        }
        if kind == SimdFaultInjectionKind::UnsupportedFeature && feature.simd_supported {
            return Err("unsupported SIMD fault injection requires an unsupported feature set");
        }
        if kind == SimdFaultInjectionKind::IllegalInstruction && !feature.simd_supported {
            return Err("SIMD illegal instruction injection requires a supported feature set");
        }
        if kind == SimdFaultInjectionKind::IllegalInstruction
            && (feature.vector_register_count < vector_register_count
                || feature.vector_register_bits < vector_register_bits)
        {
            return Err(
                "SIMD fault injection feature set does not satisfy the requested vector shape",
            );
        }
        if let Some(vector_state_ref) = vector_state {
            let Some(vector_record) = self.vector_states.iter().find(|record| {
                record.id == vector_state_ref.id && record.generation == vector_state_ref.generation
            }) else {
                return Err("SIMD fault injection vector state generation is missing");
            };
            if !vector_record.state.is_live_owned()
                || vector_record.owner_activation != activation
                || vector_record.code_object != code_object
                || vector_record.target_feature_set != target_feature_set
            {
                return Err(
                    "SIMD fault injection vector state does not match activation/code/feature",
                );
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_simd_fault_injection_with_id(
        &mut self,
        injection: SimdFaultInjectionId,
        activation: ContractObjectRef,
        code_object: ContractObjectRef,
        trap: ContractObjectRef,
        target_feature_set: ContractObjectRef,
        vector_state: Option<ContractObjectRef>,
        kind: SimdFaultInjectionKind,
        effect: SimdFaultInjectionEffect,
        required_abi: &str,
        vector_register_count: u16,
        vector_register_bits: u16,
        injected_faults: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_simd_fault_injection(
                injection,
                activation,
                code_object,
                trap,
                target_feature_set,
                vector_state,
                kind,
                effect,
                required_abi,
                vector_register_count,
                vector_register_bits,
                injected_faults,
            )
            .is_err()
        {
            return false;
        }
        self.next_simd_fault_injection_id = self.next_simd_fault_injection_id.max(injection + 1);
        let event = self.event_log.push(
            "simd-runtime",
            EventKind::SimdFaultInjectionRecorded {
                injection,
                activation,
                code_object,
                trap,
                target_feature_set,
                vector_state,
                kind,
                effect,
                generation: 1,
            },
        );
        self.simd_fault_injections.push(SimdFaultInjectionRecord {
            id: injection,
            activation,
            code_object,
            trap,
            target_feature_set,
            vector_state,
            kind,
            effect,
            required_abi: required_abi.to_string(),
            vector_register_count,
            vector_register_bits,
            injected_faults,
            generation: 1,
            state: SimdFaultInjectionState::Recorded,
            recorded_at_event: event,
            note: note.to_string(),
        });
        true
    }

    pub fn simd_fault_injections(&self) -> &[SimdFaultInjectionRecord] {
        &self.simd_fault_injections
    }

    pub fn simd_fault_injection_count(&self) -> usize {
        self.simd_fault_injections.len()
    }

    pub fn check_simd_fault_injection_invariants(&self) -> Result<(), SemanticInvariantError> {
        for injection in &self.simd_fault_injections {
            if injection.id == 0
                || injection.generation == 0
                || injection.state != SimdFaultInjectionState::Recorded
                || injection.required_abi.is_empty()
                || injection.vector_register_count == 0
                || injection.vector_register_bits == 0
                || injection.injected_faults == 0
                || injection.activation.kind != ContractObjectKind::Activation
                || injection.code_object.kind != ContractObjectKind::CodeObject
                || injection.trap.kind != ContractObjectKind::Trap
                || injection.target_feature_set.kind != ContractObjectKind::TargetFeatureSet
            {
                return Err(SemanticInvariantError::SimdFaultInjectionInvalid {
                    injection: injection.id,
                });
            }
            let Some(feature) = self.target_feature_sets.iter().find(|record| {
                record.id == injection.target_feature_set.id
                    && record.generation == injection.target_feature_set.generation
            }) else {
                return Err(SemanticInvariantError::SimdFaultInjectionMissingTarget {
                    injection: injection.id,
                    target: injection.target_feature_set,
                });
            };
            if feature.simd_abi != injection.required_abi
                || (injection.kind == SimdFaultInjectionKind::IllegalInstruction
                    && (feature.vector_register_count < injection.vector_register_count
                        || feature.vector_register_bits < injection.vector_register_bits))
                || (injection.kind == SimdFaultInjectionKind::UnsupportedFeature
                    && (feature.simd_supported || injection.vector_state.is_some()))
                || (injection.kind == SimdFaultInjectionKind::IllegalInstruction
                    && (!feature.simd_supported
                        || injection.effect != SimdFaultInjectionEffect::ActivationTrapped))
            {
                return Err(SemanticInvariantError::SimdFaultInjectionInvalid {
                    injection: injection.id,
                });
            }
            if let Some(vector_state) = injection.vector_state {
                let Some(vector_record) = self.vector_states.iter().find(|record| {
                    record.id == vector_state.id && record.generation == vector_state.generation
                }) else {
                    return Err(SemanticInvariantError::SimdFaultInjectionMissingTarget {
                        injection: injection.id,
                        target: vector_state,
                    });
                };
                if !vector_record.state.is_live_owned()
                    || vector_record.owner_activation != injection.activation
                    || vector_record.code_object != injection.code_object
                    || vector_record.target_feature_set != injection.target_feature_set
                {
                    return Err(SemanticInvariantError::SimdFaultInjectionInvalid {
                        injection: injection.id,
                    });
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == injection.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SimdFaultInjectionRecorded {
                            injection: event_injection,
                            activation,
                            code_object,
                            trap,
                            target_feature_set,
                            vector_state,
                            kind,
                            effect,
                            generation,
                        } if *event_injection == injection.id
                            && *activation == injection.activation
                            && *code_object == injection.code_object
                            && *trap == injection.trap
                            && *target_feature_set == injection.target_feature_set
                            && *vector_state == injection.vector_state
                            && *kind == injection.kind
                            && *effect == injection.effect
                            && *generation == injection.generation
                    )
            }) {
                return Err(SemanticInvariantError::SimdFaultInjectionMissingEvent {
                    injection: injection.id,
                    event: injection.recorded_at_event,
                });
            }
        }
        Ok(())
    }
}
