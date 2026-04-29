use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_simd_context_switch_benchmark(
        &self,
        benchmark: SimdContextSwitchBenchmarkId,
        preemption: ContractObjectRef,
        activation_resume: ContractObjectRef,
        saved_vector_state: ContractObjectRef,
        restored_vector_state: ContractObjectRef,
        target_feature_set: ContractObjectRef,
        simd_abi: &str,
        vector_register_count: u16,
        vector_register_bits: u16,
        sample_count: u64,
        scalar_context_switch_nanos: u64,
        vector_context_switch_nanos: u64,
        overhead_nanos: u64,
        budget_nanos: u64,
    ) -> Result<(), &'static str> {
        if benchmark == 0 {
            return Err("SIMD context switch benchmark id=0 is invalid");
        }
        if preemption.kind != ContractObjectKind::Preemption
            || activation_resume.kind != ContractObjectKind::ActivationResume
            || saved_vector_state.kind != ContractObjectKind::VectorState
            || restored_vector_state.kind != ContractObjectKind::VectorState
            || target_feature_set.kind != ContractObjectKind::TargetFeatureSet
            || preemption.generation == 0
            || activation_resume.generation == 0
            || saved_vector_state.generation == 0
            || restored_vector_state.generation == 0
            || target_feature_set.generation == 0
        {
            return Err("SIMD context switch benchmark requires exact preempt/resume/vector refs");
        }
        if simd_abi.is_empty()
            || vector_register_count == 0
            || vector_register_bits == 0
            || vector_register_bits % 8 != 0
            || sample_count == 0
            || scalar_context_switch_nanos == 0
            || vector_context_switch_nanos == 0
            || budget_nanos == 0
        {
            return Err("SIMD context switch benchmark requires nonzero shape and metrics");
        }
        let Some(feature) = self.target_feature_sets.iter().find(|record| {
            record.id == target_feature_set.id && record.generation == target_feature_set.generation
        }) else {
            return Err("SIMD context switch benchmark target feature set is missing");
        };
        let Some(preemption_record) = self.preemptions.iter().find(|record| {
            record.id == preemption.id && record.generation == preemption.generation
        }) else {
            return Err("SIMD context switch benchmark preemption record is missing");
        };
        let Some(resume_record) = self.activation_resumes.iter().find(|record| {
            record.id == activation_resume.id && record.generation == activation_resume.generation
        }) else {
            return Err("SIMD context switch benchmark activation resume record is missing");
        };
        if preemption_record.activation != resume_record.activation
            || preemption_record.activation_generation_after
                != resume_record.activation_generation_before
        {
            return Err("SIMD context switch benchmark preempt/resume generations do not match");
        }
        if resume_record.saved_vector_state != Some(saved_vector_state)
            || resume_record.restored_vector_state != Some(restored_vector_state)
            || resume_record.vector_status != ActivationVectorState::Clean
        {
            return Err("SIMD context switch benchmark resume vector refs do not match");
        }
        let Some(saved_vector) = self.vector_states.iter().find(|record| {
            record.id == saved_vector_state.id && record.generation == saved_vector_state.generation
        }) else {
            return Err("SIMD context switch benchmark saved vector state is missing");
        };
        let Some(restored_vector) = self.vector_states.iter().find(|record| {
            record.id == restored_vector_state.id
                && record.generation == restored_vector_state.generation
        }) else {
            return Err("SIMD context switch benchmark restored vector state is missing");
        };
        if saved_vector.target_feature_set != target_feature_set
            || restored_vector.target_feature_set != target_feature_set
            || saved_vector.simd_abi != simd_abi
            || restored_vector.simd_abi != simd_abi
            || saved_vector.vector_register_count != vector_register_count
            || restored_vector.vector_register_count != vector_register_count
            || saved_vector.vector_register_bits != vector_register_bits
            || restored_vector.vector_register_bits != vector_register_bits
        {
            return Err("SIMD context switch benchmark vector state shape does not match");
        }
        if !feature.simd_supported
            || feature.simd_abi != simd_abi
            || feature.vector_register_count < vector_register_count
            || feature.vector_register_bits < vector_register_bits
        {
            return Err(
                "SIMD context switch benchmark target feature set does not satisfy vector shape",
            );
        }
        if vector_context_switch_nanos <= scalar_context_switch_nanos {
            return Err("SIMD context switch benchmark vector path must include extra cost");
        }
        let expected_overhead = vector_context_switch_nanos - scalar_context_switch_nanos;
        if overhead_nanos != expected_overhead {
            return Err("SIMD context switch benchmark overhead does not match measurements");
        }
        if overhead_nanos > budget_nanos {
            return Err("SIMD context switch benchmark overhead exceeds budget");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_simd_context_switch_benchmark_with_id(
        &mut self,
        benchmark: SimdContextSwitchBenchmarkId,
        preemption: ContractObjectRef,
        activation_resume: ContractObjectRef,
        saved_vector_state: ContractObjectRef,
        restored_vector_state: ContractObjectRef,
        target_feature_set: ContractObjectRef,
        simd_abi: &str,
        vector_register_count: u16,
        vector_register_bits: u16,
        sample_count: u64,
        scalar_context_switch_nanos: u64,
        vector_context_switch_nanos: u64,
        overhead_nanos: u64,
        budget_nanos: u64,
        note: &str,
    ) -> bool {
        if self.simd_context_switch_benchmarks.iter().any(|record| record.id == benchmark) {
            return false;
        }
        if self
            .validate_simd_context_switch_benchmark(
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
            )
            .is_err()
        {
            return false;
        }
        self.next_simd_context_switch_benchmark_id =
            self.next_simd_context_switch_benchmark_id.max(benchmark + 1);
        let event = self.event_log.push(
            "simd-runtime",
            EventKind::SimdContextSwitchBenchmarkRecorded {
                benchmark,
                preemption,
                activation_resume,
                saved_vector_state,
                restored_vector_state,
                target_feature_set,
                simd_abi: simd_abi.to_string(),
                vector_register_count,
                vector_register_bits,
                sample_count,
                scalar_context_switch_nanos,
                vector_context_switch_nanos,
                overhead_nanos,
                budget_nanos,
                generation: 1,
            },
        );
        self.simd_context_switch_benchmarks.push(SimdContextSwitchBenchmarkRecord {
            id: benchmark,
            preemption,
            activation_resume,
            saved_vector_state,
            restored_vector_state,
            target_feature_set,
            simd_abi: simd_abi.to_string(),
            vector_register_count,
            vector_register_bits,
            sample_count,
            scalar_context_switch_nanos,
            vector_context_switch_nanos,
            overhead_nanos,
            budget_nanos,
            generation: 1,
            state: SimdContextSwitchBenchmarkState::Recorded,
            recorded_at_event: event,
            note: note.to_string(),
        });
        true
    }

    pub fn simd_context_switch_benchmarks(&self) -> &[SimdContextSwitchBenchmarkRecord] {
        &self.simd_context_switch_benchmarks
    }

    pub fn simd_context_switch_benchmark_count(&self) -> usize {
        self.simd_context_switch_benchmarks.len()
    }

    pub fn check_simd_context_switch_benchmark_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for benchmark in &self.simd_context_switch_benchmarks {
            if benchmark.id == 0
                || benchmark.generation == 0
                || benchmark.state != SimdContextSwitchBenchmarkState::Recorded
                || self
                    .validate_simd_context_switch_benchmark(
                        benchmark.id,
                        benchmark.preemption,
                        benchmark.activation_resume,
                        benchmark.saved_vector_state,
                        benchmark.restored_vector_state,
                        benchmark.target_feature_set,
                        &benchmark.simd_abi,
                        benchmark.vector_register_count,
                        benchmark.vector_register_bits,
                        benchmark.sample_count,
                        benchmark.scalar_context_switch_nanos,
                        benchmark.vector_context_switch_nanos,
                        benchmark.overhead_nanos,
                        benchmark.budget_nanos,
                    )
                    .is_err()
            {
                return Err(SemanticInvariantError::SimdContextSwitchBenchmarkInvalid {
                    benchmark: benchmark.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == benchmark.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SimdContextSwitchBenchmarkRecorded {
                            benchmark: event_benchmark,
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
                        } if *event_benchmark == benchmark.id
                            && *preemption == benchmark.preemption
                            && *activation_resume == benchmark.activation_resume
                            && *saved_vector_state == benchmark.saved_vector_state
                            && *restored_vector_state == benchmark.restored_vector_state
                            && *target_feature_set == benchmark.target_feature_set
                            && simd_abi == &benchmark.simd_abi
                            && *vector_register_count == benchmark.vector_register_count
                            && *vector_register_bits == benchmark.vector_register_bits
                            && *sample_count == benchmark.sample_count
                            && *scalar_context_switch_nanos
                                == benchmark.scalar_context_switch_nanos
                            && *vector_context_switch_nanos
                                == benchmark.vector_context_switch_nanos
                            && *overhead_nanos == benchmark.overhead_nanos
                            && *budget_nanos == benchmark.budget_nanos
                            && *generation == benchmark.generation
                    )
            }) {
                return Err(SemanticInvariantError::SimdContextSwitchBenchmarkMissingEvent {
                    benchmark: benchmark.id,
                    event: benchmark.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_simd_context_switch_overhead_for_test(
        &mut self,
        benchmark: SimdContextSwitchBenchmarkId,
        overhead_nanos: u64,
    ) {
        if let Some(record) =
            self.simd_context_switch_benchmarks.iter_mut().find(|record| record.id == benchmark)
        {
            record.overhead_nanos = overhead_nanos;
        }
    }
}
