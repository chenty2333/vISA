use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_simd_benchmark(
        &self,
        benchmark: SimdBenchmarkId,
        target_feature_set: ContractObjectRef,
        scalar_code_object: ContractObjectRef,
        vector_code_object: ContractObjectRef,
        simd_abi: &str,
        vector_register_count: u16,
        vector_register_bits: u16,
        workload_units: u64,
        scalar_nanos: u64,
        vector_nanos: u64,
        speedup_milli: u64,
        context_overhead_nanos: u64,
    ) -> Result<(), &'static str> {
        if benchmark == 0 {
            return Err("SIMD benchmark id=0 is invalid");
        }
        if target_feature_set.kind != ContractObjectKind::TargetFeatureSet
            || scalar_code_object.kind != ContractObjectKind::CodeObject
            || vector_code_object.kind != ContractObjectKind::CodeObject
            || target_feature_set.generation == 0
            || scalar_code_object.generation == 0
            || vector_code_object.generation == 0
        {
            return Err("SIMD benchmark requires exact feature/scalar/vector code refs");
        }
        if scalar_code_object == vector_code_object {
            return Err("SIMD benchmark requires distinct scalar and vector code objects");
        }
        if simd_abi.is_empty()
            || vector_register_count == 0
            || vector_register_bits == 0
            || vector_register_bits % 8 != 0
            || workload_units == 0
            || scalar_nanos == 0
            || vector_nanos == 0
            || speedup_milli == 0
        {
            return Err("SIMD benchmark requires nonzero ABI, vector shape, workload, and metrics");
        }
        let Some(feature) = self.target_feature_sets.iter().find(|record| {
            record.id == target_feature_set.id && record.generation == target_feature_set.generation
        }) else {
            return Err("SIMD benchmark target feature set is missing");
        };
        if !feature.simd_supported
            || feature.simd_abi != simd_abi
            || feature.vector_register_count < vector_register_count
            || feature.vector_register_bits < vector_register_bits
        {
            return Err("SIMD benchmark target feature set does not satisfy vector workload");
        }
        if vector_nanos >= scalar_nanos {
            return Err("SIMD benchmark vector path must be faster than scalar path");
        }
        let expected_speedup = ((scalar_nanos as u128) * 1000u128 / (vector_nanos as u128)) as u64;
        let expected_overhead = scalar_nanos - vector_nanos;
        if speedup_milli != expected_speedup || context_overhead_nanos != expected_overhead {
            return Err("SIMD benchmark metrics do not match scalar/vector measurements");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_simd_benchmark_with_id(
        &mut self,
        benchmark: SimdBenchmarkId,
        target_feature_set: ContractObjectRef,
        scalar_code_object: ContractObjectRef,
        vector_code_object: ContractObjectRef,
        simd_abi: &str,
        vector_register_count: u16,
        vector_register_bits: u16,
        workload_units: u64,
        scalar_nanos: u64,
        vector_nanos: u64,
        speedup_milli: u64,
        context_overhead_nanos: u64,
        note: &str,
    ) -> bool {
        if self
            .simd_benchmarks
            .iter()
            .any(|record| record.id == benchmark)
        {
            return false;
        }
        if self
            .validate_simd_benchmark(
                benchmark,
                target_feature_set,
                scalar_code_object,
                vector_code_object,
                simd_abi,
                vector_register_count,
                vector_register_bits,
                workload_units,
                scalar_nanos,
                vector_nanos,
                speedup_milli,
                context_overhead_nanos,
            )
            .is_err()
        {
            return false;
        }
        self.next_simd_benchmark_id = self.next_simd_benchmark_id.max(benchmark + 1);
        let event = self.event_log.push(
            "simd-runtime",
            EventKind::SimdBenchmarkRecorded {
                benchmark,
                target_feature_set,
                scalar_code_object,
                vector_code_object,
                simd_abi: simd_abi.to_string(),
                vector_register_count,
                vector_register_bits,
                workload_units,
                scalar_nanos,
                vector_nanos,
                speedup_milli,
                context_overhead_nanos,
                generation: 1,
            },
        );
        self.simd_benchmarks.push(SimdBenchmarkRecord {
            id: benchmark,
            target_feature_set,
            scalar_code_object,
            vector_code_object,
            simd_abi: simd_abi.to_string(),
            vector_register_count,
            vector_register_bits,
            workload_units,
            scalar_nanos,
            vector_nanos,
            speedup_milli,
            context_overhead_nanos,
            generation: 1,
            state: SimdBenchmarkState::Recorded,
            recorded_at_event: event,
            note: note.to_string(),
        });
        true
    }

    pub fn simd_benchmarks(&self) -> &[SimdBenchmarkRecord] {
        &self.simd_benchmarks
    }

    pub fn simd_benchmark_count(&self) -> usize {
        self.simd_benchmarks.len()
    }

    pub fn check_simd_benchmark_invariants(&self) -> Result<(), SemanticInvariantError> {
        for benchmark in &self.simd_benchmarks {
            if benchmark.id == 0
                || benchmark.generation == 0
                || benchmark.state != SimdBenchmarkState::Recorded
                || self
                    .validate_simd_benchmark(
                        benchmark.id,
                        benchmark.target_feature_set,
                        benchmark.scalar_code_object,
                        benchmark.vector_code_object,
                        &benchmark.simd_abi,
                        benchmark.vector_register_count,
                        benchmark.vector_register_bits,
                        benchmark.workload_units,
                        benchmark.scalar_nanos,
                        benchmark.vector_nanos,
                        benchmark.speedup_milli,
                        benchmark.context_overhead_nanos,
                    )
                    .is_err()
            {
                return Err(SemanticInvariantError::SimdBenchmarkInvalid {
                    benchmark: benchmark.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == benchmark.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SimdBenchmarkRecorded {
                            benchmark: event_benchmark,
                            target_feature_set,
                            scalar_code_object,
                            vector_code_object,
                            simd_abi,
                            vector_register_count,
                            vector_register_bits,
                            workload_units,
                            scalar_nanos,
                            vector_nanos,
                            speedup_milli,
                            context_overhead_nanos,
                            generation,
                        } if *event_benchmark == benchmark.id
                            && *target_feature_set == benchmark.target_feature_set
                            && *scalar_code_object == benchmark.scalar_code_object
                            && *vector_code_object == benchmark.vector_code_object
                            && simd_abi == &benchmark.simd_abi
                            && *vector_register_count == benchmark.vector_register_count
                            && *vector_register_bits == benchmark.vector_register_bits
                            && *workload_units == benchmark.workload_units
                            && *scalar_nanos == benchmark.scalar_nanos
                            && *vector_nanos == benchmark.vector_nanos
                            && *speedup_milli == benchmark.speedup_milli
                            && *context_overhead_nanos == benchmark.context_overhead_nanos
                            && *generation == benchmark.generation
                    )
            }) {
                return Err(SemanticInvariantError::SimdBenchmarkMissingEvent {
                    benchmark: benchmark.id,
                    event: benchmark.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_simd_benchmark_speedup_for_test(
        &mut self,
        benchmark: SimdBenchmarkId,
        speedup_milli: u64,
    ) {
        if let Some(record) = self
            .simd_benchmarks
            .iter_mut()
            .find(|record| record.id == benchmark)
        {
            record.speedup_milli = speedup_milli;
        }
    }
}
