use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_integrated_simd_migration(
        &self,
        integrated: IntegratedSimdMigrationId,
        scenario: &str,
        activation_migration: ActivationMigrationId,
        activation_migration_generation: Generation,
        invariant_checks: u32,
    ) -> Result<(), &'static str> {
        if integrated == 0 {
            return Err("integrated SIMD migration id=0 is invalid");
        }
        if self
            .integrated_simd_migrations
            .iter()
            .any(|record| record.id == integrated)
        {
            return Err("integrated SIMD migration evidence already exists");
        }
        if scenario.is_empty() {
            return Err("integrated SIMD migration scenario is empty");
        }
        if activation_migration_generation == 0 || invariant_checks == 0 {
            return Err("integrated SIMD migration refs must carry generations");
        }

        let Some(migration) = self.activation_migrations.iter().find(|record| {
            record.id == activation_migration
                && record.generation == activation_migration_generation
        }) else {
            return Err("integrated SIMD migration missing activation migration evidence");
        };
        let (Some(source_vector_ref), Some(migrated_vector_ref), Some(context)) = (
            migration.source_vector_state,
            migration.migrated_vector_state,
            migration.context,
        ) else {
            return Err("integrated SIMD migration requires vector migration refs");
        };
        let Some(context_generation_after) = migration.context_generation_after else {
            return Err("integrated SIMD migration requires context generation after migration");
        };
        if migration.state != ActivationMigrationState::Applied
            || migration.source_hart == migration.target_hart
            || migration.activation_generation_after <= migration.activation_generation_before
            || migration.vector_status != ActivationVectorState::Clean
            || migration.vector_migrated_at_event.is_none()
            || source_vector_ref.kind != ContractObjectKind::VectorState
            || migrated_vector_ref.kind != ContractObjectKind::VectorState
            || source_vector_ref == migrated_vector_ref
        {
            return Err(
                "integrated SIMD migration requires applied cross-hart clean vector migration",
            );
        }

        let Some(source_vector) = self.vector_states.iter().find(|record| {
            record.id == source_vector_ref.id && record.generation == source_vector_ref.generation
        }) else {
            return Err("integrated SIMD migration missing source vector state");
        };
        let Some(migrated_vector) = self.vector_states.iter().find(|record| {
            record.id == migrated_vector_ref.id
                && record.generation == migrated_vector_ref.generation
        }) else {
            return Err("integrated SIMD migration missing migrated vector state");
        };
        if source_vector.state != VectorStateState::Dropped
            || migrated_vector.state != VectorStateState::Reserved
            || source_vector.owner_activation
                != ContractObjectRef::new(
                    ContractObjectKind::Activation,
                    migration.activation,
                    migration.activation_generation_before,
                )
            || migrated_vector.owner_activation
                != ContractObjectRef::new(
                    ContractObjectKind::Activation,
                    migration.activation,
                    migration.activation_generation_after,
                )
            || source_vector.owner_store != migrated_vector.owner_store
            || source_vector.code_object != migrated_vector.code_object
            || source_vector.target_feature_set != migrated_vector.target_feature_set
            || source_vector.simd_abi != migrated_vector.simd_abi
            || source_vector.vector_register_count != migrated_vector.vector_register_count
            || source_vector.vector_register_bits != migrated_vector.vector_register_bits
        {
            return Err("integrated SIMD migration vector state attribution mismatch");
        }

        let Some(feature) = self.target_feature_sets.iter().find(|record| {
            record.id == migrated_vector.target_feature_set.id
                && record.generation == migrated_vector.target_feature_set.generation
        }) else {
            return Err("integrated SIMD migration missing target feature set");
        };
        if feature.state != TargetFeatureSetState::Discovered
            || !feature.simd_supported
            || feature.simd_abi != migrated_vector.simd_abi
            || feature.vector_register_count != migrated_vector.vector_register_count
            || feature.vector_register_bits != migrated_vector.vector_register_bits
        {
            return Err("integrated SIMD migration target feature set mismatch");
        }

        if self.vector_states.iter().any(|record| {
            record.owner_activation
                == ContractObjectRef::new(
                    ContractObjectKind::Activation,
                    migration.activation,
                    migration.activation_generation_before,
                )
                && record.state == VectorStateState::Reserved
        }) {
            return Err(
                "integrated SIMD migration leaves live vector state on old activation generation",
            );
        }
        if !self.activation_contexts.iter().any(|record| {
            record.id == context
                && record.generation == context_generation_after
                && record.activation == migration.activation
                && record.activation_generation == migration.activation_generation_after
                && record.vector_state == Some(migrated_vector_ref)
                && record.vector_status == ActivationVectorState::Clean
        }) {
            return Err("integrated SIMD migration missing clean migrated activation context");
        }

        Ok(())
    }

    pub fn record_integrated_simd_migration_with_id(
        &mut self,
        integrated: IntegratedSimdMigrationId,
        scenario: &str,
        activation_migration: ActivationMigrationId,
        activation_migration_generation: Generation,
        invariant_checks: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_integrated_simd_migration(
                integrated,
                scenario,
                activation_migration,
                activation_migration_generation,
                invariant_checks,
            )
            .is_err()
        {
            return false;
        }

        let Some(migration) = self.activation_migrations.iter().find(|record| {
            record.id == activation_migration
                && record.generation == activation_migration_generation
        }) else {
            return false;
        };
        let Some(source_vector_state) = migration.source_vector_state else {
            return false;
        };
        let Some(migrated_vector_state) = migration.migrated_vector_state else {
            return false;
        };
        let Some(context) = migration.context else {
            return false;
        };
        let Some(context_generation_after) = migration.context_generation_after else {
            return false;
        };
        let Some(migrated_vector) = self.vector_states.iter().find(|record| {
            record.id == migrated_vector_state.id
                && record.generation == migrated_vector_state.generation
        }) else {
            return false;
        };
        let target_feature_set = migrated_vector.target_feature_set.id;
        let target_feature_set_generation = migrated_vector.target_feature_set.generation;
        let simd_abi = migrated_vector.simd_abi.clone();
        let vector_register_count = migrated_vector.vector_register_count;
        let vector_register_bits = migrated_vector.vector_register_bits;
        let activation = migration.activation;
        let activation_generation_before = migration.activation_generation_before;
        let activation_generation_after = migration.activation_generation_after;
        let source_hart = migration.source_hart;
        let source_hart_generation = migration.source_hart_generation;
        let target_hart = migration.target_hart;
        let target_hart_generation = migration.target_hart_generation;
        let source_queue = migration.source_queue;
        let source_queue_generation = migration.source_queue_generation;
        let target_queue = migration.target_queue;
        let target_queue_generation = migration.target_queue_generation;
        let generation = 1;
        self.next_integrated_simd_migration_id = self
            .next_integrated_simd_migration_id
            .max(integrated.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "integrated-runtime",
            EventKind::IntegratedSimdMigrationRecorded {
                scenario: scenario.to_string(),
                integrated,
                activation_migration,
                activation_migration_generation,
                target_feature_set,
                target_feature_set_generation,
                source_vector_state,
                migrated_vector_state,
                activation,
                activation_generation_before,
                activation_generation_after,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                simd_abi: simd_abi.clone(),
                invariant_checks,
                generation,
            },
        );
        self.integrated_simd_migrations
            .push(IntegratedSimdMigrationRecord {
                id: integrated,
                scenario: scenario.to_string(),
                activation_migration,
                activation_migration_generation,
                target_feature_set,
                target_feature_set_generation,
                source_vector_state,
                migrated_vector_state,
                activation,
                activation_generation_before,
                activation_generation_after,
                context,
                context_generation_after,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                source_queue,
                source_queue_generation,
                target_queue,
                target_queue_generation,
                simd_abi,
                vector_register_count,
                vector_register_bits,
                invariant_checks,
                generation,
                state: IntegratedSimdMigrationState::Recorded,
                recorded_at_event,
                note: note.to_string(),
            });
        true
    }

    pub fn integrated_simd_migrations(&self) -> &[IntegratedSimdMigrationRecord] {
        &self.integrated_simd_migrations
    }

    pub fn integrated_simd_migration_count(&self) -> usize {
        self.integrated_simd_migrations.len()
    }

    pub fn check_integrated_simd_migration_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.integrated_simd_migrations {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSimdMigrationState::Recorded
                || record.activation_migration_generation == 0
                || record.target_feature_set_generation == 0
                || record.source_vector_state.generation == 0
                || record.migrated_vector_state.generation == 0
                || record.activation_generation_before == 0
                || record.activation_generation_after <= record.activation_generation_before
                || record.context_generation_after == 0
                || record.source_hart_generation == 0
                || record.target_hart_generation == 0
                || record.source_hart == record.target_hart
                || record.source_queue_generation == 0
                || record.target_queue_generation == 0
                || record.simd_abi.is_empty()
                || record.vector_register_count == 0
                || record.vector_register_bits == 0
                || record.invariant_checks == 0
            {
                return Err(SemanticInvariantError::IntegratedSimdMigrationInvalid {
                    integrated: record.id,
                });
            }
            if self
                .validate_integrated_simd_migration(
                    u64::MAX,
                    &record.scenario,
                    record.activation_migration,
                    record.activation_migration_generation,
                    record.invariant_checks,
                )
                .is_err()
            {
                return Err(SemanticInvariantError::IntegratedSimdMigrationInvalid {
                    integrated: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IntegratedSimdMigrationRecorded {
                            scenario,
                            integrated,
                            activation_migration,
                            activation_migration_generation,
                            target_feature_set,
                            target_feature_set_generation,
                            source_vector_state,
                            migrated_vector_state,
                            activation,
                            activation_generation_before,
                            activation_generation_after,
                            source_hart,
                            source_hart_generation,
                            target_hart,
                            target_hart_generation,
                            simd_abi,
                            invariant_checks,
                            generation,
                        } if scenario == &record.scenario
                            && *integrated == record.id
                            && *activation_migration == record.activation_migration
                            && *activation_migration_generation
                                == record.activation_migration_generation
                            && *target_feature_set == record.target_feature_set
                            && *target_feature_set_generation
                                == record.target_feature_set_generation
                            && *source_vector_state == record.source_vector_state
                            && *migrated_vector_state == record.migrated_vector_state
                            && *activation == record.activation
                            && *activation_generation_before
                                == record.activation_generation_before
                            && *activation_generation_after == record.activation_generation_after
                            && *source_hart == record.source_hart
                            && *source_hart_generation == record.source_hart_generation
                            && *target_hart == record.target_hart
                            && *target_hart_generation == record.target_hart_generation
                            && simd_abi == &record.simd_abi
                            && *invariant_checks == record.invariant_checks
                            && *generation == record.generation
                    )
            }) {
                return Err(
                    SemanticInvariantError::IntegratedSimdMigrationMissingEvent {
                        integrated: record.id,
                    },
                );
            }
        }
        Ok(())
    }
}
