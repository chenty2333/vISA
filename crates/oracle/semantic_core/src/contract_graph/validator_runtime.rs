use alloc::vec::Vec;

use super::*;

impl ContractGraphValidator {
    pub(super) fn validate_activations(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for activation in &snapshot.activations {
            let from = activation.object_ref();
            match snapshot.stores.iter().find(|store| store.id == activation.store) {
                Some(store) => {
                    if store.generation != activation.store_generation {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "activation->store",
                            from,
                            Some(store.object_ref()),
                            "activation store generation is stale",
                        ));
                    }
                    if Self::is_live_activation(activation) && store.state == StoreState::Dead {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "activation->store",
                            from,
                            Some(store.object_ref()),
                            "live activation references a dead store",
                        ));
                    }
                    if store.state == StoreState::Dead && activation.active_dmw_leases != 0 {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "activation->dmw-lease",
                            from,
                            Some(store.object_ref()),
                            "dead store still has active DMW lease through activation",
                        ));
                    }
                    Self::check_tombstone_live_edge(
                        snapshot,
                        violations,
                        from,
                        "activation->store",
                        store.object_ref(),
                        Self::is_live_activation(activation),
                    );
                }
                None => violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "activation->store",
                    from,
                    Some(ContractObjectRef::new(
                        ContractObjectKind::Store,
                        activation.store,
                        activation.store_generation,
                    )),
                    "activation references missing store",
                )),
            }
            match snapshot.code_objects.iter().find(|code| code.id == activation.code_object) {
                Some(code) => {
                    if code.generation != activation.code_generation {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "activation->code",
                            from,
                            Some(code.object_ref()),
                            "activation code generation is stale",
                        ));
                    }
                    if Self::is_live_activation(activation)
                        && matches!(
                            code.state,
                            CodeObjectState::Faulted
                                | CodeObjectState::Retired
                                | CodeObjectState::Unpublished
                        )
                    {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "activation->code",
                            from,
                            Some(code.object_ref()),
                            "live activation references non-runnable code",
                        ));
                    }
                    Self::check_tombstone_live_edge(
                        snapshot,
                        violations,
                        from,
                        "activation->code",
                        code.object_ref(),
                        Self::is_live_activation(activation),
                    );
                }
                None => violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "activation->code",
                    from,
                    Some(ContractObjectRef::new(
                        ContractObjectKind::CodeObject,
                        activation.code_object,
                        activation.code_generation,
                    )),
                    "activation references missing code object",
                )),
            }
        }
    }

    pub(super) fn validate_traps(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for trap in &snapshot.traps {
            let from = trap.object_ref();
            if let Some(activation_id) = trap.activation {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "trap->activation",
                    ContractObjectKind::Activation,
                    activation_id,
                    trap.activation_generation.unwrap_or(0),
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(store_id) = trap.store {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "trap->store",
                    ContractObjectKind::Store,
                    store_id,
                    trap.store_generation.unwrap_or(0),
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(code_id) = trap.code_object {
                let generation = trap.code_generation.unwrap_or(0);
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "trap->code",
                    ContractObjectKind::CodeObject,
                    code_id,
                    generation,
                    ContractEdgeMode::Historical,
                );
                if let Some(generation) = trap.code_generation
                    && let Some(code) = snapshot
                        .code_objects
                        .iter()
                        .find(|code| code.id == code_id && code.generation == generation)
                    && let Some(artifact) = trap.artifact
                    && code.artifact_id != artifact
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "trap->artifact",
                        from,
                        Some(ContractObjectRef::new(
                            ContractObjectKind::Artifact,
                            artifact,
                            trap.artifact_generation.unwrap_or(0),
                        )),
                        "trap artifact does not match code artifact",
                    ));
                }
            }
            if let Some(artifact_id) = trap.artifact {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "trap->artifact",
                    ContractObjectKind::Artifact,
                    artifact_id,
                    trap.artifact_generation.unwrap_or(0),
                    ContractEdgeMode::Historical,
                );
            }
            Self::validate_simd_trap(snapshot, violations, trap);
        }
    }

    pub(super) fn validate_simd_trap(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        trap: &TargetTrapRecord,
    ) {
        let is_simd_trap = trap.trap_kind.as_deref().is_some_and(|kind| kind.starts_with("simd-"));
        if !is_simd_trap && trap.simd_attribution.is_none() {
            return;
        }
        let from = trap.object_ref();
        let Some(attribution) = &trap.simd_attribution else {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                "trap->simd-requirement",
                from,
                None,
                "SIMD trap is missing SIMD attribution",
            ));
            return;
        };
        if attribution.classification == SimdTrapClassification::RequirementMissing {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                "trap->simd-requirement",
                from,
                None,
                "SIMD trap was attributed to code without a declared SIMD requirement",
            ));
        }
        if let Some(feature) = attribution.target_feature_set {
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "trap->target-feature-set",
                ContractObjectKind::TargetFeatureSet,
                feature.id,
                feature.generation,
                ContractEdgeMode::Historical,
            );
        }
        let Some(code_id) = trap.code_object else {
            violations.push(ContractViolation::new(
                ContractViolationKind::DanglingEdge,
                "trap->simd-code",
                from,
                None,
                "SIMD trap is missing code object attribution",
            ));
            return;
        };
        let Some(code) = snapshot.code_objects.iter().find(|code| code.id == code_id) else {
            return;
        };
        if trap.code_generation != Some(code.generation) {
            return;
        }
        if !code.simd_requirement.uses_simd
            || !code.simd_requirement.declared
            || code.simd_requirement.status != CodeObjectSimdRequirementStatus::Declared
        {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                "trap->simd-requirement",
                from,
                Some(code.object_ref()),
                "SIMD trap code object does not declare a valid SIMD requirement",
            ));
            return;
        }
        if attribution.required_abi != code.simd_requirement.required_abi
            || attribution.min_vector_register_count
                != code.simd_requirement.min_vector_register_count
            || attribution.min_vector_register_bits
                != code.simd_requirement.min_vector_register_bits
            || attribution.target_feature_set != code.simd_requirement.target_feature_set
            || attribution.code_requirement_status != code.simd_requirement.status
        {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                "trap->simd-requirement",
                from,
                Some(code.object_ref()),
                "SIMD trap attribution does not match CodeObject SIMD requirement",
            ));
        }
    }

    pub(super) fn validate_hostcalls(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for hostcall in &snapshot.hostcalls {
            let from = hostcall.object_ref();
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "hostcall->activation",
                ContractObjectKind::Activation,
                hostcall.activation,
                hostcall.activation_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "hostcall->store",
                ContractObjectKind::Store,
                hostcall.store,
                hostcall.store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "hostcall->code",
                ContractObjectKind::CodeObject,
                hostcall.code_object,
                hostcall.code_generation,
                ContractEdgeMode::Historical,
            );
        }
    }

    pub(super) fn validate_capabilities(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for capability in &snapshot.capabilities {
            let from = capability.object_ref();
            if capability.handle_slot == 0
                || capability.handle_generation != capability.generation as u32
                || capability.handle_tag == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "capability->handle",
                    from,
                    Some(from),
                    "capability handle slot/generation/tag does not match current capability generation",
                ));
            }
            if capability.source.trim().is_empty() {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "capability->provenance",
                    from,
                    None,
                    "capability provenance source is empty",
                ));
            }
            if !capability.revoked
                && capability.class.requires_manifest_declaration()
                && !capability.manifest_decl
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "capability->provenance",
                    from,
                    None,
                    "active capability class requires manifest declaration provenance",
                ));
            }
            if let Some(store_id) = capability.owner_store {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "capability->owner-store",
                    ContractObjectKind::Store,
                    store_id,
                    capability.owner_store_generation.unwrap_or(0),
                    if capability.revoked {
                        ContractEdgeMode::Historical
                    } else {
                        ContractEdgeMode::Live
                    },
                );
            }
            match capability.object_ref {
                Some(object_ref) => Self::check_authority_object_edge(
                    snapshot,
                    violations,
                    from,
                    "capability->object",
                    object_ref,
                    if capability.revoked {
                        ContractEdgeMode::Historical
                    } else {
                        ContractEdgeMode::Live
                    },
                ),
                None if !capability.revoked => violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "capability->object",
                    from,
                    None,
                    "active capability is missing authority object ref",
                )),
                None => {}
            }
        }
    }

    pub(super) fn validate_waits(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for wait in &snapshot.waits {
            let from = wait.object_ref();
            if wait.state == WaitState::Pending
                && wait.owner_task.is_none()
                && wait.owner_store.is_none()
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "wait->owner",
                    from,
                    None,
                    "pending wait has no owner task or owner store",
                ));
            }
            if wait.state == WaitState::Pending
                && wait.blockers.is_empty()
                && wait.deadline.is_none()
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "wait->blocker",
                    from,
                    None,
                    "pending wait has no blocker or deadline",
                ));
            }
            if wait.state == WaitState::Pending {
                if wait.owner_task.is_some() && wait.owner_task_generation.is_none() {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::HistoricalEdgeMissingGeneration,
                        "wait->owner-task",
                        from,
                        None,
                        "pending wait owner task is missing generation",
                    ));
                }
                if let Some(owner_store) = wait.owner_store {
                    Self::check_generation_edge(
                        snapshot,
                        violations,
                        from,
                        "wait->owner-store",
                        ContractObjectKind::Store,
                        owner_store,
                        wait.owner_store_generation.unwrap_or(0),
                        ContractEdgeMode::Live,
                    );
                }
                for blocker in &wait.blockers {
                    Self::check_contract_ref_edge(
                        snapshot,
                        violations,
                        from,
                        "wait->blocker",
                        *blocker,
                        ContractEdgeMode::Live,
                        None,
                    );
                }
            }
        }
    }

    pub(super) fn validate_cleanups(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for cleanup in &snapshot.cleanup_transactions {
            let from = cleanup.object_ref();
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "cleanup->store",
                ContractObjectKind::Store,
                cleanup.store,
                cleanup.store_generation,
                ContractEdgeMode::Historical,
            );
            let current_store = snapshot.stores.iter().find(|store| store.id == cleanup.store);
            if cleanup.state == CleanupTransactionState::Completed {
                match cleanup.result_store_generation {
                    Some(generation) => {
                        let result_ref = ContractObjectRef::new(
                            ContractObjectKind::Store,
                            cleanup.store,
                            generation,
                        );
                        match current_store {
                            Some(store) if generation == store.generation => {
                                if store.state != StoreState::Dead {
                                    violations.push(ContractViolation::new(
                                        ContractViolationKind::LiveObjectReferencesDeadObject,
                                        "cleanup->result-store",
                                        from,
                                        Some(store.object_ref()),
                                        "completed cleanup result points to a live current store",
                                    ));
                                }
                            }
                            _ if Self::has_tombstone(snapshot, result_ref) => {}
                            Some(store) => violations.push(ContractViolation::new(
                                ContractViolationKind::GenerationMismatch,
                                "cleanup->result-store",
                                from,
                                Some(store.object_ref()),
                                "completed cleanup result store generation is neither current nor tombstoned",
                            )),
                            None => violations.push(ContractViolation::new(
                                ContractViolationKind::DanglingEdge,
                                "cleanup->result-store",
                                from,
                                Some(result_ref),
                                "completed cleanup result store generation has no current object or tombstone",
                            )),
                        }
                    }
                    None => violations.push(ContractViolation::new(
                        ContractViolationKind::HistoricalEdgeMissingGeneration,
                        "cleanup->result-store",
                        from,
                        current_store.map(StoreRecord::object_ref),
                        "completed cleanup is missing result store generation",
                    )),
                }
            }
            if let Some(activation_id) = cleanup.activation {
                match cleanup.activation_generation {
                    Some(generation) => Self::check_generation_edge(
                        snapshot,
                        violations,
                        from,
                        "cleanup->activation",
                        ContractObjectKind::Activation,
                        activation_id,
                        generation,
                        ContractEdgeMode::Historical,
                    ),
                    None => {
                        if snapshot
                            .activations
                            .iter()
                            .all(|activation| activation.id != activation_id)
                        {
                            violations.push(ContractViolation::new(
                                ContractViolationKind::DanglingEdge,
                                "cleanup->activation",
                                from,
                                Some(ContractObjectRef::new(
                                    ContractObjectKind::Activation,
                                    activation_id,
                                    0,
                                )),
                                "cleanup references missing activation",
                            ));
                        }
                    }
                }
            }
            if let Some(code_id) = cleanup.code_object {
                if let Some(generation) = cleanup.code_generation {
                    Self::check_generation_edge(
                        snapshot,
                        violations,
                        from,
                        "cleanup->code",
                        ContractObjectKind::CodeObject,
                        code_id,
                        generation,
                        ContractEdgeMode::Historical,
                    );
                }
                match snapshot.code_objects.iter().find(|code| code.id == code_id) {
                    Some(code) => {
                        if cleanup.state == CleanupTransactionState::Completed {
                            if code.bound_store == Some(cleanup.store)
                                && code.bound_store_generation == Some(cleanup.store_generation)
                            {
                                violations.push(ContractViolation::new(
                                    ContractViolationKind::LiveObjectReferencesDeadObject,
                                    "cleanup->code",
                                    from,
                                    Some(code.object_ref()),
                                    "completed cleanup left code object bound to store",
                                ));
                            }
                            if cleanup.unbound_code_object
                                && !matches!(
                                    code.state,
                                    CodeObjectState::Retired
                                        | CodeObjectState::Unpublished
                                        | CodeObjectState::Faulted
                                )
                            {
                                violations.push(ContractViolation::new(
                                    ContractViolationKind::LiveObjectReferencesDeadObject,
                                    "cleanup->code",
                                    from,
                                    Some(code.object_ref()),
                                    "completed cleanup did not retire or unpublish code object",
                                ));
                            }
                        }
                    }
                    None => violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        "cleanup->code",
                        from,
                        Some(ContractObjectRef::new(ContractObjectKind::CodeObject, code_id, 0)),
                        "cleanup references missing code object",
                    )),
                }
            }
            for capability_ref in &cleanup.revoked_capability_refs {
                match snapshot
                    .capabilities
                    .iter()
                    .find(|capability| capability.id == capability_ref.id)
                {
                    Some(capability) if capability.generation != capability_ref.generation => {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "cleanup->capability",
                            from,
                            Some(capability.object_ref()),
                            "cleanup capability generation is stale",
                        ));
                    }
                    Some(capability) => {
                        if cleanup.state == CleanupTransactionState::Completed
                            && !capability.revoked
                        {
                            violations.push(ContractViolation::new(
                                ContractViolationKind::LiveObjectReferencesDeadObject,
                                "cleanup->capability",
                                from,
                                Some(capability.object_ref()),
                                "completed cleanup listed an active capability as revoked",
                            ));
                        }
                    }
                    None => violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        "cleanup->capability",
                        from,
                        Some(*capability_ref),
                        "cleanup references missing capability",
                    )),
                }
            }
            if cleanup.revoked_capability_refs.is_empty() {
                for capability_id in &cleanup.revoked_capabilities {
                    match snapshot
                        .capabilities
                        .iter()
                        .find(|capability| capability.id == *capability_id)
                    {
                        Some(capability) if cleanup.state == CleanupTransactionState::Completed => {
                            if !capability.revoked {
                                violations.push(ContractViolation::new(
                                    ContractViolationKind::LiveObjectReferencesDeadObject,
                                    "cleanup->capability",
                                    from,
                                    Some(capability.object_ref()),
                                    "completed cleanup listed an active capability as revoked",
                                ));
                            }
                        }
                        Some(_) => {}
                        None => violations.push(ContractViolation::new(
                            ContractViolationKind::DanglingEdge,
                            "cleanup->capability",
                            from,
                            Some(ContractObjectRef::new(
                                ContractObjectKind::Capability,
                                *capability_id,
                                0,
                            )),
                            "cleanup references missing capability",
                        )),
                    }
                }
            }
            Self::validate_cleanup_effects(snapshot, violations, cleanup);
        }
    }

    pub(super) fn validate_cleanup_effects(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        cleanup: &FaultCleanupTransaction,
    ) {
        let from = cleanup.object_ref();
        for effect in &cleanup.effects {
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "cleanup->effect-target",
                effect.target.kind,
                effect.target.id,
                effect.expected_generation,
                ContractEdgeMode::CleanupEffect,
            );
            if effect.status != CleanupEffectStatus::Applied {
                continue;
            }
            match effect.kind {
                CleanupEffectKind::MarkStoreDead => {
                    match snapshot.stores.iter().find(|store| {
                        store.id == effect.target.id
                            && store.generation == effect.expected_generation
                    }) {
                        Some(store) if store.state == StoreState::Dead => {}
                        Some(store) => violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "cleanup->effect-target",
                            from,
                            Some(store.object_ref()),
                            "mark-store-dead effect target is not dead",
                        )),
                        None => {}
                    }
                }
                CleanupEffectKind::RevokeCapability => {
                    match snapshot.capabilities.iter().find(|capability| {
                        capability.id == effect.target.id
                            && capability.generation == effect.expected_generation
                    }) {
                        Some(capability) if capability.revoked => {}
                        Some(capability) => violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "cleanup->effect-target",
                            from,
                            Some(capability.object_ref()),
                            "revoke-capability effect target is still active",
                        )),
                        None => {}
                    }
                }
                CleanupEffectKind::UnbindCode => {
                    match snapshot.code_objects.iter().find(|code| {
                        code.id == effect.target.id && code.generation == effect.expected_generation
                    }) {
                        Some(code)
                            if (code.bound_store != Some(cleanup.store)
                                || code.bound_store_generation
                                    != Some(cleanup.store_generation))
                                && matches!(
                                    code.state,
                                    CodeObjectState::Faulted
                                        | CodeObjectState::Retired
                                        | CodeObjectState::Unpublished
                                ) => {}
                        Some(code) => violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "cleanup->effect-target",
                            from,
                            Some(code.object_ref()),
                            "unbind-code effect left code live or bound",
                        )),
                        None => {}
                    }
                }
                CleanupEffectKind::EmitTombstone => {
                    if !Self::has_tombstone(snapshot, effect.target) {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::DanglingEdge,
                            "cleanup->effect-target",
                            from,
                            Some(effect.target),
                            "emit-tombstone effect has no matching tombstone",
                        ));
                    }
                }
                CleanupEffectKind::StopNewActivation
                | CleanupEffectKind::SealActivation
                | CleanupEffectKind::ReleaseLeases
                | CleanupEffectKind::CancelWaits
                | CleanupEffectKind::DropResources
                | CleanupEffectKind::RecordFailureEffect => {}
            }
        }
    }

    pub(super) fn validate_explicit_edges(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for edge in &snapshot.explicit_edges {
            if edge.mode == ContractEdgeMode::External {
                Self::validate_external_edge(snapshot, violations, edge);
                continue;
            }

            if let Some(source) = Self::object_ref_by_id_generation(
                snapshot,
                edge.from.kind,
                edge.from.id,
                edge.from.generation,
            )
            .or_else(|| Self::current_object_ref(snapshot, edge.from.kind, edge.from.id))
            {
                if source.generation != edge.from.generation {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        &edge.label,
                        edge.from,
                        Some(source),
                        "edge source generation does not match source object",
                    ));
                }
                if edge.mode == ContractEdgeMode::Live {
                    if let Some(reason) = Self::inactive_reason(snapshot, edge.from) {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::LiveEdgeReferencesInactiveObject,
                            &edge.label,
                            edge.from,
                            Some(source),
                            reason,
                        ));
                    }
                }
            } else if !Self::has_tombstone(snapshot, edge.from) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    &edge.label,
                    edge.from,
                    None,
                    "edge source is missing",
                ));
            }

            if edge.mode == ContractEdgeMode::CleanupEffect
                && Self::cleanup_effect_label_creates_live_ownership(&edge.label)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::CleanupEffectCreatesLiveOwnership,
                    &edge.label,
                    edge.from,
                    Some(edge.to),
                    "cleanup effect edge uses a live-ownership relation",
                ));
            }

            Self::check_generation_edge(
                snapshot,
                violations,
                edge.from,
                &edge.label,
                edge.to.kind,
                edge.to.id,
                edge.to.generation,
                edge.mode,
            );
        }
    }

    pub(super) fn validate_external_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        edge: &ContractEdgeRecord,
    ) {
        if edge.to.kind != ContractObjectKind::ExternalObject {
            violations.push(ContractViolation::new(
                ContractViolationKind::DanglingEdge,
                &edge.label,
                edge.from,
                Some(edge.to),
                "external edge target is not an external object",
            ));
            return;
        }

        let declaration =
            snapshot.external_objects.iter().find(|declaration| declaration.object == edge.to);
        let Some(declaration) = declaration else {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMissingDeclaration,
                &edge.label,
                edge.from,
                Some(edge.to),
                "external edge target has no declaration",
            ));
            return;
        };

        match (&edge.provider, &edge.class) {
            (Some(provider), Some(class))
                if *provider == declaration.provider && *class == declaration.class => {}
            (Some(_), Some(_)) => violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                &edge.label,
                edge.from,
                Some(edge.to),
                "external edge provider/class metadata does not match declaration",
            )),
            _ => violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                &edge.label,
                edge.from,
                Some(edge.to),
                "external edge is missing provider/class metadata",
            )),
        }
    }

    pub(super) fn check_authority_object_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        from: ContractObjectRef,
        edge: &str,
        authority: AuthorityObjectRef,
        semantics: ContractEdgeMode,
    ) {
        let object = authority.object();
        let class = authority.class().as_str();
        if matches!(authority, AuthorityObjectRef::External { .. }) {
            if Self::has_declared_object(snapshot, object, Some(class)) {
                return;
            }
            if Self::has_declared_object(snapshot, object, None) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    edge,
                    from,
                    Some(object),
                    "external authority object declaration has mismatched class metadata",
                ));
            } else {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMissingDeclaration,
                    edge,
                    from,
                    Some(object),
                    "external authority object is missing a matching declaration",
                ));
            }
            return;
        }
        Self::check_contract_ref_edge(
            snapshot,
            violations,
            from,
            edge,
            object,
            semantics,
            Some(class),
        );
    }

    pub(super) fn check_contract_ref_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        from: ContractObjectRef,
        edge: &str,
        target: ContractObjectRef,
        semantics: ContractEdgeMode,
        class: Option<&str>,
    ) {
        if Self::is_graph_modeled_kind(target.kind) {
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                edge,
                target.kind,
                target.id,
                target.generation,
                semantics,
            );
            return;
        }

        if Self::has_declared_object(snapshot, target, class) {
            return;
        }
        if class.is_some() && Self::has_declared_object(snapshot, target, None) {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                edge,
                from,
                Some(target),
                "declared authority/wait target has mismatched class metadata",
            ));
            return;
        }

        violations.push(ContractViolation::new(
            ContractViolationKind::ExternalEdgeMissingDeclaration,
            edge,
            from,
            Some(target),
            "authority/wait target is not represented by a declared contract object",
        ));
    }

    pub(super) fn check_generation_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        from: ContractObjectRef,
        edge: &str,
        kind: ContractObjectKind,
        id: u64,
        generation: Generation,
        semantics: ContractEdgeMode,
    ) {
        if semantics != ContractEdgeMode::Live
            && kind != ContractObjectKind::ExternalObject
            && generation == 0
        {
            violations.push(ContractViolation::new(
                ContractViolationKind::HistoricalEdgeMissingGeneration,
                edge,
                from,
                Some(ContractObjectRef::new(kind, id, generation)),
                "historical/cleanup edge is missing exact target generation",
            ));
            return;
        }
        let target = Self::object_ref_by_id_generation(snapshot, kind, id, generation)
            .or_else(|| Self::current_object_ref(snapshot, kind, id));
        match target {
            Some(target) if target.generation != generation => {
                let has_exact_tombstone =
                    Self::has_tombstone(snapshot, ContractObjectRef::new(kind, id, generation));
                if semantics == ContractEdgeMode::Live && has_exact_tombstone {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::TombstoneReferencedByLiveEdge,
                        edge,
                        from,
                        Some(ContractObjectRef::new(kind, id, generation)),
                        "live edge references a tombstoned generation",
                    ));
                } else if !has_exact_tombstone
                    || !matches!(
                        semantics,
                        ContractEdgeMode::Historical | ContractEdgeMode::CleanupEffect
                    )
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        edge,
                        from,
                        Some(target),
                        "edge generation does not match target object",
                    ));
                }
            }
            Some(target) => {
                Self::check_tombstone_live_edge(
                    snapshot,
                    violations,
                    from,
                    edge,
                    target,
                    semantics == ContractEdgeMode::Live,
                );
                if semantics == ContractEdgeMode::Live
                    && let Some(reason) = Self::inactive_reason(snapshot, target)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::LiveEdgeReferencesInactiveObject,
                        edge,
                        from,
                        Some(target),
                        reason,
                    ));
                }
            }
            None => {
                let target_ref = ContractObjectRef::new(kind, id, generation);
                let has_exact_tombstone = Self::has_tombstone(snapshot, target_ref);
                if semantics == ContractEdgeMode::Live && has_exact_tombstone {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::TombstoneReferencedByLiveEdge,
                        edge,
                        from,
                        Some(target_ref),
                        "live edge references a tombstoned generation",
                    ));
                } else if !has_exact_tombstone
                    || !matches!(
                        semantics,
                        ContractEdgeMode::Historical | ContractEdgeMode::CleanupEffect
                    )
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        edge,
                        from,
                        Some(target_ref),
                        "edge references missing target",
                    ));
                }
            }
        }
    }
}
