use contract_core::{
    ActivationRole, ActivationStatus, CONTRACT_VERSION, CanonicalState, Digest, EffectOutcome,
    ExtensionSupport, HandoffPhase, Identity, NodeIdentity, Ownership, Rejection, SnapshotEnvelope,
    TimerDisposition, TimerStatus,
};

/// Restore a destination candidate from a validated portable snapshot.
pub fn restore(
    envelope: &SnapshotEnvelope,
    computed_body_integrity: Digest,
    expected_component_digest: Digest,
    expected_profile_digest: Digest,
    expected_profile_version: contract_core::SchemaVersion,
    supported_extensions: &[ExtensionSupport],
    destination: NodeIdentity,
) -> Result<CanonicalState, Rejection> {
    if !envelope.version.is_supported() {
        return Err(Rejection::UnsupportedVersion { found: envelope.version });
    }
    if envelope.integrity != computed_body_integrity {
        return Err(Rejection::SnapshotIntegrityMismatch);
    }
    let snapshot = &envelope.body;
    if !snapshot.version.is_supported() {
        return Err(Rejection::UnsupportedVersion { found: snapshot.version });
    }
    if snapshot.snapshot.handoff.is_zero()
        || snapshot.snapshot.snapshot.is_zero()
        || snapshot.source_node.is_zero()
        || destination.is_zero()
        || snapshot.component.identity.is_zero()
    {
        return Err(Rejection::SnapshotMismatch);
    }
    if snapshot.component_digest != expected_component_digest {
        return Err(Rejection::SnapshotMismatch);
    }
    if snapshot.profile_digest != expected_profile_digest
        || snapshot.profile_version != expected_profile_version
    {
        return Err(Rejection::ProfileMismatch);
    }
    if let Some(extension) = snapshot.extensions.iter().find(|extension| {
        extension.required
            && !supported_extensions.iter().any(|supported| {
                supported.id == extension.id && supported.version == extension.version
            })
    }) {
        return Err(Rejection::UnsupportedExtension {
            id: extension.id,
            version: extension.version,
        });
    }
    if snapshot.operations.iter().any(|record| record.outcome.is_none()) {
        let operation = snapshot
            .operations
            .iter()
            .find(|record| record.outcome.is_none())
            .map(|record| record.request.operation)
            .unwrap_or(Identity::ZERO);
        return Err(Rejection::InFlightEffect { operation });
    }
    if let Some(record) = snapshot
        .operations
        .iter()
        .find(|record| record.outcome.as_ref().is_some_and(EffectOutcome::is_indeterminate))
    {
        return Err(Rejection::IndeterminateEffect { operation: record.request.operation });
    }

    Ok(CanonicalState {
        version: CONTRACT_VERSION,
        profile_version: snapshot.profile_version,
        component: snapshot.component,
        component_digest: snapshot.component_digest,
        profile_digest: snapshot.profile_digest,
        phase: HandoffPhase::Exported,
        activation: contract_core::Activation {
            node: destination,
            role: ActivationRole::Destination,
            status: ActivationStatus::Inactive,
        },
        ownership: Ownership::owned(snapshot.source_node, snapshot.source_lease_epoch),
        portable_state: snapshot.portable_state.clone(),
        timer: contract_core::TimerState {
            claim: snapshot.claims.timer.clone(),
            status: TimerStatus::Frozen(snapshot.timer),
            active_operation: match snapshot.timer {
                TimerDisposition::Pending { arm_operation, .. } => Some(arm_operation),
                _ => None,
            },
        },
        key_value: contract_core::KeyValueState {
            claim: snapshot.claims.key_value.clone(),
            last_version: snapshot.key_value_last_version,
            last_operation: snapshot.key_value_last_operation,
        },
        extensions: snapshot.extensions.clone(),
        authorities: snapshot.authorities.clone(),
        operations: snapshot.operations.clone(),
        exported_snapshot: Some(snapshot.snapshot.clone()),
        prepared_destination: None,
        preparation_cleanup: None,
        evidence: alloc::vec![snapshot.snapshot.evidence],
    })
}
