use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub fn record_profile_gate_rejected(
        &mut self,
        package: impl Into<String>,
        artifact: impl Into<String>,
        artifact_id: Option<ArtifactId>,
        required_profile: impl Into<String>,
        reported_profile: impl Into<String>,
        enforced_profile: impl Into<String>,
        reason: impl Into<String>,
        missing_required: Vec<String>,
        degraded_optional: Vec<String>,
        forbidden_present: Vec<String>,
    ) -> EventId {
        self.event_log.push(
            "profile",
            EventKind::ProfileGateRejected {
                package: package.into(),
                artifact: artifact.into(),
                artifact_id,
                required_profile: required_profile.into(),
                reported_profile: reported_profile.into(),
                enforced_profile: enforced_profile.into(),
                reason: reason.into(),
                missing_required,
                degraded_optional,
                forbidden_present,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_profile_gate_degraded(
        &mut self,
        package: impl Into<String>,
        artifact: impl Into<String>,
        artifact_id: Option<ArtifactId>,
        required_profile: impl Into<String>,
        reported_profile: impl Into<String>,
        enforced_profile: impl Into<String>,
        reason: impl Into<String>,
        degraded_optional: Vec<String>,
    ) -> EventId {
        self.event_log.push(
            "profile",
            EventKind::ProfileGateDegraded {
                package: package.into(),
                artifact: artifact.into(),
                artifact_id,
                required_profile: required_profile.into(),
                reported_profile: reported_profile.into(),
                enforced_profile: enforced_profile.into(),
                reason: reason.into(),
                degraded_optional,
            },
        )
    }
}
