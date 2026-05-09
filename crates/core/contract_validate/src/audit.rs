use super::*;

pub const REAL_TARGET_SUBSTRATE_POLICY: &str = "real-target-substrate";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalAuditSeverity {
    Info,
    Warning,
    Error,
}

impl ExternalAuditSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalAuditFinding {
    pub severity: ExternalAuditSeverity,
    pub code: &'static str,
    pub detail: String,
}

impl ExternalAuditFinding {
    fn new(severity: ExternalAuditSeverity, code: &'static str, detail: impl Into<String>) -> Self {
        Self { severity, code, detail: detail.into() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalMigrationAuditReport {
    pub package_id: String,
    pub contract_package_valid: bool,
    pub replay_quiescent: bool,
    pub portable_artifact_execution_claim: bool,
    pub visa_native_portable_artifact_execution_claim: bool,
    pub real_target_substrate_claim: bool,
    pub visa_native_artifact_count: usize,
    pub frontend_personality_artifact_count: usize,
    pub linux_weighted_artifact_count: usize,
    pub findings: Vec<ExternalAuditFinding>,
}

impl ExternalMigrationAuditReport {
    pub fn ok(&self) -> bool {
        self.findings.iter().all(|finding| finding.severity != ExternalAuditSeverity::Error)
    }

    pub fn errors(&self) -> impl Iterator<Item = &ExternalAuditFinding> {
        self.findings.iter().filter(|finding| finding.severity == ExternalAuditSeverity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &ExternalAuditFinding> {
        self.findings.iter().filter(|finding| finding.severity == ExternalAuditSeverity::Warning)
    }
}

/// Audit a migration package as an external consumer.
///
/// This is intentionally separate from `semantic_core` graph validation. It
/// consumes the serialized package facts and classifies what the package can
/// claim about vISA-native workload usage, portable artifact execution, replay
/// quiescence, and real target substrate evidence.
pub fn audit_migration_package(package: &MigrationPackageManifest) -> ExternalMigrationAuditReport {
    let mut findings = Vec::new();

    let contract_package_valid = match validate_migration_package(package) {
        Ok(()) => true,
        Err(error) => {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Error,
                "contract-package-invalid",
                error.to_string(),
            ));
            false
        }
    };

    let replay_quiescent = match validate_replay_quiescent(package) {
        Ok(()) => true,
        Err(error) => {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Warning,
                "not-replay-quiescent",
                error.to_string(),
            ));
            false
        }
    };

    if package.semantic.target_artifacts.is_empty() {
        findings.push(ExternalAuditFinding::new(
            ExternalAuditSeverity::Error,
            "missing-target-artifact-evidence",
            "no TargetArtifactImage evidence is present",
        ));
    }

    let visa_native_artifact_count = package
        .semantic
        .target_artifacts
        .iter()
        .filter(|artifact| is_visa_native(artifact))
        .count();
    let frontend_personality_artifact_count = package
        .semantic
        .target_artifacts
        .iter()
        .filter(|artifact| artifact.role.contains("personality"))
        .count();
    let linux_weighted_artifact_count = package
        .semantic
        .target_artifacts
        .iter()
        .filter(|artifact| {
            lower_contains(&artifact.package, "linux") || lower_contains(&artifact.role, "linux")
        })
        .count();

    if visa_native_artifact_count == 0 {
        findings.push(ExternalAuditFinding::new(
            ExternalAuditSeverity::Warning,
            "missing-visa-native-consumer",
            "package has no artifact whose role or hostcalls identify it as a vISA-native workload",
        ));
    }
    if linux_weighted_artifact_count > 0 && visa_native_artifact_count == 0 {
        findings.push(ExternalAuditFinding::new(
            ExternalAuditSeverity::Warning,
            "linux-weighted-without-native-consumer",
            "Linux-weighted artifacts are present but no vISA-native artifact is present",
        ));
    }

    let portable_artifact_execution_claim = !package.semantic.target_artifacts.is_empty()
        && !package.semantic.code_objects.is_empty()
        && !package.semantic.activation_records.is_empty()
        && (!package.semantic.hostcall_trace.is_empty()
            || !package.semantic.trap_records.is_empty());
    let visa_native_portable_artifact_execution_claim = portable_artifact_execution_claim
        && visa_native_artifact_participates_in_execution(package);
    if !portable_artifact_execution_claim {
        findings.push(ExternalAuditFinding::new(
            ExternalAuditSeverity::Warning,
            "portable-artifact-execution-incomplete",
            "package lacks the target artifact -> code object -> activation -> hostcall/trap evidence chain",
        ));
    }
    if portable_artifact_execution_claim && !visa_native_portable_artifact_execution_claim {
        findings.push(ExternalAuditFinding::new(
            ExternalAuditSeverity::Warning,
            "portable-artifact-execution-without-visa-native-chain",
            "portable artifact evidence exists, but no vISA-native artifact participates in activation plus hostcall/trap evidence",
        ));
    }

    let real_target_substrate_claim =
        package.substrate_boundary.native_state_policy == REAL_TARGET_SUBSTRATE_POLICY;
    if real_target_substrate_claim {
        if package.required_artifact_profile.target_arch == "target-native" {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Error,
                "real-target-without-concrete-arch",
                "real target substrate claim uses target-native instead of a concrete target arch",
            ));
        }
        if package.semantic.substrate_events.is_empty()
            && package.substrate_boundary.active_mmio_authority_count == 0
            && package.substrate_boundary.active_dma_authority_count == 0
            && package.substrate_boundary.active_irq_authority_count == 0
            && package.substrate_boundary.active_packet_device_authority_count == 0
            && package.substrate_boundary.active_virtio_queue_authority_count == 0
        {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Error,
                "real-target-without-extraction-events",
                "real target substrate claim has no substrate events or active extracted authorities",
            ));
        }
    } else {
        findings.push(ExternalAuditFinding::new(
            ExternalAuditSeverity::Info,
            "no-real-target-substrate-claim",
            "native_state_policy does not claim real target substrate execution",
        ));
    }

    ExternalMigrationAuditReport {
        package_id: package.package_id.clone(),
        contract_package_valid,
        replay_quiescent,
        portable_artifact_execution_claim,
        visa_native_portable_artifact_execution_claim,
        real_target_substrate_claim,
        visa_native_artifact_count,
        frontend_personality_artifact_count,
        linux_weighted_artifact_count,
        findings,
    }
}

fn is_visa_native(artifact: &artifact_manifest::TargetArtifactImageManifest) -> bool {
    artifact.role == "visa-native-workload"
        || lower_contains(&artifact.artifact_name, "visa-native")
        || artifact.hostcalls.iter().any(|hostcall| hostcall.object.starts_with("visa."))
}

fn visa_native_artifact_participates_in_execution(package: &MigrationPackageManifest) -> bool {
    let native_artifact_ids = package
        .semantic
        .target_artifacts
        .iter()
        .filter(|artifact| is_visa_native(artifact))
        .map(|artifact| artifact.id)
        .collect::<Vec<_>>();
    if native_artifact_ids.is_empty() {
        return false;
    }

    let has_native_activation = package
        .semantic
        .activation_records
        .iter()
        .any(|activation| native_artifact_ids.contains(&activation.artifact));
    let has_native_effect = package
        .semantic
        .hostcall_trace
        .iter()
        .any(|hostcall| native_artifact_ids.contains(&hostcall.artifact))
        || package
            .semantic
            .trap_records
            .iter()
            .any(|trap| trap.artifact.is_some_and(|id| native_artifact_ids.contains(&id)));

    has_native_activation && has_native_effect
}

fn lower_contains(value: &str, needle: &str) -> bool {
    value.to_ascii_lowercase().contains(needle)
}
