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
    pub authority_extraction_event_count: usize,
    pub linked_authority_extraction_event_count: usize,
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
        .filter(|artifact| artifact_is_personality(artifact))
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

    let linked_portable_execution_chain =
        contract_package_valid && artifact_participates_in_execution(package, |_| true);
    let linked_visa_native_execution_chain =
        contract_package_valid && artifact_participates_in_execution(package, is_visa_native);
    let portable_boundary_validation =
        package_has_boundary_validation(package, EvidenceBoundaryLevel::PortableArtifactExecution);
    let portable_artifact_execution_claim =
        linked_portable_execution_chain && portable_boundary_validation;
    let visa_native_portable_artifact_execution_claim =
        linked_visa_native_execution_chain && portable_boundary_validation;
    if !portable_artifact_execution_claim {
        if !linked_portable_execution_chain {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Warning,
                "portable-artifact-execution-incomplete",
                "package lacks the target artifact -> code object -> activation -> hostcall/trap evidence chain",
            ));
        } else {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Warning,
                "portable-artifact-execution-without-validation",
                "package has a linked portable execution chain but lacks successful portable snapshot/replay boundary validation",
            ));
        }
    }
    if portable_artifact_execution_claim && !visa_native_portable_artifact_execution_claim {
        findings.push(ExternalAuditFinding::new(
            ExternalAuditSeverity::Warning,
            "portable-artifact-execution-without-visa-native-chain",
            "portable artifact evidence exists, but no vISA-native artifact participates in activation plus hostcall/trap evidence",
        ));
    }

    let authority_extraction_event_count = package
        .semantic
        .substrate_events
        .iter()
        .filter(|event| event.event_kind == "authority-extracted")
        .count();
    let linked_authority_extraction_event_count =
        linked_real_target_extraction_evidence_count(package);
    let real_target_substrate_claim =
        package.substrate_boundary.native_state_policy == REAL_TARGET_SUBSTRATE_POLICY;
    if real_target_substrate_claim {
        let real_target_boundary_validation =
            package_has_boundary_validation(package, EvidenceBoundaryLevel::RealTargetSubstrate);
        if !portable_artifact_execution_claim {
            if linked_portable_execution_chain && !portable_boundary_validation {
                findings.push(ExternalAuditFinding::new(
                    ExternalAuditSeverity::Error,
                    "real-target-without-portable-artifact-validation",
                    "real target substrate claim requires portable snapshot/replay boundary validation",
                ));
            } else {
                findings.push(ExternalAuditFinding::new(
                    ExternalAuditSeverity::Error,
                    "real-target-without-portable-artifact-chain",
                    "real target substrate claim requires a linked artifact -> code object -> activation -> hostcall/trap chain",
                ));
            }
        }
        if !real_target_boundary_validation {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Error,
                "real-target-without-boundary-validation",
                "real target substrate claim requires real-target-substrate snapshot/replay boundary validation",
            ));
        }
        if !real_target_has_concrete_arch(package) {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Error,
                "real-target-without-concrete-arch",
                "real target substrate claim requires a concrete target arch in both target and required artifact profile metadata",
            ));
        }
        if real_target_has_concrete_arch(package)
            && (!is_supported_real_target_arch(&package.target.arch_requirement)
                || !is_supported_real_target_arch(&package.required_artifact_profile.target_arch))
        {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Error,
                "real-target-unknown-arch",
                "real target substrate claim requires a supported canonical target arch token",
            ));
        }
        if real_target_has_concrete_arch(package)
            && package.target.arch_requirement != package.required_artifact_profile.target_arch
        {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Error,
                "real-target-arch-mismatch",
                "real target substrate claim target arch metadata is internally inconsistent",
            ));
        }
        if linked_authority_extraction_event_count == 0 {
            findings.push(ExternalAuditFinding::new(
                ExternalAuditSeverity::Error,
                "real-target-without-extraction-events",
                "real target substrate claim has no authority extraction event attributed to the linked execution chain",
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
        authority_extraction_event_count,
        linked_authority_extraction_event_count,
        findings,
    }
}

fn package_has_boundary_validation(
    package: &MigrationPackageManifest,
    required: EvidenceBoundaryLevel,
) -> bool {
    boundary_validation_report_satisfies(&package.semantic.snapshot_validation, required)
        && boundary_validation_report_satisfies(&package.semantic.replay_validation, required)
}

fn boundary_validation_report_satisfies(
    report: &artifact_manifest::BoundaryValidationReportManifest,
    required: EvidenceBoundaryLevel,
) -> bool {
    report.ok
        && report.violation_count == 0
        && !report.validator.is_empty()
        && EvidenceBoundaryLevel::parse(&report.evidence_boundary)
            .is_some_and(|level| level.satisfies(required))
}

fn real_target_has_concrete_arch(package: &MigrationPackageManifest) -> bool {
    !package.target.arch_requirement.is_empty()
        && !package.required_artifact_profile.target_arch.is_empty()
        && package.target.arch_requirement != "target-native"
        && package.required_artifact_profile.target_arch != "target-native"
}

fn is_visa_native(artifact: &artifact_manifest::TargetArtifactImageManifest) -> bool {
    !artifact_is_personality(artifact)
        && (artifact.role == "visa-native-workload"
            || artifact.hostcalls.iter().any(|hostcall| hostcall.object.starts_with("visa.")))
}

fn artifact_is_personality(artifact: &artifact_manifest::TargetArtifactImageManifest) -> bool {
    lower_contains(&artifact.role, "personality")
}

fn artifact_participates_in_execution(
    package: &MigrationPackageManifest,
    predicate: impl Fn(&artifact_manifest::TargetArtifactImageManifest) -> bool,
) -> bool {
    package
        .semantic
        .target_artifacts
        .iter()
        .filter(|artifact| predicate(artifact))
        .any(|artifact| artifact_has_linked_execution_chain(package, artifact))
}

fn artifact_has_linked_execution_chain(
    package: &MigrationPackageManifest,
    artifact: &artifact_manifest::TargetArtifactImageManifest,
) -> bool {
    artifact_has_linked_execution_chain_for_store(package, artifact, None)
}

fn artifact_has_linked_execution_chain_for_store(
    package: &MigrationPackageManifest,
    artifact: &artifact_manifest::TargetArtifactImageManifest,
    required_store: Option<u64>,
) -> bool {
    package
        .semantic
        .code_objects
        .iter()
        .filter(|code| code_matches_artifact_manifest(artifact, code))
        .any(|code| code_has_linked_execution_effect(package, artifact, code, required_store))
}

fn code_matches_artifact_manifest(
    artifact: &artifact_manifest::TargetArtifactImageManifest,
    code: &artifact_manifest::CodeObjectManifest,
) -> bool {
    code.artifact_id == artifact.id
        && code.package == artifact.package
        && code.owner_profile == artifact.target_profile
        && code.code_hash == artifact.code_hash
        && code_has_executable_binding_state(code)
        && hostcall_tables_match(&code.hostcalls, &artifact.hostcalls)
        && trap_metadata_tables_match(&code.trap_metadata, &artifact.trap_metadata)
        && address_map_tables_match(&code.address_map, &artifact.address_map)
}

fn code_has_executable_binding_state(code: &artifact_manifest::CodeObjectManifest) -> bool {
    code.state == "bound-to-store" && code.text_permission == "rx" && code.rodata_permission == "ro"
}

fn hostcall_tables_match(
    code_hostcalls: &[artifact_manifest::HostcallSpecManifest],
    artifact_hostcalls: &[artifact_manifest::HostcallSpecManifest],
) -> bool {
    code_hostcalls.len() == artifact_hostcalls.len()
        && code_hostcalls.iter().zip(artifact_hostcalls.iter()).all(|(code, artifact)| {
            code.number == artifact.number
                && code.name == artifact.name
                && code.category == artifact.category
                && code.object == artifact.object
                && code.operation == artifact.operation
                && code.may_pending == artifact.may_pending
        })
}

fn trap_metadata_tables_match(
    code_metadata: &[artifact_manifest::TargetTrapMetadataManifest],
    artifact_metadata: &[artifact_manifest::TargetTrapMetadataManifest],
) -> bool {
    code_metadata.len() == artifact_metadata.len()
        && code_metadata.iter().zip(artifact_metadata.iter()).all(|(code, artifact)| {
            code.class == artifact.class
                && code.symbol == artifact.symbol
                && code.offset == artifact.offset
        })
}

fn address_map_tables_match(
    code_entries: &[artifact_manifest::TargetAddressMapEntryManifest],
    artifact_entries: &[artifact_manifest::TargetAddressMapEntryManifest],
) -> bool {
    code_entries.len() == artifact_entries.len()
        && code_entries.iter().zip(artifact_entries.iter()).all(|(code, artifact)| {
            code.symbol == artifact.symbol
                && code.offset == artifact.offset
                && code.len == artifact.len
        })
}

fn code_has_linked_execution_effect(
    package: &MigrationPackageManifest,
    artifact: &artifact_manifest::TargetArtifactImageManifest,
    code: &artifact_manifest::CodeObjectManifest,
    required_store: Option<u64>,
) -> bool {
    let artifact_id = artifact.id;
    package
        .semantic
        .activation_records
        .iter()
        .filter(|activation| {
            activation.artifact == artifact_id
                && activation.code_object == code.id
                && code_matches_activation_store(code, activation)
                && activation_entry_matches_artifact_exports(artifact, activation)
                && required_store.is_none_or(|store| activation.store == store)
        })
        .any(|activation| {
            package.semantic.hostcall_trace.iter().any(|hostcall| {
                hostcall.artifact == artifact_id
                    && hostcall.code_object == code.id
                    && hostcall.activation == activation.id
                    && hostcall_has_live_success_effect(hostcall)
                    && hostcall_matches_activation_generation(package, code, activation, hostcall)
                    && hostcall_matches_declared_abi(code, hostcall)
                    && hostcall_cap_args_backed_by_live_capability_records(package, hostcall)
            }) || package.semantic.trap_records.iter().any(|trap| {
                trap.artifact == Some(artifact_id)
                    && trap.code_object == Some(code.id)
                    && trap.activation == Some(activation.id)
                    && trap_has_attributed_execution_effect(trap)
                    && trap_matches_activation_generation(package, code, activation, trap)
                    && trap_matches_declared_metadata(code, trap)
            })
        })
}

fn activation_entry_matches_artifact_exports(
    artifact: &artifact_manifest::TargetArtifactImageManifest,
    activation: &artifact_manifest::ActivationRecordManifest,
) -> bool {
    !activation.entry.is_empty()
        && artifact
            .exports
            .iter()
            .any(|export| activation_entry_matches_export(&activation.entry, export))
}

fn activation_entry_matches_export(entry: &str, export: &str) -> bool {
    entry == export || entry.strip_prefix("symbol:").is_some_and(|symbol| symbol == export)
}

fn code_matches_activation_store(
    code: &artifact_manifest::CodeObjectManifest,
    activation: &artifact_manifest::ActivationRecordManifest,
) -> bool {
    code.bound_store == Some(activation.store)
        && code.bound_store_generation == Some(activation.store_generation)
}

fn hostcall_matches_activation_generation(
    package: &MigrationPackageManifest,
    code: &artifact_manifest::CodeObjectManifest,
    activation: &artifact_manifest::ActivationRecordManifest,
    trace: &artifact_manifest::HostcallTraceManifest,
) -> bool {
    activation_generation_is_current_or_tombstoned(
        package,
        activation.id,
        activation.generation,
        trace.activation_generation,
    ) && trace.code_generation == code.generation
        && trace.store == activation.store
        && trace.store_generation == activation.store_generation
}

fn hostcall_has_live_success_effect(trace: &artifact_manifest::HostcallTraceManifest) -> bool {
    hostcall_record_mode_proves_execution(&trace.record_mode)
        && trace.allowed
        && hostcall_gate_status_is_success(&trace.gate_status)
        && hostcall_result_is_success(&trace.result)
        && trace.ret_tag == "ok"
}

fn hostcall_record_mode_proves_execution(record_mode: &str) -> bool {
    matches!(
        record_mode,
        "deterministic" | "record-input" | "record-output" | "record-input-output" | "live"
    )
}

fn hostcall_gate_status_is_success(gate_status: &str) -> bool {
    matches!(gate_status, "exit" | "allowed")
}

fn hostcall_result_is_success(result: &str) -> bool {
    matches!(result, "complete" | "ok")
}

fn hostcall_matches_declared_abi(
    code: &artifact_manifest::CodeObjectManifest,
    trace: &artifact_manifest::HostcallTraceManifest,
) -> bool {
    code.hostcalls.iter().any(|declared| {
        declared.number == trace.hostcall_number
            && declared.name == trace.name
            && declared.category == trace.category
            && declared.object == trace.object
            && declared.operation == trace.operation
    })
}

fn trap_matches_activation_generation(
    package: &MigrationPackageManifest,
    code: &artifact_manifest::CodeObjectManifest,
    activation: &artifact_manifest::ActivationRecordManifest,
    trap: &artifact_manifest::TrapRecordManifest,
) -> bool {
    trap.activation_generation.is_some_and(|generation| {
        activation_generation_is_current_or_tombstoned(
            package,
            activation.id,
            activation.generation,
            generation,
        )
    }) && trap.code_generation == Some(code.generation)
        && trap.store == Some(activation.store)
        && trap.store_generation == Some(activation.store_generation)
}

fn activation_generation_is_current_or_tombstoned(
    package: &MigrationPackageManifest,
    activation_id: u64,
    current_generation: u64,
    evidence_generation: u64,
) -> bool {
    evidence_generation == current_generation
        || (evidence_generation < current_generation
            && package.semantic.tombstones.iter().any(|tombstone| {
                tombstone.kind == "activation"
                    && tombstone.id == activation_id
                    && tombstone.generation == evidence_generation
            }))
}

fn trap_has_attributed_execution_effect(trap: &artifact_manifest::TrapRecordManifest) -> bool {
    trap.attribution_status == "trap-map-attributed"
        && !trap.fault_policy.is_empty()
        && !trap.effect.is_empty()
}

fn trap_matches_declared_metadata(
    code: &artifact_manifest::CodeObjectManifest,
    trap: &artifact_manifest::TrapRecordManifest,
) -> bool {
    trap.offset.is_some_and(|offset| {
        code.trap_metadata
            .iter()
            .any(|metadata| metadata.class == trap.class && metadata.offset == offset)
    })
}

fn linked_real_target_extraction_evidence_count(package: &MigrationPackageManifest) -> usize {
    package
        .semantic
        .substrate_events
        .iter()
        .filter(|event| {
            event.event_kind == "authority-extracted"
                && substrate_event_has_concrete_extraction_context(event)
                && event.store.is_some_and(|store| {
                    event.artifact.is_some_and(|artifact_id| {
                        package
                            .semantic
                            .target_artifacts
                            .iter()
                            .find(|artifact| artifact.id == artifact_id)
                            .is_some_and(|artifact| {
                                artifact_has_linked_execution_chain_for_store(
                                    package,
                                    artifact,
                                    Some(store),
                                ) && extraction_event_matches_linked_hostcall(
                                    package,
                                    event,
                                    artifact,
                                    artifact_id,
                                    store,
                                )
                            })
                    })
                })
        })
        .count()
}

fn substrate_event_has_concrete_extraction_context(
    event: &artifact_manifest::SubstrateEventManifest,
) -> bool {
    !event.authority.is_empty()
        && !event.operation.is_empty()
        && event.requester.as_deref().is_some_and(|requester| !requester.is_empty())
        && !event.explanation.is_empty()
}

fn extraction_event_matches_linked_hostcall(
    package: &MigrationPackageManifest,
    event: &artifact_manifest::SubstrateEventManifest,
    artifact: &artifact_manifest::TargetArtifactImageManifest,
    artifact_id: u64,
    store: u64,
) -> bool {
    package
        .semantic
        .code_objects
        .iter()
        .filter(|code| {
            code.artifact_id == artifact_id
                && code_matches_artifact_manifest(artifact, code)
                && code.bound_store == Some(store)
                && code.bound_store_generation.is_some()
        })
        .any(|code| {
            package
                .semantic
                .activation_records
                .iter()
                .filter(|activation| {
                    activation.artifact == artifact_id
                        && activation.code_object == code.id
                        && code_matches_activation_store(code, activation)
                        && activation_entry_matches_artifact_exports(artifact, activation)
                })
                .any(|activation| {
                    package.semantic.hostcall_trace.iter().any(|hostcall| {
                        hostcall.artifact == artifact_id
                            && hostcall.store == store
                            && hostcall.code_object == code.id
                            && hostcall.activation == activation.id
                            && hostcall_has_live_success_effect(hostcall)
                            && hostcall_matches_activation_generation(
                                package, code, activation, hostcall,
                            )
                            && hostcall_matches_declared_abi(code, hostcall)
                            && hostcall_cap_args_backed_by_live_capability_records(
                                package, hostcall,
                            )
                            && substrate_event_matches_hostcall(event, hostcall)
                    })
                })
        })
}

fn hostcall_cap_args_backed_by_live_capability_records(
    package: &MigrationPackageManifest,
    hostcall: &artifact_manifest::HostcallTraceManifest,
) -> bool {
    if hostcall_requires_capability(hostcall) && hostcall.cap_args.is_empty() {
        return false;
    }
    hostcall.cap_args.iter().all(|arg| {
        package
            .semantic
            .capability_records
            .iter()
            .any(|record| capability_record_matches_hostcall_arg(record, hostcall, arg))
    })
}

fn capability_record_matches_hostcall_arg(
    record: &artifact_manifest::CapabilityRecordManifest,
    hostcall: &artifact_manifest::HostcallTraceManifest,
    arg: &artifact_manifest::CapabilityHandleArgManifest,
) -> bool {
    record.id == arg.id
        && record.generation == arg.generation
        && !record.revoked
        && record.subject == hostcall.subject
        && record.object == hostcall.object
        && (arg.object.is_empty() || arg.object == record.object)
        && arg.rights_mask != 0
        && arg.rights.iter().any(|right| right == &hostcall.operation)
        && arg.owner_store.is_none_or(|store| store == hostcall.store)
        && arg
            .owner_store_generation
            .is_none_or(|generation| generation == hostcall.store_generation)
        && record.rights.iter().any(|right| right == &hostcall.operation)
        && record.owner_store.is_none_or(|store| store == hostcall.store)
        && record
            .owner_store_generation
            .is_none_or(|generation| generation == hostcall.store_generation)
}

fn hostcall_requires_capability(hostcall: &artifact_manifest::HostcallTraceManifest) -> bool {
    hostcall_category_requires_capability(&hostcall.category)
        || hostcall_object_requires_capability(&hostcall.object)
}

fn hostcall_category_requires_capability(category: &str) -> bool {
    matches!(
        normalize_token(category).as_str(),
        "device"
            | "packetdevice"
            | "mmio"
            | "dma"
            | "irq"
            | "virtqueue"
            | "dmw"
            | "codepublish"
            | "snapshot"
            | "guestmemory"
            | "timer"
            | "faultdomain"
            | "eventlog"
            | "storecontrol"
    )
}

fn hostcall_object_requires_capability(object: &str) -> bool {
    matches!(
        normalize_token(object).as_str(),
        "device"
            | "visadevice"
            | "packetdevice"
            | "visapacketdevice"
            | "mmio"
            | "visammio"
            | "dma"
            | "visadma"
            | "irq"
            | "visairq"
            | "virtqueue"
            | "visavirtqueue"
            | "dmw"
            | "visadmw"
            | "codepublish"
            | "visacodepublish"
            | "snapshot"
            | "visasnapshot"
            | "guestmemory"
            | "visaguestmemory"
            | "memory"
            | "visamemory"
            | "timer"
            | "visatimer"
            | "faultdomain"
            | "visafaultdomain"
            | "eventlog"
            | "visaeventlog"
            | "storecontrol"
            | "visastorecontrol"
    )
}

fn substrate_event_matches_hostcall(
    event: &artifact_manifest::SubstrateEventManifest,
    hostcall: &artifact_manifest::HostcallTraceManifest,
) -> bool {
    substrate_requester_matches_hostcall_subject(event.requester.as_deref(), &hostcall.subject)
        && substrate_authority_matches_hostcall_object(&event.authority, &hostcall.object)
        && substrate_operation_matches_hostcall(
            &event.operation,
            &hostcall.object,
            &hostcall.operation,
        )
        && substrate_capability_matches_hostcall_cap_args(event.capability.as_ref(), hostcall)
}

fn substrate_requester_matches_hostcall_subject(requester: Option<&str>, subject: &str) -> bool {
    requester.is_some_and(|requester| !requester.is_empty() && requester == subject)
        && !subject.is_empty()
}

fn substrate_capability_matches_hostcall_cap_args(
    capability: Option<&artifact_manifest::CapabilityHandleArgManifest>,
    hostcall: &artifact_manifest::HostcallTraceManifest,
) -> bool {
    match capability {
        Some(capability) => hostcall
            .cap_args
            .iter()
            .any(|arg| arg.id == capability.id && arg.generation == capability.generation),
        None => hostcall.cap_args.is_empty(),
    }
}

fn substrate_authority_matches_hostcall_object(authority: &str, object: &str) -> bool {
    let authority = normalize_token(authority);
    let object = normalize_token(object);
    let expected = match object.as_str() {
        "visaconsole" | "console" => "console",
        "visatimer" | "timer" => "timer",
        "visamemory" | "memory" | "guestmemory" => "guestmemory",
        "visadmw" | "dmw" => "dmw",
        "visammio" | "mmio" => "mmio",
        "visadma" | "dma" => "dma",
        "visairq" | "irq" => "irq",
        "visasnapshot" | "snapshot" => "snapshot",
        _ => object.as_str(),
    };
    authority == expected || authority == format!("{expected}authority")
}

fn substrate_operation_matches_hostcall(operation: &str, object: &str, hostcall_op: &str) -> bool {
    let operation = normalize_token(operation);
    let hostcall_op = normalize_token(hostcall_op);
    operation == hostcall_op
        || canonical_substrate_operation(object, hostcall_op.as_str())
            .is_some_and(|canonical| operation == normalize_token(canonical))
}

fn canonical_substrate_operation(object: &str, operation: &str) -> Option<&'static str> {
    let object = normalize_token(object);
    match (object.as_str(), operation) {
        ("visaconsole" | "console", "write") => Some("console_write"),
        ("visatimer" | "timer", "now") => Some("now"),
        ("visatimer" | "timer", "arm") => Some("arm_timer"),
        ("visamemory" | "memory" | "guestmemory", "copyin") => Some("copyin"),
        ("visamemory" | "memory" | "guestmemory", "copyout") => Some("copyout"),
        ("visadmw" | "dmw", "map") => Some("map_user_window"),
        ("visadmw" | "dmw", "unmap") => Some("unmap_user_window"),
        ("visammio" | "mmio", "read32") => Some("mmio_read32"),
        ("visammio" | "mmio", "write32") => Some("mmio_write32"),
        ("visadma" | "dma", "alloc") => Some("dma_alloc"),
        ("visadma" | "dma", "free") => Some("dma_free"),
        ("visairq" | "irq", "ack") => Some("irq_ack"),
        ("visairq" | "irq", "mask") => Some("irq_mask"),
        ("visairq" | "irq", "unmask") => Some("irq_unmask"),
        ("visasnapshot" | "snapshot", "enter") => Some("enter_snapshot_barrier"),
        ("visasnapshot" | "snapshot", "exit") => Some("exit_snapshot_barrier"),
        _ => None,
    }
}

fn normalize_token(value: &str) -> String {
    value.chars().filter(|ch| ch.is_ascii_alphanumeric()).flat_map(char::to_lowercase).collect()
}

fn lower_contains(value: &str, needle: &str) -> bool {
    value.to_ascii_lowercase().contains(needle)
}
