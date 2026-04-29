use super::super::*;
pub(crate) fn boundary_validation_report_manifest(
    report: &BoundaryValidationReport,
) -> BoundaryValidationReportManifest {
    BoundaryValidationReportManifest {
        validator: report.validator.as_str().to_owned(),
        ok: report.is_ok(),
        violation_count: report.violations.len(),
        violations: report.violations.iter().map(boundary_validation_violation_manifest).collect(),
    }
}

pub(crate) fn boundary_validation_violation_manifest(
    violation: &BoundaryValidationViolation,
) -> BoundaryValidationViolationManifest {
    BoundaryValidationViolationManifest {
        validator: violation.validator.as_str().to_owned(),
        kind: violation.kind.as_str().to_owned(),
        object: violation.object.clone(),
        detail: violation.detail.clone(),
    }
}

pub(crate) fn validation_roots(report: &BoundaryValidationReportManifest) -> Vec<String> {
    let mut roots = Vec::new();
    roots.push(format!(
        "boundary-validation validator={} ok={} violations={}",
        report.validator, report.ok, report.violation_count
    ));
    roots.extend(report.violations.iter().map(|violation| {
        format!(
            "boundary-validation validator={} kind={} object={} detail={}",
            violation.validator, violation.kind, violation.object, violation.detail
        )
    }));
    roots
}

pub(crate) fn hostcall_manifest(hostcall: &HostcallSpec) -> HostcallSpecManifest {
    HostcallSpecManifest {
        number: hostcall.number,
        name: hostcall.name.clone(),
        category: hostcall.category.as_str().to_owned(),
        object: hostcall.object.clone(),
        operation: hostcall.operation.clone(),
        may_pending: hostcall.may_pending,
    }
}

pub(crate) fn target_capability_manifest(
    capability: &TargetCapabilitySpec,
) -> TargetCapabilitySpecManifest {
    TargetCapabilitySpecManifest {
        object: capability.object.clone(),
        operations: capability.operations.clone(),
        lifetime: capability.lifetime.clone(),
        class: capability.class.as_str().to_owned(),
    }
}

pub(crate) fn trap_metadata_manifest(metadata: &TargetTrapMetadata) -> TargetTrapMetadataManifest {
    TargetTrapMetadataManifest {
        class: metadata.class.as_str().to_owned(),
        symbol: metadata.symbol.clone(),
        offset: metadata.offset,
    }
}

pub(crate) fn address_map_manifest(entry: &TargetAddressMapEntry) -> TargetAddressMapEntryManifest {
    TargetAddressMapEntryManifest {
        symbol: entry.symbol.clone(),
        offset: entry.offset,
        len: entry.len,
    }
}

pub(crate) fn validate_bundle_manifest(
    manifest: &ArtifactBundleManifest,
) -> Result<ValidatedArtifactPlan, Box<dyn Error>> {
    build_validated_artifact_plan(manifest).map_err(Into::into)
}

pub(crate) fn validate_migration_package(
    package: &MigrationPackageManifest,
    manifest: &ArtifactBundleManifest,
) -> Result<(), Box<dyn Error>> {
    validate_migration_against_manifest(package, manifest)?;
    validate_replay_quiescent(package)?;
    Ok(())
}

pub(crate) fn restore_migration_package(
    package: &MigrationPackageManifest,
    semantic: &SemanticGraph,
    plan: &ValidatedArtifactPlan,
) -> Result<(), Box<dyn Error>> {
    if package.semantic.fault_domain_count > semantic.fault_domain_count() {
        return Err(
            "migration package requires more fault domains than the executor rebuilt".into()
        );
    }
    if package.semantic.store_count > semantic.store_count() {
        return Err("migration package requires more stores than the executor rebuilt".into());
    }
    if package.semantic.capability_count > semantic.capabilities().records().len() {
        return Err("migration package requires more capabilities than the executor rebound".into());
    }
    for capability in &package.logical_capabilities {
        if is_semantic_evidence_capability(capability) {
            continue;
        }
        let Some(module) = plan.entry(&capability.subject) else {
            return Err(format!(
                "migration package capability subject {} is not in target load plan",
                capability.subject
            )
            .into());
        };
        let Some(target_capability) =
            module.capabilities.iter().find(|target| target.name == capability.object)
        else {
            return Err(format!(
                "target manifest cannot satisfy capability {}::{}",
                capability.subject, capability.object
            )
            .into());
        };
        if target_capability.lifetime != capability.lifetime {
            return Err(format!(
                "target manifest lifetime mismatch for {}::{}",
                capability.subject, capability.object
            )
            .into());
        }
        for right in &capability.rights {
            if !target_capability.rights.iter().any(|target_right| target_right == right) {
                return Err(format!(
                    "target manifest cannot satisfy right {} for {}::{}",
                    right, capability.subject, capability.object
                )
                .into());
            }
            semantic.capabilities().check(&capability.subject, &capability.object, right).map_err(
                |_| {
                    format!(
                        "target executor failed to rebind capability {}::{} right {}",
                        capability.subject, capability.object, right
                    )
                },
            )?;
        }
    }

    println!(
        "migration restore/rebind demo package={} source_arch={} target_requirement={} guest_isa={}",
        package.package_id,
        package.source.arch,
        package.target.arch_requirement,
        package.guest.canonical_isa
    );
    println!(
        "restore plan: import semantic roots harts={} tasks={} resources={} authorities={}/{} waits={} pending_waits={} transactions={} active_transactions={} fastpath={}/{} boundaries={} artifacts={} activations={} executor_transitions={} sockets={} rx_bytes={} event_cursor={}",
        package.semantic.hart_count,
        package.semantic.task_count,
        package.semantic.resource_count,
        package.semantic.active_authority_count,
        package.semantic.authority_count,
        package.semantic.wait_token_count,
        package.semantic.pending_wait_count,
        package.semantic.transaction_count,
        package.semantic.active_transaction_count,
        package.semantic.active_fast_path_plan_count,
        package.semantic.fast_path_plan_count,
        package.semantic.boundary_count,
        package.semantic.artifact_verification_count,
        package.semantic.store_activation_count,
        package.semantic.executor_transition_count,
        package.semantic.network_socket_count,
        package.semantic.network_rx_queue_bytes,
        package.semantic.event_log_cursor
    );
    println!(
        "restore plan: rebuilt {} stores across {} fault domains and rebound {} logical capabilities",
        semantic.store_count(),
        semantic.fault_domain_count(),
        package.logical_capabilities.len()
    );
    println!("restore plan: not migrated = {}", package.not_migrated.join(", "));
    Ok(())
}

pub(crate) fn is_semantic_evidence_capability(capability: &MigrationCapabilityManifest) -> bool {
    SEMANTIC_EVIDENCE_CAPABILITY_SOURCES.contains(&capability.source.as_str())
}

pub(crate) fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

pub(crate) fn read_manifest(
    artifact_root: &Path,
) -> Result<ArtifactBundleManifest, Box<dyn Error>> {
    let bytes = fs::read(artifact_root.join("manifest.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn read_migration_package(
    path: &Path,
) -> Result<MigrationPackageManifest, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest dir")?);
    Ok(manifest_dir.parent().ok_or("target_executor must live in workspace root")?.to_path_buf())
}
