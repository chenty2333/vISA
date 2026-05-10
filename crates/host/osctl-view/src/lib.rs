//! Read-only Semantic Virtual ISA view renderer.
//!
//! This crate turns contract-visible vISA effects, package facts, runtime
//! attribution, profile records, and graph history into stable view output. It
//! does not mutate semantic state and does not expose private runtime structs as
//! API.

#![recursion_limit = "256"]

use std::{error::Error, fs, path::Path};

use artifact_manifest::{
    ActivationCleanupManifest, ActivationContextManifest, ActivationMigrationManifest,
    ActivationRecordManifest, ActivationResumeManifest, ActivationWaitManifest,
    ArtifactBundleManifest, BlockBenchmarkManifest, BlockCompletionObjectManifest,
    BlockDeviceObjectManifest, BlockDmaBufferManifest, BlockDriverCleanupManifest,
    BlockPageObjectManifest, BlockPendingIoPolicyManifest, BlockRangeObjectManifest,
    BlockReadPathManifest, BlockRecoveryBenchmarkManifest, BlockRequestGenerationAuditManifest,
    BlockRequestObjectManifest, BlockRequestQueueManifest, BlockWaitManifest,
    BlockWritePathManifest, BoundaryValidationReportManifest, BufferCacheObjectManifest,
    CapabilityRecordManifest, CleanupTransactionManifest, CodeObjectManifest,
    CommandResultManifest, ContractObjectRefManifest, CrossHartSchedulerDecisionManifest,
    DescriptorObjectManifest, DeviceCapabilityManifest, DeviceObjectManifest,
    DirectoryObjectManifest, DisplayCapabilityManifest, DisplayCleanupManifest,
    DisplayEventLogManifest, DisplayObjectManifest, DisplayPanicLastFrameManifest,
    DisplaySnapshotBarrierManifest, DmaBufferObjectManifest, DriverStoreBindingManifest,
    EndpointObjectManifest, Ext4AdapterObjectManifest, FakeBlockBackendObjectManifest,
    FakeNetBackendObjectManifest, FatAdapterObjectManifest, FileHandleCapabilityManifest,
    FileObjectManifest, FramebufferBenchmarkManifest, FramebufferDirtyRegionManifest,
    FramebufferFlushRegionManifest, FramebufferMappingManifest, FramebufferObjectManifest,
    FramebufferWindowLeaseManifest, FramebufferWriteManifest, FsWaitManifest,
    HartEventAttributionManifest, HartRecordManifest, HostcallTraceManifest,
    IntegratedCodePublishSmpWorkloadManifest, IntegratedDiskPreemptFaultManifest,
    IntegratedDisplayPanicManifest, IntegratedDisplaySchedulerLoadManifest,
    IntegratedNetworkDiskIoManifest, IntegratedOsctlTraceReplayManifest,
    IntegratedSimdMigrationManifest, IntegratedSmpNetworkFaultManifest,
    IntegratedSmpPreemptionCleanupManifest, IntegratedSnapshotIoLeaseBarrierManifest,
    InterfaceEventManifest, IoCleanupManifest, IoFaultInjectionManifest,
    IoValidationReportManifest, IoWaitManifest, IpiEventManifest, IrqEventManifest,
    IrqLineObjectManifest, MigrationPackageManifest, MmioRegionObjectManifest,
    NetworkBackpressureManifest, NetworkBenchmarkManifest, NetworkDriverCleanupManifest,
    NetworkFaultInjectionManifest, NetworkGenerationAuditManifest,
    NetworkRecoveryBenchmarkManifest, NetworkRxInterruptManifest, NetworkRxWaitResolutionManifest,
    NetworkStackAdapterManifest, NetworkTxCapabilityGateManifest, NetworkTxCompletionManifest,
    PacketBufferObjectManifest, PacketDescriptorObjectManifest, PacketDeviceObjectManifest,
    PacketQueueObjectManifest, PreemptionLatencySampleManifest, PreemptionManifest,
    QueueObjectManifest, RemoteParkManifest, RemotePreemptManifest, RunnableQueueManifest,
    RuntimeActivationRecordManifest, SavedContextManifest, SchedulerDecisionManifest,
    SimdBenchmarkManifest, SimdContextSwitchBenchmarkManifest, SimdFaultInjectionManifest,
    SmpCleanupQuiescenceManifest, SmpCodePublishBarrierManifest, SmpSafePointManifest,
    SmpScalingBenchmarkManifest, SmpSnapshotBarrierManifest, SmpStressRunManifest,
    SocketObjectManifest, SocketOperationManifest, SocketWaitManifest,
    StopTheWorldRendezvousManifest, StoreRecordManifest, SubstrateEventManifest,
    TargetArtifactImageManifest, TargetFeatureSetManifest, TaskRecordManifest,
    TimerInterruptManifest, TrapRecordManifest, VectorStateManifest,
    VirtioBlkBackendObjectManifest, VirtioNetBackendObjectManifest, WaitRecordManifest,
};
use contract_core::VIEW_SCHEMA_V1;
use contract_validate::{
    ArtifactInterfaceCompatibilityReport, ArtifactSubstrateCompatibilityReport,
    ExternalMigrationAuditReport, InterfaceHostCapabilitySet, ValidatedArtifactEntry,
    ValidatedArtifactPlan, audit_migration_package, build_validated_artifact_plan,
    check_artifact_manifest_interface_compatibility, check_artifact_manifest_profile_gate,
    host_validation_interface_capabilities, validate_migration_against_manifest,
    validate_migration_package, validate_replay_quiescent,
};
use semantic_core::{CapabilityClass, RuntimeMode};
use visa_profile::{SubstrateCapabilitySet, SubstrateProfile};

mod graph;
mod inspect;
mod replay;
mod views;

pub use graph::{GraphEdgeMode, print_graph};
#[cfg(test)]
use graph::{graph_edges_for_package, history_graph_edges, live_graph_edges};
use graph::{
    object_ref_json, object_ref_manifest_json, optional_object_ref_json,
    osctl_kind_from_contract_kind,
};
pub use inspect::{inspect_object, print_activation, print_event_log_tail};
pub use replay::replay_until;
use views::*;

const OSCTL_JSON_SCHEMA_VERSION: &str = "vmos-osctl-json-v1";

pub fn print_summary(path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        print_migration_summary(&package);
        return Ok(());
    }
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    print_artifact_summary(&manifest)?;
    Ok(())
}

pub fn check_path(path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        validate_migration_package(&package)?;
        println!(
            "package check ok package={} cursor={}",
            package.package_id, package.semantic.event_log_cursor
        );
        return Ok(());
    }
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    let plan = build_validated_artifact_plan(&manifest)?;
    println!(
        "manifest check ok profile={} mode={} modules={} caps={} exports={}",
        manifest.artifact_profile,
        plan.runtime_mode,
        plan.module_count(),
        plan.capability_count(),
        plan.expected_export_count()
    );
    Ok(())
}

pub fn handle_view_command(kind: &str, args: Vec<String>) -> Result<(), Box<dyn Error>> {
    let Some(subcommand) = args.first() else {
        return Err(format!("{kind} requires show/list").into());
    };
    if subcommand != "show" && subcommand != "list" {
        return Err(format!(
            "{kind} syntax is: osctl {kind} show|list [--json] <migration.json> [id]"
        )
        .into());
    }
    let mut json = false;
    let mut path = None;
    let mut id = None;
    for arg in args.iter().skip(1) {
        if arg == "--json" {
            json = true;
        } else if path.is_none() {
            path = Some(arg.clone());
        } else if id.is_none() {
            id = Some(arg.clone());
        } else {
            return Err(format!("{kind} {subcommand} received too many arguments").into());
        }
    }
    let path = path.ok_or_else(|| format!("{kind} {subcommand} requires a migration JSON path"))?;
    if !json {
        let filter = if subcommand == "show" { id.as_deref() } else { None };
        return inspect_object(kind, Path::new(&path), filter, false);
    }
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    let value = stable_view_collection_v1(kind, subcommand, &package, id.as_deref())?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub fn validate_contract(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    let structural_error =
        validate_migration_package(&package).err().map(|error| error.to_string());
    let value = contract_validation_view_v1(&package, structural_error.as_deref());
    let ok = value.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let last_error = value.get("last_error").and_then(serde_json::Value::as_str).map(str::to_owned);
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!(
            "contract validate package={} ok={} violations={} snapshot_ok={} replay_ok={}",
            package.package_id,
            ok,
            package.semantic.contract_violation_count,
            package.semantic.snapshot_validation.ok,
            package.semantic.replay_validation.ok
        );
        if let Some(error) = &structural_error {
            println!("contract validate structure_error={error}");
        }
    }
    if ok {
        Ok(())
    } else {
        Err(last_error.unwrap_or_else(|| "contract validation failed".to_owned()).into())
    }
}

pub fn audit_package(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    let report = audit_migration_package(&package);
    let value = external_audit_view_v1(&report);
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        print_external_audit_text(&report);
    }
    if report.ok() { Ok(()) } else { Err("external audit failed".into()) }
}

fn external_audit_view_v1(report: &ExternalMigrationAuditReport) -> serde_json::Value {
    let state = if report.ok() { "ok" } else { "failed" };
    let target_executor_package_gate =
        report.ok() && report.visa_native_portable_artifact_execution_claim;
    let real_target_substrate_gate = report.ok() && report.real_target_substrate_claim;
    let findings = report
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "severity": finding.severity.as_str(),
                "code": finding.code,
                "detail": finding.detail,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "schema_version": OSCTL_JSON_SCHEMA_VERSION,
        "kind": "external-audit",
        "id": 1,
        "generation": 1,
        "state": state,
        "command": "audit",
        "package": &report.package_id,
        "ok": report.ok(),
        "references": {
            "package": &report.package_id,
            "auditor": "contract_validate.external-migration-audit",
        },
        "claims": {
            "contract_package_valid": report.contract_package_valid,
            "replay_quiescent": report.replay_quiescent,
            "portable_artifact_execution": report.portable_artifact_execution_claim,
            "visa_native_portable_artifact_execution": report.visa_native_portable_artifact_execution_claim,
            "real_target_substrate": report.real_target_substrate_claim,
        },
        "gates": {
            "external_audit": report.ok(),
            "target_executor_package": target_executor_package_gate,
            "real_target_substrate": real_target_substrate_gate,
        },
        "artifact_mix": {
            "visa_native_artifacts": report.visa_native_artifact_count,
            "frontend_personality_artifacts": report.frontend_personality_artifact_count,
            "linux_weighted_artifacts": report.linux_weighted_artifact_count,
        },
        "findings": findings,
        "last_transition": {
            "finding_count": report.findings.len(),
            "error_count": report.errors().count(),
            "warning_count": report.warnings().count(),
        },
        "last_error": report.errors().next().map(|finding| finding.code),
    })
}

fn print_external_audit_text(report: &ExternalMigrationAuditReport) {
    let target_executor_package_gate =
        report.ok() && report.visa_native_portable_artifact_execution_claim;
    let real_target_substrate_gate = report.ok() && report.real_target_substrate_claim;
    println!(
        "audit package={} ok={} target_executor_package_gate={} real_target_substrate_gate={} contract_valid={} replay_quiescent={} portable_artifact_execution={} visa_native_portable_artifact_execution={} real_target_substrate={} visa_native_artifacts={} frontend_personality_artifacts={} linux_weighted_artifacts={} findings={}",
        report.package_id,
        report.ok(),
        target_executor_package_gate,
        real_target_substrate_gate,
        report.contract_package_valid,
        report.replay_quiescent,
        report.portable_artifact_execution_claim,
        report.visa_native_portable_artifact_execution_claim,
        report.real_target_substrate_claim,
        report.visa_native_artifact_count,
        report.frontend_personality_artifact_count,
        report.linux_weighted_artifact_count,
        report.findings.len()
    );
    for finding in &report.findings {
        println!(
            "audit finding severity={} code={} detail={}",
            finding.severity.as_str(),
            finding.code,
            finding.detail
        );
    }
}

fn contract_validation_view_v1(
    package: &MigrationPackageManifest,
    structural_error: Option<&str>,
) -> serde_json::Value {
    let ok = structural_error.is_none()
        && package.semantic.contract_violation_count == 0
        && package.semantic.snapshot_validation.ok
        && package.semantic.replay_validation.ok;
    let state = if ok { "ok" } else { "failed" };
    let last_error = structural_error
        .map(str::to_owned)
        .or_else(|| (!ok).then(|| "contract-validation-failed".to_owned()));
    let mut violations = package
        .semantic
        .contract_violations
        .iter()
        .map(|violation| {
            serde_json::json!({
                "code": violation.kind,
                "severity": "error",
                "subject": {
                    "kind": violation.from.kind,
                    "id": violation.from.id,
                    "generation": violation.from.generation,
                },
                "relation": violation.edge,
                "message": violation.detail,
                "to": violation.to,
            })
        })
        .collect::<Vec<_>>();
    if let Some(error) = structural_error {
        violations.push(serde_json::json!({
            "code": "package-structure",
            "severity": "error",
            "subject": {
                "kind": "migration-package",
                "id": &package.package_id,
                "generation": 1,
            },
            "relation": "structure",
            "message": error,
            "to": serde_json::Value::Null,
        }));
    }
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "schema_version": OSCTL_JSON_SCHEMA_VERSION,
        "kind": "contract-validation",
        "id": 1,
        "generation": 1,
        "state": state,
        "command": "contract.validate",
        "package": &package.package_id,
        "ok": ok,
        "references": {
            "package": &package.package_id,
            "snapshot_validator": &package.semantic.snapshot_validation.validator,
            "replay_validator": &package.semantic.replay_validation.validator,
        },
        "violations": &violations,
        "contract": {
            "ok": structural_error.is_none() && package.semantic.contract_violation_count == 0,
            "violation_count": violations.len(),
            "violations": &violations
        },
        "structure_validation": {
            "ok": structural_error.is_none(),
            "violation_count": usize::from(structural_error.is_some()),
            "violations": structural_error
                .map(|error| vec![serde_json::json!({
                    "code": "package-structure",
                    "message": error
                })])
                .unwrap_or_default()
        },
        "snapshot_validation": &package.semantic.snapshot_validation,
        "replay_validation": &package.semantic.replay_validation,
        "last_transition": {
            "snapshot_ok": package.semantic.snapshot_validation.ok,
            "replay_ok": package.semantic.replay_validation.ok,
        },
        "last_error": last_error
    })
}

pub fn print_plan(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&fs::read(path)?)?;
    let plan_result = build_validated_artifact_plan(&manifest);
    if json {
        let value = match &plan_result {
            Ok(plan) => artifact_plan_view_v1(&manifest, Some(plan), None),
            Err(error) => artifact_plan_view_v1(&manifest, None, Some(&error.to_string())),
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
        return plan_result.map(|_| ()).map_err(|error| error.into());
    }
    let plan = plan_result?;
    print_plan_text(&plan);
    Ok(())
}

pub fn check_substrate_compatibility(
    path: &Path,
    profile: &str,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&fs::read(path)?)?;
    let capabilities = substrate_capabilities_for_profile(profile)
        .ok_or_else(|| format!("unknown substrate profile `{profile}`"))?;
    let report = check_artifact_manifest_profile_gate(&manifest, profile, capabilities)?;
    if json {
        print_substrate_compatibility_json(profile, capabilities, &report)?;
    } else {
        print_substrate_compatibility_text(profile, &report);
    }
    if report.ok { Ok(()) } else { Err("substrate compatibility check failed".into()) }
}

fn substrate_capabilities_for_profile(profile: &str) -> Option<SubstrateCapabilitySet> {
    if profile == "host-validation" {
        return Some(SubstrateCapabilitySet::host_validation());
    }
    SubstrateProfile::parse(profile).map(SubstrateCapabilitySet::for_profile)
}

fn print_substrate_compatibility_text(
    profile: &str,
    report: &ArtifactSubstrateCompatibilityReport,
) {
    println!(
        "substrate check profile={} artifact_profile={} ok={} modules={}",
        profile, report.artifact_profile, report.ok, report.module_count
    );
    println!(
        "profile gate required=per-module reported={} enforced={} ok={}",
        report.reported_profile, report.enforced_profile, report.ok
    );
    for module in &report.modules {
        println!(
            "module {} required_profile={} reported_profile={} enforced_profile={} ok={} missing_required={} degraded_optional={} forbidden_requested={}",
            module.package,
            module.substrate_profile_required,
            module.reported_profile,
            module.enforced_profile,
            module.ok,
            module.missing_required.len(),
            module.degraded_optional.len(),
            module.forbidden_requested.len()
        );
        for missing in &module.missing_required {
            println!(
                "  missing authority={} required={} actual={}",
                missing.authority, missing.expected, missing.actual
            );
        }
        for degraded in &module.degraded_optional {
            println!(
                "  degraded authority={} required={} actual={}",
                degraded.authority, degraded.expected, degraded.actual
            );
        }
    }
}

fn print_substrate_compatibility_json(
    profile: &str,
    capabilities: SubstrateCapabilitySet,
    report: &ArtifactSubstrateCompatibilityReport,
) -> Result<(), Box<dyn Error>> {
    println!(
        "{}",
        serde_json::to_string_pretty(
            &substrate_compatibility_json(profile, capabilities, report,)
        )?
    );
    Ok(())
}

fn substrate_compatibility_json(
    profile: &str,
    capabilities: SubstrateCapabilitySet,
    report: &ArtifactSubstrateCompatibilityReport,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "schema_version": OSCTL_JSON_SCHEMA_VERSION,
        "kind": "substrate-compatibility",
        "command": "substrate.check",
        "profile": profile,
        "reported_profile": &report.reported_profile,
        "enforced_profile": &report.enforced_profile,
        "capabilities": substrate_capabilities_json(capabilities),
        "artifact_profile": &report.artifact_profile,
        "ok": report.ok,
        "module_count": report.module_count,
        "modules": report.modules.iter().map(|module| serde_json::json!({
            "package": &module.package,
            "substrate_profile_required": &module.substrate_profile_required,
            "required_profile": &module.substrate_profile_required,
            "reported_profile": &module.reported_profile,
            "enforced_profile": &module.enforced_profile,
            "ok": module.ok,
            "profile_ok": module.profile_ok,
            "authority_ok": module.authority_ok,
            "missing_required": module.missing_required.iter().map(|item| serde_json::json!({
                "authority": &item.authority,
                "expected": &item.expected,
                "actual": &item.actual
            })).collect::<Vec<_>>(),
            "degraded_optional": module.degraded_optional.iter().map(|item| serde_json::json!({
                "authority": &item.authority,
                "expected": &item.expected,
                "actual": &item.actual
            })).collect::<Vec<_>>(),
            "forbidden_authorities": &module.forbidden_authorities,
            "forbidden_requested": &module.forbidden_requested
        })).collect::<Vec<_>>()
    })
}

fn substrate_capabilities_json(capabilities: SubstrateCapabilitySet) -> serde_json::Value {
    serde_json::json!({
        "console": capabilities.console,
        "timer": capabilities.timer,
        "event_queue": capabilities.event_queue,
        "guest_memory": capabilities.guest_memory,
        "artifact_loading": capabilities.artifact_loading,
        "dmw": capabilities.dmw.as_str(),
        "mmio": capabilities.mmio,
        "irq": capabilities.irq,
        "dma": capabilities.dma.as_str(),
        "snapshot": capabilities.snapshot.as_str(),
        "code_publish": capabilities.code_publish.as_str()
    })
}

pub fn check_interface_compatibility(
    path: &Path,
    profile: &str,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&fs::read(path)?)?;
    let capabilities = interface_capabilities_for_profile(profile)
        .ok_or_else(|| format!("unknown interface profile `{profile}`"))?;
    let report = check_artifact_manifest_interface_compatibility(&manifest, &capabilities)?;
    if json {
        print_interface_compatibility_json(profile, &capabilities, &report)?;
    } else {
        print_interface_compatibility_text(profile, &report);
    }
    if report.ok { Ok(()) } else { Err("interface compatibility check failed".into()) }
}

fn interface_capabilities_for_profile(profile: &str) -> Option<InterfaceHostCapabilitySet> {
    match profile {
        "host-validation" => Some(host_validation_interface_capabilities()),
        "none" => Some(InterfaceHostCapabilitySet::empty()),
        _ => None,
    }
}

fn print_interface_compatibility_text(
    profile: &str,
    report: &ArtifactInterfaceCompatibilityReport,
) {
    println!(
        "interface check profile={} artifact_profile={} ok={} modules={}",
        profile, report.artifact_profile, report.ok, report.module_count
    );
    for module in &report.modules {
        println!(
            "module {} ok={} missing_wasi={} degraded_wasi={} missing_wit={} version_mismatch={}",
            module.package,
            module.ok,
            module.missing_required_wasi_worlds.len(),
            module.degraded_optional_wasi_worlds.len(),
            module.missing_custom_wit_worlds.len(),
            module.version_mismatches.len()
        );
        for world in &module.missing_required_wasi_worlds {
            println!("  missing required_wasi_world={world}");
        }
        for world in &module.missing_custom_wit_worlds {
            println!("  missing custom_wit_world={world}");
        }
        for mismatch in &module.version_mismatches {
            println!(
                "  version field={} expected={} actual={}",
                mismatch.field, mismatch.expected, mismatch.actual
            );
        }
    }
}

fn print_interface_compatibility_json(
    profile: &str,
    capabilities: &InterfaceHostCapabilitySet,
    report: &ArtifactInterfaceCompatibilityReport,
) -> Result<(), Box<dyn Error>> {
    let value = serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "schema_version": OSCTL_JSON_SCHEMA_VERSION,
        "kind": "interface-compatibility",
        "command": "interface.check",
        "profile": profile,
        "capabilities": {
            "wasi_worlds": &capabilities.wasi_worlds,
            "custom_wit_worlds": &capabilities.custom_wit_worlds,
            "component_model_version": &capabilities.component_model_version,
            "wasi_profile": &capabilities.wasi_profile,
            "hostcall_abi_version": &capabilities.hostcall_abi_version,
            "capability_abi_version": &capabilities.capability_abi_version,
            "semantic_contract_version": &capabilities.semantic_contract_version
        },
        "artifact_profile": &report.artifact_profile,
        "ok": report.ok,
        "module_count": report.module_count,
        "modules": report.modules.iter().map(|module| serde_json::json!({
            "package": &module.package,
            "ok": module.ok,
            "missing_required_wasi_worlds": &module.missing_required_wasi_worlds,
            "degraded_optional_wasi_worlds": &module.degraded_optional_wasi_worlds,
            "missing_custom_wit_worlds": &module.missing_custom_wit_worlds,
            "version_mismatches": module.version_mismatches.iter().map(|mismatch| serde_json::json!({
                "field": &mismatch.field,
                "expected": &mismatch.expected,
                "actual": &mismatch.actual
            })).collect::<Vec<_>>()
        })).collect::<Vec<_>>()
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub fn print_interface_events(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    if json {
        let value = serde_json::json!({
            "schema": VIEW_SCHEMA_V1,
            "schema_version": OSCTL_JSON_SCHEMA_VERSION,
            "kind": "interface-events",
            "command": "interface.events",
            "package": &package.package_id,
            "event_count": package.semantic.interface_events.len(),
            "events": package.semantic.interface_events.iter().map(interface_event_view_v1).collect::<Vec<_>>(),
            "references": {
                "event_log_cursor": package.semantic.event_log_cursor,
                "root_count": package.semantic.roots.interface_event_roots.len()
            }
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    println!(
        "interface events package={} events={} roots={}",
        package.package_id,
        package.semantic.interface_events.len(),
        package.semantic.roots.interface_event_roots.len()
    );
    for event in &package.semantic.interface_events {
        println!(
            "{} interface={} operation={} requester={} explanation={}",
            event.interface_kind,
            event.interface,
            event.operation,
            event.requester.as_deref().unwrap_or("none"),
            event.explanation
        );
    }
    Ok(())
}

fn interface_event_view_v1(event: &InterfaceEventManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "interface-event",
        "id": event.id,
        "generation": 1,
        "state": "unsupported",
        "interface_kind": &event.interface_kind,
        "interface": &event.interface,
        "operation": &event.operation,
        "requester": &event.requester,
        "references": {
            "artifact": event.artifact,
            "store": event.store,
            "event_epoch": event.epoch
        },
        "last_transition": {
            "interface_kind": &event.interface_kind,
            "interface": &event.interface,
            "operation": &event.operation
        },
        "last_error": &event.explanation
    })
}

pub fn print_substrate_events(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    if json {
        let value = serde_json::json!({
            "schema": VIEW_SCHEMA_V1,
            "schema_version": OSCTL_JSON_SCHEMA_VERSION,
            "kind": "substrate-events",
            "command": "substrate.events",
            "package": &package.package_id,
            "event_count": package.semantic.substrate_events.len(),
            "events": package.semantic.substrate_events.iter().map(substrate_event_view_v1).collect::<Vec<_>>(),
            "references": {
                "event_log_cursor": package.semantic.event_log_cursor,
                "root_count": package.semantic.roots.substrate_event_roots.len()
            }
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    println!(
        "substrate events package={} events={} roots={}",
        package.package_id,
        package.semantic.substrate_events.len(),
        package.semantic.roots.substrate_event_roots.len()
    );
    for event in &package.semantic.substrate_events {
        println!(
            "{} authority={} operation={} requester={} explanation={}",
            event.event_kind,
            event.authority,
            event.operation,
            event.requester.as_deref().unwrap_or("none"),
            event.explanation
        );
    }
    Ok(())
}

fn substrate_event_view_v1(event: &SubstrateEventManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "substrate-event",
        "id": event.id,
        "generation": 1,
        "state": &event.event_kind,
        "authority": &event.authority,
        "operation": &event.operation,
        "requester": &event.requester,
        "capability": &event.capability,
        "references": {
            "artifact": event.artifact,
            "store": event.store,
            "event_epoch": event.epoch
        },
        "last_transition": {
            "event_kind": &event.event_kind,
            "authority": &event.authority,
            "operation": &event.operation
        },
        "last_error": &event.explanation
    })
}

fn command_result_view_v1(result: &CommandResultManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "command",
        "id": result.id,
        "generation": 1,
        "state": &result.status,
        "issuer": &result.issuer,
        "command_name": &result.command,
        "references": {
            "events": &result.events,
            "effects": &result.effects,
        },
        "violations": &result.violations,
        "last_transition": {
            "event_count": result.events.len(),
            "effect_count": result.effects.len(),
        },
        "last_error": result.violations.first(),
    })
}

pub fn print_modes() -> Result<(), Box<dyn Error>> {
    for mode in RuntimeMode::all() {
        println!(
            "mode {} event_log={} dmw={} fastpath={} deterministic={} capability_audit={} debug_metadata={} nondeterminism={}",
            mode.as_str(),
            mode.event_log_policy(),
            mode.dmw_policy(),
            if mode.fast_path_enabled() { "enabled" } else { "disabled" },
            mode.deterministic_boundary(),
            mode.capability_audit_policy(),
            mode.debug_metadata_policy(),
            mode.nondeterminism_policy()
        );
    }
    Ok(())
}

pub fn print_caps(path: &Path, subject: Option<&str>) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        println!(
            "capability ledger package={} caps={} cursor={}",
            package.package_id,
            package.logical_capabilities.len(),
            package.semantic.event_log_cursor
        );
        for capability in package
            .logical_capabilities
            .iter()
            .filter(|capability| subject.is_none_or(|subject| capability.subject == subject))
        {
            println!(
                "cap subject={} object={} class={} rights={} lifetime={} generation={} source={} owner_store={}@{} owner_task={} revoked={}",
                capability.subject,
                capability.object,
                display_capability_class(&capability.class, &capability.object),
                capability.rights.join("+"),
                capability.lifetime,
                capability.generation,
                display_default(&capability.source, "unknown"),
                display_option_u64(capability.owner_store),
                display_option_u64(capability.owner_store_generation),
                display_option_u64(capability.owner_task),
                capability.revoked
            );
        }
        return Ok(());
    }

    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    let plan = build_validated_artifact_plan(&manifest)?;
    println!(
        "capability manifest profile={} mode={} caps={} modules={}",
        plan.artifact_profile,
        plan.runtime_mode,
        plan.capability_count(),
        plan.module_count()
    );
    for module in &plan.modules {
        if subject.is_some_and(|subject| module.package != subject) {
            continue;
        }
        for capability in &module.capabilities {
            println!(
                "cap subject={} object={} class={} rights={} lifetime={} source=artifact-manifest owner_store=planned-store",
                module.package,
                capability.name,
                CapabilityClass::from_object(&capability.name).as_str(),
                capability.rights.join("+"),
                capability.lifetime
            );
        }
    }
    Ok(())
}

pub fn print_state(path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        println!(
            "semantic state package={} cursor={} harts={} tasks={} runtime_activations={} runnable_queues={} activation_contexts={} saved_contexts={} timer_interrupts={} ipi_events={} remote_preempts={} remote_parks={} preemptions={} scheduler_decisions={} cross_hart_scheduler_decisions={} activation_migrations={} smp_safe_points={} stop_the_world_rendezvous={} smp_code_publish_barriers={} smp_cleanup_quiescence={} smp_snapshot_barriers={} smp_stress_runs={} smp_scaling_benchmarks={} target_feature_sets={} devices={} queues={} descriptors={} dma_buffers={} mmio_regions={} irq_lines={} irq_events={} device_capabilities={} driver_store_bindings={} io_waits={} io_cleanups={} io_fault_injections={} io_validation_reports={} packet_devices={} packet_buffers={} packet_queues={} packet_descriptors={} fake_net_backends={} virtio_net_backends={} block_devices={} block_ranges={} block_requests={} block_completions={} block_waits={} fake_block_backends={} virtio_blk_backends={} activation_resumes={} activation_waits={} activation_cleanups={} preemption_latency_samples={} hart_event_attributions={} resources={} stores={} caps={} waits={} authorities={}/{} boundaries={} artifacts={} activations={} executor_transitions={} target_artifacts={} code_objects={} activation_records={} traps={} hostcalls={} migration_objects={}",
            package.package_id,
            package.semantic.event_log_cursor,
            package.semantic.hart_count,
            package.semantic.task_count,
            package.semantic.runtime_activation_count,
            package.semantic.runnable_queue_count,
            package.semantic.activation_context_count,
            package.semantic.saved_context_count,
            package.semantic.timer_interrupt_count,
            package.semantic.ipi_event_count,
            package.semantic.remote_preempt_count,
            package.semantic.remote_park_count,
            package.semantic.preemption_count,
            package.semantic.scheduler_decision_count,
            package.semantic.cross_hart_scheduler_decision_count,
            package.semantic.activation_migration_count,
            package.semantic.smp_safe_point_count,
            package.semantic.stop_the_world_rendezvous_count,
            package.semantic.smp_code_publish_barrier_count,
            package.semantic.smp_cleanup_quiescence_count,
            package.semantic.smp_snapshot_barrier_count,
            package.semantic.smp_stress_run_count,
            package.semantic.smp_scaling_benchmark_count,
            package.semantic.target_feature_set_count,
            package.semantic.device_object_count,
            package.semantic.queue_object_count,
            package.semantic.descriptor_object_count,
            package.semantic.dma_buffer_object_count,
            package.semantic.mmio_region_object_count,
            package.semantic.irq_line_object_count,
            package.semantic.irq_event_count,
            package.semantic.device_capability_count,
            package.semantic.driver_store_binding_count,
            package.semantic.io_wait_count,
            package.semantic.io_cleanup_count,
            package.semantic.io_fault_injection_count,
            package.semantic.io_validation_report_count,
            package.semantic.packet_device_object_count,
            package.semantic.packet_buffer_object_count,
            package.semantic.packet_queue_object_count,
            package.semantic.packet_descriptor_object_count,
            package.semantic.fake_net_backend_object_count,
            package.semantic.virtio_net_backend_object_count,
            package.semantic.block_device_object_count,
            package.semantic.block_range_object_count,
            package.semantic.block_request_object_count,
            package.semantic.block_completion_object_count,
            package.semantic.block_wait_count,
            package.semantic.fake_block_backend_object_count,
            package.semantic.virtio_blk_backend_object_count,
            package.semantic.activation_resume_count,
            package.semantic.activation_wait_count,
            package.semantic.activation_cleanup_count,
            package.semantic.preemption_latency_sample_count,
            package.semantic.hart_event_attribution_count,
            package.semantic.resource_count,
            package.semantic.store_count,
            package.semantic.capability_count,
            package.semantic.wait_token_count,
            package.semantic.active_authority_count,
            package.semantic.authority_count,
            package.semantic.boundary_count,
            package.semantic.artifact_verification_count,
            package.semantic.store_activation_count,
            package.semantic.executor_transition_count,
            package.semantic.target_artifact_count,
            package.semantic.code_object_count,
            package.semantic.activation_record_count,
            package.semantic.trap_record_count,
            package.semantic.hostcall_trace_count,
            package.semantic.migration_object_count
        );
        println!(
            "substrate/executor boundary native_policy={} not_migrated={}",
            package.substrate_boundary.native_state_policy,
            package.not_migrated.join(", ")
        );
        println!(
            "replay boundary scheduler_cursor={} random_epoch={} irq={} dma={} net_inputs={} dmw_leases={} active_mmio={} active_dma={} active_irq={} active_packet_device={} active_virtqueue={} cow_epoch={} background_pages={}",
            package.substrate_boundary.scheduler_decision_cursor,
            package.substrate_boundary.random_epoch,
            package.substrate_boundary.pending_irq_causes,
            package.substrate_boundary.pending_dma_completions,
            package.substrate_boundary.pending_network_inputs,
            package.substrate_boundary.active_dmw_lease_count,
            package.substrate_boundary.active_mmio_authority_count,
            package.substrate_boundary.active_dma_authority_count,
            package.substrate_boundary.active_irq_authority_count,
            package.substrate_boundary.active_packet_device_authority_count,
            package.substrate_boundary.active_virtio_queue_authority_count,
            package.substrate_boundary.cow_epoch,
            package.substrate_boundary.background_copy_pages
        );
        return Ok(());
    }

    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    let plan = build_validated_artifact_plan(&manifest)?;
    let mode = RuntimeMode::parse(&plan.runtime_mode).unwrap_or(RuntimeMode::Research);
    println!(
        "planned semantic/executor boundary profile={} mode={} modules={} caps={} exports={}",
        plan.artifact_profile,
        plan.runtime_mode,
        plan.module_count(),
        plan.capability_count(),
        plan.expected_export_count()
    );
    println!(
        "mode policy event_log={} dmw={} fastpath={} deterministic={} capability_audit={} metadata={} nondeterminism={}",
        mode.event_log_policy(),
        mode.dmw_policy(),
        if mode.fast_path_enabled() { "enabled" } else { "disabled" },
        mode.deterministic_boundary(),
        mode.capability_audit_policy(),
        mode.debug_metadata_policy(),
        mode.nondeterminism_policy()
    );
    println!(
        "executor boundary engine={} execution_mode={} artifact_format={} runtime_executor={}",
        plan.compiler_engine,
        plan.compiler_execution_mode,
        plan.artifact_format,
        plan.runtime_executor_abi
    );
    Ok(())
}

fn print_migration_summary(package: &MigrationPackageManifest) {
    println!(
        "migration package={} format={} source={} target={} guest_isa={} cursor={}",
        package.package_id,
        package.package_format,
        package.source.arch,
        package.target.arch_requirement,
        package.guest.canonical_isa,
        package.semantic.event_log_cursor
    );
    println!(
        "semantic roots: harts={} tasks={} resources={} authorities={}/{} waits={} capabilities={} stores={} fastpath={}/{} boundaries={} artifacts={} activations={} executor_transitions={} target_artifacts={} code_objects={} activation_records={} traps={} hostcalls={} migration_objects={} timer_interrupts={} ipi_events={} remote_preempts={} remote_parks={} cross_hart_scheduler_decisions={} activation_migrations={} smp_safe_points={} stop_the_world_rendezvous={} smp_code_publish_barriers={} smp_cleanup_quiescence={} smp_snapshot_barriers={} smp_stress_runs={} smp_scaling_benchmarks={} devices={} queues={} descriptors={} dma_buffers={} mmio_regions={} irq_lines={} irq_events={} device_capabilities={} driver_store_bindings={} io_waits={} io_cleanups={} io_fault_injections={} io_validation_reports={} packet_devices={} packet_buffers={} packet_queues={} packet_descriptors={} fake_net_backends={} virtio_net_backends={} socket_waits={} network_backpressures={} network_driver_cleanups={} network_generation_audits={} network_fault_injections={} network_benchmarks={} network_recovery_benchmarks={} block_devices={} block_ranges={} block_requests={} block_completions={} block_waits={} fake_block_backends={} virtio_blk_backends={} block_read_paths={} block_write_paths={} block_request_queues={} block_dma_buffers={} block_page_objects={} buffer_cache_objects={} file_objects={} directory_objects={} fat_adapter_objects={} ext4_adapter_objects={} file_handle_capabilities={} fs_waits={} block_driver_cleanups={} block_recovery_benchmarks={} target_feature_sets={} activation_cleanups={} preemption_latency_samples={} hart_event_attributions={} substrate_events={} command_results={} interface_events={}",
        package.semantic.hart_count,
        package.semantic.task_count,
        package.semantic.resource_count,
        package.semantic.active_authority_count,
        package.semantic.authority_count,
        package.semantic.wait_token_count,
        package.semantic.capability_count,
        package.semantic.store_count,
        package.semantic.active_fast_path_plan_count,
        package.semantic.fast_path_plan_count,
        package.semantic.boundary_count,
        package.semantic.artifact_verification_count,
        package.semantic.store_activation_count,
        package.semantic.executor_transition_count,
        package.semantic.target_artifact_count,
        package.semantic.code_object_count,
        package.semantic.activation_record_count,
        package.semantic.trap_record_count,
        package.semantic.hostcall_trace_count,
        package.semantic.migration_object_count,
        package.semantic.timer_interrupt_count,
        package.semantic.ipi_event_count,
        package.semantic.remote_preempt_count,
        package.semantic.remote_park_count,
        package.semantic.cross_hart_scheduler_decision_count,
        package.semantic.activation_migration_count,
        package.semantic.smp_safe_point_count,
        package.semantic.stop_the_world_rendezvous_count,
        package.semantic.smp_code_publish_barrier_count,
        package.semantic.smp_cleanup_quiescence_count,
        package.semantic.smp_snapshot_barrier_count,
        package.semantic.smp_stress_run_count,
        package.semantic.smp_scaling_benchmark_count,
        package.semantic.device_object_count,
        package.semantic.queue_object_count,
        package.semantic.descriptor_object_count,
        package.semantic.dma_buffer_object_count,
        package.semantic.mmio_region_object_count,
        package.semantic.irq_line_object_count,
        package.semantic.irq_event_count,
        package.semantic.device_capability_count,
        package.semantic.driver_store_binding_count,
        package.semantic.io_wait_count,
        package.semantic.io_cleanup_count,
        package.semantic.io_fault_injection_count,
        package.semantic.io_validation_report_count,
        package.semantic.packet_device_object_count,
        package.semantic.packet_buffer_object_count,
        package.semantic.packet_queue_object_count,
        package.semantic.packet_descriptor_object_count,
        package.semantic.fake_net_backend_object_count,
        package.semantic.virtio_net_backend_object_count,
        package.semantic.socket_wait_count,
        package.semantic.network_backpressure_count,
        package.semantic.network_driver_cleanup_count,
        package.semantic.network_generation_audit_count,
        package.semantic.network_fault_injection_count,
        package.semantic.network_benchmark_count,
        package.semantic.network_recovery_benchmark_count,
        package.semantic.block_device_object_count,
        package.semantic.block_range_object_count,
        package.semantic.block_request_object_count,
        package.semantic.block_completion_object_count,
        package.semantic.block_wait_count,
        package.semantic.fake_block_backend_object_count,
        package.semantic.virtio_blk_backend_object_count,
        package.semantic.block_read_path_count,
        package.semantic.block_write_path_count,
        package.semantic.block_request_queue_count,
        package.semantic.block_dma_buffer_count,
        package.semantic.block_page_object_count,
        package.semantic.buffer_cache_object_count,
        package.semantic.file_object_count,
        package.semantic.directory_object_count,
        package.semantic.fat_adapter_object_count,
        package.semantic.ext4_adapter_object_count,
        package.semantic.file_handle_capability_count,
        package.semantic.fs_wait_count,
        package.semantic.block_driver_cleanup_count,
        package.semantic.block_recovery_benchmark_count,
        package.semantic.target_feature_set_count,
        package.semantic.activation_cleanup_count,
        package.semantic.preemption_latency_sample_count,
        package.semantic.hart_event_attribution_count,
        package.semantic.substrate_event_count,
        package.semantic.command_result_count,
        package.semantic.interface_event_count
    );
    println!(
        "substrate boundary: irq={} dma={} net_inputs={} dmw={} active_mmio={} active_dma={} active_irq={} active_packet_device={} active_virtqueue={} cow_epoch={} background_pages={}",
        package.substrate_boundary.pending_irq_causes,
        package.substrate_boundary.pending_dma_completions,
        package.substrate_boundary.pending_network_inputs,
        package.substrate_boundary.active_dmw_lease_count,
        package.substrate_boundary.active_mmio_authority_count,
        package.substrate_boundary.active_dma_authority_count,
        package.substrate_boundary.active_irq_authority_count,
        package.substrate_boundary.active_packet_device_authority_count,
        package.substrate_boundary.active_virtio_queue_authority_count,
        package.substrate_boundary.cow_epoch,
        package.substrate_boundary.background_copy_pages
    );
    print_roots("hart", &package.semantic.roots.hart_roots);
    print_roots("boundary", &package.semantic.roots.boundary_roots);
    print_roots("artifact-verification", &package.semantic.roots.artifact_verification_roots);
    print_roots("store-activation", &package.semantic.roots.store_activation_roots);
    print_roots("executor-transition", &package.semantic.roots.executor_transition_roots);
    print_roots("target-artifact", &package.semantic.roots.target_artifact_roots);
    print_roots("code-object", &package.semantic.roots.code_object_roots);
    print_roots("activation-record", &package.semantic.roots.activation_record_roots);
    print_roots("trap", &package.semantic.roots.trap_roots);
    print_roots("hostcall", &package.semantic.roots.hostcall_trace_roots);
    print_roots("migration-object", &package.semantic.roots.migration_object_roots);
    print_roots("substrate-event", &package.semantic.roots.substrate_event_roots);
    print_roots("command-result", &package.semantic.roots.command_result_roots);
    print_roots("interface-event", &package.semantic.roots.interface_event_roots);
    print_roots("socket-wait", &package.semantic.roots.socket_wait_roots);
    print_roots("network-backpressure", &package.semantic.roots.network_backpressure_roots);
    print_roots("network-driver-cleanup", &package.semantic.roots.network_driver_cleanup_roots);
    print_roots("fat-adapter-object", &package.semantic.roots.fat_adapter_object_roots);
    print_roots("ext4-adapter-object", &package.semantic.roots.ext4_adapter_object_roots);
    print_roots("file-handle-capability", &package.semantic.roots.file_handle_capability_roots);
    print_roots("fs-wait", &package.semantic.roots.fs_wait_roots);
    print_roots("block-driver-cleanup", &package.semantic.roots.block_driver_cleanup_roots);
    print_roots("block-pending-io-policy", &package.semantic.roots.block_pending_io_policy_roots);
    print_roots(
        "block-request-generation-audit",
        &package.semantic.roots.block_request_generation_audit_roots,
    );
    print_roots("block-benchmark", &package.semantic.roots.block_benchmark_roots);
    print_roots("block-recovery-benchmark", &package.semantic.roots.block_recovery_benchmark_roots);
    print_roots("target-feature-set", &package.semantic.roots.target_feature_set_roots);
}

fn print_artifact_summary(manifest: &ArtifactBundleManifest) -> Result<(), Box<dyn Error>> {
    let plan = build_validated_artifact_plan(manifest)?;
    println!(
        "artifact bundle profile={} runtime_mode={} arch={} engine={} mode={} runtime_executor={} signature_profile={}",
        manifest.artifact_profile,
        plan.runtime_mode,
        manifest.target.arch,
        manifest.compiler.engine,
        manifest.compiler.execution_mode,
        manifest.compiler.runtime_executor_abi,
        manifest.target.artifact_signature_profile
    );
    println!(
        "contract version={} world={} catalog={} packages={}",
        manifest.contract.contract_version,
        manifest.contract.supervisor_world,
        manifest.contract.catalog_fingerprint,
        manifest.contract.package_set_fingerprint
    );
    println!(
        "abi machine={} supervisor={} linux={} wasm_profile={} network={}",
        manifest.target.machine_abi_version,
        manifest.target.supervisor_abi_version,
        manifest.target.linux_abi_profile,
        manifest.target.wasm_feature_profile,
        manifest.target.network_contract_version
    );
    println!(
        "modules={} caps={} exports={}",
        plan.module_count(),
        plan.capability_count(),
        plan.expected_export_count()
    );
    for module in &plan.modules {
        println!(
            "module {} role={} exports={} caps={} deps={} wasi_req={} wit={} substrate_profile={} abi={} binding={} signer={}",
            module.package,
            module.role,
            module.expected_exports.len(),
            module.capabilities.len(),
            module.service_dependencies.len(),
            module.interfaces.required_wasi_worlds.len(),
            module.interfaces.custom_wit_worlds.len(),
            module.interfaces.substrate_profile_required,
            short_hash(&module.abi_fingerprint),
            short_hash(&module.manifest_binding_hash),
            module.signer
        );
    }
    Ok(())
}

fn print_plan_text(plan: &ValidatedArtifactPlan) {
    let mode = RuntimeMode::parse(&plan.runtime_mode).unwrap_or(RuntimeMode::Research);
    println!(
        "load plan profile={} mode={} contract={} world={} target={} engine={} exec_mode={} format={} runtime={}",
        plan.artifact_profile,
        plan.runtime_mode,
        plan.contract_version,
        plan.supervisor_world,
        plan.target_arch,
        plan.compiler_engine,
        plan.compiler_execution_mode,
        plan.artifact_format,
        plan.runtime_executor_abi
    );
    println!(
        "mode policy event_log={} dmw={} fastpath={} deterministic={} capability_audit={} metadata={} nondeterminism={}",
        mode.event_log_policy(),
        mode.dmw_policy(),
        if mode.fast_path_enabled() { "enabled" } else { "disabled" },
        mode.deterministic_boundary(),
        mode.capability_audit_policy(),
        mode.debug_metadata_policy(),
        mode.nondeterminism_policy()
    );
    println!(
        "load plan modules={} caps={} exports={}",
        plan.module_count(),
        plan.capability_count(),
        plan.expected_export_count()
    );
    for module in &plan.modules {
        println!(
            "load {} artifact={} role={} policy={} target={} target_hash={} payload={} cwasm={} hash={} abi={} binding={} limits=mem{} table{} hostcalls{}",
            module.package,
            module.artifact_name,
            module.role,
            module.fault_policy,
            module.target_artifact_path,
            short_hash(&module.target_artifact_sha256),
            module.code_payload_format,
            module.cwasm_path,
            short_hash(&module.cwasm_sha256),
            short_hash(&module.abi_fingerprint),
            short_hash(&module.manifest_binding_hash),
            module.resource_limits.max_memory_pages,
            module.resource_limits.max_table_elements,
            module.resource_limits.max_hostcalls_per_activation
        );
    }
}

fn print_roots(label: &str, roots: &[String]) {
    for root in roots {
        println!("{label} {root}");
    }
}

fn display_capability_class<'a>(class: &'a str, object: &str) -> &'a str {
    if class.is_empty() { CapabilityClass::from_object(object).as_str() } else { class }
}

fn display_default<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

fn display_option_u64(value: Option<u64>) -> String {
    value.map(|value| value.to_string()).unwrap_or_else(|| "none".to_owned())
}

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

#[cfg(test)]
mod tests;
