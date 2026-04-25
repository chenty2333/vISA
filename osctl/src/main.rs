#![recursion_limit = "256"]

use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

use artifact_manifest::{
    ArtifactBundleManifest, BoundaryValidationReportManifest, CapabilityRecordManifest,
    CleanupTransactionManifest, MigrationPackageManifest, StoreRecordManifest, WaitRecordManifest,
};
use contract_core::{
    VIEW_SCHEMA_V1, ValidatedArtifactPlan, build_validated_artifact_plan,
    validate_migration_against_manifest, validate_migration_package, validate_replay_quiescent,
};
use semantic_core::{CapabilityClass, RuntimeMode};

const OSCTL_JSON_SCHEMA_VERSION: &str = "vmos-osctl-json-v1";

fn main() {
    if let Err(err) = run() {
        eprintln!("osctl error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Ok(());
    };

    match command.as_str() {
        "summary" => {
            let Some(path) = args.next() else {
                return Err("summary requires a manifest/package JSON path".into());
            };
            print_summary(Path::new(&path))
        }
        "check" => {
            let Some(path) = args.next() else {
                return Err("check requires a manifest/package JSON path".into());
            };
            check_path(Path::new(&path))
        }
        "plan" => {
            let mut json = false;
            let mut path = None;
            for arg in args {
                if arg == "--json" {
                    json = true;
                } else if path.is_none() {
                    path = Some(arg);
                } else {
                    return Err("plan received too many positional paths".into());
                }
            }
            let path = path.ok_or("plan requires a manifest JSON path")?;
            print_plan(Path::new(&path), json)
        }
        "modes" => print_modes(),
        "caps" => {
            let mut subject = None;
            let mut path = None;
            while let Some(arg) = args.next() {
                if arg == "--subject" {
                    subject = Some(args.next().ok_or("caps --subject requires a value")?);
                } else if path.is_none() {
                    path = Some(arg);
                } else {
                    return Err("caps received too many positional paths".into());
                }
            }
            let path = path.ok_or("caps requires a manifest/package JSON path")?;
            print_caps(Path::new(&path), subject.as_deref())
        }
        "store" | "cap" | "capability" | "wait" | "cleanup" => {
            handle_view_command(&command, args.collect())
        }
        "state" => {
            let Some(path) = args.next() else {
                return Err("state requires a manifest/package JSON path".into());
            };
            print_state(Path::new(&path))
        }
        "graph" => {
            let Some(path) = args.next() else {
                return Err("graph requires a migration package JSON path".into());
            };
            print_graph(Path::new(&path))
        }
        "activation" => {
            let mut blocked_only = false;
            let mut path = None;
            for arg in args {
                if arg == "--blocked" {
                    blocked_only = true;
                } else if path.is_none() {
                    path = Some(arg);
                } else {
                    return Err("activation received too many positional paths".into());
                }
            }
            let path = path.ok_or("activation requires a migration package JSON path")?;
            print_activation(Path::new(&path), blocked_only)
        }
        "event-log" => {
            let Some(subcommand) = args.next() else {
                return Err("event-log requires a subcommand".into());
            };
            if subcommand != "tail" {
                return Err("event-log syntax is: osctl event-log tail <migration.json>".into());
            }
            let Some(path) = args.next() else {
                return Err("event-log tail requires a migration package JSON path".into());
            };
            print_event_log_tail(Path::new(&path))
        }
        "inspect" => {
            let Some(kind) = args.next() else {
                return Err("inspect requires an object kind".into());
            };
            let mut json = false;
            let mut path = None;
            let mut filter = None;
            for arg in args {
                if arg == "--json" {
                    json = true;
                } else if path.is_none() {
                    path = Some(arg);
                } else if filter.is_none() {
                    filter = Some(arg);
                } else {
                    return Err("inspect received too many arguments".into());
                }
            }
            let path = path.ok_or("inspect requires a manifest/package JSON path")?;
            inspect_object(&kind, Path::new(&path), filter.as_deref(), json)
        }
        "contract" => {
            let Some(subcommand) = args.next() else {
                return Err("contract requires a subcommand".into());
            };
            if subcommand != "validate" {
                return Err(
                    "contract syntax is: osctl contract validate [--json] <migration.json>".into(),
                );
            }
            let mut json = false;
            let mut path = None;
            for arg in args {
                if arg == "--json" {
                    json = true;
                } else if path.is_none() {
                    path = Some(arg);
                } else {
                    return Err("contract validate received too many arguments".into());
                }
            }
            let path = path.ok_or("contract validate requires a migration package JSON path")?;
            validate_contract(Path::new(&path), json)
        }
        "replay" => {
            let Some(until_flag) = args.next() else {
                return Err(
                    "replay requires --until <cursor> [--manifest <manifest.json>] [--json] <package.json>"
                        .into(),
                );
            };
            if until_flag != "--until" {
                return Err(
                    "replay syntax is: osctl replay --until <cursor> [--manifest <manifest.json>] [--json] <package.json>".into(),
                );
            }
            let cursor = args
                .next()
                .ok_or("replay requires a cursor")?
                .parse::<u64>()?;
            let mut manifest_path = None;
            let mut package_path = None;
            let mut json = false;
            while let Some(arg) = args.next() {
                if arg == "--manifest" {
                    let path = args.next().ok_or("replay --manifest requires a path")?;
                    manifest_path = Some(path);
                } else if arg == "--json" {
                    json = true;
                } else if package_path.is_none() {
                    package_path = Some(arg);
                } else {
                    return Err("replay received too many positional paths".into());
                }
            }
            let path = package_path.ok_or("replay requires a package JSON path")?;
            replay_until(
                cursor,
                manifest_path.as_deref().map(Path::new),
                Path::new(&path),
                json,
            )
        }
        _ => {
            print_usage();
            Err(format!("unknown command `{command}`").into())
        }
    }
}

fn print_usage() {
    eprintln!("usage:");
    eprintln!("  osctl summary <manifest-or-migration.json>");
    eprintln!("  osctl check <manifest-or-migration.json>");
    eprintln!("  osctl plan [--json] <manifest.json>");
    eprintln!("  osctl modes");
    eprintln!("  osctl caps [--subject <subject>] <manifest-or-migration.json>");
    eprintln!("  osctl store|cap|wait|cleanup list --json <migration.json>");
    eprintln!("  osctl store|cap|wait|cleanup show --json <migration.json> <id>");
    eprintln!("  osctl state <manifest-or-migration.json>");
    eprintln!("  osctl graph <migration.json>");
    eprintln!("  osctl activation [--blocked] <migration.json>");
    eprintln!("  osctl event-log tail <migration.json>");
    eprintln!(
        "  osctl inspect artifact|code|store|activation|capability|wait|trap|hostcall|tombstone|contract|cleanup|memory-policy|snapshot-validation|replay-validation|event [--json] <manifest-or-migration.json> [filter]"
    );
    eprintln!("  osctl contract validate [--json] <migration.json>");
    eprintln!(
        "  osctl replay --until <event-cursor> [--manifest <manifest.json>] [--json] <migration.json>"
    );
}

fn print_summary(path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        print_migration_summary(&package);
        return Ok(());
    }
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    print_artifact_summary(&manifest)?;
    Ok(())
}

fn check_path(path: &Path) -> Result<(), Box<dyn Error>> {
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

fn handle_view_command(kind: &str, args: Vec<String>) -> Result<(), Box<dyn Error>> {
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
        let filter = if subcommand == "show" {
            id.as_deref()
        } else {
            None
        };
        return inspect_object(kind, Path::new(&path), filter, false);
    }
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    let views = stable_views_for_kind(kind, &package)?;
    let views = if subcommand == "show" {
        let id = id.ok_or_else(|| format!("{kind} show requires an id"))?;
        let selected = select_view_by_id(views, &id)?;
        vec![selected]
    } else {
        views
    };
    let count = views.len();
    let value = serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": canonical_view_kind(kind),
        "command": format!("{}.{}", canonical_view_kind(kind), subcommand),
        "package": package.package_id,
        "count": count,
        "items": views,
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn canonical_view_kind(kind: &str) -> &'static str {
    match kind {
        "cap" | "capability" => "capability",
        "store" => "store",
        "wait" => "wait",
        "cleanup" => "cleanup",
        _ => "unknown",
    }
}

fn select_view_by_id(
    views: Vec<serde_json::Value>,
    id: &str,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let parsed = id.parse::<u64>()?;
    views
        .into_iter()
        .find(|view| view.get("id").and_then(serde_json::Value::as_u64) == Some(parsed))
        .ok_or_else(|| format!("object id {id} not found").into())
}

fn store_view_v1(store: &StoreRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "store",
        "id": store.id,
        "generation": store.generation,
        "state": store.state,
        "owner": {
            "package": store.package,
            "role": store.role,
        },
        "references": {
            "artifact": store.artifact,
            "fault_domain": store.fault_domain,
            "resource": store.resource,
        },
        "last_transition": {
            "restart_count": store.restart_count,
            "fault_policy": store.fault_policy,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn capability_view_v1(capability: &CapabilityRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "capability",
        "id": capability.id,
        "generation": capability.generation,
        "state": if capability.revoked { "revoked" } else { "active" },
        "subject": capability.subject,
        "owner": {
            "store": capability.owner_store,
            "store_generation": capability.owner_store_generation,
            "task": capability.owner_task,
        },
        "references": {
            "object_ref": capability.object_ref,
            "debug_object_label": if capability.debug_object_label.is_empty() {
                &capability.object
            } else {
                &capability.debug_object_label
            },
            "parent": capability.parent,
            "manifest_decl": capability.manifest_decl,
        },
        "rights": capability.rights,
        "class": display_capability_class(&capability.class, &capability.object),
        "lifetime": capability.lifetime,
        "last_transition": {
            "source": capability.source,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn wait_view_v1(wait: &WaitRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "task": wait.owner_task,
            "store": wait.owner_store,
            "store_generation": wait.owner_store_generation,
        },
        "references": {
            "blockers": wait.blockers,
        },
        "kind_name": wait.kind,
        "deadline": wait.deadline,
        "cancel_reason": wait.cancel_reason,
        "restart_policy": wait.restart_policy,
        "saved_context": wait.saved_context,
        "last_transition": serde_json::Value::Null,
        "last_error": wait.cancel_reason,
    })
}

fn cleanup_view_v1(cleanup: &CleanupTransactionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "store": cleanup.store,
        },
        "references": {
            "target_store": {
                "id": cleanup.store,
                "generation": cleanup.store_generation,
            },
            "activation": cleanup.activation.map(|id| serde_json::json!({
                "id": id,
                "generation": cleanup.activation_generation,
            })),
            "code": cleanup.code_object.map(|id| serde_json::json!({
                "id": id,
                "generation": cleanup.code_generation,
            })),
            "revoked_capabilities": cleanup.revoked_capability_refs,
        },
        "started_at": cleanup.started_at,
        "finished_at": cleanup.finished_at,
        "reason": cleanup.reason,
        "steps": cleanup.steps,
        "effects": cleanup.effects,
        "last_transition": {
            "released_dmw_leases": cleanup.released_dmw_leases,
            "cancelled_waits": cleanup.cancelled_waits,
            "dropped_resources": cleanup.dropped_resources,
            "unbound_code_object": cleanup.unbound_code_object,
        },
        "last_error": if cleanup.state.contains("skipped") {
            Some("stale-generation")
        } else {
            None
        },
    })
}

fn stable_views_for_kind(
    kind: &str,
    package: &MigrationPackageManifest,
) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    match kind {
        "store" => Ok(package
            .semantic
            .store_records
            .iter()
            .map(store_view_v1)
            .collect()),
        "cap" | "capability" => Ok(package
            .semantic
            .capability_records
            .iter()
            .map(capability_view_v1)
            .collect()),
        "wait" => Ok(package
            .semantic
            .wait_records
            .iter()
            .map(wait_view_v1)
            .collect()),
        "cleanup" => Ok(package
            .semantic
            .cleanup_transactions
            .iter()
            .map(cleanup_view_v1)
            .collect()),
        _ => Err(format!("stable view does not support `{kind}`").into()),
    }
}

fn validate_contract(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    let ok = package.semantic.contract_violation_count == 0
        && package.semantic.snapshot_validation.ok
        && package.semantic.replay_validation.ok;
    if json {
        let state = if ok { "ok" } else { "failed" };
        let violations = package
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
        let value = serde_json::json!({
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
                "ok": package.semantic.contract_violation_count == 0,
                "violation_count": package.semantic.contract_violation_count,
                "violations": &violations
            },
            "snapshot_validation": &package.semantic.snapshot_validation,
            "replay_validation": &package.semantic.replay_validation,
            "last_transition": {
                "snapshot_ok": package.semantic.snapshot_validation.ok,
                "replay_ok": package.semantic.replay_validation.ok,
            },
            "last_error": if ok { serde_json::Value::Null } else { serde_json::json!("contract-validation-failed") }
        });
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
    }
    if ok {
        Ok(())
    } else {
        Err("contract validation failed".into())
    }
}

fn print_plan(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&fs::read(path)?)?;
    let plan = build_validated_artifact_plan(&manifest)?;
    if json {
        let mode = RuntimeMode::parse(&plan.runtime_mode).unwrap_or(RuntimeMode::Research);
        let value = serde_json::json!({
            "artifact_profile": &plan.artifact_profile,
            "runtime_mode": &plan.runtime_mode,
            "mode_policy": {
                "event_log": mode.event_log_policy(),
                "dmw": mode.dmw_policy(),
                "fastpath_enabled": mode.fast_path_enabled(),
                "deterministic_boundary": mode.deterministic_boundary(),
                "capability_audit": mode.capability_audit_policy(),
                "debug_metadata": mode.debug_metadata_policy(),
                "nondeterminism": mode.nondeterminism_policy()
            },
            "contract_version": &plan.contract_version,
            "target_arch": &plan.target_arch,
            "compiler": {
                "engine": &plan.compiler_engine,
                "execution_mode": &plan.compiler_execution_mode,
                "artifact_format": &plan.artifact_format,
                "runtime_executor_abi": &plan.runtime_executor_abi
            },
            "module_count": plan.module_count(),
            "capability_count": plan.capability_count(),
            "expected_export_count": plan.expected_export_count(),
            "modules": plan.modules.iter().map(|module| serde_json::json!({
                "package": &module.package,
                "artifact_name": &module.artifact_name,
                "role": &module.role,
                "fault_policy": &module.fault_policy,
                "cwasm_path": &module.cwasm_path,
                "cwasm_sha256": &module.cwasm_sha256,
                "abi_fingerprint": &module.abi_fingerprint,
                "manifest_binding_hash": &module.manifest_binding_hash,
                "capabilities": module.capabilities.len(),
                "dependencies": module.service_dependencies.len(),
                "resource_limits": {
                    "max_memory_pages": module.resource_limits.max_memory_pages,
                    "max_table_elements": module.resource_limits.max_table_elements,
                    "max_hostcalls_per_activation": module.resource_limits.max_hostcalls_per_activation
                }
            })).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    print_plan_text(&plan);
    Ok(())
}

fn print_modes() -> Result<(), Box<dyn Error>> {
    for mode in RuntimeMode::all() {
        println!(
            "mode {} event_log={} dmw={} fastpath={} deterministic={} capability_audit={} debug_metadata={} nondeterminism={}",
            mode.as_str(),
            mode.event_log_policy(),
            mode.dmw_policy(),
            if mode.fast_path_enabled() {
                "enabled"
            } else {
                "disabled"
            },
            mode.deterministic_boundary(),
            mode.capability_audit_policy(),
            mode.debug_metadata_policy(),
            mode.nondeterminism_policy()
        );
    }
    Ok(())
}

fn print_caps(path: &Path, subject: Option<&str>) -> Result<(), Box<dyn Error>> {
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

fn print_state(path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        println!(
            "semantic state package={} cursor={} tasks={} resources={} stores={} caps={} waits={} authorities={}/{} boundaries={} artifacts={} activations={} executor_transitions={} target_artifacts={} code_objects={} activation_records={} traps={} hostcalls={} migration_objects={}",
            package.package_id,
            package.semantic.event_log_cursor,
            package.semantic.task_count,
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
            package
                .substrate_boundary
                .active_packet_device_authority_count,
            package
                .substrate_boundary
                .active_virtio_queue_authority_count,
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
        if mode.fast_path_enabled() {
            "enabled"
        } else {
            "disabled"
        },
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

fn print_graph(path: &Path) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    println!(
        "graph package={} cursor={} task_roots={} resource_roots={} authority_roots={} store_roots={} capability_roots={} target_store_record_roots={} target_capability_record_roots={} fastpath_roots={} boundary_roots={} artifact_verification_roots={} store_activation_roots={} executor_transition_roots={} target_artifact_roots={} code_object_roots={} activation_record_roots={} trap_roots={} hostcall_trace_roots={} migration_object_roots={} tombstone_roots={} contract_violation_roots={}",
        package.package_id,
        package.semantic.event_log_cursor,
        package.semantic.roots.task_roots.len(),
        package.semantic.roots.resource_roots.len(),
        package.semantic.roots.authority_roots.len(),
        package.semantic.roots.store_roots.len(),
        package.semantic.roots.capability_roots.len(),
        package.semantic.roots.target_store_record_roots.len(),
        package.semantic.roots.target_capability_record_roots.len(),
        package.semantic.roots.fast_path_roots.len(),
        package.semantic.roots.boundary_roots.len(),
        package.semantic.roots.artifact_verification_roots.len(),
        package.semantic.roots.store_activation_roots.len(),
        package.semantic.roots.executor_transition_roots.len(),
        package.semantic.roots.target_artifact_roots.len(),
        package.semantic.roots.code_object_roots.len(),
        package.semantic.roots.activation_record_roots.len(),
        package.semantic.roots.trap_roots.len(),
        package.semantic.roots.hostcall_trace_roots.len(),
        package.semantic.roots.migration_object_roots.len(),
        package.semantic.roots.tombstone_roots.len(),
        package.semantic.roots.contract_violation_roots.len()
    );
    print_roots("task", &package.semantic.roots.task_roots);
    print_roots("resource", &package.semantic.roots.resource_roots);
    print_roots("authority", &package.semantic.roots.authority_roots);
    print_roots("store", &package.semantic.roots.store_roots);
    print_roots("capability", &package.semantic.roots.capability_roots);
    print_roots(
        "target-store",
        &package.semantic.roots.target_store_record_roots,
    );
    print_roots(
        "target-capability",
        &package.semantic.roots.target_capability_record_roots,
    );
    print_roots("fastpath", &package.semantic.roots.fast_path_roots);
    print_roots("boundary", &package.semantic.roots.boundary_roots);
    print_roots(
        "artifact-verification",
        &package.semantic.roots.artifact_verification_roots,
    );
    print_roots(
        "store-activation",
        &package.semantic.roots.store_activation_roots,
    );
    print_roots(
        "executor-transition",
        &package.semantic.roots.executor_transition_roots,
    );
    print_roots(
        "target-artifact",
        &package.semantic.roots.target_artifact_roots,
    );
    print_roots("code-object", &package.semantic.roots.code_object_roots);
    print_roots(
        "activation-record",
        &package.semantic.roots.activation_record_roots,
    );
    print_roots("trap", &package.semantic.roots.trap_roots);
    print_roots("hostcall", &package.semantic.roots.hostcall_trace_roots);
    print_roots(
        "migration-object",
        &package.semantic.roots.migration_object_roots,
    );
    print_roots("tombstone", &package.semantic.roots.tombstone_roots);
    print_roots("contract", &package.semantic.roots.contract_violation_roots);
    Ok(())
}

fn print_event_log_tail(path: &Path) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    println!(
        "event-log tail package={} cursor={} events={}",
        package.package_id,
        package.semantic.event_log_cursor,
        package.semantic.roots.event_log_tail.len()
    );
    for event in &package.semantic.roots.event_log_tail {
        println!("{event}");
    }
    Ok(())
}

fn print_activation(path: &Path, blocked_only: bool) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    println!(
        "activation package={} cursor={} roots={} blocked_only={}",
        package.package_id,
        package.semantic.event_log_cursor,
        package.semantic.roots.store_activation_roots.len(),
        blocked_only
    );
    for activation in &package.semantic.roots.store_activation_roots {
        if blocked_only && activation.contains(" blocked=none ") {
            continue;
        }
        println!("{activation}");
    }
    Ok(())
}

fn inspect_object(
    kind: &str,
    path: &Path,
    filter: Option<&str>,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        if json {
            return inspect_package_object_json(kind, &package, filter);
        }
        return inspect_package_object(kind, &package, filter);
    }
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    if json {
        return inspect_manifest_object_json(kind, &manifest, filter);
    }
    inspect_manifest_object(kind, &manifest, filter)
}

fn inspect_package_object(
    kind: &str,
    package: &MigrationPackageManifest,
    filter: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    match kind {
        "artifact" => {
            println!(
                "inspect artifact package={} count={}",
                package.package_id, package.semantic.target_artifact_count
            );
            for artifact in &package.semantic.target_artifacts {
                let line = format!(
                    "artifact id={} package={} name={} role={} kind={} profile={} abi={} binding={} hash={} exports={} hostcalls={} caps={}",
                    artifact.id,
                    artifact.package,
                    artifact.artifact_name,
                    artifact.role,
                    artifact.kind,
                    artifact.target_profile,
                    artifact.abi_fingerprint,
                    artifact.manifest_binding_hash,
                    artifact.code_hash,
                    artifact.exports.len(),
                    artifact.hostcalls.len(),
                    artifact.capabilities.len()
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.target_artifacts.is_empty() {
                print_roots_filtered(
                    "artifact-verification",
                    &package.semantic.roots.artifact_verification_roots,
                    filter,
                );
            }
        }
        "code" => {
            println!(
                "inspect code package={} count={}",
                package.package_id, package.semantic.code_object_count
            );
            for code in &package.semantic.code_objects {
                let store = code.bound_store.map_or_else(
                    || "none".to_owned(),
                    |store| {
                        format!(
                            "{store}@{}",
                            code.bound_store_generation
                                .map(|generation| generation.to_string())
                                .unwrap_or_else(|| "unknown".to_owned())
                        )
                    },
                );
                let table = display_option_u64(code.hostcall_table);
                let line = format!(
                    "code id={} artifact={} package={} state={} generation={} store={} hostcall_table={} text={:#x}+{}:{} rodata={:#x}+{}:{} hostcalls={}",
                    code.id,
                    code.artifact_id,
                    code.package,
                    code.state,
                    code.generation,
                    store,
                    table,
                    code.text_start,
                    code.text_len,
                    code.text_permission,
                    code.rodata_start,
                    code.rodata_len,
                    code.rodata_permission,
                    code.hostcalls.len()
                );
                print_if_matches(&line, filter);
            }
        }
        "store" => {
            println!(
                "inspect store package={} count={}",
                package.package_id, package.semantic.store_record_count
            );
            for store in &package.semantic.store_records {
                let resource = display_option_u64(store.resource);
                let line = format!(
                    "store id={} package={} artifact={} role={} state={} generation={} fault_policy={} fault_domain={} resource={} restart_count={}",
                    store.id,
                    store.package,
                    store.artifact,
                    store.role,
                    store.state,
                    store.generation,
                    store.fault_policy,
                    store.fault_domain,
                    resource,
                    store.restart_count
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.store_records.is_empty() {
                print_roots_filtered("store", &package.semantic.roots.store_roots, filter);
            }
            print_roots_filtered(
                "store-activation",
                &package.semantic.roots.store_activation_roots,
                filter,
            );
        }
        "activation" => {
            println!(
                "inspect activation package={} count={}",
                package.package_id, package.semantic.activation_record_count
            );
            for activation in &package.semantic.activation_records {
                let exit = display_option_u64(activation.exit_event);
                let wait = display_option_u64(activation.blocked_wait);
                let trap = display_option_u64(activation.trap);
                let ret = activation.return_tag.as_deref().unwrap_or("none");
                let line = format!(
                    "activation id={} store={} store_generation={} code={} code_generation={} artifact={} entry={} state={} generation={} start={} exit={} dmw={} wait={} trap={} return={}",
                    activation.id,
                    activation.store,
                    activation.store_generation,
                    activation.code_object,
                    activation.code_generation,
                    activation.artifact,
                    activation.entry,
                    activation.state,
                    activation.generation,
                    activation.start_event,
                    exit,
                    activation.active_dmw_leases,
                    wait,
                    trap,
                    ret
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.activation_records.is_empty() {
                print_roots_filtered(
                    "store-activation",
                    &package.semantic.roots.store_activation_roots,
                    filter,
                );
            }
        }
        "capability" | "cap" => {
            println!(
                "inspect capability package={} count={}",
                package.package_id, package.semantic.capability_record_count
            );
            for capability in &package.semantic.capability_records {
                let line = format!(
                    "cap id={} subject={} object={} class={} rights={} lifetime={} generation={} source={} owner_store={}@{} owner_task={} revoked={}",
                    capability.id,
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
                print_if_matches(&line, filter);
            }
            if package.semantic.capability_records.is_empty() {
                for capability in &package.logical_capabilities {
                    let line = format!(
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
                    print_if_matches(&line, filter);
                }
            }
        }
        "wait" => {
            println!(
                "inspect wait package={} count={}",
                package.package_id, package.semantic.wait_token_count
            );
            print_roots_filtered("wait", &package.semantic.roots.wait_roots, filter);
        }
        "trap" => {
            println!(
                "inspect trap package={} count={}",
                package.package_id, package.semantic.trap_record_count
            );
            for trap in &package.semantic.trap_records {
                let line = format!(
                    "trap id={} class={} store={}@{} activation={}@{} code={}@{} artifact={}@{} offset={} hostcall={} policy={} effect={} detail={}",
                    trap.id,
                    trap.class,
                    display_option_u64(trap.store),
                    display_option_u64(trap.store_generation),
                    display_option_u64(trap.activation),
                    display_option_u64(trap.activation_generation),
                    display_option_u64(trap.code_object),
                    display_option_u64(trap.code_generation),
                    display_option_u64(trap.artifact),
                    display_option_u64(trap.artifact_generation),
                    display_option_u64(trap.offset),
                    trap.hostcall.as_deref().unwrap_or("none"),
                    trap.fault_policy,
                    trap.effect,
                    trap.detail
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.trap_records.is_empty() {
                print_roots_filtered("trap", &package.semantic.roots.trap_roots, filter);
            }
        }
        "event" => {
            println!(
                "inspect event package={} cursor={} tail={}",
                package.package_id,
                package.semantic.event_log_cursor,
                package.semantic.roots.event_log_tail.len()
            );
            print_roots_filtered("event", &package.semantic.roots.event_log_tail, filter);
            print_roots_filtered(
                "hostcall",
                &package.semantic.roots.hostcall_trace_roots,
                filter,
            );
        }
        "hostcall" => {
            println!(
                "inspect hostcall package={} count={}",
                package.package_id, package.semantic.hostcall_trace_count
            );
            for trace in &package.semantic.hostcall_trace {
                let cap_args = trace
                    .cap_args
                    .iter()
                    .map(|cap| {
                        format!(
                            "{}:{}:{}:{}:{}",
                            cap.id,
                            cap.object,
                            cap.generation,
                            cap.rights_mask,
                            cap.rights.join("+")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let line = format!(
                    "hostcall abi={} frame_size={} seq={} caller_offset={} record_mode={} activation={} activation_generation={} store={} store_generation={} code={} code_generation={} artifact={} number={} name={} category={} subject={} object={} op={} cap_args=[{}] allowed={} result={} ret={} trap_out={} wait_out={}",
                    trace.abi_version,
                    trace.frame_size,
                    trace.hostcall_seq,
                    trace.caller_offset,
                    display_default(&trace.record_mode, "none"),
                    trace.activation,
                    trace.activation_generation,
                    trace.store,
                    trace.store_generation,
                    trace.code_object,
                    trace.code_generation,
                    trace.artifact,
                    trace.hostcall_number,
                    trace.name,
                    trace.category,
                    trace.subject,
                    trace.object,
                    trace.operation,
                    cap_args,
                    trace.allowed,
                    trace.result,
                    display_default(&trace.ret_tag, "none"),
                    display_option_u64(trace.trap_out),
                    display_option_u64(trace.wait_token_out)
                );
                print_if_matches(&line, filter);
            }
        }
        "migration" => {
            println!(
                "inspect migration package={} count={}",
                package.package_id, package.semantic.migration_object_count
            );
            for object in &package.semantic.migration_objects {
                let line = format!(
                    "migration object={} class={} reason={}",
                    object.object, object.class, object.reason
                );
                print_if_matches(&line, filter);
            }
        }
        "tombstone" => {
            println!(
                "inspect tombstone package={} count={}",
                package.package_id, package.semantic.tombstone_count
            );
            for tombstone in &package.semantic.tombstones {
                let line = format!(
                    "tombstone kind={} id={} generation={} died_at={} reason={}",
                    tombstone.kind,
                    tombstone.id,
                    tombstone.generation,
                    tombstone.died_at,
                    tombstone.reason
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.tombstones.is_empty() {
                print_roots_filtered("tombstone", &package.semantic.roots.tombstone_roots, filter);
            }
        }
        "contract" => {
            println!(
                "inspect contract package={} violations={}",
                package.package_id, package.semantic.contract_violation_count
            );
            for violation in &package.semantic.contract_violations {
                let to = violation.to.as_ref().map_or_else(
                    || "none".to_owned(),
                    |to| format!("{}:{}@{}", to.kind, to.id, to.generation),
                );
                let line = format!(
                    "contract violation kind={} edge={} from={}:{}@{} to={} detail={}",
                    violation.kind,
                    violation.edge,
                    violation.from.kind,
                    violation.from.id,
                    violation.from.generation,
                    to,
                    violation.detail
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.contract_violations.is_empty() {
                print_roots_filtered(
                    "contract",
                    &package.semantic.roots.contract_violation_roots,
                    filter,
                );
            }
        }
        "cleanup" => {
            println!(
                "inspect cleanup package={} count={}",
                package.package_id, package.semantic.cleanup_transaction_count
            );
            for cleanup in &package.semantic.cleanup_transactions {
                let activation = display_option_u64(cleanup.activation);
                let code = display_option_u64(cleanup.code_object);
                let activation_generation = display_option_u64(cleanup.activation_generation);
                let code_generation = display_option_u64(cleanup.code_generation);
                let steps = cleanup
                    .steps
                    .iter()
                    .map(|step| format!("{}:{}:{}", step.step, step.state, step.detail))
                    .collect::<Vec<_>>()
                    .join("|");
                let line = format!(
                    "cleanup id={} store={}@{} activation={}@{} code={}@{} generation={} state={} reason={} released_dmw={} cancelled_waits={} revoked_caps={} dropped_resources={} unbound_code={} effect={} steps={}",
                    cleanup.id,
                    cleanup.store,
                    cleanup.store_generation,
                    activation,
                    activation_generation,
                    code,
                    code_generation,
                    cleanup.generation,
                    cleanup.state,
                    cleanup.reason,
                    cleanup.released_dmw_leases,
                    cleanup.cancelled_waits,
                    cleanup.revoked_capabilities.len(),
                    cleanup.dropped_resources,
                    cleanup.unbound_code_object,
                    cleanup.effect,
                    steps
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.cleanup_transactions.is_empty() {
                print_roots_filtered("cleanup", &package.semantic.roots.cleanup_roots, filter);
            }
        }
        "memory-policy" => {
            println!(
                "inspect memory-policy package={} count={}",
                package.package_id, package.semantic.memory_policy_count
            );
            for policy in &package.semantic.memory_policies {
                let line = format!(
                    "memory-policy class={} owner={} perms={} migration={} snapshot={} cleanup={} alias_guest={} cross_pending={} executable={}",
                    policy.class,
                    policy.owner_kind,
                    policy.permissions,
                    policy.migration_policy,
                    policy.snapshot_policy,
                    policy.cleanup_policy,
                    policy.can_alias_guest_memory,
                    policy.can_cross_pending,
                    policy.can_be_executable
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.memory_policies.is_empty() {
                print_roots_filtered(
                    "memory-policy",
                    &package.semantic.roots.memory_policy_roots,
                    filter,
                );
            }
        }
        "snapshot-validation" => {
            print_boundary_validation(
                "snapshot-validation",
                package.package_id.as_str(),
                &package.semantic.snapshot_validation,
                &package.semantic.roots.snapshot_validation_roots,
                filter,
            );
        }
        "replay-validation" => {
            print_boundary_validation(
                "replay-validation",
                package.package_id.as_str(),
                &package.semantic.replay_validation,
                &package.semantic.roots.replay_validation_roots,
                filter,
            );
        }
        _ => return Err(format!("unknown inspect kind `{kind}`").into()),
    }
    Ok(())
}

fn inspect_package_object_json(
    kind: &str,
    package: &MigrationPackageManifest,
    filter: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let (canonical_kind, total_count, items, summary) = match kind {
        "artifact" => (
            "artifact",
            package.semantic.target_artifact_count,
            package
                .semantic
                .target_artifacts
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.target_artifact_roots.len() }),
        ),
        "code" => (
            "code",
            package.semantic.code_object_count,
            package
                .semantic
                .code_objects
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.code_object_roots.len() }),
        ),
        "store" => (
            "store",
            package.semantic.store_record_count,
            package
                .semantic
                .store_records
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.target_store_record_roots.len() }),
        ),
        "activation" => (
            "activation",
            package.semantic.activation_record_count,
            package
                .semantic
                .activation_records
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.activation_record_roots.len() }),
        ),
        "cap" | "capability" => (
            "capability",
            if package.semantic.capability_records.is_empty() {
                package.logical_capabilities.len()
            } else {
                package.semantic.capability_record_count
            },
            if package.semantic.capability_records.is_empty() {
                package
                    .logical_capabilities
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                package
                    .semantic
                    .capability_records
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<Result<Vec<_>, _>>()?
            },
            serde_json::json!({
                "root_count": if package.semantic.capability_records.is_empty() {
                    package.semantic.roots.capability_roots.len()
                } else {
                    package.semantic.roots.target_capability_record_roots.len()
                }
            }),
        ),
        "wait" => (
            "wait",
            package.semantic.wait_token_count,
            package
                .semantic
                .roots
                .wait_roots
                .iter()
                .map(|root| serde_json::json!({ "kind": "wait", "root": root }))
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.wait_roots.len() }),
        ),
        "trap" => (
            "trap",
            package.semantic.trap_record_count,
            package
                .semantic
                .trap_records
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.trap_roots.len() }),
        ),
        "hostcall" => (
            "hostcall",
            package.semantic.hostcall_trace_count,
            package
                .semantic
                .hostcall_trace
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.hostcall_trace_roots.len() }),
        ),
        "cleanup" => (
            "cleanup",
            package.semantic.cleanup_transaction_count,
            package
                .semantic
                .cleanup_transactions
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.cleanup_roots.len() }),
        ),
        "contract" => (
            "contract",
            package.semantic.contract_violation_count,
            package
                .semantic
                .contract_violations
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "ok": package.semantic.contract_violation_count == 0 }),
        ),
        "memory-policy" => (
            "memory-policy",
            package.semantic.memory_policy_count,
            package
                .semantic
                .memory_policies
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.memory_policy_roots.len() }),
        ),
        "snapshot-validation" => (
            "snapshot-validation",
            package.semantic.snapshot_validation.violation_count,
            package
                .semantic
                .snapshot_validation
                .violations
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({
                "validator": &package.semantic.snapshot_validation.validator,
                "ok": package.semantic.snapshot_validation.ok,
                "root_count": package.semantic.roots.snapshot_validation_roots.len()
            }),
        ),
        "replay-validation" => (
            "replay-validation",
            package.semantic.replay_validation.violation_count,
            package
                .semantic
                .replay_validation
                .violations
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({
                "validator": &package.semantic.replay_validation.validator,
                "ok": package.semantic.replay_validation.ok,
                "root_count": package.semantic.roots.replay_validation_roots.len()
            }),
        ),
        "event" => (
            "event",
            package.semantic.roots.event_log_tail.len(),
            package
                .semantic
                .roots
                .event_log_tail
                .iter()
                .map(|event| serde_json::json!({ "kind": "event", "summary": event }))
                .collect::<Vec<_>>(),
            serde_json::json!({ "cursor": package.semantic.event_log_cursor }),
        ),
        "migration" => (
            "migration",
            package.semantic.migration_object_count,
            package
                .semantic
                .migration_objects
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.migration_object_roots.len() }),
        ),
        "tombstone" => (
            "tombstone",
            package.semantic.tombstone_count,
            package
                .semantic
                .tombstones
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::json!({ "root_count": package.semantic.roots.tombstone_roots.len() }),
        ),
        _ => return Err(format!("unknown inspect kind `{kind}`").into()),
    };
    let items = filter_json_items(items, filter)?;
    let value = serde_json::json!({
        "schema_version": OSCTL_JSON_SCHEMA_VERSION,
        "command": "inspect",
        "kind": canonical_kind,
        "source": "semantic-package",
        "package": package.package_id,
        "total_count": total_count,
        "count": items.len(),
        "filter": filter,
        "summary": summary,
        "items": items
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn inspect_manifest_object(
    kind: &str,
    manifest: &ArtifactBundleManifest,
    filter: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    match kind {
        "artifact" => {
            let plan = build_validated_artifact_plan(manifest)?;
            println!(
                "inspect artifact manifest profile={} modules={}",
                plan.artifact_profile,
                plan.module_count()
            );
            for module in &plan.modules {
                let line = format!(
                    "artifact package={} name={} role={} cwasm={} hash={} abi={} binding={} caps={} exports={}",
                    module.package,
                    module.artifact_name,
                    module.role,
                    module.cwasm_path,
                    module.cwasm_sha256,
                    module.abi_fingerprint,
                    module.manifest_binding_hash,
                    module.capabilities.len(),
                    module.expected_exports.len()
                );
                print_if_matches(&line, filter);
            }
            Ok(())
        }
        "capability" | "cap" => print_caps_from_manifest(manifest, filter),
        _ => Err(format!("manifest inspect supports artifact/capability, not `{kind}`").into()),
    }
}

fn inspect_manifest_object_json(
    kind: &str,
    manifest: &ArtifactBundleManifest,
    filter: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let plan = build_validated_artifact_plan(manifest)?;
    let (canonical_kind, total_count, items, summary) = match kind {
        "artifact" => (
            "artifact",
            plan.module_count(),
            plan.modules
                .iter()
                .map(|module| {
                    serde_json::json!({
                        "package": &module.package,
                        "artifact_name": &module.artifact_name,
                        "role": &module.role,
                        "fault_policy": &module.fault_policy,
                        "cwasm_path": &module.cwasm_path,
                        "cwasm_sha256": &module.cwasm_sha256,
                        "abi_fingerprint": &module.abi_fingerprint,
                        "manifest_binding_hash": &module.manifest_binding_hash,
                        "capability_count": module.capabilities.len(),
                        "dependency_count": module.service_dependencies.len(),
                        "resource_limits": {
                            "max_memory_pages": module.resource_limits.max_memory_pages,
                            "max_table_elements": module.resource_limits.max_table_elements,
                            "max_hostcalls_per_activation": module.resource_limits.max_hostcalls_per_activation
                        }
                    })
                })
                .collect::<Vec<_>>(),
            serde_json::json!({
                "artifact_profile": &plan.artifact_profile,
                "runtime_mode": &plan.runtime_mode,
                "contract_version": &plan.contract_version,
                "target_arch": &plan.target_arch
            }),
        ),
        "cap" | "capability" => (
            "capability",
            plan.capability_count(),
            plan.modules
                .iter()
                .flat_map(|module| {
                    module.capabilities.iter().map(move |capability| {
                        serde_json::json!({
                            "subject": &module.package,
                            "object": &capability.name,
                            "class": CapabilityClass::from_object(&capability.name).as_str(),
                            "rights": &capability.rights,
                            "lifetime": &capability.lifetime,
                            "source": "artifact-manifest",
                            "owner_store": "planned-store"
                        })
                    })
                })
                .collect::<Vec<_>>(),
            serde_json::json!({
                "artifact_profile": &plan.artifact_profile,
                "runtime_mode": &plan.runtime_mode
            }),
        ),
        _ => return Err(format!("manifest inspect supports artifact/capability, not `{kind}`").into()),
    };
    let items = filter_json_items(items, filter)?;
    let value = serde_json::json!({
        "schema_version": OSCTL_JSON_SCHEMA_VERSION,
        "command": "inspect",
        "kind": canonical_kind,
        "source": "artifact-manifest",
        "package": manifest.artifact_profile,
        "total_count": total_count,
        "count": items.len(),
        "filter": filter,
        "summary": summary,
        "items": items
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn print_caps_from_manifest(
    manifest: &ArtifactBundleManifest,
    filter: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let plan = build_validated_artifact_plan(manifest)?;
    println!(
        "inspect capability manifest profile={} caps={}",
        plan.artifact_profile,
        plan.capability_count()
    );
    for module in &plan.modules {
        for capability in &module.capabilities {
            let line = format!(
                "cap subject={} object={} class={} rights={} lifetime={} source=artifact-manifest",
                module.package,
                capability.name,
                CapabilityClass::from_object(&capability.name).as_str(),
                capability.rights.join("+"),
                capability.lifetime
            );
            print_if_matches(&line, filter);
        }
    }
    Ok(())
}

fn print_roots_filtered(label: &str, roots: &[String], filter: Option<&str>) {
    for root in roots {
        let line = format!("{label} {root}");
        print_if_matches(&line, filter);
    }
}

fn print_boundary_validation(
    label: &str,
    package_id: &str,
    report: &BoundaryValidationReportManifest,
    roots: &[String],
    filter: Option<&str>,
) {
    println!(
        "inspect {label} package={} validator={} ok={} violations={}",
        package_id, report.validator, report.ok, report.violation_count
    );
    for violation in &report.violations {
        let line = format!(
            "boundary-validation validator={} kind={} object={} detail={}",
            violation.validator, violation.kind, violation.object, violation.detail
        );
        print_if_matches(&line, filter);
    }
    if report.violations.is_empty() {
        print_roots_filtered(label, roots, filter);
    }
}

fn filter_json_items(
    items: Vec<serde_json::Value>,
    filter: Option<&str>,
) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    let Some(filter) = filter else {
        return Ok(items);
    };
    let mut filtered = Vec::new();
    for item in items {
        if serde_json::to_string(&item)?.contains(filter) {
            filtered.push(item);
        }
    }
    Ok(filtered)
}

fn print_if_matches(line: &str, filter: Option<&str>) {
    if filter.is_none_or(|filter| line.contains(filter)) {
        println!("{line}");
    }
}

fn replay_until(
    cursor: u64,
    manifest_path: Option<&Path>,
    path: &Path,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let package = serde_json::from_slice::<MigrationPackageManifest>(&bytes)?;
    validate_replay_quiescent(&package)?;
    if let Some(manifest_path) = manifest_path {
        let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&fs::read(manifest_path)?)?;
        validate_migration_against_manifest(&package, &manifest)?;
    }
    if cursor > package.semantic.event_log_cursor {
        return Err(format!(
            "requested cursor {} exceeds package cursor {}",
            cursor, package.semantic.event_log_cursor
        )
        .into());
    }
    if json {
        print_replay_json(cursor, &package)?;
        return Ok(());
    }
    println!(
        "replay plan accepted package={} format={} cursor={} guest_isa={} scheduler_cursor={} random_epoch={}",
        package.package_id,
        package.package_format,
        cursor,
        package.guest.canonical_isa,
        package.substrate_boundary.scheduler_decision_cursor,
        package.substrate_boundary.random_epoch
    );
    println!(
        "replay imports: waits={} resources={} fastpath={}/{} sockets={} rx_bytes={}",
        package.semantic.pending_wait_count,
        package.semantic.resource_count,
        package.semantic.active_fast_path_plan_count,
        package.semantic.fast_path_plan_count,
        package.semantic.network_socket_count,
        package.semantic.network_rx_queue_bytes
    );
    println!(
        "replay roots: tasks={} resources={} authorities={} stores={} caps={} target_stores={} target_caps={} boundaries={} artifacts={} activations={} executor_transitions={} target_artifacts={} code_objects={} activation_records={} traps={} hostcalls={} migration_objects={} event_tail={}",
        package.semantic.roots.task_roots.len(),
        package.semantic.roots.resource_roots.len(),
        package.semantic.roots.authority_roots.len(),
        package.semantic.roots.store_roots.len(),
        package.semantic.roots.capability_roots.len(),
        package.semantic.roots.target_store_record_roots.len(),
        package.semantic.roots.target_capability_record_roots.len(),
        package.semantic.roots.boundary_roots.len(),
        package.semantic.roots.artifact_verification_roots.len(),
        package.semantic.roots.store_activation_roots.len(),
        package.semantic.roots.executor_transition_roots.len(),
        package.semantic.roots.target_artifact_roots.len(),
        package.semantic.roots.code_object_roots.len(),
        package.semantic.roots.activation_record_roots.len(),
        package.semantic.roots.trap_roots.len(),
        package.semantic.roots.hostcall_trace_roots.len(),
        package.semantic.roots.migration_object_roots.len(),
        package.semantic.roots.event_log_tail.len()
    );
    for boundary in &package.semantic.roots.boundary_roots {
        println!("replay boundary {boundary}");
    }
    for artifact in &package.semantic.roots.artifact_verification_roots {
        println!("replay artifact {artifact}");
    }
    for activation in &package.semantic.roots.store_activation_roots {
        println!("replay activation {activation}");
    }
    for transition in &package.semantic.roots.executor_transition_roots {
        println!("replay executor {transition}");
    }
    for artifact in &package.semantic.roots.target_artifact_roots {
        println!("replay target-artifact {artifact}");
    }
    for code in &package.semantic.roots.code_object_roots {
        println!("replay code-object {code}");
    }
    for store in &package.semantic.roots.target_store_record_roots {
        println!("replay target-store {store}");
    }
    for capability in &package.semantic.roots.target_capability_record_roots {
        println!("replay target-capability {capability}");
    }
    for activation in &package.semantic.roots.activation_record_roots {
        println!("replay activation-record {activation}");
    }
    for trap in &package.semantic.roots.trap_roots {
        println!("replay trap {trap}");
    }
    for hostcall in &package.semantic.roots.hostcall_trace_roots {
        println!("replay hostcall {hostcall}");
    }
    for object in &package.semantic.roots.migration_object_roots {
        println!("replay migration-object {object}");
    }
    Ok(())
}

fn print_replay_json(
    cursor: u64,
    package: &MigrationPackageManifest,
) -> Result<(), Box<dyn Error>> {
    let value = serde_json::json!({
        "status": "accepted",
        "package": package.package_id,
        "format": package.package_format,
        "cursor": cursor,
        "guest_isa": package.guest.canonical_isa,
        "scheduler_cursor": package.substrate_boundary.scheduler_decision_cursor,
        "random_epoch": package.substrate_boundary.random_epoch,
        "imports": {
            "pending_waits": package.semantic.pending_wait_count,
            "resources": package.semantic.resource_count,
            "active_fastpath": package.semantic.active_fast_path_plan_count,
            "fastpath": package.semantic.fast_path_plan_count,
            "sockets": package.semantic.network_socket_count,
            "rx_bytes": package.semantic.network_rx_queue_bytes
        },
        "substrate_boundary": {
            "pending_irq_causes": package.substrate_boundary.pending_irq_causes,
            "pending_dma_completions": package.substrate_boundary.pending_dma_completions,
            "active_dmw_lease_count": package.substrate_boundary.active_dmw_lease_count,
            "active_mmio_authority_count": package.substrate_boundary.active_mmio_authority_count,
            "active_dma_authority_count": package.substrate_boundary.active_dma_authority_count,
            "active_irq_authority_count": package.substrate_boundary.active_irq_authority_count,
            "active_packet_device_authority_count": package.substrate_boundary.active_packet_device_authority_count,
            "active_virtio_queue_authority_count": package.substrate_boundary.active_virtio_queue_authority_count
        },
        "roots": {
            "tasks": package.semantic.roots.task_roots.len(),
            "resources": package.semantic.roots.resource_roots.len(),
            "authorities": package.semantic.roots.authority_roots.len(),
            "stores": package.semantic.roots.store_roots.len(),
            "capabilities": package.semantic.roots.capability_roots.len(),
            "target_stores": package.semantic.roots.target_store_record_roots.len(),
            "target_capabilities": package.semantic.roots.target_capability_record_roots.len(),
            "boundaries": package.semantic.roots.boundary_roots.len(),
            "artifacts": package.semantic.roots.artifact_verification_roots.len(),
            "activations": package.semantic.roots.store_activation_roots.len(),
            "executor_transitions": package.semantic.roots.executor_transition_roots.len(),
            "target_artifacts": package.semantic.roots.target_artifact_roots.len(),
            "code_objects": package.semantic.roots.code_object_roots.len(),
            "activation_records": package.semantic.roots.activation_record_roots.len(),
            "traps": package.semantic.roots.trap_roots.len(),
            "hostcalls": package.semantic.roots.hostcall_trace_roots.len(),
            "migration_objects": package.semantic.roots.migration_object_roots.len(),
            "tombstones": package.semantic.roots.tombstone_roots.len(),
            "contract_violations": package.semantic.roots.contract_violation_roots.len(),
            "cleanup": package.semantic.roots.cleanup_roots.len(),
            "memory_policies": package.semantic.roots.memory_policy_roots.len(),
            "snapshot_validation": package.semantic.roots.snapshot_validation_roots.len(),
            "replay_validation": package.semantic.roots.replay_validation_roots.len(),
            "event_tail": package.semantic.roots.event_log_tail.len(),
            "boundary_roots": &package.semantic.roots.boundary_roots,
            "artifact_verification_roots": &package.semantic.roots.artifact_verification_roots,
            "store_activation_roots": &package.semantic.roots.store_activation_roots,
            "executor_transition_roots": &package.semantic.roots.executor_transition_roots,
            "target_artifact_roots": &package.semantic.roots.target_artifact_roots,
            "target_store_record_roots": &package.semantic.roots.target_store_record_roots,
            "target_capability_record_roots": &package.semantic.roots.target_capability_record_roots,
            "code_object_roots": &package.semantic.roots.code_object_roots,
            "activation_record_roots": &package.semantic.roots.activation_record_roots,
            "trap_roots": &package.semantic.roots.trap_roots,
            "hostcall_trace_roots": &package.semantic.roots.hostcall_trace_roots,
            "migration_object_roots": &package.semantic.roots.migration_object_roots,
            "tombstone_roots": &package.semantic.roots.tombstone_roots,
            "contract_violation_roots": &package.semantic.roots.contract_violation_roots,
            "cleanup_roots": &package.semantic.roots.cleanup_roots,
            "memory_policy_roots": &package.semantic.roots.memory_policy_roots,
            "snapshot_validation_roots": &package.semantic.roots.snapshot_validation_roots,
            "replay_validation_roots": &package.semantic.roots.replay_validation_roots
        }
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
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
        "semantic roots: tasks={} resources={} authorities={}/{} waits={} capabilities={} stores={} fastpath={}/{} boundaries={} artifacts={} activations={} executor_transitions={} target_artifacts={} code_objects={} activation_records={} traps={} hostcalls={} migration_objects={}",
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
        package.semantic.migration_object_count
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
        package
            .substrate_boundary
            .active_packet_device_authority_count,
        package
            .substrate_boundary
            .active_virtio_queue_authority_count,
        package.substrate_boundary.cow_epoch,
        package.substrate_boundary.background_copy_pages
    );
    print_roots("boundary", &package.semantic.roots.boundary_roots);
    print_roots(
        "artifact-verification",
        &package.semantic.roots.artifact_verification_roots,
    );
    print_roots(
        "store-activation",
        &package.semantic.roots.store_activation_roots,
    );
    print_roots(
        "executor-transition",
        &package.semantic.roots.executor_transition_roots,
    );
    print_roots(
        "target-artifact",
        &package.semantic.roots.target_artifact_roots,
    );
    print_roots("code-object", &package.semantic.roots.code_object_roots);
    print_roots(
        "activation-record",
        &package.semantic.roots.activation_record_roots,
    );
    print_roots("trap", &package.semantic.roots.trap_roots);
    print_roots("hostcall", &package.semantic.roots.hostcall_trace_roots);
    print_roots(
        "migration-object",
        &package.semantic.roots.migration_object_roots,
    );
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
            "module {} role={} exports={} caps={} deps={} abi={} binding={} signer={}",
            module.package,
            module.role,
            module.expected_exports.len(),
            module.capabilities.len(),
            module.service_dependencies.len(),
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
        if mode.fast_path_enabled() {
            "enabled"
        } else {
            "disabled"
        },
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
            "load {} artifact={} role={} policy={} path={} hash={} abi={} binding={} limits=mem{} table{} hostcalls{}",
            module.package,
            module.artifact_name,
            module.role,
            module.fault_policy,
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
    if class.is_empty() {
        CapabilityClass::from_object(object).as_str()
    } else {
        class
    }
}

fn display_default<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

fn display_option_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use artifact_manifest::{
        AuthorityObjectRefManifest, CleanupEffectManifest, CleanupStepManifest,
        ContractObjectRefManifest,
    };
    use semantic_core::{
        AuthorityObjectRef, CapabilityClass, CleanupStep, ContractGraphSnapshot,
        ContractObjectKind, ContractObjectRef, ExternalObjectDeclaration, FrontendKind,
        RestartPolicy, SemanticCommand, SemanticGraph, SemanticWaitKind, WaitCancelReason,
        WaitState, validate_contract_graph,
    };

    #[test]
    fn store_view_v1_exposes_stable_identity_state_and_references() {
        let view = store_view_v1(&StoreRecordManifest {
            id: 7,
            package: "vfs_service".to_owned(),
            artifact: "vfs_service.cwasm".to_owned(),
            role: "service".to_owned(),
            fault_policy: "restartable".to_owned(),
            fault_domain: 3,
            resource: Some(9),
            state: "running".to_owned(),
            generation: 2,
            restart_count: 1,
        });
        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "store");
        assert_eq!(view["id"], 7);
        assert_eq!(view["generation"], 2);
        assert_eq!(view["references"]["fault_domain"], 3);
    }

    #[test]
    fn capability_view_v1_exposes_object_ref_generation_and_state() {
        let view = capability_view_v1(&CapabilityRecordManifest {
            id: 4,
            subject: "driver".to_owned(),
            object: "packet-device.net0".to_owned(),
            object_ref: Some(AuthorityObjectRefManifest {
                scope: "internal".to_owned(),
                class: "packet-device".to_owned(),
                object: ContractObjectRefManifest {
                    kind: "resource".to_owned(),
                    id: 99,
                    generation: 1,
                },
            }),
            rights: vec!["rx".to_owned()],
            lifetime: "store".to_owned(),
            class: "packet-device".to_owned(),
            owner_store: Some(1),
            owner_store_generation: Some(1),
            owner_task: None,
            source: "manifest".to_owned(),
            generation: 3,
            parent: None,
            manifest_decl: true,
            debug_object_label: "packet-device.net0".to_owned(),
            revoked: false,
        });
        assert_eq!(view["kind"], "capability");
        assert_eq!(view["state"], "active");
        assert_eq!(view["owner"]["store_generation"], 1);
        assert_eq!(view["references"]["object_ref"]["object"]["generation"], 1);
        assert_eq!(view["generation"], 3);
    }

    #[test]
    fn wait_view_v1_exposes_blockers_cancel_reason_and_restart_policy() {
        let view = wait_view_v1(&WaitRecordManifest {
            id: 8,
            owner_task: Some(2),
            owner_store: Some(1),
            owner_store_generation: Some(1),
            kind: "timer".to_owned(),
            generation: 1,
            state: "cancelled".to_owned(),
            blockers: vec![ContractObjectRefManifest {
                kind: "capability".to_owned(),
                id: 4,
                generation: 1,
            }],
            deadline: Some(100),
            cancel_reason: Some("capability-revoked".to_owned()),
            restart_policy: "restart-if-allowed".to_owned(),
            saved_context: Some("ctx".to_owned()),
        });
        assert_eq!(view["kind"], "wait");
        assert_eq!(view["owner"]["store_generation"], 1);
        assert_eq!(view["references"]["blockers"][0]["kind"], "capability");
        assert_eq!(view["cancel_reason"], "capability-revoked");
        assert_eq!(view["restart_policy"], "restart-if-allowed");
    }

    #[test]
    fn cleanup_view_v1_exposes_steps_effects_and_status() {
        let target = ContractObjectRefManifest {
            kind: "store".to_owned(),
            id: 1,
            generation: 2,
        };
        let view = cleanup_view_v1(&CleanupTransactionManifest {
            id: 5,
            store: 1,
            store_generation: 2,
            activation: None,
            activation_generation: None,
            code_object: None,
            code_generation: None,
            generation: 1,
            started_at: 10,
            finished_at: Some(11),
            state: "completed".to_owned(),
            reason: "fault".to_owned(),
            released_dmw_leases: 1,
            cancelled_waits: 0,
            revoked_capabilities: vec![4],
            revoked_capability_refs: vec![ContractObjectRefManifest {
                kind: "capability".to_owned(),
                id: 4,
                generation: 2,
            }],
            dropped_resources: 1,
            unbound_code_object: true,
            effect: "errno".to_owned(),
            steps: vec![CleanupStepManifest {
                step: "mark-store-state".to_owned(),
                state: "done".to_owned(),
                detail: "store marked dead".to_owned(),
                target: Some(target.clone()),
                observed_generation: Some(2),
                error: None,
                idempotency_key: "mark-store-state".to_owned(),
                event_seq: 11,
            }],
            effects: vec![CleanupEffectManifest {
                kind: "mark-store-dead".to_owned(),
                target,
                expected_generation: 2,
                status: "applied".to_owned(),
                event_seq: 11,
            }],
        });
        assert_eq!(view["kind"], "cleanup");
        assert_eq!(view["steps"][0]["state"], "done");
        assert_eq!(view["effects"][0]["kind"], "mark-store-dead");
        assert_eq!(view["references"]["revoked_capabilities"][0]["id"], 4);
    }

    #[test]
    fn golden_traces_replay_to_expected_final_views() {
        let wait = parse_golden(include_str!(
            "../../semantic_core/golden_traces/golden_wait_pending_resume_v1.json"
        ));
        replay_wait_golden(&wait);

        let capability = parse_golden(include_str!(
            "../../semantic_core/golden_traces/golden_capability_revoke_generation_v1.json"
        ));
        replay_capability_golden(&capability);

        let cleanup = parse_golden(include_str!(
            "../../semantic_core/golden_traces/golden_driver_fault_cleanup_generation_safe_v1.json"
        ));
        replay_cleanup_golden(&cleanup);
    }

    fn parse_golden(source: &str) -> serde_json::Value {
        let value: serde_json::Value = serde_json::from_str(source).expect("golden trace JSON");
        assert_eq!(value["schema"], "vmos-golden-trace-v1");
        assert!(value["commands"].as_array().expect("commands").len() > 0);
        assert!(value["events"].as_array().expect("events").len() > 0);
        assert!(value["validation"]["ok"].as_bool().expect("validation ok"));
        value
    }

    fn replay_wait_golden(value: &serde_json::Value) {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
        graph.register_store("bootstrap_a", "bootstrap_a.cwasm", "service", "restartable");
        graph.register_store("bootstrap_b", "bootstrap_b.cwasm", "service", "restartable");
        let owner_store = 3;
        let owner_store_generation = 1;
        let registered_store =
            graph.register_store("timer_service", "timer.cwasm", "service", "restartable");
        assert_eq!(registered_store, owner_store);
        for command in value["commands"].as_array().expect("commands") {
            match command["op"].as_str().expect("op") {
                "CreateWait" => graph
                    .apply(SemanticCommand::CreateWait {
                        wait: command["wait"].as_u64().expect("wait"),
                        owner_task: command["owner_task"].as_u64().map(|task| task as u32),
                        owner_store: command["owner_store"].as_u64(),
                        owner_store_generation: Some(
                            command["owner_store_generation"]
                                .as_u64()
                                .unwrap_or(owner_store_generation),
                        ),
                        kind: SemanticWaitKind::Timer,
                        generation: command["generation"].as_u64().expect("generation"),
                        blockers: Vec::new(),
                        deadline: command["deadline"].as_u64(),
                        restart_policy: RestartPolicy::RestartWithAdjustedTimeout,
                        saved_context: None,
                    })
                    .expect("create wait"),
                "ResolveWait" => graph
                    .apply(SemanticCommand::ResolveWait {
                        wait: command["wait"].as_u64().expect("wait"),
                        reason: command["reason"].as_str().expect("reason").to_owned(),
                    })
                    .expect("resolve wait"),
                "ConsumeWait" => {
                    graph.record_wait_consumed(command["wait"].as_u64().expect("wait"));
                    continue;
                }
                other => panic!("unsupported wait golden command {other}"),
            };
        }
        let wait = graph
            .wait_records()
            .iter()
            .find(|wait| wait.id == 21)
            .expect("wait 21");
        assert_eq!(wait.state, WaitState::Consumed);
        assert_eq!(value["final_views"]["wait"]["state"], wait.state.as_str());
        let snapshot = ContractGraphSnapshot {
            waits: graph.wait_records().to_vec(),
            ..ContractGraphSnapshot::default()
        };
        assert_eq!(validate_contract_graph(&snapshot), Vec::new());
    }

    fn replay_capability_golden(value: &serde_json::Value) {
        let mut graph = SemanticGraph::new();
        let store =
            graph.register_store("driver_virtio_net", "driver.cwasm", "driver", "restartable");
        let object = ContractObjectRef::new(ContractObjectKind::Resource, 99, 1);
        let authority = AuthorityObjectRef::internal(CapabilityClass::PacketDevice, object);
        for command in value["commands"].as_array().expect("commands") {
            match command["op"].as_str().expect("op") {
                "GrantCapability" => {
                    graph
                        .apply(SemanticCommand::GrantCapability {
                            subject: command["subject"].as_str().expect("subject").to_owned(),
                            debug_object_label: "packet-device.net0".to_owned(),
                            object_ref: authority,
                            operations: vec!["rx".to_owned(), "tx".to_owned()],
                            lifetime: "store".to_owned(),
                            owner_store: command["owner_store"].as_u64().or(Some(store)),
                            owner_store_generation: command["owner_store_generation"]
                                .as_u64()
                                .or(Some(1)),
                            owner_task: None,
                            source: "golden-replay".to_owned(),
                            manifest_decl: true,
                        })
                        .expect("grant capability");
                }
                "CreateWait" => {
                    graph
                        .apply(SemanticCommand::CreateWait {
                            wait: command["wait"].as_u64().expect("wait"),
                            owner_task: None,
                            owner_store: command["owner_store"].as_u64().or(Some(store)),
                            owner_store_generation: command["owner_store_generation"]
                                .as_u64()
                                .or(Some(1)),
                            kind: SemanticWaitKind::DeviceIrq,
                            generation: 1,
                            blockers: vec![ContractObjectRef::new(
                                ContractObjectKind::Capability,
                                command["blocker"]["id"].as_u64().expect("cap blocker"),
                                command["blocker"]["generation"]
                                    .as_u64()
                                    .expect("cap generation"),
                            )],
                            deadline: None,
                            restart_policy: RestartPolicy::RestartIfAllowed,
                            saved_context: None,
                        })
                        .expect("create wait");
                }
                "RevokeCapability" => {
                    graph
                        .apply(SemanticCommand::RevokeCapability {
                            cap: command["cap"].as_u64().expect("cap"),
                        })
                        .expect("revoke capability");
                }
                "CancelWait" => {
                    graph
                        .apply(SemanticCommand::CancelWait {
                            wait: command["wait"].as_u64().expect("wait"),
                            errno: 125,
                            reason: WaitCancelReason::CapabilityRevoked,
                        })
                        .expect("cancel wait");
                }
                other => panic!("unsupported capability golden command {other}"),
            }
        }

        let cap = graph.capabilities().records()[0].clone();
        assert!(cap.revoked);
        assert_eq!(cap.generation, 2);
        assert_eq!(value["final_views"]["capability"]["id"], cap.id);
        let wait = graph
            .wait_records()
            .iter()
            .find(|wait| wait.id == 22)
            .expect("wait 22");
        assert_eq!(wait.state, WaitState::Cancelled);
        assert_eq!(
            wait.cancel_reason,
            Some(WaitCancelReason::CapabilityRevoked)
        );
        let snapshot = ContractGraphSnapshot {
            stores: graph.stores().to_vec(),
            capabilities: graph.capabilities().records().to_vec(),
            waits: graph.wait_records().to_vec(),
            external_objects: vec![ExternalObjectDeclaration::new(
                object,
                "golden-replay",
                CapabilityClass::PacketDevice.as_str(),
                "packet-device.net0",
            )],
            ..ContractGraphSnapshot::default()
        };
        assert_eq!(validate_contract_graph(&snapshot), Vec::new());
        assert_eq!(value["expected_violation_codes"][0], "revoked");
    }

    fn replay_cleanup_golden(value: &serde_json::Value) {
        let mut graph = SemanticGraph::new();
        let store =
            graph.register_store("driver_virtio_net", "driver.cwasm", "driver", "restartable");
        assert_eq!(store, 1);
        let mut last_rebind_generation = 1;
        let mut applied_step_status = None;

        for command in value["commands"].as_array().expect("commands") {
            match command["op"].as_str().expect("op") {
                "BeginCleanup" => {
                    let target = &command["target_store"];
                    assert_eq!(target["id"].as_u64().expect("target id"), store);
                    graph
                        .apply(SemanticCommand::BeginCleanup {
                            cleanup: command["cleanup"].as_u64().expect("cleanup"),
                            store,
                            generation: target["generation"].as_u64().expect("generation"),
                            reason: command["reason"].as_str().expect("reason").to_owned(),
                        })
                        .expect("begin cleanup");
                }
                "RebindStore" => {
                    let expected = &command["store"];
                    assert_eq!(expected["id"].as_u64().expect("store id"), store);
                    let rebound = graph.rebind_store_instance(store).expect("rebind store");
                    last_rebind_generation = rebound.generation;
                    assert_eq!(
                        expected["generation"].as_u64().expect("store generation"),
                        rebound.generation
                    );
                    assert_eq!(
                        expected["state"].as_str().expect("state"),
                        graph.stores()[0].state.as_str()
                    );
                }
                "ApplyCleanupStep" => {
                    let target = object_ref_from_json(&command["target"]);
                    let observed_generation = command["observed_generation"]
                        .as_u64()
                        .expect("observed generation");
                    if command["status"].as_str() == Some("skipped-stale-generation") {
                        assert_ne!(target.generation, observed_generation);
                    }
                    graph
                        .apply(SemanticCommand::ApplyCleanupStep {
                            cleanup: command["cleanup"].as_u64().expect("cleanup"),
                            step: cleanup_step_from_json(command["step"].as_str().expect("step")),
                            target,
                            observed_generation,
                        })
                        .expect("apply cleanup step");
                    applied_step_status =
                        command["status"].as_str().map(|status| status.to_owned());
                }
                "CommitCleanup" => {
                    graph
                        .apply(SemanticCommand::CommitCleanup {
                            cleanup: command["cleanup"].as_u64().expect("cleanup"),
                        })
                        .expect("commit cleanup");
                    if let Some(status) = command["status"].as_str() {
                        assert_eq!(applied_step_status.as_deref(), Some(status));
                    }
                }
                other => panic!("unsupported cleanup golden command {other}"),
            }
        }

        assert_eq!(last_rebind_generation, 2);
        assert_eq!(
            graph.stores()[0].state.as_str(),
            value["final_views"]["store"]["state"]
                .as_str()
                .expect("store state")
        );
        assert_eq!(
            value["final_views"]["store"]["generation"],
            graph.stores()[0].generation
        );
        for event in value["events"].as_array().expect("events") {
            match event["kind"].as_str().expect("event kind") {
                "CleanupStepApplied" => {
                    let expected = format!(
                        "CleanupStepApplied cleanup={} step={} target={} observed_generation={}",
                        event["cleanup"].as_u64().expect("cleanup"),
                        event["step"].as_str().expect("step"),
                        event["target"].as_str().expect("target"),
                        event["observed_generation"]
                            .as_u64()
                            .expect("observed generation")
                    );
                    assert!(
                        graph
                            .event_log_tail(16)
                            .iter()
                            .any(|record| record.summary().contains(&expected)),
                        "missing expected event {expected}"
                    );
                }
                "StoreRebound" => {
                    assert_eq!(
                        event["store"].as_str().expect("store"),
                        format!("{}@{}", store, graph.stores()[0].generation)
                    );
                }
                "FaultCleanupStarted" | "FaultCleanupSkipped" => {}
                other => panic!("unsupported cleanup golden event {other}"),
            }
        }
        let digest = cleanup_replay_digest(&graph, store);
        assert_eq!(value["state_digest"]["cleanup_once"], digest);
        assert_eq!(
            value["state_digest"]["cleanup_once"],
            value["state_digest"]["cleanup_twice"]
        );
    }

    fn object_ref_from_json(value: &serde_json::Value) -> ContractObjectRef {
        let kind = match value["kind"].as_str().expect("object kind") {
            "store" => ContractObjectKind::Store,
            "capability" => ContractObjectKind::Capability,
            "wait-token" | "wait" => ContractObjectKind::WaitToken,
            "cleanup" | "cleanup-transaction" => ContractObjectKind::CleanupTransaction,
            "resource" => ContractObjectKind::Resource,
            other => panic!("unsupported golden object kind {other}"),
        };
        ContractObjectRef::new(
            kind,
            value["id"].as_u64().expect("object id"),
            value["generation"].as_u64().expect("object generation"),
        )
    }

    fn cleanup_step_from_json(value: &str) -> CleanupStep {
        match value {
            "stop-new-activation" => CleanupStep::StopNewActivation,
            "seal-activation" => CleanupStep::SealActivation,
            "prevent-hostcalls" => CleanupStep::PreventHostcalls,
            "release-dmw-leases" => CleanupStep::ReleaseDmwLeases,
            "cancel-wait-tokens" => CleanupStep::CancelWaitTokens,
            "revoke-capabilities" => CleanupStep::RevokeCapabilities,
            "drop-resource-arena" => CleanupStep::DropResourceArena,
            "unbind-code-object" => CleanupStep::UnbindCodeObject,
            "mark-store-state" => CleanupStep::MarkStoreState,
            "record-transition" => CleanupStep::RecordTransition,
            "emit-tombstones" => CleanupStep::EmitTombstones,
            "record-failure-effect" => CleanupStep::RecordFailureEffect,
            "emit-report" => CleanupStep::EmitReport,
            other => panic!("unsupported cleanup step {other}"),
        }
    }

    fn cleanup_replay_digest(graph: &SemanticGraph, store: u64) -> String {
        let store = graph
            .stores()
            .iter()
            .find(|record| record.id == store)
            .expect("digest store");
        format!(
            "store:{}@{}:{}|code:1@1:bound|caps:active",
            store.id,
            store.generation,
            store.state.as_str()
        )
    }
}
