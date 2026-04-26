#![recursion_limit = "256"]

use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

use artifact_manifest::{
    ActivationRecordManifest, ArtifactBundleManifest, BoundaryValidationReportManifest,
    CapabilityRecordManifest, CleanupTransactionManifest, CodeObjectManifest,
    CommandResultManifest, ContractObjectRefManifest, HostcallTraceManifest,
    InterfaceEventManifest, MigrationPackageManifest, RunnableQueueManifest,
    RuntimeActivationRecordManifest, StoreRecordManifest, SubstrateEventManifest,
    TargetArtifactImageManifest, TaskRecordManifest, TrapRecordManifest, WaitRecordManifest,
};
use contract_core::{
    ArtifactInterfaceCompatibilityReport, ArtifactSubstrateCompatibilityReport,
    InterfaceHostCapabilitySet, VIEW_SCHEMA_V1, ValidatedArtifactPlan,
    build_validated_artifact_plan, check_artifact_manifest_interface_compatibility,
    check_artifact_manifest_substrate_compatibility, validate_migration_against_manifest,
    validate_migration_package, validate_replay_quiescent,
};
use semantic_core::{CapabilityClass, RuntimeMode};
use substrate_api::{SubstrateCapabilitySet, SubstrateProfile};

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
        "substrate" => {
            let Some(subcommand) = args.next() else {
                return Err("substrate requires a subcommand".into());
            };
            match subcommand.as_str() {
                "check" => {
                    let mut json = false;
                    let mut profile = "host-validation".to_owned();
                    let mut path = None;
                    while let Some(arg) = args.next() {
                        if arg == "--json" {
                            json = true;
                        } else if arg == "--profile" {
                            profile = args
                                .next()
                                .ok_or("substrate check --profile requires a value")?;
                        } else if path.is_none() {
                            path = Some(arg);
                        } else {
                            return Err("substrate check received too many positional paths".into());
                        }
                    }
                    let path = path.ok_or("substrate check requires a manifest JSON path")?;
                    check_substrate_compatibility(Path::new(&path), &profile, json)
                }
                "events" => {
                    let mut json = false;
                    let mut path = None;
                    for arg in args {
                        if arg == "--json" {
                            json = true;
                        } else if path.is_none() {
                            path = Some(arg);
                        } else {
                            return Err(
                                "substrate events received too many positional paths".into()
                            );
                        }
                    }
                    let path = path.ok_or("substrate events requires a migration package JSON path")?;
                    print_substrate_events(Path::new(&path), json)
                }
                _ => Err(
                    "substrate syntax is: osctl substrate check [--json] [--profile <name>] <manifest.json> | osctl substrate events [--json] <migration.json>"
                        .into(),
                ),
            }
        }
        "interface" => {
            let Some(subcommand) = args.next() else {
                return Err("interface requires a subcommand".into());
            };
            match subcommand.as_str() {
                "check" => {
                    let mut json = false;
                    let mut profile = "host-validation".to_owned();
                    let mut path = None;
                    while let Some(arg) = args.next() {
                        if arg == "--json" {
                            json = true;
                        } else if arg == "--profile" {
                            profile = args
                                .next()
                                .ok_or("interface check --profile requires a value")?;
                        } else if path.is_none() {
                            path = Some(arg);
                        } else {
                            return Err("interface check received too many positional paths".into());
                        }
                    }
                    let path = path.ok_or("interface check requires a manifest JSON path")?;
                    check_interface_compatibility(Path::new(&path), &profile, json)
                }
                "events" => {
                    let mut json = false;
                    let mut path = None;
                    for arg in args {
                        if arg == "--json" {
                            json = true;
                        } else if path.is_none() {
                            path = Some(arg);
                        } else {
                            return Err(
                                "interface events received too many positional paths".into()
                            );
                        }
                    }
                    let path =
                        path.ok_or("interface events requires a migration package JSON path")?;
                    print_interface_events(Path::new(&path), json)
                }
                _ => Err(
                    "interface syntax is: osctl interface check [--json] [--profile <name>] <manifest.json> | osctl interface events [--json] <migration.json>"
                        .into(),
                ),
            }
        }
        "experiment" => {
            let Some(subcommand) = args.next() else {
                return Err("experiment requires a subcommand".into());
            };
            match subcommand.as_str() {
                "report" => {
                    let mut json = false;
                    let mut path = None;
                    for arg in args {
                        if arg == "--json" {
                            json = true;
                        } else if path.is_none() {
                            path = Some(arg);
                        } else {
                            return Err("experiment report received too many arguments".into());
                        }
                    }
                    let path = path.ok_or("experiment report requires a report JSON path")?;
                    print_experiment_report(Path::new(&path), json)
                }
                _ => Err(
                    "experiment syntax is: osctl experiment report [--json] <report.json>".into(),
                ),
            }
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
        "task" | "store" | "cap" | "capability" | "wait" | "cleanup" | "command" | "scheduler"
        | "runtime-activation" | "runnable-queue" => handle_view_command(&command, args.collect()),
        "state" => {
            let Some(path) = args.next() else {
                return Err("state requires a manifest/package JSON path".into());
            };
            print_state(Path::new(&path))
        }
        "graph" => {
            let mut json = false;
            let mut mode = GraphEdgeMode::Roots;
            let mut path = None;
            for arg in args {
                if arg == "--json" {
                    json = true;
                } else if arg == "--live" {
                    mode = GraphEdgeMode::Live;
                } else if arg == "--history" {
                    mode = GraphEdgeMode::History;
                } else if path.is_none() {
                    path = Some(arg);
                } else {
                    return Err("graph received too many positional paths".into());
                }
            }
            let path = path.ok_or("graph requires a migration package JSON path")?;
            print_graph(Path::new(&path), mode, json)
        }
        "activation" => {
            let collected = args.collect::<Vec<_>>();
            if collected
                .first()
                .is_some_and(|arg| arg == "show" || arg == "list")
            {
                return handle_view_command("activation", collected);
            }
            let mut blocked_only = false;
            let mut path = None;
            for arg in collected {
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
    eprintln!("  osctl substrate check [--json] [--profile <name>] <manifest.json>");
    eprintln!("  osctl substrate events [--json] <migration.json>");
    eprintln!("  osctl interface check [--json] [--profile <name>] <manifest.json>");
    eprintln!("  osctl interface events [--json] <migration.json>");
    eprintln!("  osctl experiment report [--json] <report.json>");
    eprintln!("  osctl modes");
    eprintln!("  osctl caps [--subject <subject>] <manifest-or-migration.json>");
    eprintln!(
        "  osctl task|activation|scheduler|runnable-queue|store|cap|wait|cleanup|command list --json <migration.json>"
    );
    eprintln!("  osctl store|cap|wait|cleanup|command show --json <migration.json> <id>");
    eprintln!("  osctl state <manifest-or-migration.json>");
    eprintln!("  osctl graph [--live|--history] [--json] <migration.json>");
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

fn print_experiment_report(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
    let report: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    let schema = json_field_str(&report, "schema")?;
    if schema != "vmos-experiment-report" {
        return Err(format!(
            "experiment report schema must be vmos-experiment-report, got {schema}"
        )
        .into());
    }
    let name = json_field_str(&report, "name")?;
    let checkpoint = json_field_str(&report, "checkpoint")?;
    let commands = json_field_array(&report, "commands")?;
    let events = json_field_array(&report, "events")?;
    let metrics = json_field_object(&report, "metrics")?;
    let validation = json_field_object(&report, "validation")?;
    let contract_ok = validation
        .get("contract_ok")
        .and_then(serde_json::Value::as_bool)
        .ok_or("experiment report validation.contract_ok must be a boolean")?;
    let golden_replay_ok = validation
        .get("golden_replay_ok")
        .and_then(serde_json::Value::as_bool)
        .ok_or("experiment report validation.golden_replay_ok must be a boolean")?;
    let metric_keys: Vec<_> = metrics.keys().cloned().collect();
    let ok = contract_ok && golden_replay_ok;

    if json {
        let value = serde_json::json!({
            "schema_version": OSCTL_JSON_SCHEMA_VERSION,
            "schema": "osctl-experiment-report-view-v1",
            "report_schema": schema,
            "path": path.display().to_string(),
            "name": name,
            "checkpoint": checkpoint,
            "command_count": commands.len(),
            "event_count": events.len(),
            "metrics": metric_keys,
            "validation": {
                "ok": ok,
                "contract_ok": contract_ok,
                "golden_replay_ok": golden_replay_ok
            }
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    println!("experiment report: {name}");
    println!("  checkpoint: {checkpoint}");
    println!("  commands: {}", commands.len());
    println!("  events: {}", events.len());
    println!("  metrics: {}", metric_keys.join(", "));
    println!("  validation: {}", if ok { "ok" } else { "failed" });
    Ok(())
}

fn json_field_str<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, Box<dyn Error>> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("json field `{field}` must be a string").into())
}

fn json_field_array<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a Vec<serde_json::Value>, Box<dyn Error>> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("json field `{field}` must be an array").into())
}

fn json_field_object<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, Box<dyn Error>> {
    value
        .get(field)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| format!("json field `{field}` must be an object").into())
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
        "task" => "task",
        "activation" | "runtime-activation" => "activation",
        "scheduler" => "scheduler",
        "runnable-queue" => "runnable-queue",
        "cap" | "capability" => "capability",
        "store" => "store",
        "wait" => "wait",
        "cleanup" => "cleanup",
        "command" => "command",
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

fn task_view_v1(task: &TaskRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "task",
        "id": task.id,
        "generation": task.generation,
        "state": task.state,
        "owner": {
            "frontend": task.frontend,
        },
        "references": {
            "fault_domain": task.fault_domain,
            "pending_wait": task.pending_wait,
            "resources": task.resources,
        },
        "label": task.label,
        "last_transition": serde_json::Value::Null,
        "last_error": serde_json::Value::Null,
    })
}

fn runtime_activation_view_v1(activation: &RuntimeActivationRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation",
        "id": activation.id,
        "generation": activation.generation,
        "state": activation.state,
        "owner": {
            "task": activation.owner_task,
            "task_generation": activation.owner_task_generation,
            "store": activation.owner_store,
            "store_generation": activation.owner_store_generation,
        },
        "references": {
            "code_object": activation.code_object,
            "runnable_queue": activation.runnable_queue.map(|id| serde_json::json!({
                "id": id,
                "generation": activation.runnable_queue_generation,
            })),
        },
        "last_transition": {
            "last_event": activation.last_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn runnable_queue_view_v1(queue: &RunnableQueueManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "runnable-queue",
        "id": queue.id,
        "generation": queue.generation,
        "state": queue.state,
        "owner": {
            "scheduler": 1,
        },
        "references": {
            "entries": queue.entries.iter().map(|entry| serde_json::json!({
                "activation": {
                    "id": entry.activation,
                    "generation": entry.activation_generation,
                },
                "enqueued_at": entry.enqueued_at,
            })).collect::<Vec<_>>(),
        },
        "label": queue.label,
        "last_transition": {
            "entry_count": queue.entries.len(),
        },
        "last_error": serde_json::Value::Null,
    })
}

fn scheduler_view_v1(package: &MigrationPackageManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "scheduler",
        "id": 1,
        "generation": 1,
        "state": "active",
        "owner": {
            "package": package.package_id,
        },
        "references": {
            "tasks": package.semantic.task_records.iter().map(|task| serde_json::json!({
                "id": task.id,
                "generation": task.generation,
            })).collect::<Vec<_>>(),
            "activations": package.semantic.runtime_activation_records.iter().map(|activation| serde_json::json!({
                "id": activation.id,
                "generation": activation.generation,
                "state": activation.state,
            })).collect::<Vec<_>>(),
            "queues": package.semantic.runnable_queues.iter().map(|queue| serde_json::json!({
                "id": queue.id,
                "generation": queue.generation,
                "entries": queue.entries.len(),
            })).collect::<Vec<_>>(),
        },
        "last_transition": {
            "scheduler_decision_cursor": package.substrate_boundary.scheduler_decision_cursor,
            "task_count": package.semantic.task_record_count,
            "activation_count": package.semantic.runtime_activation_count,
            "queue_count": package.semantic.runnable_queue_count,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn artifact_view_v1(artifact: &TargetArtifactImageManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "artifact",
        "id": artifact.id,
        "generation": 1,
        "state": "verified",
        "owner": {
            "package": artifact.package,
            "role": artifact.role,
            "target_profile": artifact.target_profile,
        },
        "references": {
            "artifact_name": artifact.artifact_name,
            "artifact_hash": artifact.artifact_hash,
            "manifest_binding_hash": artifact.manifest_binding_hash,
            "abi_fingerprint": artifact.abi_fingerprint,
            "code_hash": artifact.code_hash,
        },
        "exports": artifact.exports,
        "imports": artifact.imports,
        "hostcall_count": artifact.hostcalls.len(),
        "capability_count": artifact.capabilities.len(),
        "memory_plan": artifact.memory_plan,
        "last_transition": {
            "kind": artifact.kind,
            "payload_len": artifact.payload_len,
            "trap_metadata_count": artifact.trap_metadata.len(),
            "address_map_count": artifact.address_map.len(),
        },
        "last_error": serde_json::Value::Null,
    })
}

fn code_object_view_v1(code: &CodeObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "code-object",
        "id": code.id,
        "generation": code.generation,
        "state": code.state,
        "owner": {
            "package": code.package,
            "profile": code.owner_profile,
        },
        "references": {
            "artifact": {
                "id": code.artifact_id,
                "generation": 1,
            },
            "bound_store": code.bound_store.map(|id| serde_json::json!({
                "id": id,
                "generation": code.bound_store_generation,
            })),
            "hostcall_table": code.hostcall_table,
            "code_hash": code.code_hash,
        },
        "memory": {
            "text": {
                "start": code.text_start,
                "len": code.text_len,
                "permission": code.text_permission,
            },
            "rodata": {
                "start": code.rodata_start,
                "len": code.rodata_len,
                "permission": code.rodata_permission,
            },
        },
        "hostcall_count": code.hostcalls.len(),
        "trap_metadata_count": code.trap_metadata.len(),
        "address_map_count": code.address_map.len(),
        "last_transition": serde_json::Value::Null,
        "last_error": serde_json::Value::Null,
    })
}

fn activation_view_v1(activation: &ActivationRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation",
        "id": activation.id,
        "generation": activation.generation,
        "state": activation.state,
        "owner": {
            "store": activation.store,
            "store_generation": activation.store_generation,
        },
        "references": {
            "code_object": {
                "id": activation.code_object,
                "generation": activation.code_generation,
            },
            "artifact": {
                "id": activation.artifact,
                "generation": 1,
            },
            "blocked_wait": activation.blocked_wait,
            "trap": activation.trap,
        },
        "entry": activation.entry,
        "start_event": activation.start_event,
        "exit_event": activation.exit_event,
        "last_transition": {
            "active_dmw_leases": activation.active_dmw_leases,
            "return_tag": activation.return_tag,
        },
        "last_error": activation.trap,
    })
}

fn trap_view_v1(trap: &TrapRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "trap",
        "id": trap.id,
        "generation": trap.generation,
        "state": "recorded",
        "owner": {
            "store": trap.store,
            "store_generation": trap.store_generation,
            "activation": trap.activation,
            "activation_generation": trap.activation_generation,
        },
        "references": {
            "code_object": trap.code_object.map(|id| serde_json::json!({
                "id": id,
                "generation": trap.code_generation,
            })),
            "artifact": trap.artifact.map(|id| serde_json::json!({
                "id": id,
                "generation": trap.artifact_generation,
            })),
            "hostcall": trap.hostcall,
        },
        "trap_class": trap.class,
        "offset": trap.offset,
        "target_pc": trap.target_pc,
        "trap_kind": trap.trap_kind,
        "function_index": trap.function_index,
        "wasm_offset": trap.wasm_offset,
        "debug_symbol": trap.debug_symbol,
        "classification_status": trap.classification_status,
        "detail": trap.detail,
        "last_transition": {
            "fault_policy": trap.fault_policy,
            "effect": trap.effect,
        },
        "last_error": trap.detail,
    })
}

fn hostcall_trace_view_v1(hostcall: &HostcallTraceManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "hostcall",
        "id": hostcall.id,
        "generation": hostcall.generation,
        "state": hostcall.result,
        "owner": {
            "activation": hostcall.activation,
            "activation_generation": hostcall.activation_generation,
            "store": hostcall.store,
            "store_generation": hostcall.store_generation,
        },
        "references": {
            "code_object": {
                "id": hostcall.code_object,
                "generation": hostcall.code_generation,
            },
            "artifact": {
                "id": hostcall.artifact,
                "generation": hostcall.artifact_generation,
            },
            "trap_out": hostcall.trap_out,
            "trap_generation_out": hostcall.trap_generation_out,
            "wait_token_out": hostcall.wait_token_out,
            "wait_token_generation_out": hostcall.wait_token_generation_out,
        },
        "abi": {
            "version": hostcall.abi_version,
            "frame_size": hostcall.frame_size,
            "flags": hostcall.flags,
        },
        "call": {
            "number": hostcall.hostcall_number,
            "sequence": hostcall.hostcall_seq,
            "caller_offset": hostcall.caller_offset,
            "name": hostcall.name,
            "category": hostcall.category,
            "subject": hostcall.subject,
            "object": hostcall.object,
            "operation": hostcall.operation,
            "record_mode": hostcall.record_mode,
        },
        "args": hostcall.args,
        "cap_args": hostcall.cap_args,
        "return": {
            "tag": hostcall.ret_tag,
            "ret0": hostcall.ret0,
            "ret1": hostcall.ret1,
        },
        "last_transition": {
            "allowed": hostcall.allowed,
        },
        "last_error": if hostcall.allowed {
            serde_json::Value::Null
        } else {
            serde_json::json!("hostcall-denied")
        },
    })
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
    let target_generation = if cleanup.target_store_generation == 0 {
        cleanup.store_generation
    } else {
        cleanup.target_store_generation
    };
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
                "generation": target_generation,
            },
            "result_store": {
                "id": cleanup.store,
                "generation": cleanup.result_store_generation,
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
        "task" => Ok(package
            .semantic
            .task_records
            .iter()
            .map(task_view_v1)
            .collect()),
        "activation" | "runtime-activation" => Ok(package
            .semantic
            .runtime_activation_records
            .iter()
            .map(runtime_activation_view_v1)
            .collect()),
        "scheduler" => Ok(vec![scheduler_view_v1(package)]),
        "runnable-queue" => Ok(package
            .semantic
            .runnable_queues
            .iter()
            .map(runnable_queue_view_v1)
            .collect()),
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
        "command" => Ok(package
            .semantic
            .command_results
            .iter()
            .map(command_result_view_v1)
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
                "target_artifact_format": &plan.target_artifact_format,
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
                "target_artifact_path": &module.target_artifact_path,
                "target_artifact_sha256": &module.target_artifact_sha256,
                "code_payload_format": &module.code_payload_format,
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

fn check_substrate_compatibility(
    path: &Path,
    profile: &str,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&fs::read(path)?)?;
    let capabilities = substrate_capabilities_for_profile(profile)
        .ok_or_else(|| format!("unknown substrate profile `{profile}`"))?;
    let report = check_artifact_manifest_substrate_compatibility(&manifest, capabilities)?;
    if json {
        print_substrate_compatibility_json(profile, capabilities, &report)?;
    } else {
        print_substrate_compatibility_text(profile, &report);
    }
    if report.ok {
        Ok(())
    } else {
        Err("substrate compatibility check failed".into())
    }
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
    for module in &report.modules {
        println!(
            "module {} required_profile={} ok={} missing_required={} degraded_optional={} forbidden_requested={}",
            module.package,
            module.substrate_profile_required,
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
    let value = serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "schema_version": OSCTL_JSON_SCHEMA_VERSION,
        "kind": "substrate-compatibility",
        "command": "substrate.check",
        "profile": profile,
        "capabilities": substrate_capabilities_json(capabilities),
        "artifact_profile": &report.artifact_profile,
        "ok": report.ok,
        "module_count": report.module_count,
        "modules": report.modules.iter().map(|module| serde_json::json!({
            "package": &module.package,
            "substrate_profile_required": &module.substrate_profile_required,
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
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
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

fn check_interface_compatibility(
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
    if report.ok {
        Ok(())
    } else {
        Err("interface compatibility check failed".into())
    }
}

fn interface_capabilities_for_profile(profile: &str) -> Option<InterfaceHostCapabilitySet> {
    match profile {
        "host-validation" => Some(InterfaceHostCapabilitySet::host_validation()),
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

fn print_interface_events(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
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

fn print_substrate_events(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
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
            "semantic state package={} cursor={} tasks={} runtime_activations={} runnable_queues={} resources={} stores={} caps={} waits={} authorities={}/{} boundaries={} artifacts={} activations={} executor_transitions={} target_artifacts={} code_objects={} activation_records={} traps={} hostcalls={} migration_objects={}",
            package.package_id,
            package.semantic.event_log_cursor,
            package.semantic.task_count,
            package.semantic.runtime_activation_count,
            package.semantic.runnable_queue_count,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GraphEdgeMode {
    Roots,
    Live,
    History,
}

impl GraphEdgeMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Roots => "roots",
            Self::Live => "live",
            Self::History => "history",
        }
    }
}

fn print_graph(path: &Path, mode: GraphEdgeMode, json: bool) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    if json || mode != GraphEdgeMode::Roots {
        let edges = graph_edges_for_package(&package, mode);
        if json {
            let value = serde_json::json!({
                "schema": VIEW_SCHEMA_V1,
                "schema_version": OSCTL_JSON_SCHEMA_VERSION,
                "kind": "contract-graph",
                "command": "graph",
                "mode": mode.as_str(),
                "package": package.package_id,
                "edge_count": edges.len(),
                "edges": edges,
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            println!(
                "graph package={} mode={} edges={}",
                package.package_id,
                mode.as_str(),
                edges.len()
            );
            for edge in edges {
                println!("{edge}");
            }
        }
        return Ok(());
    }
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

fn graph_edges_for_package(
    package: &MigrationPackageManifest,
    mode: GraphEdgeMode,
) -> Vec<serde_json::Value> {
    match mode {
        GraphEdgeMode::Roots => {
            let mut edges = live_graph_edges(package);
            edges.extend(history_graph_edges(package));
            edges
        }
        GraphEdgeMode::Live => live_graph_edges(package),
        GraphEdgeMode::History => history_graph_edges(package),
    }
}

fn live_graph_edges(package: &MigrationPackageManifest) -> Vec<serde_json::Value> {
    let mut edges = Vec::new();
    for activation in &package.semantic.runtime_activation_records {
        if matches!(
            activation.state.as_str(),
            "runnable" | "running" | "pending"
        ) {
            let task_generation = package
                .semantic
                .task_records
                .iter()
                .find(|task| {
                    task.id == activation.owner_task
                        && task.generation == activation.owner_task_generation
                })
                .map(|task| task.generation)
                .unwrap_or(activation.owner_task_generation);
            edges.push(graph_edge(
                object_ref_json("task", activation.owner_task, task_generation),
                object_ref_json("activation", activation.id, activation.generation),
                "owns",
                "live",
                activation.last_event,
            ));
            if let (Some(queue), Some(queue_generation)) = (
                activation.runnable_queue,
                activation.runnable_queue_generation,
            ) {
                edges.push(graph_edge(
                    object_ref_json("activation", activation.id, activation.generation),
                    object_ref_json("runnable-queue", queue, queue_generation),
                    "queued-in",
                    "live",
                    activation.last_event,
                ));
            }
        }
    }
    for queue in &package.semantic.runnable_queues {
        if queue.state != "active" {
            continue;
        }
        for entry in &queue.entries {
            edges.push(graph_edge(
                object_ref_json("runnable-queue", queue.id, queue.generation),
                object_ref_json("activation", entry.activation, entry.activation_generation),
                "contains",
                "live",
                Some(entry.enqueued_at),
            ));
        }
    }
    for activation in &package.semantic.activation_records {
        if activation.state == "running" {
            edges.push(graph_edge(
                object_ref_json("store", activation.store, activation.store_generation),
                object_ref_json("activation", activation.id, activation.generation),
                "owns",
                "live",
                Some(activation.start_event),
            ));
            edges.push(graph_edge(
                object_ref_json("activation", activation.id, activation.generation),
                object_ref_json(
                    "code-object",
                    activation.code_object,
                    activation.code_generation,
                ),
                "bound-to",
                "live",
                Some(activation.start_event),
            ));
        }
    }
    for code in &package.semantic.code_objects {
        if let Some(store) = code.bound_store {
            edges.push(graph_edge(
                object_ref_json("store", store, code.bound_store_generation.unwrap_or(0)),
                object_ref_json("code-object", code.id, code.generation),
                "bound-to",
                "live",
                None,
            ));
        }
    }
    for capability in &package.semantic.capability_records {
        if capability.revoked {
            continue;
        }
        if let Some(store) = capability.owner_store {
            edges.push(graph_edge(
                object_ref_json(
                    "store",
                    store,
                    capability.owner_store_generation.unwrap_or(0),
                ),
                object_ref_json("capability", capability.id, capability.generation),
                "owns",
                "live",
                None,
            ));
        }
        if let Some(object_ref) = &capability.object_ref {
            let mode = if object_ref.scope == "external" || object_ref.object.kind == "external" {
                "external"
            } else {
                "live"
            };
            edges.push(graph_edge(
                object_ref_json("capability", capability.id, capability.generation),
                object_ref_manifest_json(&object_ref.object),
                "authorizes",
                mode,
                None,
            ));
        }
    }
    for wait in &package.semantic.wait_records {
        if wait.state != "pending" {
            continue;
        }
        if let Some(store) = wait.owner_store {
            edges.push(graph_edge(
                object_ref_json("wait-token", wait.id, wait.generation),
                object_ref_json("store", store, wait.owner_store_generation.unwrap_or(0)),
                "belongs-to",
                "live",
                None,
            ));
        }
        if let Some(task) = wait.owner_task {
            edges.push(graph_edge(
                object_ref_json("wait-token", wait.id, wait.generation),
                object_ref_json("task", task, 1),
                "belongs-to",
                "live",
                None,
            ));
        }
        for blocker in &wait.blockers {
            edges.push(graph_edge(
                object_ref_json("wait-token", wait.id, wait.generation),
                object_ref_manifest_json(blocker),
                "blocks-on",
                if blocker.kind == "external" {
                    "external"
                } else {
                    "live"
                },
                None,
            ));
        }
    }
    edges
}

fn history_graph_edges(package: &MigrationPackageManifest) -> Vec<serde_json::Value> {
    let mut edges = Vec::new();
    for trap in &package.semantic.trap_records {
        let from = object_ref_json("trap", trap.id, trap.generation);
        if let Some(store) = trap.store {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("store", store, trap.store_generation.unwrap_or(0)),
                "recorded",
                "historical",
                None,
            ));
        }
        if let Some(activation) = trap.activation {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "activation",
                    activation,
                    trap.activation_generation.unwrap_or(0),
                ),
                "recorded",
                "historical",
                None,
            ));
        }
        if let Some(code_object) = trap.code_object {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "code-object",
                    code_object,
                    trap.code_generation.unwrap_or(0),
                ),
                "recorded",
                "historical",
                None,
            ));
        }
        if let Some(artifact) = trap.artifact {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("artifact", artifact, trap.artifact_generation.unwrap_or(1)),
                "recorded",
                "historical",
                None,
            ));
        }
    }
    for hostcall in &package.semantic.hostcall_trace {
        let from = object_ref_json("hostcall", hostcall.id, hostcall.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                hostcall.activation,
                hostcall.activation_generation,
            ),
            "recorded",
            "historical",
            None,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", hostcall.store, hostcall.store_generation),
            "recorded",
            "historical",
            None,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "code-object",
                hostcall.code_object,
                hostcall.code_generation,
            ),
            "recorded",
            "historical",
            None,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("artifact", hostcall.artifact, hostcall.artifact_generation),
            "recorded",
            "historical",
            None,
        ));
        if let Some(trap) = hostcall.trap_out {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("trap", trap, hostcall.trap_generation_out.unwrap_or(0)),
                "caused",
                "historical",
                None,
            ));
        }
        if let Some(wait) = hostcall.wait_token_out {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "wait-token",
                    wait,
                    hostcall.wait_token_generation_out.unwrap_or(0),
                ),
                "caused",
                "historical",
                None,
            ));
        }
    }
    for cleanup in &package.semantic.cleanup_transactions {
        let from = object_ref_json("cleanup", cleanup.id, cleanup.generation);
        let target_generation = if cleanup.target_store_generation == 0 {
            cleanup.store_generation
        } else {
            cleanup.target_store_generation
        };
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.store, target_generation),
            "killed",
            "cleanup-effect",
            Some(cleanup.started_at),
        ));
        if let Some(activation) = cleanup.activation {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "activation",
                    activation,
                    cleanup.activation_generation.unwrap_or(0),
                ),
                "released",
                "cleanup-effect",
                cleanup.finished_at,
            ));
        }
        if let Some(code) = cleanup.code_object {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("code-object", code, cleanup.code_generation.unwrap_or(0)),
                "unbound",
                "cleanup-effect",
                cleanup.finished_at,
            ));
        }
        for capability in &cleanup.revoked_capability_refs {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(capability),
                "revoked",
                "cleanup-effect",
                cleanup.finished_at,
            ));
        }
        for effect in &cleanup.effects {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(&effect.target),
                &effect.kind,
                "cleanup-effect",
                Some(effect.event_seq),
            ));
        }
    }
    edges
}

fn graph_edge(
    from: serde_json::Value,
    to: serde_json::Value,
    relation: &str,
    mode: &str,
    created_at_event: Option<u64>,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "from": from,
        "to": to,
        "relation": relation,
        "mode": mode,
        "created_at_event": created_at_event,
    })
}

fn object_ref_json(kind: &str, id: u64, generation: u64) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "id": id,
        "generation": generation,
    })
}

fn object_ref_manifest_json(object: &ContractObjectRefManifest) -> serde_json::Value {
    object_ref_json(&object.kind, object.id, object.generation)
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
                    "artifact id={} package={} name={} role={} kind={} profile={} artifact_hash={} abi={} binding={} code_hash={} exports={} hostcalls={} caps={}",
                    artifact.id,
                    artifact.package,
                    artifact.artifact_name,
                    artifact.role,
                    artifact.kind,
                    artifact.target_profile,
                    artifact.artifact_hash,
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
                    "trap id={} class={} store={}@{} activation={}@{} code={}@{} artifact={}@{} pc={} offset={} trap_kind={} hostcall={} policy={} effect={} detail={}",
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
                    display_option_u64(trap.target_pc),
                    display_option_u64(trap.offset),
                    trap.trap_kind.as_deref().unwrap_or("none"),
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
                    "hostcall abi={} frame_size={} seq={} caller_offset={} record_mode={} activation={} activation_generation={} store={} store_generation={} code={} code_generation={} artifact={} artifact_generation={} number={} name={} category={} subject={} object={} op={} cap_args=[{}] allowed={} result={} ret={} trap_out={} trap_generation_out={} wait_out={} wait_generation_out={}",
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
                    trace.artifact_generation,
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
                    display_option_u64(trace.trap_generation_out),
                    display_option_u64(trace.wait_token_out),
                    display_option_u64(trace.wait_token_generation_out)
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
                let target_store_generation = if cleanup.target_store_generation == 0 {
                    cleanup.store_generation
                } else {
                    cleanup.target_store_generation
                };
                let result_store_generation = display_option_u64(cleanup.result_store_generation);
                let steps = cleanup
                    .steps
                    .iter()
                    .map(|step| format!("{}:{}:{}", step.step, step.state, step.detail))
                    .collect::<Vec<_>>()
                    .join("|");
                let line = format!(
                    "cleanup id={} target_store={}@{} result_store={}@{} activation={}@{} code={}@{} generation={} state={} reason={} released_dmw={} cancelled_waits={} revoked_caps={} dropped_resources={} unbound_code={} effect={} steps={}",
                    cleanup.id,
                    cleanup.store,
                    target_store_generation,
                    cleanup.store,
                    result_store_generation,
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
        "command" => {
            println!(
                "inspect command package={} count={}",
                package.package_id, package.semantic.command_result_count
            );
            for result in &package.semantic.command_results {
                let line = format!(
                    "command id={} issuer={} name={} status={} events={} effects={} violations={}",
                    result.id,
                    result.issuer,
                    result.command,
                    result.status,
                    result.events.len(),
                    result.effects.len(),
                    result.violations.join("|")
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.command_results.is_empty() {
                print_roots_filtered(
                    "command",
                    &package.semantic.roots.command_result_roots,
                    filter,
                );
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
                .map(artifact_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.target_artifact_roots.len() }),
        ),
        "code" => (
            "code",
            package.semantic.code_object_count,
            package
                .semantic
                .code_objects
                .iter()
                .map(code_object_view_v1)
                .collect::<Vec<_>>(),
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
                .map(activation_view_v1)
                .collect::<Vec<_>>(),
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
                .map(trap_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.trap_roots.len() }),
        ),
        "hostcall" => (
            "hostcall",
            package.semantic.hostcall_trace_count,
            package
                .semantic
                .hostcall_trace
                .iter()
                .map(hostcall_trace_view_v1)
                .collect::<Vec<_>>(),
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
        "command" => (
            "command",
            package.semantic.command_result_count,
            package
                .semantic
                .command_results
                .iter()
                .map(command_result_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.command_result_roots.len() }),
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
                    "artifact package={} name={} role={} target_artifact={} target_hash={} payload={} cwasm={} hash={} abi={} binding={} caps={} exports={}",
                    module.package,
                    module.artifact_name,
                    module.role,
                    module.target_artifact_path,
                    module.target_artifact_sha256,
                    module.code_payload_format,
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
                        "target_artifact_path": &module.target_artifact_path,
                        "target_artifact_sha256": &module.target_artifact_sha256,
                        "code_payload_format": &module.code_payload_format,
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
        "replay roots: tasks={} resources={} authorities={} stores={} caps={} target_stores={} target_caps={} boundaries={} artifacts={} activations={} executor_transitions={} target_artifacts={} code_objects={} activation_records={} traps={} hostcalls={} migration_objects={} substrate_events={} command_results={} interface_events={} event_tail={}",
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
        package.semantic.roots.substrate_event_roots.len(),
        package.semantic.roots.command_result_roots.len(),
        package.semantic.roots.interface_event_roots.len(),
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
            "substrate_events": package.semantic.roots.substrate_event_roots.len(),
            "command_results": package.semantic.roots.command_result_roots.len(),
            "interface_events": package.semantic.roots.interface_event_roots.len(),
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
            "replay_validation_roots": &package.semantic.roots.replay_validation_roots,
            "substrate_event_roots": &package.semantic.roots.substrate_event_roots,
            "command_result_roots": &package.semantic.roots.command_result_roots,
            "interface_event_roots": &package.semantic.roots.interface_event_roots
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
        "semantic roots: tasks={} resources={} authorities={}/{} waits={} capabilities={} stores={} fastpath={}/{} boundaries={} artifacts={} activations={} executor_transitions={} target_artifacts={} code_objects={} activation_records={} traps={} hostcalls={} migration_objects={} substrate_events={} command_results={} interface_events={}",
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
    print_roots(
        "substrate-event",
        &package.semantic.roots.substrate_event_roots,
    );
    print_roots(
        "command-result",
        &package.semantic.roots.command_result_roots,
    );
    print_roots(
        "interface-event",
        &package.semantic.roots.interface_event_roots,
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
    fn preemptive_runtime_views_expose_task_activation_and_scheduler_state() {
        let task = task_view_v1(&TaskRecordManifest {
            id: 7,
            label: "linux-thread-7".to_owned(),
            frontend: "linux-elf".to_owned(),
            state: "runnable".to_owned(),
            generation: 1,
            fault_domain: None,
            pending_wait: None,
            resources: vec![3],
        });
        assert_eq!(task["kind"], "task");
        assert_eq!(task["owner"]["frontend"], "linux-elf");
        assert_eq!(task["references"]["resources"][0], 3);

        let activation = runtime_activation_view_v1(&RuntimeActivationRecordManifest {
            id: 11,
            owner_task: 7,
            owner_task_generation: 1,
            owner_store: None,
            owner_store_generation: None,
            code_object: Some(ContractObjectRefManifest {
                kind: "code-object".to_owned(),
                id: 4,
                generation: 1,
            }),
            generation: 2,
            state: "runnable".to_owned(),
            runnable_queue: Some(1),
            runnable_queue_generation: Some(1),
            last_event: Some(9),
        });
        assert_eq!(activation["kind"], "activation");
        assert_eq!(activation["owner"]["task"], 7);
        assert_eq!(activation["owner"]["task_generation"], 1);
        assert_eq!(activation["references"]["runnable_queue"]["id"], 1);
        assert_eq!(activation["references"]["runnable_queue"]["generation"], 1);

        let mut package = minimal_graph_package();
        package.package_id = "p0-test".to_owned();
        package.substrate_boundary.scheduler_decision_cursor = 12;
        package.semantic.task_record_count = 1;
        package.semantic.runtime_activation_count = 1;
        package.semantic.runnable_queue_count = 1;
        package.semantic.task_records.push(TaskRecordManifest {
            id: 7,
            label: "linux-thread-7".to_owned(),
            frontend: "linux-elf".to_owned(),
            state: "runnable".to_owned(),
            generation: 1,
            fault_domain: None,
            pending_wait: None,
            resources: Vec::new(),
        });
        package
            .semantic
            .runtime_activation_records
            .push(RuntimeActivationRecordManifest {
                id: 11,
                owner_task: 7,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
                generation: 2,
                state: "runnable".to_owned(),
                runnable_queue: Some(1),
                runnable_queue_generation: Some(1),
                last_event: Some(9),
            });
        package
            .semantic
            .runnable_queues
            .push(RunnableQueueManifest {
                id: 1,
                label: "main-rq".to_owned(),
                generation: 1,
                state: "active".to_owned(),
                entries: vec![artifact_manifest::RunnableQueueEntryManifest {
                    activation: 11,
                    activation_generation: 2,
                    enqueued_at: 9,
                }],
            });
        let scheduler = scheduler_view_v1(&package);
        assert_eq!(scheduler["kind"], "scheduler");
        assert_eq!(scheduler["references"]["queues"][0]["entries"], 1);
        assert_eq!(
            scheduler["last_transition"]["scheduler_decision_cursor"],
            12
        );

        let edges = live_graph_edges(&package);
        assert!(edges.iter().any(|edge| edge["from"]["kind"] == "task"
            && edge["from"]["generation"] == 1
            && edge["to"]["kind"] == "activation"
            && edge["to"]["generation"] == 2));
        assert!(edges.iter().any(|edge| edge["from"]["kind"] == "activation"
            && edge["to"]["kind"] == "runnable-queue"
            && edge["to"]["generation"] == 1));
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
            target_store_generation: 1,
            result_store_generation: Some(2),
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
        assert_eq!(view["references"]["target_store"]["generation"], 1);
        assert_eq!(view["references"]["result_store"]["generation"], 2);
        assert_eq!(view["references"]["revoked_capabilities"][0]["id"], 4);
    }

    #[test]
    fn executor_object_views_do_not_dump_internal_schema() {
        let artifact = artifact_view_v1(&TargetArtifactImageManifest {
            id: 2,
            package: "driver_virtio_net".to_owned(),
            artifact_name: "driver_virtio_net".to_owned(),
            role: "driver".to_owned(),
            kind: "target-artifact-image-v1".to_owned(),
            target_profile: "host-validation".to_owned(),
            artifact_hash: "artifact".to_owned(),
            abi_fingerprint: "abi".to_owned(),
            manifest_binding_hash: "binding".to_owned(),
            code_hash: "code".to_owned(),
            exports: vec!["memory".to_owned()],
            payload_len: 4096,
            ..TargetArtifactImageManifest::default()
        });
        assert_eq!(artifact["schema"], VIEW_SCHEMA_V1);
        assert_eq!(artifact["kind"], "artifact");
        assert_eq!(artifact["state"], "verified");
        assert_eq!(artifact["references"]["artifact_hash"], "artifact");
        assert_eq!(artifact["references"]["manifest_binding_hash"], "binding");
        assert_eq!(artifact["last_transition"]["payload_len"], 4096);

        let code = code_object_view_v1(&CodeObjectManifest {
            id: 3,
            artifact_id: 2,
            package: "driver_virtio_net".to_owned(),
            owner_profile: "host-validation".to_owned(),
            generation: 4,
            state: "bound-to-store".to_owned(),
            bound_store: Some(1),
            bound_store_generation: Some(7),
            text_start: 0x1000,
            text_len: 128,
            text_permission: "rx".to_owned(),
            code_hash: "code".to_owned(),
            ..CodeObjectManifest::default()
        });
        assert_eq!(code["kind"], "code-object");
        assert_eq!(code["generation"], 4);
        assert_eq!(code["references"]["bound_store"]["generation"], 7);
        assert_eq!(code["memory"]["text"]["permission"], "rx");
    }

    #[test]
    fn trace_views_expose_attribution_generations() {
        let activation = activation_view_v1(&ActivationRecordManifest {
            id: 10,
            store: 1,
            store_generation: 2,
            code_object: 3,
            code_generation: 4,
            artifact: 5,
            entry: "_start".to_owned(),
            generation: 6,
            state: "running".to_owned(),
            start_event: 7,
            active_dmw_leases: 1,
            ..ActivationRecordManifest::default()
        });
        assert_eq!(activation["kind"], "activation");
        assert_eq!(activation["owner"]["store_generation"], 2);
        assert_eq!(activation["references"]["code_object"]["generation"], 4);

        let trap = trap_view_v1(&TrapRecordManifest {
            id: 11,
            generation: 1,
            class: "capability-trap".to_owned(),
            store: Some(1),
            store_generation: Some(2),
            activation: Some(10),
            activation_generation: Some(6),
            code_object: Some(3),
            code_generation: Some(4),
            artifact: Some(5),
            artifact_generation: Some(1),
            fault_policy: "restart".to_owned(),
            effect: "cleanup".to_owned(),
            detail: "denied".to_owned(),
            ..TrapRecordManifest::default()
        });
        assert_eq!(trap["kind"], "trap");
        assert_eq!(trap["owner"]["activation_generation"], 6);
        assert_eq!(trap["references"]["code_object"]["generation"], 4);
        assert_eq!(trap["last_error"], "denied");

        let hostcall = hostcall_trace_view_v1(&HostcallTraceManifest {
            id: 12,
            generation: 1,
            abi_version: "vmos-target-hostcall-frame-v1".to_owned(),
            frame_size: 128,
            activation: 10,
            activation_generation: 6,
            store: 1,
            store_generation: 2,
            code_object: 3,
            code_generation: 4,
            artifact: 5,
            artifact_generation: 7,
            hostcall_number: 64,
            hostcall_seq: 99,
            caller_offset: 16,
            name: "mmio.read32".to_owned(),
            category: "mmio".to_owned(),
            object: "mmio.bar0".to_owned(),
            operation: "read32".to_owned(),
            allowed: false,
            result: "trap".to_owned(),
            ..HostcallTraceManifest::default()
        });
        assert_eq!(hostcall["kind"], "hostcall");
        assert_eq!(hostcall["owner"]["activation_generation"], 6);
        assert_eq!(hostcall["references"]["artifact"]["generation"], 7);
        assert_eq!(hostcall["call"]["caller_offset"], 16);
        assert_eq!(hostcall["last_error"], "hostcall-denied");
    }

    #[test]
    fn substrate_event_view_v1_explains_unsupported_authority() {
        let view = substrate_event_view_v1(&SubstrateEventManifest {
            id: 21,
            epoch: 34,
            event_kind: "unsupported".to_owned(),
            authority: "DmaAuthority".to_owned(),
            operation: "dma_alloc".to_owned(),
            requester: Some("driver.fake_net".to_owned()),
            artifact: Some(9),
            store: Some(4),
            capability: None,
            explanation: "driver.fake_net observed DmaAuthority::dma_alloc as unsupported"
                .to_owned(),
        });
        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "substrate-event");
        assert_eq!(view["id"], 21);
        assert_eq!(view["state"], "unsupported");
        assert_eq!(view["authority"], "DmaAuthority");
        assert_eq!(view["operation"], "dma_alloc");
        assert_eq!(view["requester"], "driver.fake_net");
        assert_eq!(view["references"]["artifact"], 9);
        assert_eq!(view["references"]["store"], 4);
        assert_eq!(view["references"]["event_epoch"], 34);
        assert_eq!(
            view["last_error"],
            "driver.fake_net observed DmaAuthority::dma_alloc as unsupported"
        );
    }

    #[test]
    fn command_result_view_v1_exposes_status_events_and_violations() {
        let view = command_result_view_v1(&CommandResultManifest {
            id: 5,
            issuer: "target-executor-command-probe".to_owned(),
            command: "create-wait".to_owned(),
            status: "rejected".to_owned(),
            events: Vec::new(),
            effects: Vec::new(),
            violations: vec!["create-wait requires owner task or owner store".to_owned()],
        });
        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "command");
        assert_eq!(view["id"], 5);
        assert_eq!(view["state"], "rejected");
        assert_eq!(view["issuer"], "target-executor-command-probe");
        assert_eq!(view["command_name"], "create-wait");
        assert_eq!(view["last_transition"]["event_count"], 0);
        assert_eq!(
            view["last_error"],
            "create-wait requires owner task or owner store"
        );
    }

    #[test]
    fn interface_event_view_v1_explains_unsupported_interface() {
        let view = interface_event_view_v1(&InterfaceEventManifest {
            id: 8,
            epoch: 13,
            interface_kind: "standard-wasi".to_owned(),
            interface: "wasi:clocks/monotonic-clock".to_owned(),
            operation: "subscribe".to_owned(),
            requester: Some("target-executor-interface-probe".to_owned()),
            artifact: None,
            store: None,
            explanation:
                "target-executor-interface-probe observed standard-wasi wasi:clocks/monotonic-clock::subscribe as unsupported"
                    .to_owned(),
        });
        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "interface-event");
        assert_eq!(view["state"], "unsupported");
        assert_eq!(view["interface_kind"], "standard-wasi");
        assert_eq!(view["interface"], "wasi:clocks/monotonic-clock");
        assert_eq!(view["operation"], "subscribe");
        assert_eq!(view["references"]["event_epoch"], 13);
        assert_eq!(
            view["last_error"],
            "target-executor-interface-probe observed standard-wasi wasi:clocks/monotonic-clock::subscribe as unsupported"
        );
    }

    #[test]
    fn graph_json_edges_separate_live_history_and_cleanup_modes() {
        let mut package = minimal_graph_package();
        package
            .semantic
            .activation_records
            .push(ActivationRecordManifest {
                id: 10,
                store: 1,
                store_generation: 2,
                code_object: 3,
                code_generation: 4,
                artifact: 5,
                entry: "_start".to_owned(),
                generation: 6,
                state: "running".to_owned(),
                start_event: 7,
                ..ActivationRecordManifest::default()
            });
        package.semantic.code_objects.push(CodeObjectManifest {
            id: 3,
            artifact_id: 5,
            package: "driver".to_owned(),
            owner_profile: "host-validation".to_owned(),
            generation: 4,
            state: "bound-to-store".to_owned(),
            bound_store: Some(1),
            bound_store_generation: Some(2),
            ..CodeObjectManifest::default()
        });
        package
            .semantic
            .capability_records
            .push(CapabilityRecordManifest {
                id: 20,
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
                owner_store_generation: Some(2),
                source: "test".to_owned(),
                generation: 1,
                manifest_decl: true,
                ..CapabilityRecordManifest::default()
            });
        package.semantic.wait_records.push(WaitRecordManifest {
            id: 30,
            owner_store: Some(1),
            owner_store_generation: Some(2),
            kind: "device-irq".to_owned(),
            generation: 1,
            state: "pending".to_owned(),
            blockers: vec![ContractObjectRefManifest {
                kind: "capability".to_owned(),
                id: 20,
                generation: 1,
            }],
            restart_policy: "restart-if-allowed".to_owned(),
            ..WaitRecordManifest::default()
        });
        package.semantic.trap_records.push(TrapRecordManifest {
            id: 40,
            generation: 1,
            class: "capability-trap".to_owned(),
            store: Some(1),
            store_generation: Some(2),
            activation: Some(10),
            activation_generation: Some(6),
            code_object: Some(3),
            code_generation: Some(4),
            artifact: Some(5),
            artifact_generation: Some(1),
            fault_policy: "restart".to_owned(),
            effect: "cleanup".to_owned(),
            detail: "denied".to_owned(),
            ..TrapRecordManifest::default()
        });
        package.semantic.hostcall_trace.push(HostcallTraceManifest {
            id: 50,
            generation: 1,
            activation: 10,
            activation_generation: 6,
            store: 1,
            store_generation: 2,
            code_object: 3,
            code_generation: 4,
            artifact: 5,
            artifact_generation: 7,
            hostcall_number: 1,
            name: "hostcall.packet-device.net0.rx".to_owned(),
            category: "packet-device".to_owned(),
            object: "packet-device.net0".to_owned(),
            operation: "rx".to_owned(),
            allowed: true,
            result: "complete".to_owned(),
            trap_out: Some(40),
            trap_generation_out: Some(1),
            ..HostcallTraceManifest::default()
        });
        package
            .semantic
            .cleanup_transactions
            .push(CleanupTransactionManifest {
                id: 60,
                store: 1,
                store_generation: 2,
                target_store_generation: 2,
                activation: Some(10),
                activation_generation: Some(6),
                code_object: Some(3),
                code_generation: Some(4),
                generation: 1,
                started_at: 8,
                finished_at: Some(9),
                state: "completed".to_owned(),
                reason: "fault".to_owned(),
                released_dmw_leases: 0,
                cancelled_waits: 1,
                revoked_capabilities: vec![20],
                revoked_capability_refs: vec![ContractObjectRefManifest {
                    kind: "capability".to_owned(),
                    id: 20,
                    generation: 1,
                }],
                dropped_resources: 0,
                unbound_code_object: true,
                effect: "restart".to_owned(),
                steps: Vec::new(),
                effects: Vec::new(),
                result_store_generation: Some(3),
            });

        let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "owns"
            && edge["to"]["kind"] == "activation"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "authorizes"
            && edge["to"]["kind"] == "resource"));

        let history = graph_edges_for_package(&package, GraphEdgeMode::History);
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["from"]["kind"] == "hostcall"
            && edge["to"]["kind"] == "activation"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["from"]["kind"] == "hostcall"
            && edge["to"]["kind"] == "artifact"
            && edge["to"]["generation"] == 7));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["from"]["kind"] == "hostcall"
            && edge["relation"] == "caused"
            && edge["to"]["kind"] == "trap"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
            && edge["relation"] == "revoked"
            && edge["to"]["kind"] == "capability"));
    }

    fn minimal_graph_package() -> MigrationPackageManifest {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "package_format": "vmos-semantic-package-v1",
            "package_id": "graph-test",
            "source": { "arch": "x86_64" },
            "target": { "arch_requirement": "target-native" },
            "required_artifact_profile": {
                "artifact_profile": "host-validation",
                "target_arch": "target-native",
                "machine_abi_version": "test",
                "supervisor_abi_version": "test",
                "wasm_feature_profile": "test",
                "memory64": false,
                "multi_memory": false,
                "dmw_layout": "logical",
                "network_contract_version": "test",
                "compiler_engine": "wasmtime",
                "compiler_execution_mode": "precompiled-core-module",
                "artifact_format": "target-artifact-image-v1",
                "runtime_executor_abi": "vmos-runtime-only-executor-v0"
            },
            "guest": {
                "canonical_isa": "riscv64",
                "register_count": 33,
                "memory_page_count": 0,
                "vma_count": 0,
                "signal_queue_count": 0,
                "note": "test"
            },
            "semantic": {
                "barrier_id": 1,
                "event_log_cursor": 0,
                "task_count": 0,
                "resource_count": 0,
                "wait_token_count": 0,
                "capability_count": 0,
                "fault_domain_count": 0
            },
            "logical_capabilities": [],
            "substrate_boundary": {
                "timer_epoch": 0,
                "pending_irq_causes": 0,
                "pending_dma_completions": 0,
                "active_dmw_lease_count": 0,
                "active_mmio_authority_count": 0,
                "active_dma_authority_count": 0,
                "active_irq_authority_count": 0,
                "active_packet_device_authority_count": 0,
                "active_virtio_queue_authority_count": 0,
                "pending_network_inputs": 0,
                "random_epoch": 0,
                "scheduler_decision_cursor": 0,
                "cow_epoch": 0,
                "background_copy_pages": 0,
                "native_state_policy": "test"
            },
            "not_migrated": []
        }))
        .expect("minimal graph package")
    }

    #[test]
    fn substrate_profile_selection_is_stable_for_json_checks() {
        let host = substrate_capabilities_for_profile("host-validation").expect("host profile");
        let semantic =
            substrate_capabilities_for_profile("semantic-harness").expect("semantic profile");

        assert!(host.artifact_loading);
        assert_eq!(host.dmw.as_str(), "logical");
        assert!(host.mmio);
        assert_eq!(host.snapshot.as_str(), "deterministic-replay");
        assert!(!semantic.artifact_loading);
        assert_eq!(semantic.dma.as_str(), "none");
        assert!(substrate_capabilities_for_profile("unknown-profile").is_none());
    }

    #[test]
    fn interface_profile_selection_is_stable_for_json_checks() {
        let host = interface_capabilities_for_profile("host-validation").expect("host profile");
        let none = interface_capabilities_for_profile("none").expect("none profile");

        assert!(
            host.custom_wit_worlds
                .iter()
                .any(|world| world == "semantic:machine")
        );
        assert!(none.custom_wit_worlds.is_empty());
        assert!(interface_capabilities_for_profile("unknown-profile").is_none());
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

    #[test]
    fn target_runtime_cwasm_golden_traces_parse() {
        for source in [
            include_str!(
                "../../tests/golden/target-runtime/cwasm_payload_loaded_as_target_artifact.trace.json"
            ),
            include_str!(
                "../../tests/golden/target-runtime/cwasm_host_validation_export_smoke.trace.json"
            ),
            include_str!(
                "../../tests/golden/target-runtime/cwasm_host_validation_trap_visible.trace.json"
            ),
        ] {
            let value: serde_json::Value =
                serde_json::from_str(source).expect("target-runtime golden trace JSON");
            assert_eq!(value["schema"], "vmos-golden-trace");
            assert!(
                value["contract_refs"]
                    .as_array()
                    .expect("contract_refs")
                    .len()
                    > 0
            );
            assert!(value["events"].as_array().expect("events").len() > 0);
            assert!(value["validation"]["ok"].as_bool().expect("validation ok"));
        }
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
