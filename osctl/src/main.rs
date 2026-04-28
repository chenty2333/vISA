#![recursion_limit = "256"]

use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

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
    IntegratedSmpPreemptionCleanupManifest, InterfaceEventManifest, IoCleanupManifest,
    IoFaultInjectionManifest, IoValidationReportManifest, IoWaitManifest, IpiEventManifest,
    IrqEventManifest, IrqLineObjectManifest, MigrationPackageManifest, MmioRegionObjectManifest,
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
        "hart"
        | "task"
        | "store"
        | "cap"
        | "capability"
        | "wait"
        | "cleanup"
        | "command"
        | "scheduler"
        | "runtime-activation"
        | "runnable-queue"
        | "activation-context"
        | "saved-context"
        | "timer-interrupt"
        | "ipi-event"
        | "ipi"
        | "remote-preempt"
        | "remote-park"
        | "preemption"
        | "scheduler-decision"
        | "cross-hart-scheduler-decision"
        | "activation-migration"
        | "smp-safe-point"
        | "safepoint"
        | "stop-the-world-rendezvous"
        | "stop-the-world"
        | "stw"
        | "smp-code-publish-barrier"
        | "code-publish-barrier"
        | "publish-barrier"
        | "smp-cleanup-quiescence"
        | "cleanup-quiescence"
        | "smp-snapshot-barrier"
        | "snapshot-barrier"
        | "smp-stress-run"
        | "smp-stress"
        | "smp-scaling-benchmark"
        | "smp-scaling"
        | "integrated-smp-preemption-cleanup"
        | "integrated-smp-cleanup"
        | "smp-preemption-cleanup"
        | "device"
        | "device-object"
        | "queue"
        | "queue-object"
        | "descriptor"
        | "descriptor-object"
        | "dma-buffer"
        | "dma-buffer-object"
        | "mmio-region"
        | "mmio-region-object"
        | "irq-line"
        | "irq-line-object"
        | "irq-event"
        | "device-capability"
        | "io-capability"
        | "driver-store-binding"
        | "driver-binding"
        | "io-wait"
        | "io-wait-token"
        | "io-cleanup"
        | "io-fault"
        | "io-fault-injection"
        | "io-validation"
        | "io-validation-report"
        | "io-validator"
        | "packet-device"
        | "packet-device-object"
        | "net-device"
        | "packet-buffer"
        | "packet-buffer-object"
        | "packet-queue"
        | "packet-queue-object"
        | "rx-queue"
        | "tx-queue"
        | "packet-descriptor"
        | "packet-descriptor-object"
        | "fake-net-backend"
        | "fake-net-backend-object"
        | "virtio-net-backend"
        | "virtio-net-backend-object"
        | "network-rx-interrupt"
        | "rx-interrupt"
        | "network-rx-wait-resolution"
        | "rx-wait-resolution"
        | "network-tx-capability-gate"
        | "tx-capability-gate"
        | "network-tx-completion"
        | "tx-completion"
        | "network-stack-adapter"
        | "smoltcp-adapter"
        | "socket-object"
        | "socket"
        | "endpoint-object"
        | "endpoint"
        | "socket-operation"
        | "socket-op"
        | "socket-wait"
        | "socket-wait-token"
        | "network-backpressure"
        | "backpressure"
        | "drop-policy"
        | "network-driver-cleanup"
        | "network-cleanup"
        | "network-generation-audit"
        | "generation-audit"
        | "stale-generation-audit"
        | "network-fault-injection"
        | "packet-loss"
        | "packet-error"
        | "network-benchmark"
        | "network-throughput"
        | "network-latency"
        | "network-recovery-benchmark"
        | "network-recovery"
        | "block-device"
        | "block-device-object"
        | "block"
        | "block-range"
        | "block-range-object"
        | "sector-range"
        | "block-request"
        | "block-request-object"
        | "block-completion"
        | "block-completion-object"
        | "block-wait"
        | "block-wait-token"
        | "fake-block-backend"
        | "fake-block-backend-object"
        | "virtio-blk-backend"
        | "virtio-blk-backend-object"
        | "block-read-path"
        | "block-read"
        | "block-write-path"
        | "block-write"
        | "block-request-queue"
        | "block-queue"
        | "block-dma-buffer"
        | "block-buffer"
        | "block-page-object"
        | "block-page"
        | "buffer-cache-object"
        | "buffer-cache"
        | "fs-cache"
        | "file-object"
        | "directory-object"
        | "directory"
        | "fat-adapter-object"
        | "fat-adapter"
        | "ext4-adapter-object"
        | "ext4-adapter"
        | "file-handle-capability"
        | "file-handle"
        | "file-capability"
        | "fs-wait"
        | "filesystem-wait"
        | "file-wait"
        | "block-driver-cleanup"
        | "disk-driver-cleanup"
        | "disk-cleanup"
        | "block-pending-io-policy"
        | "pending-block-io"
        | "pending-io-policy"
        | "block-request-generation-audit"
        | "stale-block-request-generation"
        | "block-generation-audit"
        | "block-benchmark"
        | "disk-benchmark"
        | "block-iops"
        | "block-recovery-benchmark"
        | "disk-recovery-benchmark"
        | "disk-recovery"
        | "target-feature-set"
        | "target-feature"
        | "target-feature-set-object"
        | "vector-state"
        | "vector"
        | "simd-vector-state"
        | "simd-fault-injection"
        | "simd-fault"
        | "simd-benchmark"
        | "simd-scalar-vector-benchmark"
        | "simd-context-switch-benchmark"
        | "simd-context-switch"
        | "simd-switch-benchmark"
        | "framebuffer-object"
        | "framebuffer"
        | "fb"
        | "display-object"
        | "display"
        | "display-mode"
        | "display-capability"
        | "display-cap"
        | "framebuffer-window-lease"
        | "fb-window-lease"
        | "display-lease"
        | "framebuffer-mapping"
        | "fb-mapping"
        | "display-mapping"
        | "framebuffer-write"
        | "fb-write"
        | "display-write"
        | "framebuffer-flush-region"
        | "flush-region"
        | "display-flush"
        | "framebuffer-dirty-region"
        | "dirty-region"
        | "display-dirty"
        | "display-event-log"
        | "display-log"
        | "display-cleanup"
        | "display-snapshot-barrier"
        | "display-snapshot"
        | "display-panic-last-frame"
        | "panic-last-frame"
        | "framebuffer-benchmark"
        | "fb-benchmark"
        | "display-benchmark"
        | "file"
        | "activation-resume"
        | "activation-wait"
        | "activation-cleanup"
        | "preemption-latency"
        | "hart-event"
        | "hart-event-attribution"
        | "context" => handle_view_command(&command, args.collect()),
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
        "  osctl hart|task|activation|activation-context|saved-context|timer-interrupt|ipi-event|remote-preempt|remote-park|preemption|scheduler-decision|cross-hart-scheduler-decision|activation-migration|smp-safe-point|safepoint|stop-the-world-rendezvous|stop-the-world|stw|smp-code-publish-barrier|smp-cleanup-quiescence|smp-snapshot-barrier|smp-stress-run|smp-scaling-benchmark|integrated-smp-preemption-cleanup|device|queue|descriptor|dma-buffer|mmio-region|irq-line|irq-event|device-capability|driver-store-binding|io-wait|io-cleanup|io-fault-injection|io-validation-report|packet-device|packet-buffer|packet-queue|packet-descriptor|fake-net-backend|virtio-net-backend|network-rx-interrupt|network-rx-wait-resolution|network-tx-capability-gate|network-tx-completion|network-stack-adapter|socket-object|endpoint-object|socket-operation|socket-wait|network-backpressure|network-driver-cleanup|network-generation-audit|network-fault-injection|network-benchmark|network-recovery-benchmark|block-device|block-range|block-request|block-completion|block-wait|fake-block-backend|virtio-blk-backend|block-read-path|block-write-path|block-request-queue|block-dma-buffer|block-page-object|buffer-cache-object|fs-cache|file-object|file|directory-object|directory|fat-adapter-object|fat-adapter|ext4-adapter-object|ext4-adapter|file-handle-capability|file-handle|fs-wait|block-driver-cleanup|block-pending-io-policy|block-request-generation-audit|block-benchmark|block-recovery-benchmark|target-feature-set|vector-state|simd-fault-injection|simd-benchmark|simd-context-switch-benchmark|framebuffer-object|framebuffer|display-object|display|display-capability|display-cap|framebuffer-window-lease|fb-window-lease|display-lease|framebuffer-mapping|fb-mapping|display-mapping|framebuffer-write|fb-write|display-write|framebuffer-flush-region|flush-region|display-flush|framebuffer-dirty-region|dirty-region|display-dirty|display-event-log|display-log|display-cleanup|display-snapshot-barrier|display-panic-last-frame|framebuffer-benchmark|activation-resume|activation-wait|activation-cleanup|preemption-latency|hart-event|scheduler|runnable-queue|store|cap|wait|cleanup|command list --json <migration.json>"
    );
    eprintln!("  osctl store|cap|wait|cleanup|command show --json <migration.json> <id>");
    eprintln!("  osctl state <manifest-or-migration.json>");
    eprintln!("  osctl graph [--live|--history] [--json] <migration.json>");
    eprintln!("  osctl activation [--blocked] <migration.json>");
    eprintln!("  osctl event-log tail <migration.json>");
    eprintln!(
        "  osctl inspect artifact|code|store|activation|capability|wait|trap|hostcall|tombstone|contract|cleanup|file-handle-capability|fs-wait|block-driver-cleanup|block-pending-io-policy|block-request-generation-audit|block-benchmark|block-recovery-benchmark|target-feature-set|vector-state|simd-fault-injection|simd-benchmark|simd-context-switch-benchmark|framebuffer-object|display-object|display-capability|framebuffer-window-lease|framebuffer-mapping|framebuffer-write|framebuffer-flush-region|framebuffer-dirty-region|display-event-log|display-cleanup|display-snapshot-barrier|display-panic-last-frame|framebuffer-benchmark|integrated-smp-preemption-cleanup|memory-policy|snapshot-validation|replay-validation|event [--json] <manifest-or-migration.json> [filter]"
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
        "hart" => "hart",
        "task" => "task",
        "activation" | "runtime-activation" => "activation",
        "activation-context" | "context" => "activation-context",
        "saved-context" => "saved-context",
        "timer-interrupt" => "timer-interrupt",
        "ipi" | "ipi-event" => "ipi-event",
        "remote-preempt" => "remote-preempt",
        "remote-park" => "remote-park",
        "preemption" => "preemption",
        "scheduler-decision" => "scheduler-decision",
        "cross-hart-scheduler-decision" => "cross-hart-scheduler-decision",
        "activation-migration" => "activation-migration",
        "smp-safe-point" | "safepoint" => "smp-safe-point",
        "stop-the-world-rendezvous" | "stop-the-world" | "stw" => "stop-the-world-rendezvous",
        "smp-code-publish-barrier" | "code-publish-barrier" | "publish-barrier" => {
            "smp-code-publish-barrier"
        }
        "smp-cleanup-quiescence" | "cleanup-quiescence" => "smp-cleanup-quiescence",
        "smp-snapshot-barrier" | "snapshot-barrier" => "smp-snapshot-barrier",
        "smp-stress-run" | "smp-stress" => "smp-stress-run",
        "smp-scaling-benchmark" | "smp-scaling" => "smp-scaling-benchmark",
        "device" | "device-object" => "device",
        "queue" | "queue-object" => "queue",
        "descriptor" | "descriptor-object" => "descriptor",
        "dma-buffer" | "dma-buffer-object" => "dma-buffer",
        "mmio-region" | "mmio-region-object" => "mmio-region",
        "irq-line" | "irq-line-object" => "irq-line",
        "irq-event" => "irq-event",
        "device-capability" | "io-capability" => "device-capability",
        "driver-store-binding" | "driver-binding" => "driver-store-binding",
        "io-wait" | "io-wait-token" => "io-wait",
        "io-cleanup" => "io-cleanup",
        "io-fault" | "io-fault-injection" => "io-fault-injection",
        "io-validation" | "io-validation-report" | "io-validator" => "io-validation-report",
        "packet-device" | "packet-device-object" | "net-device" => "packet-device",
        "packet-buffer" | "packet-buffer-object" => "packet-buffer",
        "packet-queue" | "packet-queue-object" | "rx-queue" | "tx-queue" => "packet-queue",
        "packet-descriptor" | "packet-descriptor-object" => "packet-descriptor",
        "fake-net-backend" | "fake-net-backend-object" => "fake-net-backend",
        "virtio-net-backend" | "virtio-net-backend-object" => "virtio-net-backend",
        "network-rx-interrupt" | "rx-interrupt" => "network-rx-interrupt",
        "network-rx-wait-resolution" | "rx-wait-resolution" => "network-rx-wait-resolution",
        "network-tx-capability-gate" | "tx-capability-gate" => "network-tx-capability-gate",
        "network-tx-completion" | "tx-completion" => "network-tx-completion",
        "network-stack-adapter" | "smoltcp-adapter" => "network-stack-adapter",
        "socket-object" | "socket" => "socket-object",
        "endpoint-object" | "endpoint" => "endpoint-object",
        "socket-operation" | "socket-op" => "socket-operation",
        "socket-wait" | "socket-wait-token" => "socket-wait",
        "network-backpressure" | "backpressure" | "drop-policy" => "network-backpressure",
        "network-driver-cleanup" | "network-cleanup" => "network-driver-cleanup",
        "network-generation-audit" | "generation-audit" | "stale-generation-audit" => {
            "network-generation-audit"
        }
        "network-fault-injection" | "packet-loss" | "packet-error" => "network-fault-injection",
        "network-benchmark" | "network-throughput" | "network-latency" => "network-benchmark",
        "network-recovery-benchmark" | "network-recovery" => "network-recovery-benchmark",
        "block-device" | "block-device-object" | "block" => "block-device",
        "block-range" | "block-range-object" | "sector-range" => "block-range",
        "block-request" | "block-request-object" => "block-request",
        "block-completion" | "block-completion-object" => "block-completion",
        "block-wait" | "block-wait-token" => "block-wait",
        "fake-block-backend" | "fake-block-backend-object" => "fake-block-backend",
        "virtio-blk-backend" | "virtio-blk-backend-object" => "virtio-blk-backend",
        "block-read-path" | "block-read" => "block-read-path",
        "block-write-path" | "block-write" => "block-write-path",
        "block-request-queue" | "block-queue" => "block-request-queue",
        "block-dma-buffer" | "block-buffer" => "block-dma-buffer",
        "block-page-object" | "block-page" => "block-page-object",
        "buffer-cache-object" | "buffer-cache" | "fs-cache" => "buffer-cache-object",
        "file-object" | "file" => "file-object",
        "directory-object" | "directory" => "directory-object",
        "fat-adapter-object" | "fat-adapter" => "fat-adapter-object",
        "ext4-adapter-object" | "ext4-adapter" => "ext4-adapter-object",
        "file-handle-capability" | "file-handle" | "file-capability" => "file-handle-capability",
        "fs-wait" | "filesystem-wait" | "file-wait" => "fs-wait",
        "block-driver-cleanup" | "disk-driver-cleanup" | "disk-cleanup" => "block-driver-cleanup",
        "block-pending-io-policy" | "pending-block-io" | "pending-io-policy" => {
            "block-pending-io-policy"
        }
        "block-request-generation-audit"
        | "stale-block-request-generation"
        | "block-generation-audit" => "block-request-generation-audit",
        "block-benchmark" | "disk-benchmark" | "block-iops" => "block-benchmark",
        "block-recovery-benchmark" | "disk-recovery-benchmark" | "disk-recovery" => {
            "block-recovery-benchmark"
        }
        "target-feature-set" | "target-feature" | "target-feature-set-object" => {
            "target-feature-set"
        }
        "vector-state" | "vector" | "simd-vector-state" => "vector-state",
        "simd-fault-injection" | "simd-fault" => "simd-fault-injection",
        "simd-benchmark" | "simd-scalar-vector-benchmark" => "simd-benchmark",
        "simd-context-switch-benchmark" | "simd-context-switch" | "simd-switch-benchmark" => {
            "simd-context-switch-benchmark"
        }
        "framebuffer-object" | "framebuffer" | "fb" => "framebuffer-object",
        "display-object" | "display" | "display-mode" => "display-object",
        "display-capability" | "display-cap" => "display-capability",
        "framebuffer-window-lease" | "fb-window-lease" | "display-lease" => {
            "framebuffer-window-lease"
        }
        "framebuffer-mapping" | "fb-mapping" | "display-mapping" => "framebuffer-mapping",
        "framebuffer-write" | "fb-write" | "display-write" => "framebuffer-write",
        "framebuffer-flush-region" | "flush-region" | "display-flush" => "framebuffer-flush-region",
        "framebuffer-dirty-region" | "dirty-region" | "display-dirty" => "framebuffer-dirty-region",
        "display-event-log" | "display-log" => "display-event-log",
        "display-cleanup" => "display-cleanup",
        "display-snapshot-barrier" | "display-snapshot" => "display-snapshot-barrier",
        "display-panic-last-frame" | "panic-last-frame" => "display-panic-last-frame",
        "framebuffer-benchmark" | "fb-benchmark" | "display-benchmark" => "framebuffer-benchmark",
        "integrated-smp-preemption-cleanup"
        | "integrated-smp-cleanup"
        | "smp-preemption-cleanup" => "integrated-smp-preemption-cleanup",
        "activation-resume" => "activation-resume",
        "activation-wait" => "activation-wait",
        "activation-cleanup" => "activation-cleanup",
        "preemption-latency" => "preemption-latency",
        "hart-event" | "hart-event-attribution" => "hart-event-attribution",
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

fn hart_view_v1(hart: &HartRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "hart",
        "id": hart.id,
        "generation": hart.generation,
        "state": hart.state,
        "owner": {
            "hardware_id": hart.hardware_id,
            "boot": hart.boot,
        },
        "references": {
            "scheduler": {
                "id": 1,
                "generation": 1,
            },
            "current_activation": hart.current_activation.map(|id| serde_json::json!({
                "id": id,
                "generation": hart.current_activation_generation,
            })),
            "current_task": hart.current_task.map(|id| serde_json::json!({
                "id": id,
                "generation": hart.current_task_generation,
            })),
            "current_store": hart.current_store.map(|id| serde_json::json!({
                "id": id,
                "generation": hart.current_store_generation,
            })),
        },
        "label": hart.label,
        "note": hart.note,
        "last_transition": {
            "last_event": hart.last_event,
            "last_current_event": hart.last_current_event,
        },
        "last_error": serde_json::Value::Null,
    })
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
    let owner_hart = match (queue.owner_hart, queue.owner_hart_generation) {
        (Some(id), Some(generation)) => serde_json::json!({
            "kind": "hart",
            "id": id,
            "generation": generation,
        }),
        _ => serde_json::Value::Null,
    };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "runnable-queue",
        "id": queue.id,
        "generation": queue.generation,
        "state": queue.state,
        "owner": {
            "hart": owner_hart,
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

fn activation_context_view_v1(context: &ActivationContextManifest) -> serde_json::Value {
    let vector_status = if context.vector_status.is_empty() {
        "absent"
    } else {
        context.vector_status.as_str()
    };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation-context",
        "id": context.id,
        "generation": context.generation,
        "state": context.state,
        "owner": {
            "task": context.owner_task,
            "task_generation": context.owner_task_generation,
            "store": context.owner_store,
            "store_generation": context.owner_store_generation,
        },
        "references": {
            "activation": {
                "id": context.activation,
                "generation": context.activation_generation,
            },
            "current_saved_context": context.current_saved_context.map(|id| serde_json::json!({
                "id": id,
                "generation": context.current_saved_context_generation,
            })),
            "vector_state": context.vector_state.as_ref().map(object_ref_manifest_json),
        },
        "vector_context": {
            "status": vector_status,
            "vector_state": context.vector_state.as_ref().map(object_ref_manifest_json),
            "last_event": context.vector_state_event,
        },
        "last_transition": {
            "last_event": context.last_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn saved_context_view_v1(saved: &SavedContextManifest) -> serde_json::Value {
    let vector_status = if saved.vector_status.is_empty() {
        "absent"
    } else {
        saved.vector_status.as_str()
    };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "saved-context",
        "id": saved.id,
        "generation": saved.generation,
        "state": saved.state,
        "owner": {
            "task": saved.owner_task,
            "task_generation": saved.owner_task_generation,
        },
        "references": {
            "activation_context": {
                "id": saved.context,
                "generation": saved.context_generation,
            },
            "activation": {
                "id": saved.activation,
                "generation": saved.activation_generation,
            },
            "source_preemption": saved.source_preemption.map(|id| serde_json::json!({
                "id": id,
                "generation": saved.source_preemption_generation,
            })),
            "vector_state": saved.vector_state.as_ref().map(object_ref_manifest_json),
        },
        "machine_frame": {
            "pc": saved.pc,
            "sp": saved.sp,
            "flags": saved.flags,
            "integer_registers": saved.integer_registers,
        },
        "vector_context": {
            "status": vector_status,
            "vector_state": saved.vector_state.as_ref().map(object_ref_manifest_json),
            "saved_at_event": saved.vector_saved_at_event,
        },
        "reason": saved.reason,
        "note": saved.note,
        "last_transition": {
            "saved_at_event": saved.saved_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn timer_interrupt_view_v1(interrupt: &TimerInterruptManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "timer-interrupt",
        "id": interrupt.id,
        "generation": interrupt.generation,
        "state": interrupt.state,
        "owner": {
            "hart": {
                "id": interrupt.hart,
                "generation": interrupt.hart_generation,
                "hardware_id": interrupt.hardware_hart,
            },
            "timer_epoch": interrupt.timer_epoch,
        },
        "references": {
            "activation": interrupt.target_activation.map(|id| serde_json::json!({
                "id": id,
                "generation": interrupt.target_activation_generation,
            })),
            "task": interrupt.target_task.map(|id| serde_json::json!({
                "id": id,
                "generation": interrupt.target_task_generation,
            })),
        },
        "note": interrupt.note,
        "last_transition": {
            "recorded_at_event": interrupt.recorded_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn ipi_event_view_v1(ipi: &IpiEventManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "ipi-event",
        "id": ipi.id,
        "generation": ipi.generation,
        "state": ipi.state,
        "owner": {
            "source_hart": {
                "id": ipi.source_hart,
                "generation": ipi.source_hart_generation,
                "hardware_id": ipi.source_hardware_hart,
            },
            "target_hart": {
                "id": ipi.target_hart,
                "generation": ipi.target_hart_generation,
                "hardware_id": ipi.target_hardware_hart,
            },
        },
        "references": {
            "source_hart": {
                "id": ipi.source_hart,
                "generation": ipi.source_hart_generation,
                "hardware_id": ipi.source_hardware_hart,
            },
            "target_hart": {
                "id": ipi.target_hart,
                "generation": ipi.target_hart_generation,
                "hardware_id": ipi.target_hardware_hart,
            },
            "event": {
                "id": ipi.recorded_at_event,
            },
        },
        "ipi_kind": ipi.kind,
        "reason": ipi.reason,
        "note": ipi.note,
        "last_transition": {
            "recorded_at_event": ipi.recorded_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn remote_preempt_view_v1(remote: &RemotePreemptManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "remote-preempt",
        "id": remote.id,
        "generation": remote.generation,
        "state": remote.state,
        "owner": {
            "source_hart": {
                "id": remote.source_hart,
                "generation": remote.source_hart_generation,
            },
            "target_hart": {
                "id": remote.target_hart,
                "generation_before": remote.target_hart_generation_before,
                "generation_after": remote.target_hart_generation_after,
            },
        },
        "references": {
            "ipi": {
                "id": remote.ipi,
                "generation": remote.ipi_generation,
            },
            "activation": {
                "id": remote.activation,
                "generation_before": remote.activation_generation_before,
                "generation_after": remote.activation_generation_after,
            },
            "queue": {
                "id": remote.queue,
                "generation": remote.queue_generation,
            },
            "event": {
                "id": remote.preempted_at_event,
            },
        },
        "note": remote.note,
        "last_transition": {
            "preempted_at_event": remote.preempted_at_event,
            "target_hart_generation_after": remote.target_hart_generation_after,
            "activation_generation_after": remote.activation_generation_after,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn remote_park_view_v1(remote: &RemoteParkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "remote-park",
        "id": remote.id,
        "generation": remote.generation,
        "state": remote.state,
        "owner": {
            "source_hart": {
                "id": remote.source_hart,
                "generation": remote.source_hart_generation,
            },
            "target_hart": {
                "id": remote.target_hart,
                "generation_before": remote.target_hart_generation_before,
                "generation_after": remote.target_hart_generation_after,
            },
        },
        "references": {
            "ipi": {
                "id": remote.ipi,
                "generation": remote.ipi_generation,
            },
            "event": {
                "id": remote.parked_at_event,
            },
        },
        "reason": remote.reason,
        "note": remote.note,
        "last_transition": {
            "parked_at_event": remote.parked_at_event,
            "target_hart_generation_after": remote.target_hart_generation_after,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn hart_event_attribution_view_v1(attribution: &HartEventAttributionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "hart-event-attribution",
        "id": attribution.id,
        "generation": attribution.generation,
        "state": attribution.state,
        "owner": {
            "hart": {
                "id": attribution.hart,
                "generation": attribution.hart_generation,
                "hardware_id": attribution.hardware_hart,
            },
        },
        "references": {
            "event": {
                "id": attribution.event,
                "source": attribution.event_source,
                "kind": attribution.event_kind,
            },
            "activation": attribution.activation.map(|id| serde_json::json!({
                "id": id,
                "generation": attribution.activation_generation,
            })),
            "task": attribution.task.map(|id| serde_json::json!({
                "id": id,
                "generation": attribution.task_generation,
            })),
            "store": attribution.store.map(|id| serde_json::json!({
                "id": id,
                "generation": attribution.store_generation,
            })),
        },
        "note": attribution.note,
        "last_transition": {
            "event": attribution.event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn preemption_view_v1(preemption: &PreemptionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "preemption",
        "id": preemption.id,
        "generation": preemption.generation,
        "state": preemption.state,
        "owner": {
            "scheduler": 1,
        },
        "references": {
            "activation": {
                "id": preemption.activation,
                "generation_before": preemption.activation_generation_before,
                "generation_after": preemption.activation_generation_after,
            },
            "timer_interrupt": {
                "id": preemption.timer_interrupt,
                "generation": preemption.timer_interrupt_generation,
            },
            "queue": {
                "id": preemption.queue,
                "generation": preemption.queue_generation,
            },
        },
        "note": preemption.note,
        "last_transition": {
            "preempted_at_event": preemption.preempted_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn scheduler_decision_view_v1(decision: &SchedulerDecisionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "scheduler-decision",
        "id": decision.id,
        "generation": decision.generation,
        "state": decision.state,
        "owner": {
            "scheduler": 1,
            "task": decision.owner_task,
            "task_generation": decision.owner_task_generation,
        },
        "references": {
            "queue": {
                "id": decision.queue,
                "generation": decision.queue_generation,
            },
            "selected_activation": {
                "id": decision.selected_activation,
                "generation": decision.selected_activation_generation,
            },
        },
        "reason": decision.reason,
        "note": decision.note,
        "last_transition": {
            "decided_at_event": decision.decided_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn cross_hart_scheduler_decision_view_v1(
    decision: &CrossHartSchedulerDecisionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "cross-hart-scheduler-decision",
        "id": decision.id,
        "generation": decision.generation,
        "state": decision.state,
        "owner": {
            "scheduler": 1,
            "deciding_hart": {
                "id": decision.deciding_hart,
                "generation": decision.deciding_hart_generation,
            },
            "target_hart": {
                "id": decision.target_hart,
                "generation": decision.target_hart_generation,
            },
        },
        "references": {
            "scheduler_decision": {
                "id": decision.scheduler_decision,
                "generation": decision.scheduler_decision_generation,
            },
            "queue": {
                "id": decision.queue,
                "generation": decision.queue_generation,
                "owner_hart_generation": decision.queue_owner_hart_generation,
            },
            "selected_activation": {
                "id": decision.selected_activation,
                "generation": decision.selected_activation_generation,
            },
            "event": {
                "id": decision.decided_at_event,
            },
        },
        "reason": decision.reason,
        "note": decision.note,
        "last_transition": {
            "decided_at_event": decision.decided_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn activation_migration_view_v1(migration: &ActivationMigrationManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation-migration",
        "id": migration.id,
        "generation": migration.generation,
        "state": migration.state,
        "owner": {
            "task": migration.owner_task,
            "task_generation": migration.owner_task_generation,
            "source_hart": {
                "id": migration.source_hart,
                "generation": migration.source_hart_generation,
            },
            "target_hart": {
                "id": migration.target_hart,
                "generation": migration.target_hart_generation,
            },
        },
        "references": {
            "activation": {
                "id": migration.activation,
                "generation_before": migration.activation_generation_before,
                "generation_after": migration.activation_generation_after,
            },
            "context": migration.context.map(|context| serde_json::json!({
                "id": context,
                "generation_before": migration.context_generation_before,
                "generation_after": migration.context_generation_after,
            })),
            "source_vector_state": migration.source_vector_state.as_ref().map(object_ref_manifest_json),
            "migrated_vector_state": migration.migrated_vector_state.as_ref().map(object_ref_manifest_json),
            "source_queue": {
                "id": migration.source_queue,
                "generation": migration.source_queue_generation,
                "owner_hart_generation": migration.source_queue_owner_hart_generation,
            },
            "target_queue": {
                "id": migration.target_queue,
                "generation": migration.target_queue_generation,
                "owner_hart_generation": migration.target_queue_owner_hart_generation,
            },
            "event": {
                "id": migration.migrated_at_event,
            },
        },
        "vector_migration": {
            "status": if migration.vector_status.is_empty() {
                "absent"
            } else {
                migration.vector_status.as_str()
            },
            "source_vector_state": migration.source_vector_state.as_ref().map(object_ref_manifest_json),
            "migrated_vector_state": migration.migrated_vector_state.as_ref().map(object_ref_manifest_json),
            "event": migration.vector_migrated_at_event,
        },
        "reason": migration.reason,
        "note": migration.note,
        "last_transition": {
            "migrated_at_event": migration.migrated_at_event,
            "activation_generation_after": migration.activation_generation_after,
            "vector_migrated_at_event": migration.vector_migrated_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn smp_safe_point_view_v1(safe_point: &SmpSafePointManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-safe-point",
        "id": safe_point.id,
        "generation": safe_point.generation,
        "state": safe_point.state,
        "owner": {
            "coordinator_hart": {
                "id": safe_point.coordinator_hart,
                "generation": safe_point.coordinator_hart_generation,
            },
        },
        "references": {
            "participants": safe_point.participants.iter().map(|participant| serde_json::json!({
                "hart": {
                    "id": participant.hart,
                    "generation": participant.hart_generation,
                },
                "hardware_hart": participant.hardware_hart,
                "hart_state": participant.hart_state,
                "current_activation": participant.current_activation,
                "current_activation_generation": participant.current_activation_generation,
            })).collect::<Vec<_>>(),
            "event": {
                "id": safe_point.recorded_at_event,
            },
        },
        "reason": safe_point.reason,
        "note": safe_point.note,
        "last_transition": {
            "recorded_at_event": safe_point.recorded_at_event,
            "participant_count": safe_point.participants.len(),
        },
        "last_error": serde_json::Value::Null,
    })
}

fn stop_the_world_rendezvous_view_v1(
    rendezvous: &StopTheWorldRendezvousManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "stop-the-world-rendezvous",
        "id": rendezvous.id,
        "generation": rendezvous.generation,
        "state": rendezvous.state,
        "owner": {
            "coordinator_hart": {
                "id": rendezvous.coordinator_hart,
                "generation": rendezvous.coordinator_hart_generation,
            },
        },
        "references": {
            "safe_point": {
                "id": rendezvous.safe_point,
                "generation": rendezvous.safe_point_generation,
            },
            "participants": rendezvous.participants.iter().map(|participant| serde_json::json!({
                "hart": {
                    "id": participant.hart,
                    "generation": participant.hart_generation,
                },
                "hardware_hart": participant.hardware_hart,
                "hart_state": participant.hart_state,
            })).collect::<Vec<_>>(),
            "event": {
                "id": rendezvous.completed_at_event,
            },
        },
        "epoch": rendezvous.epoch,
        "stop_new_activations": rendezvous.stop_new_activations,
        "reason": rendezvous.reason,
        "note": rendezvous.note,
        "last_transition": {
            "completed_at_event": rendezvous.completed_at_event,
            "participant_count": rendezvous.participants.len(),
            "epoch": rendezvous.epoch,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn smp_code_publish_barrier_view_v1(barrier: &SmpCodePublishBarrierManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-code-publish-barrier",
        "id": barrier.id,
        "generation": barrier.generation,
        "state": barrier.state,
        "owner": {
            "rendezvous": {
                "id": barrier.rendezvous,
                "generation": barrier.rendezvous_generation,
            },
            "code_publish_epoch": {
                "before": barrier.code_publish_epoch_before,
                "after": barrier.code_publish_epoch_after,
            },
        },
        "references": {
            "rendezvous": {
                "kind": "stop-the-world-rendezvous",
                "id": barrier.rendezvous,
                "generation": barrier.rendezvous_generation,
                "epoch": barrier.rendezvous_epoch,
            },
            "participants": barrier.participants.iter().map(|participant| serde_json::json!({
                "hart": {
                    "kind": "hart",
                    "id": participant.hart,
                    "generation": participant.hart_generation,
                },
                "hardware_hart": participant.hardware_hart,
                "last_seen_code_epoch_before": participant.last_seen_code_epoch_before,
                "last_seen_code_epoch_after": participant.last_seen_code_epoch_after,
                "semantic_icache_sync": participant.semantic_icache_sync,
            })).collect::<Vec<_>>(),
            "event": {
                "id": barrier.validated_at_event,
            },
        },
        "remote_icache_sync_required": barrier.remote_icache_sync_required,
        "code_publish_executed": barrier.code_publish_executed,
        "reason": barrier.reason,
        "note": barrier.note,
        "last_transition": {
            "validated_at_event": barrier.validated_at_event,
            "participant_count": barrier.participants.len(),
            "code_publish_epoch_before": barrier.code_publish_epoch_before,
            "code_publish_epoch_after": barrier.code_publish_epoch_after,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn smp_cleanup_quiescence_view_v1(quiescence: &SmpCleanupQuiescenceManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-cleanup-quiescence",
        "id": quiescence.id,
        "generation": quiescence.generation,
        "state": quiescence.state,
        "owner": {
            "store": {
                "id": quiescence.store,
                "target_generation": quiescence.target_store_generation,
                "result_generation": quiescence.result_store_generation,
            },
            "cleanup": {
                "id": quiescence.cleanup,
                "generation": quiescence.cleanup_generation,
            },
        },
        "references": {
            "cleanup": {
                "kind": "activation-cleanup",
                "id": quiescence.cleanup,
                "generation": quiescence.cleanup_generation,
            },
            "store": {
                "kind": "store",
                "id": quiescence.store,
                "target_generation": quiescence.target_store_generation,
                "result_generation": quiescence.result_store_generation,
            },
            "activation": {
                "kind": "activation",
                "id": quiescence.activation,
                "generation_after": quiescence.activation_generation_after,
            },
            "rendezvous": {
                "kind": "stop-the-world-rendezvous",
                "id": quiescence.rendezvous,
                "generation": quiescence.rendezvous_generation,
                "epoch": quiescence.rendezvous_epoch,
            },
            "participants": quiescence.participants.iter().map(|participant| serde_json::json!({
                "hart": {
                    "kind": "hart",
                    "id": participant.hart,
                    "generation": participant.hart_generation,
                },
                "hardware_hart": participant.hardware_hart,
                "hart_state": participant.hart_state,
                "current_activation": participant.current_activation,
                "current_activation_generation": participant.current_activation_generation,
                "current_store": participant.current_store,
                "current_store_generation": participant.current_store_generation,
                "quiesced": participant.quiesced,
            })).collect::<Vec<_>>(),
            "event": {
                "id": quiescence.validated_at_event,
            },
        },
        "postconditions": {
            "no_running_activation": quiescence.no_running_activation,
            "no_pending_wait": quiescence.no_pending_wait,
            "no_live_capability": quiescence.no_live_capability,
            "no_live_resource": quiescence.no_live_resource,
        },
        "reason": quiescence.reason,
        "note": quiescence.note,
        "last_transition": {
            "validated_at_event": quiescence.validated_at_event,
            "participant_count": quiescence.participants.len(),
            "rendezvous_epoch": quiescence.rendezvous_epoch,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn smp_snapshot_barrier_view_v1(barrier: &SmpSnapshotBarrierManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-snapshot-barrier",
        "id": barrier.id,
        "generation": barrier.generation,
        "state": barrier.state,
        "owner": {
            "rendezvous": {
                "id": barrier.rendezvous,
                "generation": barrier.rendezvous_generation,
                "epoch": barrier.rendezvous_epoch,
            },
        },
        "references": {
            "rendezvous": {
                "kind": "stop-the-world-rendezvous",
                "id": barrier.rendezvous,
                "generation": barrier.rendezvous_generation,
                "epoch": barrier.rendezvous_epoch,
            },
            "participants": barrier.participants.iter().map(|participant| serde_json::json!({
                "hart": {
                    "kind": "hart",
                    "id": participant.hart,
                    "generation": participant.hart_generation,
                },
                "hardware_hart": participant.hardware_hart,
                "hart_state": participant.hart_state,
                "event_log_cursor_observed": participant.event_log_cursor_observed,
                "snapshot_safe": participant.snapshot_safe,
            })).collect::<Vec<_>>(),
            "event": {
                "id": barrier.validated_at_event,
            },
        },
        "postconditions": {
            "snapshot_validation_ok": barrier.snapshot_validation_ok,
            "pending_wait_count": barrier.pending_wait_count,
            "active_transaction_count": barrier.active_transaction_count,
            "active_dmw_lease_count": barrier.active_dmw_lease_count,
            "active_nonconvertible_activation_count": barrier.active_nonconvertible_activation_count,
            "in_flight_dma_count": barrier.in_flight_dma_count,
            "unsealed_event_log": barrier.unsealed_event_log,
            "unflushed_trap_record_count": barrier.unflushed_trap_record_count,
            "pending_cleanup_count": barrier.pending_cleanup_count,
            "native_activation_stack_live": barrier.native_activation_stack_live,
            "raw_dma_binding_count": barrier.raw_dma_binding_count,
            "raw_mmio_binding_count": barrier.raw_mmio_binding_count,
        },
        "reason": barrier.reason,
        "note": barrier.note,
        "last_transition": {
            "event_log_cursor": barrier.event_log_cursor,
            "validated_at_event": barrier.validated_at_event,
            "participant_count": barrier.participants.len(),
            "rendezvous_epoch": barrier.rendezvous_epoch,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn smp_stress_run_view_v1(run: &SmpStressRunManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-stress-run",
        "id": run.id,
        "generation": run.generation,
        "state": run.state,
        "owner": {
            "scenario": run.scenario,
        },
        "references": {
            "last_safe_point": object_ref_json("smp-safe-point", run.last_safe_point, run.last_safe_point_generation),
            "last_rendezvous": object_ref_json("stop-the-world-rendezvous", run.last_rendezvous, run.last_rendezvous_generation),
            "last_code_publish_barrier": object_ref_json("smp-code-publish-barrier", run.last_code_publish_barrier, run.last_code_publish_barrier_generation),
            "last_cleanup_quiescence": object_ref_json("smp-cleanup-quiescence", run.last_cleanup_quiescence, run.last_cleanup_quiescence_generation),
            "last_snapshot_barrier": object_ref_json("smp-snapshot-barrier", run.last_snapshot_barrier, run.last_snapshot_barrier_generation),
            "last_activation_migration": object_ref_json("activation-migration", run.last_activation_migration, run.last_activation_migration_generation),
            "last_remote_preempt": object_ref_json("remote-preempt", run.last_remote_preempt, run.last_remote_preempt_generation),
            "last_remote_park": object_ref_json("remote-park", run.last_remote_park, run.last_remote_park_generation),
            "event": {
                "id": run.recorded_at_event,
            },
        },
        "coverage": {
            "iterations": run.iterations,
            "hart_count": run.hart_count,
            "safe_points": run.observed_safe_point_count,
            "stop_the_world_rendezvous": run.observed_rendezvous_count,
            "code_publish_barriers": run.observed_code_publish_barrier_count,
            "cleanup_quiescence": run.observed_cleanup_quiescence_count,
            "snapshot_barriers": run.observed_snapshot_barrier_count,
            "activation_migrations": run.observed_activation_migration_count,
            "remote_preempts": run.observed_remote_preempt_count,
            "remote_parks": run.observed_remote_park_count,
            "invariant_checks": run.invariant_checks,
            "property_failures": run.property_failures,
        },
        "reason": run.reason,
        "note": run.note,
        "last_transition": {
            "event_log_cursor": run.event_log_cursor,
            "recorded_at_event": run.recorded_at_event,
            "scenario": run.scenario,
            "property_failures": run.property_failures,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn smp_scaling_benchmark_view_v1(benchmark: &SmpScalingBenchmarkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-scaling-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "scenario": benchmark.scenario,
        },
        "references": {
            "stress_run": object_ref_json("smp-stress-run", benchmark.stress_run, benchmark.stress_run_generation),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "metrics": {
            "hart_count": benchmark.hart_count,
            "workload_units": benchmark.workload_units,
            "baseline_single_hart_nanos": benchmark.baseline_single_hart_nanos,
            "measured_smp_nanos": benchmark.measured_smp_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "speedup_milli": benchmark.speedup_milli,
            "efficiency_milli": benchmark.efficiency_milli,
        },
        "coverage": {
            "stress_safe_points": benchmark.stress_safe_point_count,
            "stress_rendezvous": benchmark.stress_rendezvous_count,
            "stress_property_failures": benchmark.stress_property_failures,
        },
        "note": benchmark.note,
        "last_transition": {
            "event_log_cursor": benchmark.event_log_cursor,
            "recorded_at_event": benchmark.recorded_at_event,
            "scenario": benchmark.scenario,
            "within_budget": benchmark.measured_smp_nanos <= benchmark.budget_nanos,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn integrated_smp_preemption_cleanup_view_v1(
    record: &IntegratedSmpPreemptionCleanupManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-smp-preemption-cleanup",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": {
            "scenario": record.scenario,
            "cleanup_store": object_ref_json("store", record.cleanup_store, record.target_store_generation),
            "runtime_activation": {
                "id": record.cleanup_activation,
                "generation_after_cleanup": record.cleanup_activation_generation_after,
                "note": "runtime-preemptive-activation-not-target-executor-object",
            },
        },
        "references": {
            "smp_stress_run": object_ref_json("smp-stress-run", record.stress_run, record.stress_run_generation),
            "preemption": object_ref_json("preemption", record.preemption, record.preemption_generation),
            "timer_interrupt": object_ref_json("timer-interrupt", record.timer_interrupt, record.timer_interrupt_generation),
            "saved_context": object_ref_json("saved-context", record.saved_context, record.saved_context_generation),
            "remote_preempt": object_ref_json("remote-preempt", record.remote_preempt, record.remote_preempt_generation),
            "activation_cleanup": object_ref_json(
                "activation-cleanup",
                record.activation_cleanup,
                record.activation_cleanup_generation,
            ),
            "smp_cleanup_quiescence": object_ref_json(
                "smp-cleanup-quiescence",
                record.smp_cleanup_quiescence,
                record.smp_cleanup_quiescence_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "closure": {
            "hart_count": record.hart_count,
            "invariant_checks": record.invariant_checks,
            "target_store_generation": record.target_store_generation,
            "result_store_generation": record.result_store_generation,
            "cleanup_generation_safe": record.result_store_generation > record.target_store_generation,
            "requires_no_resume_after_cleanup": true,
            "requires_wait_cancelling_cleanup": true,
        },
        "authority": {
            "uses_semantic_preemption_cleanup_evidence": true,
            "real_smp_preemption_executed": false,
            "real_cross_hart_substrate_interrupt_executed": false,
        },
        "note": record.note,
        "last_transition": {
            "recorded_at_event": record.recorded_at_event,
            "scenario": record.scenario,
            "cleanup_store_generation_after": record.result_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn device_object_view_v1(device: &DeviceObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "device",
        "id": device.id,
        "generation": device.generation,
        "state": device.state,
        "owner": {
            "class": device.class,
            "backend": device.backend,
            "bus": device.bus,
        },
        "references": {
            "resource": object_ref_json("resource", device.resource, device.resource_generation),
            "event": {
                "id": device.recorded_at_event,
            },
        },
        "identity": {
            "name": device.name,
            "vendor": device.vendor,
            "model": device.model,
        },
        "note": device.note,
        "last_transition": {
            "recorded_at_event": device.recorded_at_event,
            "resource_generation": device.resource_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn queue_object_view_v1(queue: &QueueObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "queue",
        "id": queue.id,
        "generation": queue.generation,
        "state": queue.state,
        "owner": {
            "device": object_ref_json("device", queue.device, queue.device_generation),
        },
        "references": {
            "device": object_ref_json("device", queue.device, queue.device_generation),
            "event": {
                "id": queue.recorded_at_event,
            },
        },
        "identity": {
            "name": queue.name,
            "role": queue.role,
            "queue_index": queue.queue_index,
        },
        "capacity": {
            "depth": queue.depth,
        },
        "note": queue.note,
        "last_transition": {
            "recorded_at_event": queue.recorded_at_event,
            "device_generation": queue.device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn descriptor_object_view_v1(descriptor: &DescriptorObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "descriptor",
        "id": descriptor.id,
        "generation": descriptor.generation,
        "state": descriptor.state,
        "owner": {
            "queue": object_ref_json(
                "queue",
                descriptor.queue,
                descriptor.queue_generation
            ),
        },
        "references": {
            "queue": object_ref_json(
                "queue",
                descriptor.queue,
                descriptor.queue_generation
            ),
            "event": {
                "id": descriptor.recorded_at_event,
            },
        },
        "identity": {
            "slot": descriptor.slot,
            "access": descriptor.access,
        },
        "capacity": {
            "length": descriptor.length,
        },
        "note": descriptor.note,
        "last_transition": {
            "recorded_at_event": descriptor.recorded_at_event,
            "queue_generation": descriptor.queue_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn dma_buffer_object_view_v1(dma_buffer: &DmaBufferObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "dma-buffer",
        "id": dma_buffer.id,
        "generation": dma_buffer.generation,
        "state": dma_buffer.state,
        "owner": {
            "descriptor": object_ref_json(
                "descriptor",
                dma_buffer.descriptor,
                dma_buffer.descriptor_generation
            ),
        },
        "references": {
            "descriptor": object_ref_json(
                "descriptor",
                dma_buffer.descriptor,
                dma_buffer.descriptor_generation
            ),
            "resource": object_ref_json(
                "resource",
                dma_buffer.resource,
                dma_buffer.resource_generation
            ),
            "event": {
                "id": dma_buffer.recorded_at_event,
            },
        },
        "identity": {
            "access": dma_buffer.access,
        },
        "capacity": {
            "length": dma_buffer.length,
        },
        "note": dma_buffer.note,
        "last_transition": {
            "recorded_at_event": dma_buffer.recorded_at_event,
            "descriptor_generation": dma_buffer.descriptor_generation,
            "resource_generation": dma_buffer.resource_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn mmio_region_object_view_v1(mmio_region: &MmioRegionObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "mmio-region",
        "id": mmio_region.id,
        "generation": mmio_region.generation,
        "state": mmio_region.state,
        "owner": {
            "device": object_ref_json(
                "device",
                mmio_region.device,
                mmio_region.device_generation
            ),
        },
        "references": {
            "device": object_ref_json(
                "device",
                mmio_region.device,
                mmio_region.device_generation
            ),
            "resource": object_ref_json(
                "resource",
                mmio_region.resource,
                mmio_region.resource_generation
            ),
            "event": {
                "id": mmio_region.recorded_at_event,
            },
        },
        "identity": {
            "region_index": mmio_region.region_index,
            "offset": mmio_region.offset,
            "access": mmio_region.access,
        },
        "capacity": {
            "length": mmio_region.length,
        },
        "note": mmio_region.note,
        "last_transition": {
            "recorded_at_event": mmio_region.recorded_at_event,
            "device_generation": mmio_region.device_generation,
            "resource_generation": mmio_region.resource_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn irq_line_object_view_v1(irq_line: &IrqLineObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "irq-line",
        "id": irq_line.id,
        "generation": irq_line.generation,
        "state": irq_line.state,
        "owner": {
            "device": object_ref_json(
                "device",
                irq_line.device,
                irq_line.device_generation
            ),
        },
        "references": {
            "device": object_ref_json(
                "device",
                irq_line.device,
                irq_line.device_generation
            ),
            "resource": object_ref_json(
                "resource",
                irq_line.resource,
                irq_line.resource_generation
            ),
            "event": {
                "id": irq_line.recorded_at_event,
            },
        },
        "identity": {
            "irq_number": irq_line.irq_number,
            "trigger": irq_line.trigger,
            "polarity": irq_line.polarity,
        },
        "note": irq_line.note,
        "last_transition": {
            "recorded_at_event": irq_line.recorded_at_event,
            "device_generation": irq_line.device_generation,
            "resource_generation": irq_line.resource_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn irq_event_view_v1(irq_event: &IrqEventManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "irq-event",
        "id": irq_event.id,
        "generation": irq_event.generation,
        "state": irq_event.state,
        "owner": {
            "device": object_ref_json(
                "device",
                irq_event.device,
                irq_event.device_generation
            ),
            "driver_store": object_ref_json(
                "store",
                irq_event.driver_store,
                irq_event.driver_store_generation
            ),
        },
        "references": {
            "irq_line": object_ref_json(
                "irq-line",
                irq_event.irq_line,
                irq_event.irq_line_generation
            ),
            "device": object_ref_json(
                "device",
                irq_event.device,
                irq_event.device_generation
            ),
            "driver_store": object_ref_json(
                "store",
                irq_event.driver_store,
                irq_event.driver_store_generation
            ),
            "event": {
                "id": irq_event.recorded_at_event,
            },
        },
        "identity": {
            "irq_number": irq_event.irq_number,
            "sequence": irq_event.sequence,
        },
        "note": irq_event.note,
        "last_transition": {
            "recorded_at_event": irq_event.recorded_at_event,
            "irq_line_generation": irq_event.irq_line_generation,
            "device_generation": irq_event.device_generation,
            "driver_store_generation": irq_event.driver_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn device_capability_view_v1(device_capability: &DeviceCapabilityManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "device-capability",
        "id": device_capability.id,
        "generation": device_capability.generation,
        "state": device_capability.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                device_capability.driver_store,
                device_capability.driver_store_generation
            ),
        },
        "references": {
            "target": object_ref_manifest_json(&device_capability.target),
            "capability": object_ref_json(
                "capability",
                device_capability.capability,
                device_capability.capability_generation
            ),
            "driver_store": object_ref_json(
                "store",
                device_capability.driver_store,
                device_capability.driver_store_generation
            ),
            "event": {
                "id": device_capability.recorded_at_event,
            },
        },
        "authority": {
            "class": device_capability.class,
            "operation": device_capability.operation,
            "handle": {
                "slot": device_capability.handle_slot,
                "generation": device_capability.handle_generation,
                "tag": device_capability.handle_tag,
            },
        },
        "note": device_capability.note,
        "last_transition": {
            "recorded_at_event": device_capability.recorded_at_event,
            "driver_store_generation": device_capability.driver_store_generation,
            "target_generation": device_capability.target.generation,
            "capability_generation": device_capability.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn driver_store_binding_view_v1(binding: &DriverStoreBindingManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "driver-store-binding",
        "id": binding.id,
        "generation": binding.generation,
        "state": binding.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                binding.driver_store,
                binding.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                binding.device,
                binding.device_generation
            ),
        },
        "references": {
            "driver_store": object_ref_json(
                "store",
                binding.driver_store,
                binding.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                binding.device,
                binding.device_generation
            ),
            "device_capability": object_ref_json(
                "device-capability",
                binding.device_capability,
                binding.device_capability_generation
            ),
            "capability": object_ref_json(
                "capability",
                binding.capability,
                binding.capability_generation
            ),
            "event": {
                "id": binding.recorded_at_event,
            },
        },
        "note": binding.note,
        "last_transition": {
            "recorded_at_event": binding.recorded_at_event,
            "driver_store_generation": binding.driver_store_generation,
            "device_generation": binding.device_generation,
            "device_capability_generation": binding.device_capability_generation,
            "capability_generation": binding.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn io_wait_view_v1(io_wait: &IoWaitManifest) -> serde_json::Value {
    let completion_irq_event = match (
        io_wait.completion_irq_event,
        io_wait.completion_irq_event_generation,
    ) {
        (Some(irq_event), Some(irq_event_generation)) => {
            object_ref_json("irq-event", irq_event, irq_event_generation)
        }
        _ => serde_json::Value::Null,
    };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "io-wait",
        "id": io_wait.id,
        "generation": io_wait.generation,
        "state": io_wait.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                io_wait.driver_store,
                io_wait.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                io_wait.device,
                io_wait.device_generation
            ),
        },
        "references": {
            "wait": object_ref_json(
                "wait-token",
                io_wait.wait,
                io_wait.wait_generation
            ),
            "driver_store": object_ref_json(
                "store",
                io_wait.driver_store,
                io_wait.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                io_wait.device,
                io_wait.device_generation
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                io_wait.driver_binding,
                io_wait.driver_binding_generation
            ),
            "blocker": object_ref_manifest_json(&io_wait.blocker),
            "completion_irq_event": completion_irq_event,
            "created_event": {
                "id": io_wait.created_at_event,
            },
            "completed_event": io_wait.completed_at_event.map(|id| serde_json::json!({ "id": id })),
        },
        "cancel_reason": io_wait.cancel_reason,
        "note": io_wait.note,
        "last_transition": {
            "created_at_event": io_wait.created_at_event,
            "completed_at_event": io_wait.completed_at_event,
            "wait_generation": io_wait.wait_generation,
            "driver_store_generation": io_wait.driver_store_generation,
            "device_generation": io_wait.device_generation,
            "driver_binding_generation": io_wait.driver_binding_generation,
        },
        "last_error": io_wait.cancel_reason,
    })
}

fn io_cleanup_view_v1(cleanup: &IoCleanupManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "io-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                cleanup.device,
                cleanup.device_generation
            ),
        },
        "references": {
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                cleanup.device,
                cleanup.device_generation
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation
            ),
            "cancelled_io_waits": cleanup
                .cancelled_io_waits
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "revoked_device_capabilities": cleanup
                .revoked_device_capabilities
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "revoked_capabilities": cleanup
                .revoked_capabilities
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "released_dma_buffers": cleanup
                .released_dma_buffers
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "released_mmio_regions": cleanup
                .released_mmio_regions
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "released_irq_lines": cleanup
                .released_irq_lines
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
        },
        "reason": cleanup.reason,
        "steps": cleanup
            .steps
            .iter()
            .map(|step| {
                serde_json::json!({
                    "kind": step.kind,
                    "target": object_ref_manifest_json(&step.target),
                    "observed_generation": step.observed_generation,
                    "status": step.status,
                    "event": step.event,
                })
            })
            .collect::<Vec<_>>(),
        "note": cleanup.note,
        "last_transition": {
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
            "driver_store_generation": cleanup.driver_store_generation,
            "device_generation": cleanup.device_generation,
            "driver_binding_generation": cleanup.driver_binding_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn io_fault_injection_view_v1(fault: &IoFaultInjectionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "io-fault-injection",
        "id": fault.id,
        "generation": fault.generation,
        "state": fault.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                fault.driver_store,
                fault.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                fault.device,
                fault.device_generation
            ),
        },
        "references": {
            "driver_store": object_ref_json(
                "store",
                fault.driver_store,
                fault.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                fault.device,
                fault.device_generation
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                fault.driver_binding,
                fault.driver_binding_generation
            ),
            "target": object_ref_manifest_json(&fault.target),
            "cleanup": object_ref_json(
                "io-cleanup",
                fault.cleanup,
                fault.cleanup_generation
            ),
            "injected_event": {
                "id": fault.injected_at_event,
            },
        },
        "fault": {
            "kind": fault.kind,
        },
        "note": fault.note,
        "last_transition": {
            "injected_at_event": fault.injected_at_event,
            "driver_store_generation": fault.driver_store_generation,
            "device_generation": fault.device_generation,
            "driver_binding_generation": fault.driver_binding_generation,
            "cleanup_generation": fault.cleanup_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn io_validation_report_view_v1(report: &IoValidationReportManifest) -> serde_json::Value {
    let violations = report
        .violations
        .iter()
        .map(|violation| {
            serde_json::json!({
                "code": violation.code,
                "subject": object_ref_manifest_json(&violation.subject),
                "relation": violation.relation,
                "message": violation.message,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "io-validation-report",
        "id": report.id,
        "generation": report.generation,
        "state": report.state,
        "owner": serde_json::Value::Null,
        "references": {
            "validated_event": {
                "id": report.validated_at_event,
            },
            "event_log_cursor": report.event_log_cursor,
        },
        "observed": {
            "devices": report.observed_device_count,
            "queues": report.observed_queue_count,
            "descriptors": report.observed_descriptor_count,
            "dma_buffers": report.observed_dma_buffer_count,
            "mmio_regions": report.observed_mmio_region_count,
            "irq_lines": report.observed_irq_line_count,
            "irq_events": report.observed_irq_event_count,
            "device_capabilities": report.observed_device_capability_count,
            "driver_bindings": report.observed_driver_binding_count,
            "io_waits": report.observed_io_wait_count,
            "io_cleanups": report.observed_io_cleanup_count,
            "io_fault_injections": report.observed_io_fault_injection_count,
        },
        "validation": {
            "ok": report.state == "passed" && report.violation_count == 0,
            "violation_count": report.violation_count,
            "violations": violations,
        },
        "note": report.note,
        "last_transition": {
            "validated_at_event": report.validated_at_event,
            "event_log_cursor": report.event_log_cursor,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn packet_device_object_view_v1(packet_device: &PacketDeviceObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "packet-device",
        "id": packet_device.id,
        "generation": packet_device.generation,
        "state": packet_device.state,
        "owner": {
            "device": object_ref_json("device", packet_device.device, packet_device.device_generation),
        },
        "references": {
            "device": object_ref_json("device", packet_device.device, packet_device.device_generation),
            "event": {
                "id": packet_device.recorded_at_event,
            },
        },
        "identity": {
            "name": packet_device.name,
            "mac": packet_device.mac,
        },
        "contract": {
            "mtu": packet_device.mtu,
            "rx_queue_depth": packet_device.rx_queue_depth,
            "tx_queue_depth": packet_device.tx_queue_depth,
            "frame_format_version": packet_device.frame_format_version,
            "max_payload_len": packet_device.max_payload_len,
        },
        "note": packet_device.note,
        "last_transition": {
            "recorded_at_event": packet_device.recorded_at_event,
            "device_generation": packet_device.device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_device_object_view_v1(block_device: &BlockDeviceObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-device",
        "id": block_device.id,
        "generation": block_device.generation,
        "state": block_device.state,
        "owner": {
            "device": object_ref_json("device", block_device.device, block_device.device_generation),
        },
        "references": {
            "device": object_ref_json("device", block_device.device, block_device.device_generation),
            "event": {
                "id": block_device.recorded_at_event,
            },
        },
        "identity": {
            "name": block_device.name,
        },
        "contract": {
            "sector_size": block_device.sector_size,
            "sector_count": block_device.sector_count,
            "read_only": block_device.read_only,
            "max_transfer_sectors": block_device.max_transfer_sectors,
        },
        "note": block_device.note,
        "last_transition": {
            "recorded_at_event": block_device.recorded_at_event,
            "device_generation": block_device.device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_range_object_view_v1(block_range: &BlockRangeObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-range",
        "id": block_range.id,
        "generation": block_range.generation,
        "state": block_range.state,
        "owner": {
            "block_device": object_ref_json(
                "block-device",
                block_range.block_device,
                block_range.block_device_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                block_range.block_device,
                block_range.block_device_generation,
            ),
            "event": {
                "id": block_range.recorded_at_event,
            },
        },
        "sector_range": {
            "start_sector": block_range.start_sector,
            "sector_count": block_range.sector_count,
        },
        "byte_range": {
            "byte_offset": block_range.byte_offset,
            "byte_len": block_range.byte_len,
        },
        "note": block_range.note,
        "last_transition": {
            "recorded_at_event": block_range.recorded_at_event,
            "block_device_generation": block_range.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_request_object_view_v1(request: &BlockRequestObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-request",
        "id": request.id,
        "generation": request.generation,
        "state": request.state,
        "owner": {
            "block_device": object_ref_json(
                "block-device",
                request.block_device,
                request.block_device_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                request.block_device,
                request.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                request.block_range,
                request.block_range_generation,
            ),
            "event": {
                "id": request.recorded_at_event,
            },
        },
        "request": {
            "operation": request.operation,
            "sequence": request.sequence,
            "byte_len": request.byte_len,
        },
        "note": request.note,
        "last_transition": {
            "recorded_at_event": request.recorded_at_event,
            "block_device_generation": request.block_device_generation,
            "block_range_generation": request.block_range_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_completion_object_view_v1(
    completion: &BlockCompletionObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-completion",
        "id": completion.id,
        "generation": completion.generation,
        "state": completion.state,
        "owner": {
            "block_request": object_ref_json(
                "block-request",
                completion.block_request,
                completion.block_request_generation,
            ),
        },
        "references": {
            "block_request": object_ref_json(
                "block-request",
                completion.block_request,
                completion.block_request_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                completion.block_device,
                completion.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                completion.block_range,
                completion.block_range_generation,
            ),
            "event": {
                "id": completion.recorded_at_event,
            },
        },
        "completion": {
            "sequence": completion.sequence,
            "completed_bytes": completion.completed_bytes,
            "status": completion.status,
        },
        "note": completion.note,
        "last_transition": {
            "recorded_at_event": completion.recorded_at_event,
            "block_request_generation": completion.block_request_generation,
            "block_device_generation": completion.block_device_generation,
            "block_range_generation": completion.block_range_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_wait_view_v1(wait: &BlockWaitManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "wait": object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "block_request": object_ref_json(
                "block-request",
                wait.block_request,
                wait.block_request_generation,
            ),
        },
        "references": {
            "wait": object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "block_request": object_ref_json(
                "block-request",
                wait.block_request,
                wait.block_request_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                wait.block_device,
                wait.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                wait.block_range,
                wait.block_range_generation,
            ),
            "completion": optional_object_ref_json(
                "block-completion",
                wait.completion,
                wait.completion_generation,
            ),
            "created_event": {
                "id": wait.created_at_event,
            },
            "completed_event": wait.completed_at_event.map(|event| serde_json::json!({ "id": event })),
        },
        "wait": {
            "operation": wait.operation,
            "sequence": wait.sequence,
            "byte_len": wait.byte_len,
            "cancel_reason": wait.cancel_reason,
        },
        "note": wait.note,
        "last_transition": {
            "created_at_event": wait.created_at_event,
            "completed_at_event": wait.completed_at_event,
            "wait_generation": wait.wait_generation,
            "block_request_generation": wait.block_request_generation,
            "block_device_generation": wait.block_device_generation,
            "block_range_generation": wait.block_range_generation,
        },
        "last_error": wait.cancel_reason,
    })
}

fn fake_block_backend_object_view_v1(
    backend: &FakeBlockBackendObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "fake-block-backend",
        "id": backend.id,
        "generation": backend.generation,
        "state": backend.state,
        "owner": {
            "block_device": object_ref_json(
                "block-device",
                backend.block_device,
                backend.block_device_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                backend.block_device,
                backend.block_device_generation,
            ),
            "event": {
                "id": backend.recorded_at_event,
            },
        },
        "identity": {
            "name": backend.name,
            "provider": backend.provider,
            "profile": backend.profile,
            "deterministic_seed": backend.deterministic_seed,
        },
        "contract": {
            "sector_size": backend.sector_size,
            "sector_count": backend.sector_count,
            "read_only": backend.read_only,
            "max_transfer_sectors": backend.max_transfer_sectors,
        },
        "note": backend.note,
        "last_transition": {
            "recorded_at_event": backend.recorded_at_event,
            "block_device_generation": backend.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn virtio_blk_backend_object_view_v1(
    backend: &VirtioBlkBackendObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "virtio-blk-backend",
        "id": backend.id,
        "generation": backend.generation,
        "state": backend.state,
        "owner": {
            "block_device": object_ref_json(
                "block-device",
                backend.block_device,
                backend.block_device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                backend.block_device,
                backend.block_device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
            "device": object_ref_json(
                "device",
                backend.device,
                backend.device_generation,
            ),
            "event": {
                "id": backend.recorded_at_event,
            },
        },
        "identity": {
            "name": backend.name,
            "provider": backend.provider,
            "profile": backend.profile,
            "model": backend.model,
        },
        "contract": {
            "sector_size": backend.sector_size,
            "sector_count": backend.sector_count,
            "read_only": backend.read_only,
            "max_transfer_sectors": backend.max_transfer_sectors,
            "device_features": backend.device_features,
            "driver_features": backend.driver_features,
            "negotiated_features": backend.negotiated_features,
            "request_queue_index": backend.request_queue_index,
            "queue_size": backend.queue_size,
            "irq_vector": backend.irq_vector,
        },
        "note": backend.note,
        "last_transition": {
            "recorded_at_event": backend.recorded_at_event,
            "block_device_generation": backend.block_device_generation,
            "driver_binding_generation": backend.driver_binding_generation,
            "device_generation": backend.device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_read_path_view_v1(read_path: &BlockReadPathManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-read-path",
        "id": read_path.id,
        "generation": read_path.generation,
        "state": read_path.state,
        "owner": {
            "block_request": object_ref_json(
                "block-request",
                read_path.block_request,
                read_path.block_request_generation,
            ),
        },
        "references": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&read_path.backend_kind),
                read_path.backend,
                read_path.backend_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                read_path.block_request,
                read_path.block_request_generation,
            ),
            "block_completion": object_ref_json(
                "block-completion",
                read_path.block_completion,
                read_path.block_completion_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                read_path.block_device,
                read_path.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                read_path.block_range,
                read_path.block_range_generation,
            ),
            "event": {
                "id": read_path.recorded_at_event,
            },
        },
        "read": {
            "sequence": read_path.sequence,
            "completed_bytes": read_path.completed_bytes,
            "data_digest": read_path.data_digest,
        },
        "note": read_path.note,
        "last_transition": {
            "recorded_at_event": read_path.recorded_at_event,
            "backend_generation": read_path.backend_generation,
            "block_request_generation": read_path.block_request_generation,
            "block_completion_generation": read_path.block_completion_generation,
            "block_device_generation": read_path.block_device_generation,
            "block_range_generation": read_path.block_range_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_write_path_view_v1(write_path: &BlockWritePathManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-write-path",
        "id": write_path.id,
        "generation": write_path.generation,
        "state": write_path.state,
        "owner": {
            "block_request": object_ref_json(
                "block-request",
                write_path.block_request,
                write_path.block_request_generation,
            ),
        },
        "references": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&write_path.backend_kind),
                write_path.backend,
                write_path.backend_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                write_path.block_request,
                write_path.block_request_generation,
            ),
            "block_completion": object_ref_json(
                "block-completion",
                write_path.block_completion,
                write_path.block_completion_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                write_path.block_device,
                write_path.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                write_path.block_range,
                write_path.block_range_generation,
            ),
            "event": {
                "id": write_path.recorded_at_event,
            },
        },
        "write": {
            "sequence": write_path.sequence,
            "completed_bytes": write_path.completed_bytes,
            "payload_digest": write_path.payload_digest,
        },
        "note": write_path.note,
        "last_transition": {
            "recorded_at_event": write_path.recorded_at_event,
            "backend_generation": write_path.backend_generation,
            "block_request_generation": write_path.block_request_generation,
            "block_completion_generation": write_path.block_completion_generation,
            "block_device_generation": write_path.block_device_generation,
            "block_range_generation": write_path.block_range_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_request_queue_view_v1(queue: &BlockRequestQueueManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-request-queue",
        "id": queue.id,
        "generation": queue.generation,
        "state": queue.state,
        "owner": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&queue.backend_kind),
                queue.backend,
                queue.backend_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                queue.block_device,
                queue.block_device_generation,
            ),
        },
        "references": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&queue.backend_kind),
                queue.backend,
                queue.backend_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                queue.block_device,
                queue.block_device_generation,
            ),
            "entries": queue
                .entries
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "request": object_ref_json(
                            "block-request",
                            entry.request,
                            entry.request_generation,
                        ),
                        "completion": optional_object_ref_json(
                            "block-completion",
                            entry.completion,
                            entry.completion_generation,
                        ),
                        "sequence": entry.sequence,
                        "operation": entry.operation,
                        "byte_len": entry.byte_len,
                        "state": entry.state,
                    })
                })
                .collect::<Vec<_>>(),
            "event": {
                "id": queue.recorded_at_event,
            },
        },
        "queue": {
            "depth": queue.depth,
            "entry_count": queue.entries.len(),
            "pending_count": queue.pending_count,
            "completed_count": queue.completed_count,
            "first_sequence": queue.first_sequence,
            "last_sequence": queue.last_sequence,
        },
        "note": queue.note,
        "last_transition": {
            "recorded_at_event": queue.recorded_at_event,
            "backend_generation": queue.backend_generation,
            "block_device_generation": queue.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_dma_buffer_view_v1(buffer: &BlockDmaBufferManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-dma-buffer",
        "id": buffer.id,
        "generation": buffer.generation,
        "state": buffer.state,
        "owner": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&buffer.backend_kind),
                buffer.backend,
                buffer.backend_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                buffer.block_request,
                buffer.block_request_generation,
            ),
        },
        "references": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&buffer.backend_kind),
                buffer.backend,
                buffer.backend_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                buffer.block_request,
                buffer.block_request_generation,
            ),
            "dma_buffer": object_ref_json(
                "dma-buffer",
                buffer.dma_buffer,
                buffer.dma_buffer_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                buffer.block_device,
                buffer.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                buffer.block_range,
                buffer.block_range_generation,
            ),
            "descriptor": object_ref_json(
                "descriptor",
                buffer.descriptor,
                buffer.descriptor_generation,
            ),
            "queue": object_ref_json("queue", buffer.queue, buffer.queue_generation),
            "event": {
                "id": buffer.recorded_at_event,
            },
        },
        "buffer": {
            "operation": buffer.operation,
            "access": buffer.access,
            "byte_len": buffer.byte_len,
            "buffer_len": buffer.buffer_len,
            "buffer_digest": buffer.buffer_digest,
        },
        "note": buffer.note,
        "last_transition": {
            "recorded_at_event": buffer.recorded_at_event,
            "block_request_generation": buffer.block_request_generation,
            "dma_buffer_generation": buffer.dma_buffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_page_object_view_v1(page: &BlockPageObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-page-object",
        "id": page.id,
        "generation": page.generation,
        "state": page.state,
        "owner": {
            "page": object_ref_manifest_json(&page.page),
            "block_dma_buffer": object_ref_json(
                "block-dma-buffer",
                page.block_dma_buffer,
                page.block_dma_buffer_generation,
            ),
        },
        "references": {
            "block_dma_buffer": object_ref_json(
                "block-dma-buffer",
                page.block_dma_buffer,
                page.block_dma_buffer_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                page.block_request,
                page.block_request_generation,
            ),
            "block_completion": object_ref_json(
                "block-completion",
                page.block_completion,
                page.block_completion_generation,
            ),
            "dma_buffer": object_ref_json(
                "dma-buffer",
                page.dma_buffer,
                page.dma_buffer_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                page.block_device,
                page.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                page.block_range,
                page.block_range_generation,
            ),
            "aspace": object_ref_manifest_json(&page.aspace),
            "vma_region": object_ref_manifest_json(&page.vma_region),
            "page": object_ref_manifest_json(&page.page),
            "event": {
                "id": page.recorded_at_event,
            },
        },
        "page": {
            "dirty_generation": page.page_dirty_generation,
            "backing": page.page_backing,
            "cow_state": page.cow_state,
            "page_state": page.page_state,
            "offset": page.page_offset,
            "byte_len": page.byte_len,
            "operation": page.operation,
        },
        "note": page.note,
        "last_transition": {
            "recorded_at_event": page.recorded_at_event,
            "block_dma_buffer_generation": page.block_dma_buffer_generation,
            "page_generation": page.page.generation,
            "page_dirty_generation": page.page_dirty_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn buffer_cache_object_view_v1(cache: &BufferCacheObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "buffer-cache-object",
        "id": cache.id,
        "generation": cache.generation,
        "state": cache.state,
        "owner": {
            "page": object_ref_manifest_json(&cache.page),
            "block_range": object_ref_json(
                "block-range",
                cache.block_range,
                cache.block_range_generation,
            ),
        },
        "references": {
            "block_page_object": object_ref_json(
                "block-page-object",
                cache.block_page_object,
                cache.block_page_object_generation,
            ),
            "block_dma_buffer": object_ref_json(
                "block-dma-buffer",
                cache.block_dma_buffer,
                cache.block_dma_buffer_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                cache.block_device,
                cache.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                cache.block_range,
                cache.block_range_generation,
            ),
            "aspace": object_ref_manifest_json(&cache.aspace),
            "vma_region": object_ref_manifest_json(&cache.vma_region),
            "page": object_ref_manifest_json(&cache.page),
            "event": {
                "id": cache.recorded_at_event,
            },
        },
        "cache": {
            "page_dirty_generation": cache.page_dirty_generation,
            "page_offset": cache.page_offset,
            "block_offset": cache.block_offset,
            "byte_len": cache.byte_len,
            "operation": cache.operation,
            "cache_state": cache.cache_state,
            "coherency_epoch": cache.coherency_epoch,
        },
        "note": cache.note,
        "last_transition": {
            "recorded_at_event": cache.recorded_at_event,
            "block_page_object_generation": cache.block_page_object_generation,
            "page_generation": cache.page.generation,
            "page_dirty_generation": cache.page_dirty_generation,
            "coherency_epoch": cache.coherency_epoch,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn file_object_view_v1(file: &FileObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "file-object",
        "id": file.id,
        "generation": file.generation,
        "state": file.state,
        "owner": {
            "namespace": file.namespace,
            "file_key": file.file_key,
            "path": file.path,
        },
        "references": {
            "buffer_cache_object": object_ref_json(
                "buffer-cache-object",
                file.buffer_cache_object,
                file.buffer_cache_object_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                file.block_device,
                file.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                file.block_range,
                file.block_range_generation,
            ),
            "page": object_ref_manifest_json(&file.page),
            "event": {
                "id": file.recorded_at_event,
            },
        },
        "file": {
            "file_offset": file.file_offset,
            "byte_len": file.byte_len,
            "file_size": file.file_size,
            "content_digest": file.content_digest,
            "cache_state": file.cache_state,
            "page_dirty_generation": file.page_dirty_generation,
        },
        "note": file.note,
        "last_transition": {
            "recorded_at_event": file.recorded_at_event,
            "buffer_cache_object_generation": file.buffer_cache_object_generation,
            "page_generation": file.page.generation,
            "page_dirty_generation": file.page_dirty_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn directory_object_view_v1(directory: &DirectoryObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "directory-object",
        "id": directory.id,
        "generation": directory.generation,
        "state": directory.state,
        "owner": {
            "namespace": directory.namespace,
            "directory_key": directory.directory_key,
            "directory_path": directory.directory_path,
            "entry_name": directory.entry_name,
        },
        "references": {
            "file_object": object_ref_json(
                "file-object",
                directory.file_object,
                directory.file_object_generation,
            ),
            "event": {
                "id": directory.recorded_at_event,
            },
        },
        "directory": {
            "entry_kind": directory.entry_kind,
            "child_file_key": directory.child_file_key,
            "child_path": directory.child_path,
            "file_size": directory.file_size,
            "content_digest": directory.content_digest,
        },
        "note": directory.note,
        "last_transition": {
            "recorded_at_event": directory.recorded_at_event,
            "file_object_generation": directory.file_object_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn fat_adapter_object_view_v1(adapter: &FatAdapterObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "fat-adapter-object",
        "id": adapter.id,
        "generation": adapter.generation,
        "state": adapter.state,
        "owner": {
            "implementation": adapter.implementation,
            "version": adapter.version,
            "profile": adapter.profile,
            "volume_label": adapter.volume_label,
            "adapter_path": adapter.adapter_path,
            "semantic_path": adapter.semantic_path,
        },
        "references": {
            "directory_object": object_ref_json(
                "directory-object",
                adapter.directory_object,
                adapter.directory_object_generation,
            ),
            "file_object": object_ref_json(
                "file-object",
                adapter.file_object,
                adapter.file_object_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                adapter.block_device,
                adapter.block_device_generation,
            ),
            "event": {
                "id": adapter.recorded_at_event,
            },
        },
        "fat": {
            "image_bytes": adapter.image_bytes,
            "bytes_written": adapter.bytes_written,
            "bytes_read": adapter.bytes_read,
            "write_digest": adapter.write_digest,
            "read_digest": adapter.read_digest,
            "file_content_digest": adapter.file_content_digest,
        },
        "note": adapter.note,
        "last_transition": {
            "recorded_at_event": adapter.recorded_at_event,
            "directory_object_generation": adapter.directory_object_generation,
            "file_object_generation": adapter.file_object_generation,
            "block_device_generation": adapter.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn ext4_adapter_object_view_v1(adapter: &Ext4AdapterObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "ext4-adapter-object",
        "id": adapter.id,
        "generation": adapter.generation,
        "state": adapter.state,
        "owner": {
            "implementation": adapter.implementation,
            "version": adapter.version,
            "profile": adapter.profile,
            "volume_label": adapter.volume_label,
            "adapter_path": adapter.adapter_path,
            "semantic_path": adapter.semantic_path,
        },
        "references": {
            "directory_object": object_ref_json(
                "directory-object",
                adapter.directory_object,
                adapter.directory_object_generation,
            ),
            "file_object": object_ref_json(
                "file-object",
                adapter.file_object,
                adapter.file_object_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                adapter.block_device,
                adapter.block_device_generation,
            ),
            "event": {
                "id": adapter.recorded_at_event,
            },
        },
        "ext4": {
            "image_bytes": adapter.image_bytes,
            "bytes_read": adapter.bytes_read,
            "read_digest": adapter.read_digest,
            "file_content_digest": adapter.file_content_digest,
            "directory_entries": adapter.directory_entries,
            "read_only_enforced": adapter.read_only_enforced,
        },
        "note": adapter.note,
        "last_transition": {
            "recorded_at_event": adapter.recorded_at_event,
            "directory_object_generation": adapter.directory_object_generation,
            "file_object_generation": adapter.file_object_generation,
            "block_device_generation": adapter.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn file_handle_capability_view_v1(capability: &FileHandleCapabilityManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "file-handle-capability",
        "id": capability.id,
        "generation": capability.generation,
        "state": capability.state,
        "owner": {
            "store": object_ref_json(
                "store",
                capability.owner_store,
                capability.owner_store_generation,
            ),
            "operation": capability.operation,
        },
        "references": {
            "file_object": object_ref_json(
                "file-object",
                capability.file_object,
                capability.file_object_generation,
            ),
            "directory_object": object_ref_json(
                "directory-object",
                capability.directory_object,
                capability.directory_object_generation,
            ),
            "capability": object_ref_json(
                "capability",
                capability.capability,
                capability.capability_generation,
            ),
            "event": {
                "id": capability.recorded_at_event,
            },
        },
        "handle": {
            "slot": capability.handle_slot,
            "generation": capability.handle_generation,
            "tag": capability.handle_tag,
        },
        "file_access": {
            "operation": capability.operation,
            "file_offset": capability.file_offset,
            "byte_len": capability.byte_len,
            "content_digest": capability.content_digest,
        },
        "note": capability.note,
        "last_transition": {
            "recorded_at_event": capability.recorded_at_event,
            "owner_store_generation": capability.owner_store_generation,
            "file_object_generation": capability.file_object_generation,
            "directory_object_generation": capability.directory_object_generation,
            "capability_generation": capability.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn fs_wait_view_v1(wait: &FsWaitManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "fs-wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "store": object_ref_json(
                "store",
                wait.owner_store,
                wait.owner_store_generation,
            ),
            "operation": wait.operation,
        },
        "references": {
            "wait": object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "owner_store": object_ref_json(
                "store",
                wait.owner_store,
                wait.owner_store_generation,
            ),
            "file_object": object_ref_json(
                "file-object",
                wait.file_object,
                wait.file_object_generation,
            ),
            "directory_object": object_ref_json(
                "directory-object",
                wait.directory_object,
                wait.directory_object_generation,
            ),
            "file_handle_capability": object_ref_json(
                "file-handle-capability",
                wait.file_handle_capability,
                wait.file_handle_capability_generation,
            ),
            "blocker": object_ref_manifest_json(&wait.blocker),
            "created_event": {
                "id": wait.created_at_event,
            },
            "completed_event": wait.completed_at_event.map(|id| serde_json::json!({ "id": id })),
        },
        "wait": {
            "operation": wait.operation,
            "sequence": wait.sequence,
            "byte_len": wait.byte_len,
            "cancel_reason": wait.cancel_reason,
        },
        "note": wait.note,
        "last_transition": {
            "created_at_event": wait.created_at_event,
            "completed_at_event": wait.completed_at_event,
            "wait_generation": wait.wait_generation,
            "file_handle_capability_generation": wait.file_handle_capability_generation,
        },
        "last_error": wait.cancel_reason.as_ref().map(|reason| serde_json::json!({
            "cancel_reason": reason,
        })).unwrap_or(serde_json::Value::Null),
    })
}

fn block_driver_cleanup_view_v1(cleanup: &BlockDriverCleanupManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-driver-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                cleanup.block_device,
                cleanup.block_device_generation,
            ),
        },
        "references": {
            "io_cleanup": object_ref_json(
                "io-cleanup",
                cleanup.io_cleanup,
                cleanup.io_cleanup_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "device": object_ref_json(
                "device",
                cleanup.device,
                cleanup.device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                cleanup.block_device,
                cleanup.block_device_generation,
            ),
            "backend": object_ref_manifest_json(&cleanup.backend),
            "cancelled_block_waits": cleanup
                .cancelled_block_waits
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "cancelled_wait_tokens": cleanup
                .cancelled_wait_tokens
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "revoked_device_capabilities": cleanup
                .revoked_device_capabilities
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "released_dma_buffers": cleanup
                .released_dma_buffers
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "started_event": {
                "id": cleanup.started_at_event,
            },
            "completed_event": cleanup.completed_at_event.map(|id| serde_json::json!({ "id": id })),
        },
        "cleanup": {
            "reason": cleanup.reason,
            "cancelled_block_wait_count": cleanup.cancelled_block_waits.len(),
            "released_dma_buffer_count": cleanup.released_dma_buffers.len(),
            "revoked_device_capability_count": cleanup.revoked_device_capabilities.len(),
        },
        "note": cleanup.note,
        "last_transition": {
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
            "io_cleanup_generation": cleanup.io_cleanup_generation,
            "driver_store_generation": cleanup.driver_store_generation,
            "block_device_generation": cleanup.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_pending_io_policy_view_v1(policy: &BlockPendingIoPolicyManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-pending-io-policy",
        "id": policy.id,
        "generation": policy.generation,
        "state": policy.state,
        "owner": {
            "block_wait": object_ref_json(
                "block-wait",
                policy.block_wait,
                policy.block_wait_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                policy.block_request,
                policy.block_request_generation,
            ),
        },
        "references": {
            "block_wait": object_ref_json(
                "block-wait",
                policy.block_wait,
                policy.block_wait_generation,
            ),
            "wait": object_ref_json("wait-token", policy.wait, policy.wait_generation),
            "block_request": object_ref_json(
                "block-request",
                policy.block_request,
                policy.block_request_generation,
            ),
            "retry_request": optional_object_ref_json(
                "block-request",
                policy.retry_request,
                policy.retry_request_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                policy.block_device,
                policy.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                policy.block_range,
                policy.block_range_generation,
            ),
            "event": {
                "id": policy.recorded_at_event,
            },
        },
        "policy": {
            "operation": policy.operation,
            "sequence": policy.sequence,
            "byte_len": policy.byte_len,
            "action": policy.action,
            "errno": policy.errno,
            "retry_attempt": policy.retry_attempt,
            "max_retries": policy.max_retries,
        },
        "note": policy.note,
        "last_transition": {
            "recorded_at_event": policy.recorded_at_event,
            "block_wait_generation": policy.block_wait_generation,
            "block_request_generation": policy.block_request_generation,
            "retry_request_generation": policy.retry_request_generation,
        },
        "last_error": if policy.action == "eio" {
            serde_json::json!({ "errno": policy.errno })
        } else {
            serde_json::Value::Null
        },
    })
}

fn block_request_generation_audit_view_v1(
    audit: &BlockRequestGenerationAuditManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-request-generation-audit",
        "id": audit.id,
        "generation": audit.generation,
        "state": audit.state,
        "owner": {
            "block_request": object_ref_json(
                "block-request",
                audit.block_request,
                audit.block_request_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                audit.block_device,
                audit.block_device_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                audit.block_device,
                audit.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                audit.block_range,
                audit.block_range_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                audit.block_request,
                audit.block_request_generation,
            ),
            "backend": object_ref_manifest_json(&audit.backend),
            "dma_buffer": object_ref_manifest_json(&audit.dma_buffer),
            "event": {
                "id": audit.recorded_at_event,
            },
        },
        "audit": {
            "rejected_completion_generation_probes": audit.rejected_completion_generation_probes,
            "rejected_wait_generation_probes": audit.rejected_wait_generation_probes,
            "rejected_dma_generation_probes": audit.rejected_dma_generation_probes,
            "rejected_queue_generation_probes": audit.rejected_queue_generation_probes,
        },
        "note": audit.note,
        "last_transition": {
            "recorded_at_event": audit.recorded_at_event,
            "block_device_generation": audit.block_device_generation,
            "block_range_generation": audit.block_range_generation,
            "block_request_generation": audit.block_request_generation,
            "backend_generation": audit.backend.generation,
            "dma_buffer_generation": audit.dma_buffer.generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_benchmark_view_v1(benchmark: &BlockBenchmarkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
        },
        "references": {
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                benchmark.block_range,
                benchmark.block_range_generation,
            ),
            "read_path": object_ref_json(
                "block-read-path",
                benchmark.read_path,
                benchmark.read_path_generation,
            ),
            "write_path": object_ref_json(
                "block-write-path",
                benchmark.write_path,
                benchmark.write_path_generation,
            ),
            "request_queue": object_ref_json(
                "block-request-queue",
                benchmark.request_queue,
                benchmark.request_queue_generation,
            ),
            "block_dma_buffer": object_ref_json(
                "block-dma-buffer",
                benchmark.block_dma_buffer,
                benchmark.block_dma_buffer_generation,
            ),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "sample_requests": benchmark.sample_requests,
            "sample_bytes": benchmark.sample_bytes,
            "read_completed_requests": benchmark.read_completed_requests,
            "write_completed_requests": benchmark.write_completed_requests,
            "queue_completed_requests": benchmark.queue_completed_requests,
            "measured_nanos": benchmark.measured_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "iops": benchmark.iops,
            "throughput_bytes_per_sec": benchmark.throughput_bytes_per_sec,
            "p50_latency_nanos": benchmark.p50_latency_nanos,
            "p99_latency_nanos": benchmark.p99_latency_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "backend_generation": benchmark.backend.generation,
            "block_device_generation": benchmark.block_device_generation,
            "block_range_generation": benchmark.block_range_generation,
            "read_path_generation": benchmark.read_path_generation,
            "write_path_generation": benchmark.write_path_generation,
            "request_queue_generation": benchmark.request_queue_generation,
            "block_dma_buffer_generation": benchmark.block_dma_buffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn block_recovery_benchmark_view_v1(
    benchmark: &BlockRecoveryBenchmarkManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-recovery-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
        },
        "references": {
            "cleanup": object_ref_json(
                "block-driver-cleanup",
                benchmark.cleanup,
                benchmark.cleanup_generation,
            ),
            "io_cleanup": object_ref_json(
                "io-cleanup",
                benchmark.io_cleanup,
                benchmark.io_cleanup_generation,
            ),
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
            "device": object_ref_json("device", benchmark.device, benchmark.device_generation),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                benchmark.driver_binding,
                benchmark.driver_binding_generation,
            ),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "recovery_start_event": benchmark.recovery_start_event,
            "recovery_complete_event": benchmark.recovery_complete_event,
            "cancelled_block_waits": benchmark.cancelled_block_waits,
            "cancelled_wait_tokens": benchmark.cancelled_wait_tokens,
            "released_dma_buffers": benchmark.released_dma_buffers,
            "revoked_device_capabilities": benchmark.revoked_device_capabilities,
            "recovery_nanos": benchmark.recovery_nanos,
            "budget_nanos": benchmark.budget_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "cleanup_generation": benchmark.cleanup_generation,
            "io_cleanup_generation": benchmark.io_cleanup_generation,
            "backend_generation": benchmark.backend.generation,
            "block_device_generation": benchmark.block_device_generation,
            "driver_store_generation": benchmark.driver_store_generation,
            "device_generation": benchmark.device_generation,
            "driver_binding_generation": benchmark.driver_binding_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn target_feature_set_view_v1(feature: &TargetFeatureSetManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "target-feature-set",
        "id": feature.id,
        "generation": feature.generation,
        "state": feature.state,
        "owner": {
            "target_profile": feature.target_profile,
            "target_arch": feature.target_arch,
        },
        "references": {
            "event": {
                "id": feature.recorded_at_event,
            },
        },
        "features": {
            "base_isa": feature.base_isa,
            "simd": {
                "abi": feature.simd_abi,
                "supported": feature.simd_supported,
                "vector_register_count": feature.vector_register_count,
                "vector_register_bits": feature.vector_register_bits,
                "scalar_fallback": feature.scalar_fallback,
                "unsupported_reason": feature.unsupported_reason,
            },
        },
        "discovery": {
            "name": feature.name,
            "source": feature.discovery_source,
        },
        "note": feature.note,
        "last_transition": {
            "recorded_at_event": feature.recorded_at_event,
            "simd_supported": feature.simd_supported,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn vector_state_view_v1(vector_state: &VectorStateManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "vector-state",
        "id": vector_state.id,
        "generation": vector_state.generation,
        "state": vector_state.state,
        "owner": {
            "activation": object_ref_manifest_json(&vector_state.owner_activation),
            "store": object_ref_manifest_json(&vector_state.owner_store),
        },
        "references": {
            "code_object": object_ref_manifest_json(&vector_state.code_object),
            "target_feature_set": object_ref_manifest_json(&vector_state.target_feature_set),
            "event": {
                "id": vector_state.recorded_at_event,
            },
        },
        "simd": {
            "abi": vector_state.simd_abi,
            "vector_register_count": vector_state.vector_register_count,
            "vector_register_bits": vector_state.vector_register_bits,
            "register_bytes": vector_state.register_bytes,
        },
        "note": vector_state.note,
        "last_transition": {
            "recorded_at_event": vector_state.recorded_at_event,
            "state": vector_state.state,
        },
        "last_error": if vector_state.state == "unavailable" {
            serde_json::json!("simd-unavailable")
        } else {
            serde_json::Value::Null
        },
    })
}

fn simd_fault_injection_view_v1(injection: &SimdFaultInjectionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "simd-fault-injection",
        "id": injection.id,
        "generation": injection.generation,
        "state": injection.state,
        "owner": {
            "activation": object_ref_manifest_json(&injection.activation),
        },
        "references": {
            "activation": object_ref_manifest_json(&injection.activation),
            "code_object": object_ref_manifest_json(&injection.code_object),
            "trap": object_ref_manifest_json(&injection.trap),
            "target_feature_set": object_ref_manifest_json(&injection.target_feature_set),
            "vector_state": injection.vector_state.as_ref().map(object_ref_manifest_json),
            "event": {
                "id": injection.recorded_at_event,
            },
        },
        "fault": {
            "kind": injection.kind,
            "effect": injection.effect,
            "required_abi": injection.required_abi,
            "vector_register_count": injection.vector_register_count,
            "vector_register_bits": injection.vector_register_bits,
            "injected_faults": injection.injected_faults,
        },
        "note": injection.note,
        "last_transition": {
            "recorded_at_event": injection.recorded_at_event,
            "effect": injection.effect,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn simd_benchmark_view_v1(benchmark: &SimdBenchmarkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "simd-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
        },
        "references": {
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
            "scalar_code_object": object_ref_manifest_json(&benchmark.scalar_code_object),
            "vector_code_object": object_ref_manifest_json(&benchmark.vector_code_object),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "simd": {
            "abi": benchmark.simd_abi,
            "vector_register_count": benchmark.vector_register_count,
            "vector_register_bits": benchmark.vector_register_bits,
        },
        "metrics": {
            "workload_units": benchmark.workload_units,
            "scalar_nanos": benchmark.scalar_nanos,
            "vector_nanos": benchmark.vector_nanos,
            "speedup_milli": benchmark.speedup_milli,
            "context_overhead_nanos": benchmark.context_overhead_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "state": benchmark.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn simd_context_switch_benchmark_view_v1(
    benchmark: &SimdContextSwitchBenchmarkManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "simd-context-switch-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
            "activation_resume": object_ref_manifest_json(&benchmark.activation_resume),
        },
        "references": {
            "preemption": object_ref_manifest_json(&benchmark.preemption),
            "activation_resume": object_ref_manifest_json(&benchmark.activation_resume),
            "saved_vector_state": object_ref_manifest_json(&benchmark.saved_vector_state),
            "restored_vector_state": object_ref_manifest_json(&benchmark.restored_vector_state),
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "simd": {
            "abi": benchmark.simd_abi,
            "vector_register_count": benchmark.vector_register_count,
            "vector_register_bits": benchmark.vector_register_bits,
        },
        "metrics": {
            "sample_count": benchmark.sample_count,
            "scalar_context_switch_nanos": benchmark.scalar_context_switch_nanos,
            "vector_context_switch_nanos": benchmark.vector_context_switch_nanos,
            "overhead_nanos": benchmark.overhead_nanos,
            "budget_nanos": benchmark.budget_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "state": benchmark.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn packet_buffer_object_view_v1(packet_buffer: &PacketBufferObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "packet-buffer",
        "id": packet_buffer.id,
        "generation": packet_buffer.generation,
        "state": packet_buffer.state,
        "owner": {
            "packet_device": object_ref_json(
                "packet-device",
                packet_buffer.packet_device,
                packet_buffer.packet_device_generation
            ),
        },
        "references": {
            "packet_device": object_ref_json(
                "packet-device",
                packet_buffer.packet_device,
                packet_buffer.packet_device_generation
            ),
            "event": {
                "id": packet_buffer.recorded_at_event,
            },
        },
        "contract": {
            "direction": packet_buffer.direction,
            "frame_format_version": packet_buffer.frame_format_version,
            "capacity": packet_buffer.capacity,
            "payload_len": packet_buffer.payload_len,
            "sequence": packet_buffer.sequence,
        },
        "note": packet_buffer.note,
        "last_transition": {
            "recorded_at_event": packet_buffer.recorded_at_event,
            "packet_device_generation": packet_buffer.packet_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn packet_queue_object_view_v1(packet_queue: &PacketQueueObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "packet-queue",
        "id": packet_queue.id,
        "generation": packet_queue.generation,
        "state": packet_queue.state,
        "owner": {
            "packet_device": object_ref_json(
                "packet-device",
                packet_queue.packet_device,
                packet_queue.packet_device_generation
            ),
        },
        "references": {
            "packet_device": object_ref_json(
                "packet-device",
                packet_queue.packet_device,
                packet_queue.packet_device_generation
            ),
            "event": {
                "id": packet_queue.recorded_at_event,
            },
        },
        "identity": {
            "name": packet_queue.name,
            "role": packet_queue.role,
            "queue_index": packet_queue.queue_index,
        },
        "contract": {
            "depth": packet_queue.depth,
        },
        "note": packet_queue.note,
        "last_transition": {
            "recorded_at_event": packet_queue.recorded_at_event,
            "packet_device_generation": packet_queue.packet_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn packet_descriptor_object_view_v1(
    packet_descriptor: &PacketDescriptorObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "packet-descriptor",
        "id": packet_descriptor.id,
        "generation": packet_descriptor.generation,
        "state": packet_descriptor.state,
        "owner": {
            "packet_queue": object_ref_json(
                "packet-queue",
                packet_descriptor.packet_queue,
                packet_descriptor.packet_queue_generation
            ),
            "packet_buffer": object_ref_json(
                "packet-buffer",
                packet_descriptor.packet_buffer,
                packet_descriptor.packet_buffer_generation
            ),
        },
        "references": {
            "packet_queue": object_ref_json(
                "packet-queue",
                packet_descriptor.packet_queue,
                packet_descriptor.packet_queue_generation
            ),
            "packet_buffer": object_ref_json(
                "packet-buffer",
                packet_descriptor.packet_buffer,
                packet_descriptor.packet_buffer_generation
            ),
            "event": {
                "id": packet_descriptor.recorded_at_event,
            },
        },
        "identity": {
            "slot": packet_descriptor.slot,
        },
        "contract": {
            "length": packet_descriptor.length,
        },
        "note": packet_descriptor.note,
        "last_transition": {
            "recorded_at_event": packet_descriptor.recorded_at_event,
            "packet_queue_generation": packet_descriptor.packet_queue_generation,
            "packet_buffer_generation": packet_descriptor.packet_buffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn fake_net_backend_object_view_v1(backend: &FakeNetBackendObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "fake-net-backend",
        "id": backend.id,
        "generation": backend.generation,
        "state": backend.state,
        "owner": {
            "packet_device": object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation
            ),
        },
        "references": {
            "packet_device": object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation
            ),
            "event": {
                "id": backend.recorded_at_event,
            },
        },
        "identity": {
            "name": backend.name,
            "provider": backend.provider,
            "profile": backend.profile,
            "deterministic_seed": backend.deterministic_seed,
        },
        "contract": {
            "mtu": backend.mtu,
            "rx_queue_depth": backend.rx_queue_depth,
            "tx_queue_depth": backend.tx_queue_depth,
            "mac": backend.mac,
            "frame_format_version": backend.frame_format_version,
            "max_payload_len": backend.max_payload_len,
        },
        "note": backend.note,
        "last_transition": {
            "recorded_at_event": backend.recorded_at_event,
            "packet_device_generation": backend.packet_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn virtio_net_backend_object_view_v1(
    backend: &VirtioNetBackendObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "virtio-net-backend",
        "id": backend.id,
        "generation": backend.generation,
        "state": backend.state,
        "owner": {
            "packet_device": object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
        },
        "references": {
            "packet_device": object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
            "device": object_ref_json("device", backend.device, backend.device_generation),
            "event": {
                "id": backend.recorded_at_event,
            },
        },
        "identity": {
            "name": backend.name,
            "provider": backend.provider,
            "profile": backend.profile,
            "model": backend.model,
        },
        "contract": {
            "mtu": backend.mtu,
            "rx_queue_depth": backend.rx_queue_depth,
            "tx_queue_depth": backend.tx_queue_depth,
            "mac": backend.mac,
            "frame_format_version": backend.frame_format_version,
            "max_payload_len": backend.max_payload_len,
            "device_features": backend.device_features,
            "driver_features": backend.driver_features,
            "negotiated_features": backend.negotiated_features,
            "rx_queue_index": backend.rx_queue_index,
            "tx_queue_index": backend.tx_queue_index,
            "queue_size": backend.queue_size,
            "irq_vector": backend.irq_vector,
        },
        "note": backend.note,
        "last_transition": {
            "recorded_at_event": backend.recorded_at_event,
            "packet_device_generation": backend.packet_device_generation,
            "driver_binding_generation": backend.driver_binding_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_rx_interrupt_view_v1(rx: &NetworkRxInterruptManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-rx-interrupt",
        "id": rx.id,
        "generation": rx.generation,
        "state": rx.state,
        "owner": {
            "virtio_net_backend": object_ref_json(
                "virtio-net-backend",
                rx.virtio_net_backend,
                rx.virtio_net_backend_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                rx.packet_device,
                rx.packet_device_generation,
            ),
        },
        "references": {
            "virtio_net_backend": object_ref_json(
                "virtio-net-backend",
                rx.virtio_net_backend,
                rx.virtio_net_backend_generation,
            ),
            "irq_event": object_ref_json(
                "irq-event",
                rx.irq_event,
                rx.irq_event_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                rx.packet_device,
                rx.packet_device_generation,
            ),
            "rx_queue": object_ref_json(
                "packet-queue",
                rx.rx_queue,
                rx.rx_queue_generation,
            ),
            "event": {
                "id": rx.recorded_at_event,
            },
        },
        "readiness": {
            "ready_descriptors": rx.ready_descriptors,
            "sequence": rx.sequence,
        },
        "note": rx.note,
        "last_transition": {
            "recorded_at_event": rx.recorded_at_event,
            "irq_event_generation": rx.irq_event_generation,
            "rx_queue_generation": rx.rx_queue_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_rx_wait_resolution_view_v1(
    resolution: &NetworkRxWaitResolutionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-rx-wait-resolution",
        "id": resolution.id,
        "generation": resolution.generation,
        "state": resolution.state,
        "owner": {
            "io_wait": object_ref_json(
                "io-wait",
                resolution.io_wait,
                resolution.io_wait_generation,
            ),
            "wait": object_ref_json(
                "wait-token",
                resolution.wait,
                resolution.wait_generation,
            ),
        },
        "references": {
            "io_wait": object_ref_json(
                "io-wait",
                resolution.io_wait,
                resolution.io_wait_generation,
            ),
            "wait": object_ref_json(
                "wait-token",
                resolution.wait,
                resolution.wait_generation,
            ),
            "rx_interrupt": object_ref_json(
                "network-rx-interrupt",
                resolution.rx_interrupt,
                resolution.rx_interrupt_generation,
            ),
            "irq_event": object_ref_json(
                "irq-event",
                resolution.irq_event,
                resolution.irq_event_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                resolution.packet_device,
                resolution.packet_device_generation,
            ),
            "rx_queue": object_ref_json(
                "packet-queue",
                resolution.rx_queue,
                resolution.rx_queue_generation,
            ),
            "event": {
                "id": resolution.resolved_at_event,
            },
        },
        "readiness": {
            "ready_descriptors": resolution.ready_descriptors,
            "sequence": resolution.sequence,
        },
        "note": resolution.note,
        "last_transition": {
            "resolved_at_event": resolution.resolved_at_event,
            "io_wait_generation": resolution.io_wait_generation,
            "rx_interrupt_generation": resolution.rx_interrupt_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_tx_capability_gate_view_v1(gate: &NetworkTxCapabilityGateManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-tx-capability-gate",
        "id": gate.id,
        "generation": gate.generation,
        "state": gate.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                gate.driver_store,
                gate.driver_store_generation,
            ),
        },
        "references": {
            "packet_device": object_ref_json(
                "packet-device",
                gate.packet_device,
                gate.packet_device_generation,
            ),
            "tx_queue": object_ref_json(
                "packet-queue",
                gate.tx_queue,
                gate.tx_queue_generation,
            ),
            "packet_descriptor": object_ref_json(
                "packet-descriptor",
                gate.packet_descriptor,
                gate.packet_descriptor_generation,
            ),
            "packet_buffer": object_ref_json(
                "packet-buffer",
                gate.packet_buffer,
                gate.packet_buffer_generation,
            ),
            "device_capability": object_ref_json(
                "device-capability",
                gate.device_capability,
                gate.device_capability_generation,
            ),
            "capability": object_ref_json(
                "capability",
                gate.capability,
                gate.capability_generation,
            ),
            "event": {
                "id": gate.recorded_at_event,
            },
        },
        "authority": {
            "class": "packet-device",
            "operation": gate.operation,
            "handle_slot": gate.handle_slot,
            "handle_generation": gate.handle_generation,
            "handle_tag": gate.handle_tag,
        },
        "tx": {
            "byte_len": gate.byte_len,
            "sequence": gate.sequence,
        },
        "note": gate.note,
        "last_transition": {
            "recorded_at_event": gate.recorded_at_event,
            "packet_descriptor_generation": gate.packet_descriptor_generation,
            "capability_generation": gate.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_tx_completion_view_v1(completion: &NetworkTxCompletionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-tx-completion",
        "id": completion.id,
        "generation": completion.generation,
        "state": completion.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                completion.driver_store,
                completion.driver_store_generation,
            ),
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&completion.backend_kind),
                completion.backend,
                completion.backend_generation,
            ),
        },
        "references": {
            "tx_gate": object_ref_json(
                "network-tx-capability-gate",
                completion.tx_gate,
                completion.tx_gate_generation,
            ),
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&completion.backend_kind),
                completion.backend,
                completion.backend_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                completion.packet_device,
                completion.packet_device_generation,
            ),
            "tx_queue": object_ref_json(
                "packet-queue",
                completion.tx_queue,
                completion.tx_queue_generation,
            ),
            "packet_descriptor": object_ref_json(
                "packet-descriptor",
                completion.packet_descriptor,
                completion.packet_descriptor_generation,
            ),
            "packet_buffer": object_ref_json(
                "packet-buffer",
                completion.packet_buffer,
                completion.packet_buffer_generation,
            ),
            "event": {
                "id": completion.completed_at_event,
            },
        },
        "tx": {
            "byte_len": completion.byte_len,
            "sequence": completion.sequence,
            "completion_sequence": completion.completion_sequence,
        },
        "note": completion.note,
        "last_transition": {
            "completed_at_event": completion.completed_at_event,
            "tx_gate_generation": completion.tx_gate_generation,
            "backend_generation": completion.backend_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_stack_adapter_view_v1(adapter: &NetworkStackAdapterManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-stack-adapter",
        "id": adapter.id,
        "generation": adapter.generation,
        "state": adapter.state,
        "owner": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&adapter.backend_kind),
                adapter.backend,
                adapter.backend_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                adapter.packet_device,
                adapter.packet_device_generation,
            ),
        },
        "references": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&adapter.backend_kind),
                adapter.backend,
                adapter.backend_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                adapter.packet_device,
                adapter.packet_device_generation,
            ),
            "rx_queue": object_ref_json(
                "packet-queue",
                adapter.rx_queue,
                adapter.rx_queue_generation,
            ),
            "tx_queue": object_ref_json(
                "packet-queue",
                adapter.tx_queue,
                adapter.tx_queue_generation,
            ),
            "event": {
                "id": adapter.recorded_at_event,
            },
        },
        "adapter": {
            "implementation": adapter.implementation,
            "implementation_version": adapter.implementation_version,
            "profile": adapter.profile,
            "medium": adapter.medium,
            "socket_capacity": adapter.socket_capacity,
        },
        "network": {
            "mac": adapter.mac,
            "ipv4_addr": adapter.ipv4_addr,
            "ipv4_prefix_len": adapter.ipv4_prefix_len,
            "mtu": adapter.mtu,
            "rx_queue_depth": adapter.rx_queue_depth,
            "tx_queue_depth": adapter.tx_queue_depth,
            "max_payload_len": adapter.max_payload_len,
        },
        "note": adapter.note,
        "last_transition": {
            "recorded_at_event": adapter.recorded_at_event,
            "backend_generation": adapter.backend_generation,
            "packet_device_generation": adapter.packet_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn socket_object_view_v1(socket: &SocketObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "socket-object",
        "id": socket.id,
        "generation": socket.generation,
        "state": socket.state,
        "owner": {
            "store": object_ref_json("store", socket.owner_store, socket.owner_store_generation),
        },
        "references": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                socket.adapter,
                socket.adapter_generation,
            ),
            "owner_store": object_ref_json("store", socket.owner_store, socket.owner_store_generation),
            "event": {
                "id": socket.created_at_event,
            },
        },
        "socket": {
            "domain": socket.domain,
            "type": socket.socket_type,
            "protocol": socket.protocol,
            "canonical_protocol": socket.canonical_protocol,
            "family": socket.family,
            "transport": socket.transport,
        },
        "note": socket.note,
        "last_transition": {
            "created_at_event": socket.created_at_event,
            "adapter_generation": socket.adapter_generation,
            "owner_store_generation": socket.owner_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn endpoint_object_view_v1(endpoint: &EndpointObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "endpoint-object",
        "id": endpoint.id,
        "generation": endpoint.generation,
        "state": endpoint.state,
        "owner": {
            "store": object_ref_json(
                "store",
                endpoint.owner_store,
                endpoint.owner_store_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                endpoint.socket,
                endpoint.socket_generation,
            ),
        },
        "references": {
            "socket": object_ref_json(
                "socket-object",
                endpoint.socket,
                endpoint.socket_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                endpoint.adapter,
                endpoint.adapter_generation,
            ),
            "owner_store": object_ref_json(
                "store",
                endpoint.owner_store,
                endpoint.owner_store_generation,
            ),
            "event": {
                "id": endpoint.created_at_event,
            },
        },
        "endpoint": {
            "family": endpoint.family,
            "transport": endpoint.transport,
            "local_addr": endpoint.local_addr,
            "local_port": endpoint.local_port,
            "remote_addr": endpoint.remote_addr,
            "remote_port": endpoint.remote_port,
        },
        "note": endpoint.note,
        "last_transition": {
            "created_at_event": endpoint.created_at_event,
            "socket_generation": endpoint.socket_generation,
            "adapter_generation": endpoint.adapter_generation,
            "owner_store_generation": endpoint.owner_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn socket_operation_view_v1(operation: &SocketOperationManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "socket-operation",
        "id": operation.id,
        "generation": operation.generation,
        "state": operation.state,
        "owner": {
            "store": object_ref_json(
                "store",
                operation.owner_store,
                operation.owner_store_generation,
            ),
            "endpoint": object_ref_json(
                "endpoint-object",
                operation.endpoint,
                operation.endpoint_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                operation.socket,
                operation.socket_generation,
            ),
        },
        "references": {
            "endpoint": object_ref_json(
                "endpoint-object",
                operation.endpoint,
                operation.endpoint_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                operation.socket,
                operation.socket_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                operation.adapter,
                operation.adapter_generation,
            ),
            "owner_store": object_ref_json(
                "store",
                operation.owner_store,
                operation.owner_store_generation,
            ),
            "event": {
                "id": operation.recorded_at_event,
            },
        },
        "operation": {
            "name": operation.operation,
            "sequence": operation.sequence,
            "local_addr": operation.local_addr,
            "local_port": operation.local_port,
            "remote_addr": operation.remote_addr,
            "remote_port": operation.remote_port,
            "backlog": operation.backlog,
            "byte_len": operation.byte_len,
        },
        "note": operation.note,
        "last_transition": {
            "recorded_at_event": operation.recorded_at_event,
            "endpoint_generation": operation.endpoint_generation,
            "socket_generation": operation.socket_generation,
            "adapter_generation": operation.adapter_generation,
            "owner_store_generation": operation.owner_store_generation,
            "sequence": operation.sequence,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn socket_wait_view_v1(wait: &SocketWaitManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "socket-wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "store": object_ref_json(
                "store",
                wait.owner_store,
                wait.owner_store_generation,
            ),
            "endpoint": object_ref_json(
                "endpoint-object",
                wait.endpoint,
                wait.endpoint_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                wait.socket,
                wait.socket_generation,
            ),
            "wait": object_ref_json(
                "wait-token",
                wait.wait,
                wait.wait_generation,
            ),
        },
        "references": {
            "wait": object_ref_json(
                "wait-token",
                wait.wait,
                wait.wait_generation,
            ),
            "endpoint": object_ref_json(
                "endpoint-object",
                wait.endpoint,
                wait.endpoint_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                wait.socket,
                wait.socket_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                wait.adapter,
                wait.adapter_generation,
            ),
            "owner_store": object_ref_json(
                "store",
                wait.owner_store,
                wait.owner_store_generation,
            ),
            "blocker": object_ref_manifest_json(&wait.blocker),
            "event": {
                "id": wait.created_at_event,
            },
            "completed_event": wait.completed_at_event.map(|id| serde_json::json!({ "id": id })),
        },
        "wait": {
            "kind": wait.wait_kind,
            "ready_sequence": wait.ready_sequence,
            "byte_len": wait.byte_len,
            "cancel_reason": wait.cancel_reason,
        },
        "note": wait.note,
        "last_transition": {
            "created_at_event": wait.created_at_event,
            "completed_at_event": wait.completed_at_event,
            "wait_generation": wait.wait_generation,
            "endpoint_generation": wait.endpoint_generation,
            "socket_generation": wait.socket_generation,
            "adapter_generation": wait.adapter_generation,
            "owner_store_generation": wait.owner_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_backpressure_view_v1(backpressure: &NetworkBackpressureManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-backpressure",
        "id": backpressure.id,
        "generation": backpressure.generation,
        "state": backpressure.state,
        "owner": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                backpressure.adapter,
                backpressure.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                backpressure.packet_device,
                backpressure.packet_device_generation,
            ),
            "packet_queue": object_ref_json(
                "packet-queue",
                backpressure.packet_queue,
                backpressure.packet_queue_generation,
            ),
            "endpoint": optional_object_ref_json(
                "endpoint-object",
                backpressure.endpoint,
                backpressure.endpoint_generation,
            ),
            "socket": optional_object_ref_json(
                "socket-object",
                backpressure.socket,
                backpressure.socket_generation,
            ),
            "store": optional_object_ref_json(
                "store",
                backpressure.owner_store,
                backpressure.owner_store_generation,
            ),
        },
        "references": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                backpressure.adapter,
                backpressure.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                backpressure.packet_device,
                backpressure.packet_device_generation,
            ),
            "packet_queue": object_ref_json(
                "packet-queue",
                backpressure.packet_queue,
                backpressure.packet_queue_generation,
            ),
            "endpoint": optional_object_ref_json(
                "endpoint-object",
                backpressure.endpoint,
                backpressure.endpoint_generation,
            ),
            "socket": optional_object_ref_json(
                "socket-object",
                backpressure.socket,
                backpressure.socket_generation,
            ),
            "owner_store": optional_object_ref_json(
                "store",
                backpressure.owner_store,
                backpressure.owner_store_generation,
            ),
            "event": {
                "id": backpressure.recorded_at_event,
            },
        },
        "policy": {
            "direction": backpressure.direction,
            "reason": backpressure.reason,
            "action": backpressure.action,
            "queue_depth": backpressure.queue_depth,
            "queue_limit": backpressure.queue_limit,
            "dropped_packets": backpressure.dropped_packets,
            "dropped_bytes": backpressure.dropped_bytes,
            "sequence": backpressure.sequence,
        },
        "note": backpressure.note,
        "last_transition": {
            "recorded_at_event": backpressure.recorded_at_event,
            "adapter_generation": backpressure.adapter_generation,
            "packet_device_generation": backpressure.packet_device_generation,
            "packet_queue_generation": backpressure.packet_queue_generation,
            "endpoint_generation": backpressure.endpoint_generation,
            "socket_generation": backpressure.socket_generation,
            "owner_store_generation": backpressure.owner_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_driver_cleanup_view_v1(cleanup: &NetworkDriverCleanupManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-driver-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                cleanup.packet_device,
                cleanup.packet_device_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                cleanup.adapter,
                cleanup.adapter_generation,
            ),
        },
        "references": {
            "io_cleanup": object_ref_json(
                "io-cleanup",
                cleanup.io_cleanup,
                cleanup.io_cleanup_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "device": object_ref_json(
                "device",
                cleanup.device,
                cleanup.device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                cleanup.packet_device,
                cleanup.packet_device_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                cleanup.adapter,
                cleanup.adapter_generation,
            ),
            "backend": object_ref_manifest_json(&cleanup.backend),
            "cancelled_socket_waits": cleanup
                .cancelled_socket_waits
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "cancelled_wait_tokens": cleanup
                .cancelled_wait_tokens
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "revoked_packet_capabilities": cleanup
                .revoked_packet_capabilities
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
        },
        "cleanup": {
            "reason": cleanup.reason,
            "cancelled_socket_wait_count": cleanup.cancelled_socket_waits.len(),
            "revoked_packet_capability_count": cleanup.revoked_packet_capabilities.len(),
        },
        "note": cleanup.note,
        "last_transition": {
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
            "io_cleanup_generation": cleanup.io_cleanup_generation,
            "driver_store_generation": cleanup.driver_store_generation,
            "device_generation": cleanup.device_generation,
            "driver_binding_generation": cleanup.driver_binding_generation,
            "packet_device_generation": cleanup.packet_device_generation,
            "adapter_generation": cleanup.adapter_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_generation_audit_view_v1(audit: &NetworkGenerationAuditManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-generation-audit",
        "id": audit.id,
        "generation": audit.generation,
        "state": audit.state,
        "owner": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                audit.adapter,
                audit.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                audit.packet_device,
                audit.packet_device_generation,
            ),
        },
        "references": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                audit.adapter,
                audit.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                audit.packet_device,
                audit.packet_device_generation,
            ),
            "packet_queue": object_ref_json(
                "packet-queue",
                audit.packet_queue,
                audit.packet_queue_generation,
            ),
            "packet_descriptor": object_ref_json(
                "packet-descriptor",
                audit.packet_descriptor,
                audit.packet_descriptor_generation,
            ),
            "packet_buffer": object_ref_json(
                "packet-buffer",
                audit.packet_buffer,
                audit.packet_buffer_generation,
            ),
            "dma_buffer": object_ref_manifest_json(&audit.dma_buffer),
            "device_capability": object_ref_manifest_json(&audit.device_capability),
            "event": {
                "id": audit.recorded_at_event,
            },
        },
        "audit": {
            "rejected_packet_generation_probes": audit.rejected_packet_generation_probes,
            "rejected_dma_generation_probes": audit.rejected_dma_generation_probes,
        },
        "note": audit.note,
        "last_transition": {
            "recorded_at_event": audit.recorded_at_event,
            "adapter_generation": audit.adapter_generation,
            "packet_device_generation": audit.packet_device_generation,
            "packet_queue_generation": audit.packet_queue_generation,
            "packet_descriptor_generation": audit.packet_descriptor_generation,
            "packet_buffer_generation": audit.packet_buffer_generation,
            "dma_buffer_generation": audit.dma_buffer.generation,
            "device_capability_generation": audit.device_capability.generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_fault_injection_view_v1(injection: &NetworkFaultInjectionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-fault-injection",
        "id": injection.id,
        "generation": injection.generation,
        "state": injection.state,
        "owner": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                injection.adapter,
                injection.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                injection.packet_device,
                injection.packet_device_generation,
            ),
            "packet_queue": object_ref_json(
                "packet-queue",
                injection.packet_queue,
                injection.packet_queue_generation,
            ),
            "endpoint": optional_object_ref_json(
                "endpoint-object",
                injection.endpoint,
                injection.endpoint_generation,
            ),
            "socket": optional_object_ref_json(
                "socket-object",
                injection.socket,
                injection.socket_generation,
            ),
            "store": optional_object_ref_json(
                "store",
                injection.owner_store,
                injection.owner_store_generation,
            ),
        },
        "references": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                injection.adapter,
                injection.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                injection.packet_device,
                injection.packet_device_generation,
            ),
            "packet_queue": object_ref_json(
                "packet-queue",
                injection.packet_queue,
                injection.packet_queue_generation,
            ),
            "packet_descriptor": optional_object_ref_json(
                "packet-descriptor",
                injection.packet_descriptor,
                injection.packet_descriptor_generation,
            ),
            "packet_buffer": optional_object_ref_json(
                "packet-buffer",
                injection.packet_buffer,
                injection.packet_buffer_generation,
            ),
            "endpoint": optional_object_ref_json(
                "endpoint-object",
                injection.endpoint,
                injection.endpoint_generation,
            ),
            "socket": optional_object_ref_json(
                "socket-object",
                injection.socket,
                injection.socket_generation,
            ),
            "owner_store": optional_object_ref_json(
                "store",
                injection.owner_store,
                injection.owner_store_generation,
            ),
            "event": {
                "id": injection.recorded_at_event,
            },
        },
        "injection": {
            "direction": injection.direction,
            "kind": injection.kind,
            "effect": injection.effect,
            "injected_packets": injection.injected_packets,
            "dropped_packets": injection.dropped_packets,
            "error_packets": injection.error_packets,
            "error_code": injection.error_code,
            "sequence": injection.sequence,
        },
        "note": injection.note,
        "last_transition": {
            "recorded_at_event": injection.recorded_at_event,
            "adapter_generation": injection.adapter_generation,
            "packet_device_generation": injection.packet_device_generation,
            "packet_queue_generation": injection.packet_queue_generation,
            "packet_descriptor_generation": injection.packet_descriptor_generation,
            "packet_buffer_generation": injection.packet_buffer_generation,
            "endpoint_generation": injection.endpoint_generation,
            "socket_generation": injection.socket_generation,
            "owner_store_generation": injection.owner_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_benchmark_view_v1(benchmark: &NetworkBenchmarkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                benchmark.adapter,
                benchmark.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                benchmark.packet_device,
                benchmark.packet_device_generation,
            ),
            "store": object_ref_json(
                "store",
                benchmark.owner_store,
                benchmark.owner_store_generation,
            ),
        },
        "references": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                benchmark.adapter,
                benchmark.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                benchmark.packet_device,
                benchmark.packet_device_generation,
            ),
            "tx_queue": object_ref_json(
                "packet-queue",
                benchmark.tx_queue,
                benchmark.tx_queue_generation,
            ),
            "rx_queue": object_ref_json(
                "packet-queue",
                benchmark.rx_queue,
                benchmark.rx_queue_generation,
            ),
            "tx_completion": object_ref_json(
                "network-tx-completion",
                benchmark.tx_completion,
                benchmark.tx_completion_generation,
            ),
            "rx_wait_resolution": object_ref_json(
                "network-rx-wait-resolution",
                benchmark.rx_wait_resolution,
                benchmark.rx_wait_resolution_generation,
            ),
            "endpoint": object_ref_json(
                "endpoint-object",
                benchmark.endpoint,
                benchmark.endpoint_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                benchmark.socket,
                benchmark.socket_generation,
            ),
            "owner_store": object_ref_json(
                "store",
                benchmark.owner_store,
                benchmark.owner_store_generation,
            ),
            "backpressure": optional_object_ref_json(
                "network-backpressure",
                benchmark.backpressure,
                benchmark.backpressure_generation,
            ),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "sample_packets": benchmark.sample_packets,
            "sample_bytes": benchmark.sample_bytes,
            "tx_completed_packets": benchmark.tx_completed_packets,
            "rx_resolved_packets": benchmark.rx_resolved_packets,
            "dropped_packets": benchmark.dropped_packets,
            "measured_nanos": benchmark.measured_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "throughput_bytes_per_sec": benchmark.throughput_bytes_per_sec,
            "p50_latency_nanos": benchmark.p50_latency_nanos,
            "p99_latency_nanos": benchmark.p99_latency_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "adapter_generation": benchmark.adapter_generation,
            "packet_device_generation": benchmark.packet_device_generation,
            "tx_queue_generation": benchmark.tx_queue_generation,
            "rx_queue_generation": benchmark.rx_queue_generation,
            "tx_completion_generation": benchmark.tx_completion_generation,
            "rx_wait_resolution_generation": benchmark.rx_wait_resolution_generation,
            "endpoint_generation": benchmark.endpoint_generation,
            "socket_generation": benchmark.socket_generation,
            "owner_store_generation": benchmark.owner_store_generation,
            "backpressure_generation": benchmark.backpressure_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn network_recovery_benchmark_view_v1(
    benchmark: &NetworkRecoveryBenchmarkManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-recovery-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                benchmark.adapter,
                benchmark.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                benchmark.packet_device,
                benchmark.packet_device_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
        },
        "references": {
            "cleanup": object_ref_json(
                "network-driver-cleanup",
                benchmark.cleanup,
                benchmark.cleanup_generation,
            ),
            "io_cleanup": object_ref_json(
                "io-cleanup",
                benchmark.io_cleanup,
                benchmark.io_cleanup_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                benchmark.adapter,
                benchmark.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                benchmark.packet_device,
                benchmark.packet_device_generation,
            ),
            "backend": object_ref_manifest_json(&benchmark.backend),
            "driver_store": object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
            "fault_injection": optional_object_ref_json(
                "network-fault-injection",
                benchmark.fault_injection,
                benchmark.fault_injection_generation,
            ),
            "events": {
                "recovery_start_event": benchmark.recovery_start_event,
                "recovery_complete_event": benchmark.recovery_complete_event,
                "recorded_at_event": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "cancelled_socket_waits": benchmark.cancelled_socket_waits,
            "revoked_packet_capabilities": benchmark.revoked_packet_capabilities,
            "recovery_nanos": benchmark.recovery_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "within_budget": benchmark.recovery_nanos <= benchmark.budget_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "cleanup_generation": benchmark.cleanup_generation,
            "io_cleanup_generation": benchmark.io_cleanup_generation,
            "adapter_generation": benchmark.adapter_generation,
            "packet_device_generation": benchmark.packet_device_generation,
            "driver_store_generation": benchmark.driver_store_generation,
            "fault_injection_generation": benchmark.fault_injection_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn framebuffer_object_view_v1(framebuffer: &FramebufferObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-object",
        "id": framebuffer.id,
        "generation": framebuffer.generation,
        "state": framebuffer.state,
        "owner": {
            "resource": object_ref_json("resource", framebuffer.resource, framebuffer.resource_generation),
        },
        "references": {
            "resource": object_ref_json("resource", framebuffer.resource, framebuffer.resource_generation),
            "event": {
                "id": framebuffer.recorded_at_event,
            },
        },
        "identity": {
            "name": framebuffer.name,
        },
        "geometry": {
            "width": framebuffer.width,
            "height": framebuffer.height,
            "stride_bytes": framebuffer.stride_bytes,
            "pixel_format": framebuffer.pixel_format,
            "byte_len": framebuffer.byte_len,
        },
        "authority": {
            "write_requires": "display-capability-and-framebuffer-window-lease",
            "raw_mapping_is_semantic_truth": false,
        },
        "note": framebuffer.note,
        "last_transition": {
            "recorded_at_event": framebuffer.recorded_at_event,
            "state": framebuffer.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn display_object_view_v1(display: &DisplayObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-object",
        "id": display.id,
        "generation": display.generation,
        "state": display.state,
        "owner": {
            "framebuffer": object_ref_json(
                "framebuffer-object",
                display.framebuffer,
                display.framebuffer_generation,
            ),
        },
        "references": {
            "framebuffer": object_ref_json(
                "framebuffer-object",
                display.framebuffer,
                display.framebuffer_generation,
            ),
            "event": {
                "id": display.recorded_at_event,
            },
        },
        "identity": {
            "name": display.name,
        },
        "mode": {
            "name": display.mode_name,
            "width": display.width,
            "height": display.height,
            "refresh_millihz": display.refresh_millihz,
        },
        "authority": {
            "write_requires": "display-capability-and-framebuffer-window-lease",
            "flush_requires": "display-capability",
            "raw_mapping_is_semantic_truth": false,
        },
        "note": display.note,
        "last_transition": {
            "recorded_at_event": display.recorded_at_event,
            "state": display.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn display_capability_view_v1(capability: &DisplayCapabilityManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-capability",
        "id": capability.id,
        "generation": capability.generation,
        "state": capability.state,
        "owner": {
            "store": object_ref_json(
                "store",
                capability.owner_store,
                capability.owner_store_generation,
            ),
        },
        "references": {
            "display": object_ref_json(
                "display-object",
                capability.display,
                capability.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                capability.framebuffer,
                capability.framebuffer_generation,
            ),
            "capability": object_ref_json(
                "capability",
                capability.capability,
                capability.capability_generation,
            ),
            "event": {
                "id": capability.recorded_at_event,
            },
        },
        "authority": {
            "class": "display",
            "operations": capability.operations,
            "handle": {
                "slot": capability.handle_slot,
                "generation": capability.handle_generation,
                "tag": capability.handle_tag,
            },
            "write_requires_framebuffer_window_lease": true,
            "raw_mapping_is_semantic_truth": false,
        },
        "note": capability.note,
        "last_transition": {
            "recorded_at_event": capability.recorded_at_event,
            "owner_store_generation": capability.owner_store_generation,
            "display_generation": capability.display_generation,
            "framebuffer_generation": capability.framebuffer_generation,
            "capability_generation": capability.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn framebuffer_window_lease_view_v1(lease: &FramebufferWindowLeaseManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-window-lease",
        "id": lease.id,
        "generation": lease.generation,
        "state": lease.state,
        "owner": {
            "store": object_ref_json(
                "store",
                lease.owner_store,
                lease.owner_store_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                lease.display_capability,
                lease.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                lease.display,
                lease.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                lease.framebuffer,
                lease.framebuffer_generation,
            ),
            "event": {
                "id": lease.recorded_at_event,
            },
        },
        "window": {
            "x": lease.x,
            "y": lease.y,
            "width": lease.width,
            "height": lease.height,
            "byte_offset": lease.byte_offset,
            "byte_len": lease.byte_len,
            "access": lease.access,
        },
        "authority": {
            "requires_display_capability_operation": "lease",
            "write_requires_this_lease": true,
            "raw_mapping_is_semantic_truth": false,
            "snapshot_barrier_must_release": true,
        },
        "note": lease.note,
        "last_transition": {
            "recorded_at_event": lease.recorded_at_event,
            "owner_store_generation": lease.owner_store_generation,
            "display_capability_generation": lease.display_capability_generation,
            "display_generation": lease.display_generation,
            "framebuffer_generation": lease.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn framebuffer_mapping_view_v1(mapping: &FramebufferMappingManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-mapping",
        "id": mapping.id,
        "generation": mapping.generation,
        "state": mapping.state,
        "owner": {
            "store": object_ref_json(
                "store",
                mapping.owner_store,
                mapping.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_window_lease": object_ref_json(
                "framebuffer-window-lease",
                mapping.framebuffer_window_lease,
                mapping.framebuffer_window_lease_generation,
            ),
            "display_capability": object_ref_json(
                "display-capability",
                mapping.display_capability,
                mapping.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                mapping.display,
                mapping.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                mapping.framebuffer,
                mapping.framebuffer_generation,
            ),
            "event": {
                "id": mapping.recorded_at_event,
            },
        },
        "map_handle": {
            "slot": mapping.map_handle_slot,
            "generation": mapping.map_handle_generation,
            "tag": mapping.map_handle_tag,
            "mode": mapping.mode,
        },
        "window": {
            "x": mapping.x,
            "y": mapping.y,
            "width": mapping.width,
            "height": mapping.height,
            "byte_offset": mapping.byte_offset,
            "byte_len": mapping.byte_len,
            "access": mapping.access,
        },
        "authority": {
            "requires_framebuffer_window_lease": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "pixel_write_allowed": false,
            "flush_allowed": false,
            "snapshot_barrier_must_release": true,
        },
        "note": mapping.note,
        "last_transition": {
            "recorded_at_event": mapping.recorded_at_event,
            "owner_store_generation": mapping.owner_store_generation,
            "framebuffer_window_lease_generation": mapping.framebuffer_window_lease_generation,
            "display_capability_generation": mapping.display_capability_generation,
            "display_generation": mapping.display_generation,
            "framebuffer_generation": mapping.framebuffer_generation,
            "map_handle_generation": mapping.map_handle_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn framebuffer_write_view_v1(write: &FramebufferWriteManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-write",
        "id": write.id,
        "generation": write.generation,
        "state": write.state,
        "owner": {
            "store": object_ref_json(
                "store",
                write.owner_store,
                write.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_mapping": object_ref_json(
                "framebuffer-mapping",
                write.framebuffer_mapping,
                write.framebuffer_mapping_generation,
            ),
            "framebuffer_window_lease": object_ref_json(
                "framebuffer-window-lease",
                write.framebuffer_window_lease,
                write.framebuffer_window_lease_generation,
            ),
            "display_capability": object_ref_json(
                "display-capability",
                write.display_capability,
                write.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                write.display,
                write.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                write.framebuffer,
                write.framebuffer_generation,
            ),
            "event": {
                "id": write.recorded_at_event,
            },
        },
        "map_handle": {
            "slot": write.map_handle_slot,
            "generation": write.map_handle_generation,
            "tag": write.map_handle_tag,
        },
        "write": {
            "x": write.x,
            "y": write.y,
            "width": write.width,
            "height": write.height,
            "byte_offset": write.byte_offset,
            "byte_len": write.byte_len,
            "pixel_format": write.pixel_format,
            "payload_digest": write.payload_digest,
        },
        "authority": {
            "requires_framebuffer_mapping": true,
            "requires_framebuffer_window_lease": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "flush_allowed": false,
        },
        "note": write.note,
        "last_transition": {
            "recorded_at_event": write.recorded_at_event,
            "owner_store_generation": write.owner_store_generation,
            "framebuffer_mapping_generation": write.framebuffer_mapping_generation,
            "framebuffer_window_lease_generation": write.framebuffer_window_lease_generation,
            "display_capability_generation": write.display_capability_generation,
            "display_generation": write.display_generation,
            "framebuffer_generation": write.framebuffer_generation,
            "map_handle_generation": write.map_handle_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn framebuffer_flush_region_view_v1(flush: &FramebufferFlushRegionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-flush-region",
        "id": flush.id,
        "generation": flush.generation,
        "state": flush.state,
        "owner": {
            "store": object_ref_json(
                "store",
                flush.owner_store,
                flush.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                flush.framebuffer_write,
                flush.framebuffer_write_generation,
            ),
            "display_capability": object_ref_json(
                "display-capability",
                flush.display_capability,
                flush.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                flush.display,
                flush.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                flush.framebuffer,
                flush.framebuffer_generation,
            ),
            "event": {
                "id": flush.recorded_at_event,
            },
        },
        "flush": {
            "x": flush.x,
            "y": flush.y,
            "width": flush.width,
            "height": flush.height,
            "byte_offset": flush.byte_offset,
            "byte_len": flush.byte_len,
            "pixel_format": flush.pixel_format,
            "payload_digest": flush.payload_digest,
        },
        "authority": {
            "requires_display_capability_flush": true,
            "requires_framebuffer_write": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "real_present_executed": false,
        },
        "note": flush.note,
        "last_transition": {
            "recorded_at_event": flush.recorded_at_event,
            "owner_store_generation": flush.owner_store_generation,
            "framebuffer_write_generation": flush.framebuffer_write_generation,
            "display_capability_generation": flush.display_capability_generation,
            "display_generation": flush.display_generation,
            "framebuffer_generation": flush.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn framebuffer_dirty_region_view_v1(dirty: &FramebufferDirtyRegionManifest) -> serde_json::Value {
    let flush_ref = match (
        dirty.framebuffer_flush_region,
        dirty.framebuffer_flush_region_generation,
    ) {
        (Some(id), Some(generation)) => object_ref_json("framebuffer-flush-region", id, generation),
        _ => serde_json::Value::Null,
    };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-dirty-region",
        "id": dirty.id,
        "generation": dirty.generation,
        "state": dirty.state,
        "owner": {
            "store": object_ref_json(
                "store",
                dirty.owner_store,
                dirty.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                dirty.framebuffer_write,
                dirty.framebuffer_write_generation,
            ),
            "framebuffer_flush_region": flush_ref,
            "display_capability": object_ref_json(
                "display-capability",
                dirty.display_capability,
                dirty.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                dirty.display,
                dirty.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                dirty.framebuffer,
                dirty.framebuffer_generation,
            ),
            "dirty_event": {
                "id": dirty.dirty_at_event,
            },
            "cleaned_event": dirty.cleaned_at_event
                .map(|id| serde_json::json!({"id": id}))
                .unwrap_or(serde_json::Value::Null),
            "recorded_event": {
                "id": dirty.recorded_at_event,
            },
        },
        "region": {
            "x": dirty.x,
            "y": dirty.y,
            "width": dirty.width,
            "height": dirty.height,
            "byte_offset": dirty.byte_offset,
            "byte_len": dirty.byte_len,
            "pixel_format": dirty.pixel_format,
            "payload_digest": dirty.payload_digest,
        },
        "authority": {
            "requires_framebuffer_write": true,
            "clean_state_requires_flush_region": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "real_present_executed": false,
        },
        "note": dirty.note,
        "last_transition": {
            "dirty_at_event": dirty.dirty_at_event,
            "cleaned_at_event": dirty.cleaned_at_event,
            "recorded_at_event": dirty.recorded_at_event,
            "owner_store_generation": dirty.owner_store_generation,
            "framebuffer_write_generation": dirty.framebuffer_write_generation,
            "framebuffer_flush_region_generation": dirty.framebuffer_flush_region_generation,
            "display_capability_generation": dirty.display_capability_generation,
            "display_generation": dirty.display_generation,
            "framebuffer_generation": dirty.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn display_event_log_view_v1(log: &DisplayEventLogManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-event-log",
        "id": log.id,
        "generation": log.generation,
        "state": log.state,
        "owner": {
            "store": object_ref_json(
                "store",
                log.owner_store,
                log.owner_store_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                log.display_capability,
                log.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                log.display,
                log.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                log.framebuffer,
                log.framebuffer_generation,
            ),
            "framebuffer_dirty_region": object_ref_json(
                "framebuffer-dirty-region",
                log.framebuffer_dirty_region,
                log.framebuffer_dirty_region_generation,
            ),
            "event": {
                "id": log.recorded_at_event,
            },
        },
        "window": {
            "first_event": log.first_event,
            "last_event": log.last_event,
            "event_count": log.event_count,
            "flush_count": log.flush_count,
            "dirty_region_count": log.dirty_region_count,
        },
        "authority": {
            "read_only_control_plane": true,
            "raw_event_storage_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "real_present_executed": false,
        },
        "note": log.note,
        "last_transition": {
            "recorded_at_event": log.recorded_at_event,
            "owner_store_generation": log.owner_store_generation,
            "display_capability_generation": log.display_capability_generation,
            "display_generation": log.display_generation,
            "framebuffer_generation": log.framebuffer_generation,
            "framebuffer_dirty_region_generation": log.framebuffer_dirty_region_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn display_cleanup_view_v1(cleanup: &DisplayCleanupManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "store": object_ref_json(
                "store",
                cleanup.owner_store,
                cleanup.owner_store_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                cleanup.display_capability,
                cleanup.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                cleanup.display,
                cleanup.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                cleanup.framebuffer,
                cleanup.framebuffer_generation,
            ),
        },
        "cleanup": {
            "reason": cleanup.reason,
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
            "unmapped_framebuffer_mappings": cleanup.unmapped_framebuffer_mappings,
            "released_framebuffer_window_leases": cleanup.released_framebuffer_window_leases,
            "revoked_display_capabilities": cleanup.revoked_display_capabilities,
            "revoked_capabilities": cleanup.revoked_capabilities,
            "steps": cleanup.steps,
        },
        "authority": {
            "releases_handle_mode_mappings": true,
            "releases_framebuffer_leases": true,
            "revokes_display_capability": true,
            "real_present_executed": false,
        },
        "note": cleanup.note,
        "last_transition": {
            "completed_at_event": cleanup.completed_at_event,
            "owner_store_generation": cleanup.owner_store_generation,
            "display_capability_generation": cleanup.display_capability_generation,
            "display_generation": cleanup.display_generation,
            "framebuffer_generation": cleanup.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn display_snapshot_barrier_view_v1(barrier: &DisplaySnapshotBarrierManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-snapshot-barrier",
        "id": barrier.id,
        "generation": barrier.generation,
        "state": barrier.state,
        "owner": {
            "store": object_ref_json(
                "store",
                barrier.owner_store,
                barrier.owner_store_generation,
            ),
        },
        "references": {
            "display": object_ref_json(
                "display-object",
                barrier.display,
                barrier.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                barrier.framebuffer,
                barrier.framebuffer_generation,
            ),
            "display_cleanup": optional_object_ref_json(
                "display-cleanup",
                barrier.display_cleanup,
                barrier.display_cleanup_generation,
            ),
        },
        "snapshot": {
            "reason": barrier.reason,
            "snapshot_validation_ok": barrier.snapshot_validation_ok,
            "active_framebuffer_window_lease_count": barrier.active_framebuffer_window_lease_count,
            "active_framebuffer_mapping_count": barrier.active_framebuffer_mapping_count,
            "dirty_framebuffer_region_count": barrier.dirty_framebuffer_region_count,
            "validated_at_event": barrier.validated_at_event,
        },
        "authority": {
            "requires_no_active_framebuffer_lease": true,
            "requires_no_active_framebuffer_mapping": true,
            "requires_no_dirty_framebuffer_region": true,
            "real_snapshot_cow_executed": false,
            "real_present_executed": false,
        },
        "note": barrier.note,
        "last_transition": {
            "validated_at_event": barrier.validated_at_event,
            "owner_store_generation": barrier.owner_store_generation,
            "display_generation": barrier.display_generation,
            "framebuffer_generation": barrier.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn display_panic_last_frame_view_v1(frame: &DisplayPanicLastFrameManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-panic-last-frame",
        "id": frame.id,
        "generation": frame.generation,
        "state": frame.state,
        "owner": {
            "store": object_ref_json(
                "store",
                frame.owner_store,
                frame.owner_store_generation,
            ),
        },
        "references": {
            "display": object_ref_json(
                "display-object",
                frame.display,
                frame.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                frame.framebuffer,
                frame.framebuffer_generation,
            ),
            "display_snapshot_barrier": object_ref_json(
                "display-snapshot-barrier",
                frame.display_snapshot_barrier,
                frame.display_snapshot_barrier_generation,
            ),
            "display_event_log": object_ref_json(
                "display-event-log",
                frame.display_event_log,
                frame.display_event_log_generation,
            ),
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                frame.framebuffer_write,
                frame.framebuffer_write_generation,
            ),
            "framebuffer_flush_region": object_ref_json(
                "framebuffer-flush-region",
                frame.framebuffer_flush_region,
                frame.framebuffer_flush_region_generation,
            ),
        },
        "frame": {
            "x": frame.x,
            "y": frame.y,
            "width": frame.width,
            "height": frame.height,
            "byte_offset": frame.byte_offset,
            "byte_len": frame.byte_len,
            "pixel_format": frame.pixel_format,
            "payload_digest": frame.payload_digest,
            "summary_digest": frame.summary_digest,
        },
        "panic": {
            "epoch": frame.panic_epoch,
            "cpu": frame.panic_cpu,
            "reason_code": frame.panic_reason_code,
            "record_kind": frame.panic_record_kind,
            "summary_record_bytes": frame.summary_record_bytes,
            "raw_framebuffer_bytes_exported": frame.raw_framebuffer_bytes_exported,
            "recorded_at_event": frame.recorded_at_event,
        },
        "authority": {
            "panic_path_allocates": false,
            "raw_framebuffer_bytes_exported": frame.raw_framebuffer_bytes_exported,
            "real_panic_ring_write_executed": false,
        },
        "note": frame.note,
        "last_transition": {
            "recorded_at_event": frame.recorded_at_event,
            "owner_store_generation": frame.owner_store_generation,
            "display_generation": frame.display_generation,
            "framebuffer_generation": frame.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn activation_resume_view_v1(resume: &ActivationResumeManifest) -> serde_json::Value {
    let vector_status = if resume.vector_status.is_empty() {
        "absent"
    } else {
        resume.vector_status.as_str()
    };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation-resume",
        "id": resume.id,
        "generation": resume.generation,
        "state": resume.state,
        "owner": {
            "scheduler": 1,
            "task": resume.owner_task,
            "task_generation": resume.owner_task_generation,
        },
        "references": {
            "scheduler_decision": {
                "id": resume.scheduler_decision,
                "generation": resume.scheduler_decision_generation,
            },
            "activation": {
                "id": resume.activation,
                "generation_before": resume.activation_generation_before,
                "generation_after": resume.activation_generation_after,
            },
            "queue": {
                "id": resume.queue,
                "generation": resume.queue_generation,
            },
            "activation_context": resume.context.map(|id| serde_json::json!({
                "id": id,
                "generation_before": resume.context_generation_before,
                "generation_after": resume.context_generation_after,
            })),
            "saved_context": resume.saved_context.map(|id| serde_json::json!({
                "id": id,
                "generation": resume.saved_context_generation,
            })),
            "saved_vector_state": resume.saved_vector_state.as_ref().map(object_ref_manifest_json),
            "restored_vector_state": resume.restored_vector_state.as_ref().map(object_ref_manifest_json),
        },
        "vector_restore": {
            "status": vector_status,
            "saved_vector_state": resume.saved_vector_state.as_ref().map(object_ref_manifest_json),
            "restored_vector_state": resume.restored_vector_state.as_ref().map(object_ref_manifest_json),
            "restored_at_event": resume.vector_restored_at_event,
        },
        "note": resume.note,
        "last_transition": {
            "resumed_at_event": resume.resumed_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn activation_wait_view_v1(wait: &ActivationWaitManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation-wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "task": wait.owner_task,
            "task_generation": wait.owner_task_generation,
        },
        "references": {
            "activation": {
                "id": wait.activation,
                "generation_before": wait.activation_generation_before,
                "generation_after_block": wait.activation_generation_after_block,
                "generation_after_cancel": wait.activation_generation_after_cancel,
            },
            "wait": {
                "id": wait.wait,
                "generation": wait.wait_generation,
            },
            "queue": wait.queue.map(|id| serde_json::json!({
                "id": id,
                "generation": wait.queue_generation,
            })),
        },
        "cancel_reason": wait.cancel_reason,
        "note": wait.note,
        "last_transition": {
            "blocked_at_event": wait.blocked_at_event,
            "completed_at_event": wait.completed_at_event,
        },
        "last_error": wait.cancel_reason,
    })
}

fn activation_cleanup_view_v1(cleanup: &ActivationCleanupManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "store": cleanup.store,
            "target_store_generation": cleanup.target_store_generation,
            "result_store_generation": cleanup.result_store_generation,
            "task": cleanup.owner_task,
            "task_generation_before": cleanup.owner_task_generation_before,
            "task_generation_after": cleanup.owner_task_generation_after,
        },
        "references": {
            "activation": {
                "id": cleanup.activation,
                "generation_before": cleanup.activation_generation_before,
                "generation_after": cleanup.activation_generation_after,
            },
            "wait": cleanup.wait.map(|id| serde_json::json!({
                "id": id,
                "generation": cleanup.wait_generation,
            })),
            "steps": cleanup.steps.iter().map(|step| serde_json::json!({
                "kind": step.kind,
                "target": step.target,
                "observed_generation": step.observed_generation,
                "status": step.status,
                "event": step.event,
            })).collect::<Vec<_>>(),
        },
        "reason": cleanup.reason,
        "note": cleanup.note,
        "last_transition": {
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn preemption_latency_view_v1(sample: &PreemptionLatencySampleManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "preemption-latency",
        "id": sample.id,
        "generation": sample.generation,
        "state": sample.state,
        "owner": {
            "activation": sample.activation,
            "activation_generation_before": sample.activation_generation_before,
            "activation_generation_after": sample.activation_generation_after,
            "queue": sample.queue,
            "queue_generation": sample.queue_generation,
        },
        "references": {
            "timer_interrupt": {
                "id": sample.timer_interrupt,
                "generation": sample.timer_interrupt_generation,
            },
            "preemption": {
                "id": sample.preemption,
                "generation": sample.preemption_generation,
            },
            "scheduler_decision": {
                "id": sample.scheduler_decision,
                "generation": sample.scheduler_decision_generation,
            },
            "activation_resume": {
                "id": sample.activation_resume,
                "generation": sample.activation_resume_generation,
            },
        },
        "event_window": {
            "interrupt_recorded_at_event": sample.interrupt_recorded_at_event,
            "preempted_at_event": sample.preempted_at_event,
            "decided_at_event": sample.decided_at_event,
            "resumed_at_event": sample.resumed_at_event,
            "interrupt_to_preempt_events": sample.interrupt_to_preempt_events,
            "preempt_to_decision_events": sample.preempt_to_decision_events,
            "decision_to_resume_events": sample.decision_to_resume_events,
            "interrupt_to_resume_events": sample.interrupt_to_resume_events,
        },
        "metrics": {
            "measured_nanos": sample.measured_nanos,
            "budget_nanos": sample.budget_nanos,
            "within_budget": sample.measured_nanos <= sample.budget_nanos,
        },
        "last_transition": {
            "recorded_at_event": sample.recorded_at_event,
        },
        "last_error": serde_json::Value::Null,
        "note": sample.note,
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
            "harts": package.semantic.hart_records.iter().map(|hart| serde_json::json!({
                "id": hart.id,
                "hardware_id": hart.hardware_id,
                "generation": hart.generation,
                "state": hart.state,
                "boot": hart.boot,
                "current_activation": hart.current_activation,
                "current_activation_generation": hart.current_activation_generation,
            })).collect::<Vec<_>>(),
            "current_activation_owners": package.semantic.hart_records.iter().filter_map(|hart| {
                let activation = hart.current_activation?;
                let activation_generation = hart.current_activation_generation?;
                Some(serde_json::json!({
                    "hart": {
                        "id": hart.id,
                        "generation": hart.generation,
                        "hardware_id": hart.hardware_id,
                    },
                    "activation": {
                        "id": activation,
                        "generation": activation_generation,
                    },
                    "task": hart.current_task.map(|id| serde_json::json!({
                        "id": id,
                        "generation": hart.current_task_generation,
                    })),
                    "store": hart.current_store.map(|id| serde_json::json!({
                        "id": id,
                        "generation": hart.current_store_generation,
                    })),
                }))
            }).collect::<Vec<_>>(),
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
                "owner_hart": queue.owner_hart,
                "owner_hart_generation": queue.owner_hart_generation,
            })).collect::<Vec<_>>(),
            "activation_contexts": package.semantic.activation_contexts.iter().map(|context| serde_json::json!({
                "id": context.id,
                "generation": context.generation,
                "activation": context.activation,
                "activation_generation": context.activation_generation,
            })).collect::<Vec<_>>(),
            "saved_contexts": package.semantic.saved_contexts.iter().map(|saved| serde_json::json!({
                "id": saved.id,
                "generation": saved.generation,
                "context": saved.context,
                "context_generation": saved.context_generation,
                "vector_status": saved.vector_status,
                "vector_state": saved.vector_state.as_ref().map(object_ref_manifest_json),
            })).collect::<Vec<_>>(),
            "timer_interrupts": package.semantic.timer_interrupts.iter().map(|interrupt| serde_json::json!({
                "id": interrupt.id,
                "generation": interrupt.generation,
                "timer_epoch": interrupt.timer_epoch,
                "target_activation": interrupt.target_activation,
                "target_activation_generation": interrupt.target_activation_generation,
            })).collect::<Vec<_>>(),
            "ipi_events": package.semantic.ipi_events.iter().map(|ipi| serde_json::json!({
                "id": ipi.id,
                "generation": ipi.generation,
                "kind": ipi.kind,
                "source_hart": ipi.source_hart,
                "source_hart_generation": ipi.source_hart_generation,
                "target_hart": ipi.target_hart,
                "target_hart_generation": ipi.target_hart_generation,
                "state": ipi.state,
            })).collect::<Vec<_>>(),
            "remote_preempts": package.semantic.remote_preempts.iter().map(|remote| serde_json::json!({
                "id": remote.id,
                "generation": remote.generation,
                "ipi": remote.ipi,
                "ipi_generation": remote.ipi_generation,
                "source_hart": remote.source_hart,
                "source_hart_generation": remote.source_hart_generation,
                "target_hart": remote.target_hart,
                "target_hart_generation_before": remote.target_hart_generation_before,
                "target_hart_generation_after": remote.target_hart_generation_after,
                "activation": remote.activation,
                "activation_generation_before": remote.activation_generation_before,
                "activation_generation_after": remote.activation_generation_after,
                "queue": remote.queue,
                "queue_generation": remote.queue_generation,
                "state": remote.state,
            })).collect::<Vec<_>>(),
            "remote_parks": package.semantic.remote_parks.iter().map(|remote| serde_json::json!({
                "id": remote.id,
                "generation": remote.generation,
                "ipi": remote.ipi,
                "ipi_generation": remote.ipi_generation,
                "source_hart": remote.source_hart,
                "source_hart_generation": remote.source_hart_generation,
                "target_hart": remote.target_hart,
                "target_hart_generation_before": remote.target_hart_generation_before,
                "target_hart_generation_after": remote.target_hart_generation_after,
                "state": remote.state,
                "reason": remote.reason,
            })).collect::<Vec<_>>(),
            "hart_event_attributions": package.semantic.hart_event_attributions.iter().map(|attribution| serde_json::json!({
                "id": attribution.id,
                "generation": attribution.generation,
                "hart": attribution.hart,
                "hart_generation": attribution.hart_generation,
                "event": attribution.event,
                "event_kind": attribution.event_kind,
            })).collect::<Vec<_>>(),
            "preemptions": package.semantic.preemptions.iter().map(|preemption| serde_json::json!({
                "id": preemption.id,
                "generation": preemption.generation,
                "activation": preemption.activation,
                "activation_generation_after": preemption.activation_generation_after,
                "queue": preemption.queue,
                "queue_generation": preemption.queue_generation,
            })).collect::<Vec<_>>(),
            "scheduler_decisions": package.semantic.scheduler_decisions.iter().map(|decision| serde_json::json!({
                "id": decision.id,
                "generation": decision.generation,
                "selected_activation": decision.selected_activation,
                "selected_activation_generation": decision.selected_activation_generation,
                "queue": decision.queue,
                "queue_generation": decision.queue_generation,
            })).collect::<Vec<_>>(),
            "cross_hart_scheduler_decisions": package.semantic.cross_hart_scheduler_decisions.iter().map(|decision| serde_json::json!({
                "id": decision.id,
                "generation": decision.generation,
                "scheduler_decision": decision.scheduler_decision,
                "scheduler_decision_generation": decision.scheduler_decision_generation,
                "deciding_hart": decision.deciding_hart,
                "deciding_hart_generation": decision.deciding_hart_generation,
                "target_hart": decision.target_hart,
                "target_hart_generation": decision.target_hart_generation,
                "queue": decision.queue,
                "queue_generation": decision.queue_generation,
                "selected_activation": decision.selected_activation,
                "selected_activation_generation": decision.selected_activation_generation,
            })).collect::<Vec<_>>(),
            "activation_migrations": package.semantic.activation_migrations.iter().map(|migration| serde_json::json!({
                "id": migration.id,
                "generation": migration.generation,
                "activation": migration.activation,
                "activation_generation_before": migration.activation_generation_before,
                "activation_generation_after": migration.activation_generation_after,
                "source_hart": migration.source_hart,
                "source_hart_generation": migration.source_hart_generation,
                "target_hart": migration.target_hart,
                "target_hart_generation": migration.target_hart_generation,
                "source_queue": migration.source_queue,
                "source_queue_generation": migration.source_queue_generation,
                "target_queue": migration.target_queue,
                "target_queue_generation": migration.target_queue_generation,
            })).collect::<Vec<_>>(),
            "smp_safe_points": package.semantic.smp_safe_points.iter().map(|safe_point| serde_json::json!({
                "id": safe_point.id,
                "generation": safe_point.generation,
                "coordinator_hart": safe_point.coordinator_hart,
                "coordinator_hart_generation": safe_point.coordinator_hart_generation,
                "participant_count": safe_point.participants.len(),
                "state": safe_point.state,
            })).collect::<Vec<_>>(),
            "stop_the_world_rendezvous": package.semantic.stop_the_world_rendezvous.iter().map(|rendezvous| serde_json::json!({
                "id": rendezvous.id,
                "generation": rendezvous.generation,
                "epoch": rendezvous.epoch,
                "safe_point": rendezvous.safe_point,
                "safe_point_generation": rendezvous.safe_point_generation,
                "coordinator_hart": rendezvous.coordinator_hart,
                "coordinator_hart_generation": rendezvous.coordinator_hart_generation,
                "participant_count": rendezvous.participants.len(),
                "state": rendezvous.state,
            })).collect::<Vec<_>>(),
            "smp_code_publish_barriers": package.semantic.smp_code_publish_barriers.iter().map(|barrier| serde_json::json!({
                "id": barrier.id,
                "generation": barrier.generation,
                "rendezvous": barrier.rendezvous,
                "rendezvous_generation": barrier.rendezvous_generation,
                "code_publish_epoch_before": barrier.code_publish_epoch_before,
                "code_publish_epoch_after": barrier.code_publish_epoch_after,
                "participant_count": barrier.participants.len(),
                "remote_icache_sync_required": barrier.remote_icache_sync_required,
                "code_publish_executed": barrier.code_publish_executed,
                "state": barrier.state,
            })).collect::<Vec<_>>(),
            "smp_cleanup_quiescence": package.semantic.smp_cleanup_quiescence.iter().map(|quiescence| serde_json::json!({
                "id": quiescence.id,
                "generation": quiescence.generation,
                "cleanup": quiescence.cleanup,
                "cleanup_generation": quiescence.cleanup_generation,
                "store": quiescence.store,
                "target_store_generation": quiescence.target_store_generation,
                "result_store_generation": quiescence.result_store_generation,
                "rendezvous": quiescence.rendezvous,
                "rendezvous_generation": quiescence.rendezvous_generation,
                "participant_count": quiescence.participants.len(),
                "state": quiescence.state,
            })).collect::<Vec<_>>(),
            "smp_snapshot_barriers": package.semantic.smp_snapshot_barriers.iter().map(|barrier| serde_json::json!({
                "id": barrier.id,
                "generation": barrier.generation,
                "rendezvous": barrier.rendezvous,
                "rendezvous_generation": barrier.rendezvous_generation,
                "rendezvous_epoch": barrier.rendezvous_epoch,
                "event_log_cursor": barrier.event_log_cursor,
                "participant_count": barrier.participants.len(),
                "snapshot_validation_ok": barrier.snapshot_validation_ok,
                "state": barrier.state,
            })).collect::<Vec<_>>(),
            "smp_stress_runs": package.semantic.smp_stress_runs.iter().map(|run| serde_json::json!({
                "id": run.id,
                "generation": run.generation,
                "scenario": run.scenario,
                "iterations": run.iterations,
                "hart_count": run.hart_count,
                "safe_point_count": run.observed_safe_point_count,
                "rendezvous_count": run.observed_rendezvous_count,
                "property_failures": run.property_failures,
                "state": run.state,
            })).collect::<Vec<_>>(),
            "smp_scaling_benchmarks": package.semantic.smp_scaling_benchmarks.iter().map(|benchmark| serde_json::json!({
                "id": benchmark.id,
                "generation": benchmark.generation,
                "scenario": benchmark.scenario,
                "stress_run": object_ref_json("smp-stress-run", benchmark.stress_run, benchmark.stress_run_generation),
                "hart_count": benchmark.hart_count,
                "workload_units": benchmark.workload_units,
                "measured_smp_nanos": benchmark.measured_smp_nanos,
                "speedup_milli": benchmark.speedup_milli,
                "efficiency_milli": benchmark.efficiency_milli,
                "state": benchmark.state,
            })).collect::<Vec<_>>(),
            "activation_resumes": package.semantic.activation_resumes.iter().map(|resume| serde_json::json!({
                "id": resume.id,
                "generation": resume.generation,
                "scheduler_decision": resume.scheduler_decision,
                "scheduler_decision_generation": resume.scheduler_decision_generation,
                "activation": resume.activation,
                "activation_generation_after": resume.activation_generation_after,
            })).collect::<Vec<_>>(),
            "activation_waits": package.semantic.activation_waits.iter().map(|wait| serde_json::json!({
                "id": wait.id,
                "generation": wait.generation,
                "activation": wait.activation,
                "activation_generation_after_block": wait.activation_generation_after_block,
                "wait": wait.wait,
                "wait_generation": wait.wait_generation,
                "state": wait.state,
            })).collect::<Vec<_>>(),
            "activation_cleanups": package.semantic.activation_cleanups.iter().map(|cleanup| serde_json::json!({
                "id": cleanup.id,
                "generation": cleanup.generation,
                "store": cleanup.store,
                "result_store_generation": cleanup.result_store_generation,
                "activation": cleanup.activation,
                "activation_generation_after": cleanup.activation_generation_after,
                "state": cleanup.state,
            })).collect::<Vec<_>>(),
            "preemption_latency_samples": package.semantic.preemption_latency_samples.iter().map(|sample| serde_json::json!({
                "id": sample.id,
                "generation": sample.generation,
                "activation": sample.activation,
                "interrupt_to_resume_events": sample.interrupt_to_resume_events,
                "measured_nanos": sample.measured_nanos,
                "budget_nanos": sample.budget_nanos,
                "state": sample.state,
            })).collect::<Vec<_>>(),
        },
        "last_transition": {
            "scheduler_decision_cursor": package.substrate_boundary.scheduler_decision_cursor,
            "timer_epoch": package.substrate_boundary.timer_epoch,
            "hart_count": package.semantic.hart_count,
            "task_count": package.semantic.task_record_count,
            "activation_count": package.semantic.runtime_activation_count,
            "queue_count": package.semantic.runnable_queue_count,
            "activation_context_count": package.semantic.activation_context_count,
            "saved_context_count": package.semantic.saved_context_count,
            "timer_interrupt_count": package.semantic.timer_interrupt_count,
            "ipi_event_count": package.semantic.ipi_event_count,
            "remote_preempt_count": package.semantic.remote_preempt_count,
            "remote_park_count": package.semantic.remote_park_count,
            "hart_event_attribution_count": package.semantic.hart_event_attribution_count,
            "preemption_count": package.semantic.preemption_count,
            "scheduler_decision_count": package.semantic.scheduler_decision_count,
            "cross_hart_scheduler_decision_count": package.semantic.cross_hart_scheduler_decision_count,
            "activation_migration_count": package.semantic.activation_migration_count,
            "smp_safe_point_count": package.semantic.smp_safe_point_count,
            "stop_the_world_rendezvous_count": package.semantic.stop_the_world_rendezvous_count,
            "smp_code_publish_barrier_count": package.semantic.smp_code_publish_barrier_count,
            "smp_cleanup_quiescence_count": package.semantic.smp_cleanup_quiescence_count,
            "smp_snapshot_barrier_count": package.semantic.smp_snapshot_barrier_count,
            "smp_stress_run_count": package.semantic.smp_stress_run_count,
            "smp_scaling_benchmark_count": package.semantic.smp_scaling_benchmark_count,
            "activation_resume_count": package.semantic.activation_resume_count,
            "activation_wait_count": package.semantic.activation_wait_count,
            "activation_cleanup_count": package.semantic.activation_cleanup_count,
            "preemption_latency_sample_count": package.semantic.preemption_latency_sample_count,
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
        "simd_requirement": {
            "uses_simd": code.simd_requirement.uses_simd,
            "declared": code.simd_requirement.declared,
            "required_abi": code.simd_requirement.required_abi,
            "min_vector_register_count": code.simd_requirement.min_vector_register_count,
            "min_vector_register_bits": code.simd_requirement.min_vector_register_bits,
            "target_feature_set": code.simd_requirement.target_feature_set.as_ref().map(|feature| serde_json::json!({
                "kind": feature.kind,
                "id": feature.id,
                "generation": feature.generation,
            })),
            "status": code.simd_requirement.status,
            "note": code.simd_requirement.note,
        },
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
        "simd_attribution": trap.simd_attribution.as_ref().map(|attribution| serde_json::json!({
            "classification": attribution.classification,
            "required_abi": attribution.required_abi,
            "min_vector_register_count": attribution.min_vector_register_count,
            "min_vector_register_bits": attribution.min_vector_register_bits,
            "target_feature_set": attribution.target_feature_set.as_ref().map(|feature| serde_json::json!({
                "kind": feature.kind,
                "id": feature.id,
                "generation": feature.generation,
            })),
            "code_requirement_status": attribution.code_requirement_status,
            "note": attribution.note,
        })),
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
            "task_generation": wait.owner_task_generation,
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

fn framebuffer_benchmark_view_v1(benchmark: &FramebufferBenchmarkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "store": object_ref_json(
                "store",
                benchmark.owner_store,
                benchmark.owner_store_generation,
            ),
            "display": object_ref_json(
                "display-object",
                benchmark.display,
                benchmark.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                benchmark.framebuffer,
                benchmark.framebuffer_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                benchmark.display_capability,
                benchmark.display_capability_generation,
            ),
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                benchmark.framebuffer_write,
                benchmark.framebuffer_write_generation,
            ),
            "framebuffer_flush_region": object_ref_json(
                "framebuffer-flush-region",
                benchmark.framebuffer_flush_region,
                benchmark.framebuffer_flush_region_generation,
            ),
            "display_event_log": object_ref_json(
                "display-event-log",
                benchmark.display_event_log,
                benchmark.display_event_log_generation,
            ),
            "display_snapshot_barrier": object_ref_json(
                "display-snapshot-barrier",
                benchmark.display_snapshot_barrier,
                benchmark.display_snapshot_barrier_generation,
            ),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "sample_frames": benchmark.sample_frames,
            "sample_bytes": benchmark.sample_bytes,
            "frame_area_pixels": benchmark.frame_area_pixels,
            "write_nanos": benchmark.write_nanos,
            "flush_nanos": benchmark.flush_nanos,
            "measured_nanos": benchmark.measured_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "throughput_bytes_per_sec": benchmark.throughput_bytes_per_sec,
            "flushes_per_sec_milli": benchmark.flushes_per_sec_milli,
            "p50_latency_nanos": benchmark.p50_latency_nanos,
            "p99_latency_nanos": benchmark.p99_latency_nanos,
        },
        "authority": {
            "real_scanout_measured": false,
            "real_gpu_pipeline_measured": false,
            "uses_semantic_write_flush_evidence": true,
            "requires_quiescent_snapshot_barrier": true,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "owner_store_generation": benchmark.owner_store_generation,
            "display_generation": benchmark.display_generation,
            "framebuffer_generation": benchmark.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

fn stable_views_for_kind(
    kind: &str,
    package: &MigrationPackageManifest,
) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    match kind {
        "hart" => Ok(package
            .semantic
            .hart_records
            .iter()
            .map(hart_view_v1)
            .collect()),
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
        "activation-context" | "context" => Ok(package
            .semantic
            .activation_contexts
            .iter()
            .map(activation_context_view_v1)
            .collect()),
        "saved-context" => Ok(package
            .semantic
            .saved_contexts
            .iter()
            .map(saved_context_view_v1)
            .collect()),
        "timer-interrupt" => Ok(package
            .semantic
            .timer_interrupts
            .iter()
            .map(timer_interrupt_view_v1)
            .collect()),
        "ipi" | "ipi-event" => Ok(package
            .semantic
            .ipi_events
            .iter()
            .map(ipi_event_view_v1)
            .collect()),
        "remote-preempt" => Ok(package
            .semantic
            .remote_preempts
            .iter()
            .map(remote_preempt_view_v1)
            .collect()),
        "remote-park" => Ok(package
            .semantic
            .remote_parks
            .iter()
            .map(remote_park_view_v1)
            .collect()),
        "preemption" => Ok(package
            .semantic
            .preemptions
            .iter()
            .map(preemption_view_v1)
            .collect()),
        "scheduler-decision" => Ok(package
            .semantic
            .scheduler_decisions
            .iter()
            .map(scheduler_decision_view_v1)
            .collect()),
        "cross-hart-scheduler-decision" => Ok(package
            .semantic
            .cross_hart_scheduler_decisions
            .iter()
            .map(cross_hart_scheduler_decision_view_v1)
            .collect()),
        "activation-migration" => Ok(package
            .semantic
            .activation_migrations
            .iter()
            .map(activation_migration_view_v1)
            .collect()),
        "smp-safe-point" | "safepoint" => Ok(package
            .semantic
            .smp_safe_points
            .iter()
            .map(smp_safe_point_view_v1)
            .collect()),
        "stop-the-world-rendezvous" | "stop-the-world" | "stw" => Ok(package
            .semantic
            .stop_the_world_rendezvous
            .iter()
            .map(stop_the_world_rendezvous_view_v1)
            .collect()),
        "smp-code-publish-barrier" | "code-publish-barrier" | "publish-barrier" => Ok(package
            .semantic
            .smp_code_publish_barriers
            .iter()
            .map(smp_code_publish_barrier_view_v1)
            .collect()),
        "smp-cleanup-quiescence" | "cleanup-quiescence" => Ok(package
            .semantic
            .smp_cleanup_quiescence
            .iter()
            .map(smp_cleanup_quiescence_view_v1)
            .collect()),
        "smp-snapshot-barrier" | "snapshot-barrier" => Ok(package
            .semantic
            .smp_snapshot_barriers
            .iter()
            .map(smp_snapshot_barrier_view_v1)
            .collect()),
        "smp-stress-run" | "smp-stress" => Ok(package
            .semantic
            .smp_stress_runs
            .iter()
            .map(smp_stress_run_view_v1)
            .collect()),
        "smp-scaling-benchmark" | "smp-scaling" => Ok(package
            .semantic
            .smp_scaling_benchmarks
            .iter()
            .map(smp_scaling_benchmark_view_v1)
            .collect()),
        "integrated-smp-preemption-cleanup"
        | "integrated-smp-cleanup"
        | "smp-preemption-cleanup" => Ok(package
            .semantic
            .integrated_smp_preemption_cleanups
            .iter()
            .map(integrated_smp_preemption_cleanup_view_v1)
            .collect()),
        "device" | "device-object" => Ok(package
            .semantic
            .device_objects
            .iter()
            .map(device_object_view_v1)
            .collect()),
        "queue" | "queue-object" => Ok(package
            .semantic
            .queue_objects
            .iter()
            .map(queue_object_view_v1)
            .collect()),
        "descriptor" | "descriptor-object" => Ok(package
            .semantic
            .descriptor_objects
            .iter()
            .map(descriptor_object_view_v1)
            .collect()),
        "dma-buffer" | "dma-buffer-object" => Ok(package
            .semantic
            .dma_buffer_objects
            .iter()
            .map(dma_buffer_object_view_v1)
            .collect()),
        "mmio-region" | "mmio-region-object" => Ok(package
            .semantic
            .mmio_region_objects
            .iter()
            .map(mmio_region_object_view_v1)
            .collect()),
        "irq-line" | "irq-line-object" => Ok(package
            .semantic
            .irq_line_objects
            .iter()
            .map(irq_line_object_view_v1)
            .collect()),
        "irq-event" => Ok(package
            .semantic
            .irq_events
            .iter()
            .map(irq_event_view_v1)
            .collect()),
        "device-capability" | "io-capability" => Ok(package
            .semantic
            .device_capabilities
            .iter()
            .map(device_capability_view_v1)
            .collect()),
        "driver-store-binding" | "driver-binding" => Ok(package
            .semantic
            .driver_store_bindings
            .iter()
            .map(driver_store_binding_view_v1)
            .collect()),
        "io-wait" | "io-wait-token" => Ok(package
            .semantic
            .io_waits
            .iter()
            .map(io_wait_view_v1)
            .collect()),
        "io-cleanup" => Ok(package
            .semantic
            .io_cleanups
            .iter()
            .map(io_cleanup_view_v1)
            .collect()),
        "io-fault" | "io-fault-injection" => Ok(package
            .semantic
            .io_fault_injections
            .iter()
            .map(io_fault_injection_view_v1)
            .collect()),
        "io-validation" | "io-validation-report" | "io-validator" => Ok(package
            .semantic
            .io_validation_reports
            .iter()
            .map(io_validation_report_view_v1)
            .collect()),
        "packet-device" | "packet-device-object" | "net-device" => Ok(package
            .semantic
            .packet_device_objects
            .iter()
            .map(packet_device_object_view_v1)
            .collect()),
        "packet-buffer" | "packet-buffer-object" => Ok(package
            .semantic
            .packet_buffer_objects
            .iter()
            .map(packet_buffer_object_view_v1)
            .collect()),
        "packet-queue" | "packet-queue-object" | "rx-queue" | "tx-queue" => Ok(package
            .semantic
            .packet_queue_objects
            .iter()
            .map(packet_queue_object_view_v1)
            .collect()),
        "packet-descriptor" | "packet-descriptor-object" => Ok(package
            .semantic
            .packet_descriptors
            .iter()
            .map(packet_descriptor_object_view_v1)
            .collect()),
        "fake-net-backend" | "fake-net-backend-object" => Ok(package
            .semantic
            .fake_net_backends
            .iter()
            .map(fake_net_backend_object_view_v1)
            .collect()),
        "virtio-net-backend" | "virtio-net-backend-object" => Ok(package
            .semantic
            .virtio_net_backends
            .iter()
            .map(virtio_net_backend_object_view_v1)
            .collect()),
        "network-rx-interrupt" | "rx-interrupt" => Ok(package
            .semantic
            .network_rx_interrupts
            .iter()
            .map(network_rx_interrupt_view_v1)
            .collect()),
        "network-rx-wait-resolution" | "rx-wait-resolution" => Ok(package
            .semantic
            .network_rx_wait_resolutions
            .iter()
            .map(network_rx_wait_resolution_view_v1)
            .collect()),
        "network-tx-capability-gate" | "tx-capability-gate" => Ok(package
            .semantic
            .network_tx_capability_gates
            .iter()
            .map(network_tx_capability_gate_view_v1)
            .collect()),
        "network-tx-completion" | "tx-completion" => Ok(package
            .semantic
            .network_tx_completions
            .iter()
            .map(network_tx_completion_view_v1)
            .collect()),
        "network-stack-adapter" | "smoltcp-adapter" => Ok(package
            .semantic
            .network_stack_adapters
            .iter()
            .map(network_stack_adapter_view_v1)
            .collect()),
        "socket-object" | "socket" => Ok(package
            .semantic
            .socket_objects
            .iter()
            .map(socket_object_view_v1)
            .collect()),
        "endpoint-object" | "endpoint" => Ok(package
            .semantic
            .endpoint_objects
            .iter()
            .map(endpoint_object_view_v1)
            .collect()),
        "socket-operation" | "socket-op" => Ok(package
            .semantic
            .socket_operations
            .iter()
            .map(socket_operation_view_v1)
            .collect()),
        "socket-wait" | "socket-wait-token" => Ok(package
            .semantic
            .socket_waits
            .iter()
            .map(socket_wait_view_v1)
            .collect()),
        "network-backpressure" | "backpressure" | "drop-policy" => Ok(package
            .semantic
            .network_backpressures
            .iter()
            .map(network_backpressure_view_v1)
            .collect()),
        "network-driver-cleanup" | "network-cleanup" => Ok(package
            .semantic
            .network_driver_cleanups
            .iter()
            .map(network_driver_cleanup_view_v1)
            .collect()),
        "network-generation-audit" | "generation-audit" | "stale-generation-audit" => Ok(package
            .semantic
            .network_generation_audits
            .iter()
            .map(network_generation_audit_view_v1)
            .collect()),
        "network-fault-injection" | "packet-loss" | "packet-error" => Ok(package
            .semantic
            .network_fault_injections
            .iter()
            .map(network_fault_injection_view_v1)
            .collect()),
        "network-benchmark" | "network-throughput" | "network-latency" => Ok(package
            .semantic
            .network_benchmarks
            .iter()
            .map(network_benchmark_view_v1)
            .collect()),
        "network-recovery-benchmark" | "network-recovery" => Ok(package
            .semantic
            .network_recovery_benchmarks
            .iter()
            .map(network_recovery_benchmark_view_v1)
            .collect()),
        "block-device" | "block-device-object" | "block" => Ok(package
            .semantic
            .block_device_objects
            .iter()
            .map(block_device_object_view_v1)
            .collect()),
        "block-range" | "block-range-object" | "sector-range" => Ok(package
            .semantic
            .block_range_objects
            .iter()
            .map(block_range_object_view_v1)
            .collect()),
        "block-request" | "block-request-object" => Ok(package
            .semantic
            .block_request_objects
            .iter()
            .map(block_request_object_view_v1)
            .collect()),
        "block-completion" | "block-completion-object" => Ok(package
            .semantic
            .block_completion_objects
            .iter()
            .map(block_completion_object_view_v1)
            .collect()),
        "block-wait" | "block-wait-token" => Ok(package
            .semantic
            .block_waits
            .iter()
            .map(block_wait_view_v1)
            .collect()),
        "fake-block-backend" | "fake-block-backend-object" => Ok(package
            .semantic
            .fake_block_backends
            .iter()
            .map(fake_block_backend_object_view_v1)
            .collect()),
        "virtio-blk-backend" | "virtio-blk-backend-object" => Ok(package
            .semantic
            .virtio_blk_backends
            .iter()
            .map(virtio_blk_backend_object_view_v1)
            .collect()),
        "block-read-path" | "block-read" => Ok(package
            .semantic
            .block_read_paths
            .iter()
            .map(block_read_path_view_v1)
            .collect()),
        "block-write-path" | "block-write" => Ok(package
            .semantic
            .block_write_paths
            .iter()
            .map(block_write_path_view_v1)
            .collect()),
        "block-request-queue" | "block-queue" => Ok(package
            .semantic
            .block_request_queues
            .iter()
            .map(block_request_queue_view_v1)
            .collect()),
        "block-dma-buffer" | "block-buffer" => Ok(package
            .semantic
            .block_dma_buffers
            .iter()
            .map(block_dma_buffer_view_v1)
            .collect()),
        "block-page-object" | "block-page" => Ok(package
            .semantic
            .block_page_objects
            .iter()
            .map(block_page_object_view_v1)
            .collect()),
        "buffer-cache-object" | "buffer-cache" | "fs-cache" => Ok(package
            .semantic
            .buffer_cache_objects
            .iter()
            .map(buffer_cache_object_view_v1)
            .collect()),
        "file-object" | "file" => Ok(package
            .semantic
            .file_objects
            .iter()
            .map(file_object_view_v1)
            .collect()),
        "directory-object" | "directory" => Ok(package
            .semantic
            .directory_objects
            .iter()
            .map(directory_object_view_v1)
            .collect()),
        "fat-adapter-object" | "fat-adapter" => Ok(package
            .semantic
            .fat_adapter_objects
            .iter()
            .map(fat_adapter_object_view_v1)
            .collect()),
        "ext4-adapter-object" | "ext4-adapter" => Ok(package
            .semantic
            .ext4_adapter_objects
            .iter()
            .map(ext4_adapter_object_view_v1)
            .collect()),
        "file-handle-capability" | "file-handle" | "file-capability" => Ok(package
            .semantic
            .file_handle_capabilities
            .iter()
            .map(file_handle_capability_view_v1)
            .collect()),
        "fs-wait" | "filesystem-wait" | "file-wait" => Ok(package
            .semantic
            .fs_waits
            .iter()
            .map(fs_wait_view_v1)
            .collect()),
        "block-driver-cleanup" | "disk-driver-cleanup" | "disk-cleanup" => Ok(package
            .semantic
            .block_driver_cleanups
            .iter()
            .map(block_driver_cleanup_view_v1)
            .collect()),
        "block-pending-io-policy" | "pending-block-io" | "pending-io-policy" => Ok(package
            .semantic
            .block_pending_io_policies
            .iter()
            .map(block_pending_io_policy_view_v1)
            .collect()),
        "block-request-generation-audit"
        | "stale-block-request-generation"
        | "block-generation-audit" => Ok(package
            .semantic
            .block_request_generation_audits
            .iter()
            .map(block_request_generation_audit_view_v1)
            .collect()),
        "block-benchmark" | "disk-benchmark" | "block-iops" => Ok(package
            .semantic
            .block_benchmarks
            .iter()
            .map(block_benchmark_view_v1)
            .collect()),
        "block-recovery-benchmark" | "disk-recovery-benchmark" | "disk-recovery" => Ok(package
            .semantic
            .block_recovery_benchmarks
            .iter()
            .map(block_recovery_benchmark_view_v1)
            .collect()),
        "target-feature-set" | "target-feature" | "target-feature-set-object" => Ok(package
            .semantic
            .target_feature_sets
            .iter()
            .map(target_feature_set_view_v1)
            .collect()),
        "vector-state" | "vector" | "simd-vector-state" => Ok(package
            .semantic
            .vector_states
            .iter()
            .map(vector_state_view_v1)
            .collect()),
        "simd-fault-injection" | "simd-fault" => Ok(package
            .semantic
            .simd_fault_injections
            .iter()
            .map(simd_fault_injection_view_v1)
            .collect()),
        "simd-benchmark" | "simd-scalar-vector-benchmark" => Ok(package
            .semantic
            .simd_benchmarks
            .iter()
            .map(simd_benchmark_view_v1)
            .collect()),
        "simd-context-switch-benchmark" | "simd-context-switch" | "simd-switch-benchmark" => {
            Ok(package
                .semantic
                .simd_context_switch_benchmarks
                .iter()
                .map(simd_context_switch_benchmark_view_v1)
                .collect())
        }
        "framebuffer-object" | "framebuffer" | "fb" => Ok(package
            .semantic
            .framebuffer_objects
            .iter()
            .map(framebuffer_object_view_v1)
            .collect()),
        "display-object" | "display" | "display-mode" => Ok(package
            .semantic
            .display_objects
            .iter()
            .map(display_object_view_v1)
            .collect()),
        "display-capability" | "display-cap" => Ok(package
            .semantic
            .display_capabilities
            .iter()
            .map(display_capability_view_v1)
            .collect()),
        "framebuffer-window-lease" | "fb-window-lease" | "display-lease" => Ok(package
            .semantic
            .framebuffer_window_leases
            .iter()
            .map(framebuffer_window_lease_view_v1)
            .collect()),
        "framebuffer-mapping" | "fb-mapping" | "display-mapping" => Ok(package
            .semantic
            .framebuffer_mappings
            .iter()
            .map(framebuffer_mapping_view_v1)
            .collect()),
        "framebuffer-write" | "fb-write" | "display-write" => Ok(package
            .semantic
            .framebuffer_writes
            .iter()
            .map(framebuffer_write_view_v1)
            .collect()),
        "framebuffer-flush-region" | "flush-region" | "display-flush" => Ok(package
            .semantic
            .framebuffer_flush_regions
            .iter()
            .map(framebuffer_flush_region_view_v1)
            .collect()),
        "framebuffer-dirty-region" | "dirty-region" | "display-dirty" => Ok(package
            .semantic
            .framebuffer_dirty_regions
            .iter()
            .map(framebuffer_dirty_region_view_v1)
            .collect()),
        "display-event-log" | "display-log" => Ok(package
            .semantic
            .display_event_logs
            .iter()
            .map(display_event_log_view_v1)
            .collect()),
        "display-cleanup" => Ok(package
            .semantic
            .display_cleanups
            .iter()
            .map(display_cleanup_view_v1)
            .collect()),
        "display-snapshot-barrier" | "display-snapshot" => Ok(package
            .semantic
            .display_snapshot_barriers
            .iter()
            .map(display_snapshot_barrier_view_v1)
            .collect()),
        "display-panic-last-frame" | "panic-last-frame" => Ok(package
            .semantic
            .display_panic_last_frames
            .iter()
            .map(display_panic_last_frame_view_v1)
            .collect()),
        "framebuffer-benchmark" | "fb-benchmark" | "display-benchmark" => Ok(package
            .semantic
            .framebuffer_benchmarks
            .iter()
            .map(framebuffer_benchmark_view_v1)
            .collect()),
        "activation-resume" => Ok(package
            .semantic
            .activation_resumes
            .iter()
            .map(activation_resume_view_v1)
            .collect()),
        "activation-wait" => Ok(package
            .semantic
            .activation_waits
            .iter()
            .map(activation_wait_view_v1)
            .collect()),
        "activation-cleanup" => Ok(package
            .semantic
            .activation_cleanups
            .iter()
            .map(activation_cleanup_view_v1)
            .collect()),
        "preemption-latency" => Ok(package
            .semantic
            .preemption_latency_samples
            .iter()
            .map(preemption_latency_view_v1)
            .collect()),
        "hart-event" | "hart-event-attribution" => Ok(package
            .semantic
            .hart_event_attributions
            .iter()
            .map(hart_event_attribution_view_v1)
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
        "graph package={} cursor={} hart_roots={} task_roots={} resource_roots={} authority_roots={} store_roots={} capability_roots={} target_store_record_roots={} target_capability_record_roots={} fastpath_roots={} boundary_roots={} artifact_verification_roots={} store_activation_roots={} executor_transition_roots={} target_artifact_roots={} code_object_roots={} activation_record_roots={} trap_roots={} hostcall_trace_roots={} migration_object_roots={} tombstone_roots={} contract_violation_roots={} timer_interrupt_roots={} ipi_event_roots={} remote_preempt_roots={} remote_park_roots={} cross_hart_scheduler_decision_roots={} activation_migration_roots={} smp_safe_point_roots={} stop_the_world_rendezvous_roots={} smp_code_publish_barrier_roots={} smp_cleanup_quiescence_roots={} smp_snapshot_barrier_roots={} smp_stress_run_roots={} smp_scaling_benchmark_roots={} device_roots={} queue_roots={} descriptor_roots={} dma_buffer_roots={} mmio_region_roots={} irq_line_roots={} irq_event_roots={} device_capability_roots={} driver_store_binding_roots={} io_wait_roots={} io_cleanup_roots={} io_fault_injection_roots={} io_validation_report_roots={} packet_device_roots={} packet_buffer_roots={} packet_queue_roots={} packet_descriptor_roots={} fake_net_backend_roots={} virtio_net_backend_roots={} socket_wait_roots={} network_backpressure_roots={} network_driver_cleanup_roots={} activation_resume_roots={} activation_wait_roots={} activation_cleanup_roots={} preemption_latency_roots={} hart_event_attribution_roots={}",
        package.package_id,
        package.semantic.event_log_cursor,
        package.semantic.roots.hart_roots.len(),
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
        package.semantic.roots.contract_violation_roots.len(),
        package.semantic.roots.timer_interrupt_roots.len(),
        package.semantic.roots.ipi_event_roots.len(),
        package.semantic.roots.remote_preempt_roots.len(),
        package.semantic.roots.remote_park_roots.len(),
        package
            .semantic
            .roots
            .cross_hart_scheduler_decision_roots
            .len(),
        package.semantic.roots.activation_migration_roots.len(),
        package.semantic.roots.smp_safe_point_roots.len(),
        package.semantic.roots.stop_the_world_rendezvous_roots.len(),
        package.semantic.roots.smp_code_publish_barrier_roots.len(),
        package.semantic.roots.smp_cleanup_quiescence_roots.len(),
        package.semantic.roots.smp_snapshot_barrier_roots.len(),
        package.semantic.roots.smp_stress_run_roots.len(),
        package.semantic.roots.smp_scaling_benchmark_roots.len(),
        package.semantic.roots.device_object_roots.len(),
        package.semantic.roots.queue_object_roots.len(),
        package.semantic.roots.descriptor_object_roots.len(),
        package.semantic.roots.dma_buffer_object_roots.len(),
        package.semantic.roots.mmio_region_object_roots.len(),
        package.semantic.roots.irq_line_object_roots.len(),
        package.semantic.roots.irq_event_roots.len(),
        package.semantic.roots.device_capability_roots.len(),
        package.semantic.roots.driver_store_binding_roots.len(),
        package.semantic.roots.io_wait_roots.len(),
        package.semantic.roots.io_cleanup_roots.len(),
        package.semantic.roots.io_fault_injection_roots.len(),
        package.semantic.roots.io_validation_report_roots.len(),
        package.semantic.roots.packet_device_object_roots.len(),
        package.semantic.roots.packet_buffer_object_roots.len(),
        package.semantic.roots.packet_queue_object_roots.len(),
        package.semantic.roots.packet_descriptor_object_roots.len(),
        package.semantic.roots.fake_net_backend_object_roots.len(),
        package.semantic.roots.virtio_net_backend_object_roots.len(),
        package.semantic.roots.socket_wait_roots.len(),
        package.semantic.roots.network_backpressure_roots.len(),
        package.semantic.roots.network_driver_cleanup_roots.len(),
        package.semantic.roots.activation_resume_roots.len(),
        package.semantic.roots.activation_wait_roots.len(),
        package.semantic.roots.activation_cleanup_roots.len(),
        package.semantic.roots.preemption_latency_roots.len(),
        package.semantic.roots.hart_event_attribution_roots.len()
    );
    print_roots("hart", &package.semantic.roots.hart_roots);
    print_roots("task", &package.semantic.roots.task_roots);
    print_roots(
        "activation-context",
        &package.semantic.roots.activation_context_roots,
    );
    print_roots("saved-context", &package.semantic.roots.saved_context_roots);
    print_roots(
        "timer-interrupt",
        &package.semantic.roots.timer_interrupt_roots,
    );
    print_roots("ipi-event", &package.semantic.roots.ipi_event_roots);
    print_roots(
        "remote-preempt",
        &package.semantic.roots.remote_preempt_roots,
    );
    print_roots("remote-park", &package.semantic.roots.remote_park_roots);
    print_roots("preemption", &package.semantic.roots.preemption_roots);
    print_roots(
        "scheduler-decision",
        &package.semantic.roots.scheduler_decision_roots,
    );
    print_roots(
        "cross-hart-scheduler-decision",
        &package.semantic.roots.cross_hart_scheduler_decision_roots,
    );
    print_roots(
        "activation-migration",
        &package.semantic.roots.activation_migration_roots,
    );
    print_roots(
        "smp-safe-point",
        &package.semantic.roots.smp_safe_point_roots,
    );
    print_roots(
        "stop-the-world-rendezvous",
        &package.semantic.roots.stop_the_world_rendezvous_roots,
    );
    print_roots(
        "smp-code-publish-barrier",
        &package.semantic.roots.smp_code_publish_barrier_roots,
    );
    print_roots(
        "smp-cleanup-quiescence",
        &package.semantic.roots.smp_cleanup_quiescence_roots,
    );
    print_roots(
        "smp-snapshot-barrier",
        &package.semantic.roots.smp_snapshot_barrier_roots,
    );
    print_roots(
        "smp-stress-run",
        &package.semantic.roots.smp_stress_run_roots,
    );
    print_roots(
        "smp-scaling-benchmark",
        &package.semantic.roots.smp_scaling_benchmark_roots,
    );
    print_roots(
        "integrated-smp-preemption-cleanup",
        &package
            .semantic
            .roots
            .integrated_smp_preemption_cleanup_roots,
    );
    print_roots("device", &package.semantic.roots.device_object_roots);
    print_roots("queue", &package.semantic.roots.queue_object_roots);
    print_roots(
        "descriptor",
        &package.semantic.roots.descriptor_object_roots,
    );
    print_roots(
        "dma-buffer",
        &package.semantic.roots.dma_buffer_object_roots,
    );
    print_roots(
        "mmio-region",
        &package.semantic.roots.mmio_region_object_roots,
    );
    print_roots("irq-line", &package.semantic.roots.irq_line_object_roots);
    print_roots("irq-event", &package.semantic.roots.irq_event_roots);
    print_roots(
        "device-capability",
        &package.semantic.roots.device_capability_roots,
    );
    print_roots(
        "driver-store-binding",
        &package.semantic.roots.driver_store_binding_roots,
    );
    print_roots("io-wait", &package.semantic.roots.io_wait_roots);
    print_roots("io-cleanup", &package.semantic.roots.io_cleanup_roots);
    print_roots(
        "io-fault-injection",
        &package.semantic.roots.io_fault_injection_roots,
    );
    print_roots(
        "io-validation-report",
        &package.semantic.roots.io_validation_report_roots,
    );
    print_roots(
        "packet-device",
        &package.semantic.roots.packet_device_object_roots,
    );
    print_roots(
        "packet-buffer",
        &package.semantic.roots.packet_buffer_object_roots,
    );
    print_roots(
        "packet-queue",
        &package.semantic.roots.packet_queue_object_roots,
    );
    print_roots(
        "packet-descriptor",
        &package.semantic.roots.packet_descriptor_object_roots,
    );
    print_roots(
        "fake-net-backend",
        &package.semantic.roots.fake_net_backend_object_roots,
    );
    print_roots(
        "virtio-net-backend",
        &package.semantic.roots.virtio_net_backend_object_roots,
    );
    print_roots(
        "network-rx-interrupt",
        &package.semantic.roots.network_rx_interrupt_roots,
    );
    print_roots(
        "network-rx-wait-resolution",
        &package.semantic.roots.network_rx_wait_resolution_roots,
    );
    print_roots(
        "network-tx-capability-gate",
        &package.semantic.roots.network_tx_capability_gate_roots,
    );
    print_roots(
        "network-tx-completion",
        &package.semantic.roots.network_tx_completion_roots,
    );
    print_roots(
        "network-stack-adapter",
        &package.semantic.roots.network_stack_adapter_roots,
    );
    print_roots("socket-object", &package.semantic.roots.socket_object_roots);
    print_roots(
        "endpoint-object",
        &package.semantic.roots.endpoint_object_roots,
    );
    print_roots(
        "socket-operation",
        &package.semantic.roots.socket_operation_roots,
    );
    print_roots("socket-wait", &package.semantic.roots.socket_wait_roots);
    print_roots(
        "network-backpressure",
        &package.semantic.roots.network_backpressure_roots,
    );
    print_roots(
        "network-driver-cleanup",
        &package.semantic.roots.network_driver_cleanup_roots,
    );
    print_roots(
        "network-recovery-benchmark",
        &package.semantic.roots.network_recovery_benchmark_roots,
    );
    print_roots(
        "block-device",
        &package.semantic.roots.block_device_object_roots,
    );
    print_roots(
        "block-range",
        &package.semantic.roots.block_range_object_roots,
    );
    print_roots(
        "block-request",
        &package.semantic.roots.block_request_object_roots,
    );
    print_roots(
        "block-completion",
        &package.semantic.roots.block_completion_object_roots,
    );
    print_roots("block-wait", &package.semantic.roots.block_wait_roots);
    print_roots(
        "fake-block-backend",
        &package.semantic.roots.fake_block_backend_object_roots,
    );
    print_roots(
        "virtio-blk-backend",
        &package.semantic.roots.virtio_blk_backend_object_roots,
    );
    print_roots(
        "block-read-path",
        &package.semantic.roots.block_read_path_roots,
    );
    print_roots(
        "block-write-path",
        &package.semantic.roots.block_write_path_roots,
    );
    print_roots(
        "block-request-queue",
        &package.semantic.roots.block_request_queue_roots,
    );
    print_roots(
        "block-dma-buffer",
        &package.semantic.roots.block_dma_buffer_roots,
    );
    print_roots(
        "block-page-object",
        &package.semantic.roots.block_page_object_roots,
    );
    print_roots(
        "buffer-cache-object",
        &package.semantic.roots.buffer_cache_object_roots,
    );
    print_roots("file-object", &package.semantic.roots.file_object_roots);
    print_roots(
        "directory-object",
        &package.semantic.roots.directory_object_roots,
    );
    print_roots(
        "fat-adapter-object",
        &package.semantic.roots.fat_adapter_object_roots,
    );
    print_roots(
        "ext4-adapter-object",
        &package.semantic.roots.ext4_adapter_object_roots,
    );
    print_roots(
        "file-handle-capability",
        &package.semantic.roots.file_handle_capability_roots,
    );
    print_roots("fs-wait", &package.semantic.roots.fs_wait_roots);
    print_roots(
        "block-driver-cleanup",
        &package.semantic.roots.block_driver_cleanup_roots,
    );
    print_roots(
        "activation-resume",
        &package.semantic.roots.activation_resume_roots,
    );
    print_roots(
        "activation-wait",
        &package.semantic.roots.activation_wait_roots,
    );
    print_roots(
        "activation-cleanup",
        &package.semantic.roots.activation_cleanup_roots,
    );
    print_roots(
        "preemption-latency",
        &package.semantic.roots.preemption_latency_roots,
    );
    print_roots(
        "hart-event-attribution",
        &package.semantic.roots.hart_event_attribution_roots,
    );
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
        if let (Some(hart), Some(hart_generation)) = (queue.owner_hart, queue.owner_hart_generation)
        {
            edges.push(graph_edge(
                object_ref_json("hart", u64::from(hart), hart_generation),
                object_ref_json("runnable-queue", queue.id, queue.generation),
                "owns-runnable-queue",
                "historical",
                None,
            ));
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
    for context in &package.semantic.activation_contexts {
        if context.state == "dropped" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json(
                "activation",
                context.activation,
                context.activation_generation,
            ),
            object_ref_json("activation-context", context.id, context.generation),
            "has-context",
            "live",
            context.last_event,
        ));
        if let (Some(saved), Some(saved_generation)) = (
            context.current_saved_context,
            context.current_saved_context_generation,
        ) {
            edges.push(graph_edge(
                object_ref_json("activation-context", context.id, context.generation),
                object_ref_json("saved-context", saved, saved_generation),
                "current-saved-context",
                "live",
                context.last_event,
            ));
        }
        if let Some(vector_state) = &context.vector_state {
            edges.push(graph_edge(
                object_ref_json("activation-context", context.id, context.generation),
                object_ref_manifest_json(vector_state),
                "vector-context",
                if context.vector_status == "dirty" || context.vector_status == "clean" {
                    "live"
                } else {
                    "historical"
                },
                context.vector_state_event.or(context.last_event),
            ));
        }
    }
    for saved in &package.semantic.saved_contexts {
        if saved.state != "captured" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json(
                "activation-context",
                saved.context,
                saved.context_generation,
            ),
            object_ref_json("saved-context", saved.id, saved.generation),
            "captures",
            "live",
            Some(saved.saved_at_event),
        ));
    }
    for packet_device in &package.semantic.packet_device_objects {
        if packet_device.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("packet-device", packet_device.id, packet_device.generation),
            object_ref_json(
                "device",
                packet_device.device,
                packet_device.device_generation,
            ),
            "packet-device->device",
            "live",
            Some(packet_device.recorded_at_event),
        ));
    }
    for block_device in &package.semantic.block_device_objects {
        if block_device.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("block-device", block_device.id, block_device.generation),
            object_ref_json(
                "device",
                block_device.device,
                block_device.device_generation,
            ),
            "block-device->device",
            "live",
            Some(block_device.recorded_at_event),
        ));
    }
    for block_range in &package.semantic.block_range_objects {
        if block_range.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("block-range", block_range.id, block_range.generation),
            object_ref_json(
                "block-device",
                block_range.block_device,
                block_range.block_device_generation,
            ),
            "block-range->block-device",
            "live",
            Some(block_range.recorded_at_event),
        ));
    }
    for request in &package.semantic.block_request_objects {
        if request.state != "submitted" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("block-request", request.id, request.generation),
            object_ref_json(
                "block-device",
                request.block_device,
                request.block_device_generation,
            ),
            "block-request->block-device",
            "live",
            Some(request.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("block-request", request.id, request.generation),
            object_ref_json(
                "block-range",
                request.block_range,
                request.block_range_generation,
            ),
            "block-request->block-range",
            "live",
            Some(request.recorded_at_event),
        ));
    }
    for block_wait in &package.semantic.block_waits {
        if block_wait.state != "pending" {
            continue;
        }
        let from = object_ref_json("block-wait", block_wait.id, block_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", block_wait.wait, block_wait.wait_generation),
            "block-wait->wait-token",
            "live",
            Some(block_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                block_wait.block_request,
                block_wait.block_request_generation,
            ),
            "block-wait->block-request",
            "live",
            Some(block_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-device",
                block_wait.block_device,
                block_wait.block_device_generation,
            ),
            "block-wait->block-device",
            "live",
            Some(block_wait.created_at_event),
        ));
    }
    for backend in &package.semantic.fake_block_backends {
        if backend.state != "bound" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("fake-block-backend", backend.id, backend.generation),
            object_ref_json(
                "block-device",
                backend.block_device,
                backend.block_device_generation,
            ),
            "fake-block-backend->block-device",
            "live",
            Some(backend.recorded_at_event),
        ));
    }
    for backend in &package.semantic.virtio_blk_backends {
        if backend.state != "skeleton-ready" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("virtio-blk-backend", backend.id, backend.generation),
            object_ref_json(
                "block-device",
                backend.block_device,
                backend.block_device_generation,
            ),
            "virtio-blk-backend->block-device",
            "live",
            Some(backend.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("virtio-blk-backend", backend.id, backend.generation),
            object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
            "virtio-blk-backend->driver-binding",
            "live",
            Some(backend.recorded_at_event),
        ));
    }
    for read_path in &package.semantic.block_read_paths {
        if read_path.state != "completed" {
            continue;
        }
        let from = object_ref_json("block-read-path", read_path.id, read_path.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&read_path.backend_kind),
                read_path.backend,
                read_path.backend_generation,
            ),
            "block-read-path->backend",
            "historical",
            Some(read_path.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                read_path.block_request,
                read_path.block_request_generation,
            ),
            "block-read-path->block-request",
            "historical",
            Some(read_path.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-completion",
                read_path.block_completion,
                read_path.block_completion_generation,
            ),
            "block-read-path->block-completion",
            "historical",
            Some(read_path.recorded_at_event),
        ));
    }
    for write_path in &package.semantic.block_write_paths {
        if write_path.state != "completed" {
            continue;
        }
        let from = object_ref_json("block-write-path", write_path.id, write_path.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&write_path.backend_kind),
                write_path.backend,
                write_path.backend_generation,
            ),
            "block-write-path->backend",
            "historical",
            Some(write_path.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                write_path.block_request,
                write_path.block_request_generation,
            ),
            "block-write-path->block-request",
            "historical",
            Some(write_path.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-completion",
                write_path.block_completion,
                write_path.block_completion_generation,
            ),
            "block-write-path->block-completion",
            "historical",
            Some(write_path.recorded_at_event),
        ));
    }
    for queue in &package.semantic.block_request_queues {
        if queue.state != "active" {
            continue;
        }
        let from = object_ref_json("block-request-queue", queue.id, queue.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&queue.backend_kind),
                queue.backend,
                queue.backend_generation,
            ),
            "block-request-queue->backend",
            "historical",
            Some(queue.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                queue.block_device,
                queue.block_device_generation,
            ),
            "block-request-queue->block-device",
            "historical",
            Some(queue.recorded_at_event),
        ));
        for entry in &queue.entries {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("block-request", entry.request, entry.request_generation),
                "block-request-queue->block-request",
                "historical",
                Some(queue.recorded_at_event),
            ));
            if let (Some(completion), Some(generation)) =
                (entry.completion, entry.completion_generation)
            {
                edges.push(graph_edge(
                    from.clone(),
                    object_ref_json("block-completion", completion, generation),
                    "block-request-queue->block-completion",
                    "historical",
                    Some(queue.recorded_at_event),
                ));
            }
        }
    }
    for buffer in &package.semantic.block_dma_buffers {
        if buffer.state != "bound" {
            continue;
        }
        let from = object_ref_json("block-dma-buffer", buffer.id, buffer.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&buffer.backend_kind),
                buffer.backend,
                buffer.backend_generation,
            ),
            "block-dma-buffer->backend",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                buffer.block_request,
                buffer.block_request_generation,
            ),
            "block-dma-buffer->block-request",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "dma-buffer",
                buffer.dma_buffer,
                buffer.dma_buffer_generation,
            ),
            "block-dma-buffer->dma-buffer",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                buffer.block_device,
                buffer.block_device_generation,
            ),
            "block-dma-buffer->block-device",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-range",
                buffer.block_range,
                buffer.block_range_generation,
            ),
            "block-dma-buffer->block-range",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "descriptor",
                buffer.descriptor,
                buffer.descriptor_generation,
            ),
            "block-dma-buffer->descriptor",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("queue", buffer.queue, buffer.queue_generation),
            "block-dma-buffer->queue",
            "historical",
            Some(buffer.recorded_at_event),
        ));
    }
    for page in &package.semantic.block_page_objects {
        if page.state != "integrated" {
            continue;
        }
        let from = object_ref_json("block-page-object", page.id, page.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-dma-buffer",
                page.block_dma_buffer,
                page.block_dma_buffer_generation,
            ),
            "block-page-object->block-dma-buffer",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                page.block_request,
                page.block_request_generation,
            ),
            "block-page-object->block-request",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-completion",
                page.block_completion,
                page.block_completion_generation,
            ),
            "block-page-object->block-completion",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("dma-buffer", page.dma_buffer, page.dma_buffer_generation),
            "block-page-object->dma-buffer",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                page.block_device,
                page.block_device_generation,
            ),
            "block-page-object->block-device",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-range", page.block_range, page.block_range_generation),
            "block-page-object->block-range",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&page.aspace),
            "block-page-object->guest-address-space",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&page.vma_region),
            "block-page-object->vma-region",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&page.page),
            "block-page-object->page-object",
            "historical",
            Some(page.recorded_at_event),
        ));
    }
    for cache in &package.semantic.buffer_cache_objects {
        if cache.state == "invalidated" {
            continue;
        }
        let from = object_ref_json("buffer-cache-object", cache.id, cache.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-page-object",
                cache.block_page_object,
                cache.block_page_object_generation,
            ),
            "buffer-cache-object->block-page-object",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-dma-buffer",
                cache.block_dma_buffer,
                cache.block_dma_buffer_generation,
            ),
            "buffer-cache-object->block-dma-buffer",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                cache.block_device,
                cache.block_device_generation,
            ),
            "buffer-cache-object->block-device",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-range",
                cache.block_range,
                cache.block_range_generation,
            ),
            "buffer-cache-object->block-range",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&cache.aspace),
            "buffer-cache-object->guest-address-space",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&cache.vma_region),
            "buffer-cache-object->vma-region",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&cache.page),
            "buffer-cache-object->page-object",
            "historical",
            Some(cache.recorded_at_event),
        ));
    }
    for file in &package.semantic.file_objects {
        if file.state == "invalidated" {
            continue;
        }
        let from = object_ref_json("file-object", file.id, file.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "buffer-cache-object",
                file.buffer_cache_object,
                file.buffer_cache_object_generation,
            ),
            "file-object->buffer-cache-object",
            "historical",
            Some(file.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                file.block_device,
                file.block_device_generation,
            ),
            "file-object->block-device",
            "historical",
            Some(file.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-range", file.block_range, file.block_range_generation),
            "file-object->block-range",
            "historical",
            Some(file.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&file.page),
            "file-object->page-object",
            "historical",
            Some(file.recorded_at_event),
        ));
    }
    for directory in &package.semantic.directory_objects {
        if directory.state == "invalidated" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("directory-object", directory.id, directory.generation),
            object_ref_json(
                "file-object",
                directory.file_object,
                directory.file_object_generation,
            ),
            "directory-object->file-object",
            "historical",
            Some(directory.recorded_at_event),
        ));
    }
    for adapter in &package.semantic.fat_adapter_objects {
        if adapter.state != "verified" {
            continue;
        }
        let from = object_ref_json("fat-adapter-object", adapter.id, adapter.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "directory-object",
                adapter.directory_object,
                adapter.directory_object_generation,
            ),
            "fat-adapter-object->directory-object",
            "historical",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "file-object",
                adapter.file_object,
                adapter.file_object_generation,
            ),
            "fat-adapter-object->file-object",
            "historical",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-device",
                adapter.block_device,
                adapter.block_device_generation,
            ),
            "fat-adapter-object->block-device",
            "historical",
            Some(adapter.recorded_at_event),
        ));
    }
    for adapter in &package.semantic.ext4_adapter_objects {
        if adapter.state != "verified" {
            continue;
        }
        let from = object_ref_json("ext4-adapter-object", adapter.id, adapter.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "directory-object",
                adapter.directory_object,
                adapter.directory_object_generation,
            ),
            "ext4-adapter-object->directory-object",
            "historical",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "file-object",
                adapter.file_object,
                adapter.file_object_generation,
            ),
            "ext4-adapter-object->file-object",
            "historical",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-device",
                adapter.block_device,
                adapter.block_device_generation,
            ),
            "ext4-adapter-object->block-device",
            "historical",
            Some(adapter.recorded_at_event),
        ));
    }
    for capability in &package.semantic.file_handle_capabilities {
        if capability.state != "allowed" {
            continue;
        }
        let from = object_ref_json(
            "file-handle-capability",
            capability.id,
            capability.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                capability.owner_store,
                capability.owner_store_generation,
            ),
            "file-handle-capability->store",
            "historical",
            Some(capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "file-object",
                capability.file_object,
                capability.file_object_generation,
            ),
            "file-handle-capability->file-object",
            "historical",
            Some(capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "directory-object",
                capability.directory_object,
                capability.directory_object_generation,
            ),
            "file-handle-capability->directory-object",
            "historical",
            Some(capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "capability",
                capability.capability,
                capability.capability_generation,
            ),
            "file-handle-capability->capability",
            "historical",
            Some(capability.recorded_at_event),
        ));
    }
    for wait in &package.semantic.fs_waits {
        if wait.state != "pending" {
            continue;
        }
        let from = object_ref_json("fs-wait", wait.id, wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "fs-wait->wait-token",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "file-handle-capability",
                wait.file_handle_capability,
                wait.file_handle_capability_generation,
            ),
            "fs-wait->file-handle-capability",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("file-object", wait.file_object, wait.file_object_generation),
            "fs-wait->file-object",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&wait.blocker),
            "fs-wait->blocker",
            "live",
            Some(wait.created_at_event),
        ));
    }
    for packet_buffer in &package.semantic.packet_buffer_objects {
        if packet_buffer.state != "allocated" && packet_buffer.state != "filled" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("packet-buffer", packet_buffer.id, packet_buffer.generation),
            object_ref_json(
                "packet-device",
                packet_buffer.packet_device,
                packet_buffer.packet_device_generation,
            ),
            "packet-buffer->packet-device",
            "live",
            Some(packet_buffer.recorded_at_event),
        ));
    }
    for packet_queue in &package.semantic.packet_queue_objects {
        if packet_queue.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("packet-queue", packet_queue.id, packet_queue.generation),
            object_ref_json(
                "packet-device",
                packet_queue.packet_device,
                packet_queue.packet_device_generation,
            ),
            "packet-queue->packet-device",
            "live",
            Some(packet_queue.recorded_at_event),
        ));
    }
    for packet_descriptor in &package.semantic.packet_descriptors {
        if packet_descriptor.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json(
                "packet-descriptor",
                packet_descriptor.id,
                packet_descriptor.generation,
            ),
            object_ref_json(
                "packet-queue",
                packet_descriptor.packet_queue,
                packet_descriptor.packet_queue_generation,
            ),
            "packet-descriptor->packet-queue",
            "live",
            Some(packet_descriptor.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json(
                "packet-descriptor",
                packet_descriptor.id,
                packet_descriptor.generation,
            ),
            object_ref_json(
                "packet-buffer",
                packet_descriptor.packet_buffer,
                packet_descriptor.packet_buffer_generation,
            ),
            "packet-descriptor->packet-buffer",
            "live",
            Some(packet_descriptor.recorded_at_event),
        ));
    }
    for backend in &package.semantic.fake_net_backends {
        if backend.state != "bound" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("fake-net-backend", backend.id, backend.generation),
            object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation,
            ),
            "fake-net-backend->packet-device",
            "live",
            Some(backend.recorded_at_event),
        ));
    }
    for backend in &package.semantic.virtio_net_backends {
        if backend.state != "skeleton-ready" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("virtio-net-backend", backend.id, backend.generation),
            object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation,
            ),
            "virtio-net-backend->packet-device",
            "live",
            Some(backend.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("virtio-net-backend", backend.id, backend.generation),
            object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
            "virtio-net-backend->driver-binding",
            "live",
            Some(backend.recorded_at_event),
        ));
    }
    for adapter in &package.semantic.network_stack_adapters {
        if adapter.state != "bound" {
            continue;
        }
        let from = object_ref_json("network-stack-adapter", adapter.id, adapter.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&adapter.backend_kind),
                adapter.backend,
                adapter.backend_generation,
            ),
            "network-stack-adapter->backend",
            "live",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-device",
                adapter.packet_device,
                adapter.packet_device_generation,
            ),
            "network-stack-adapter->packet-device",
            "live",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-queue",
                adapter.rx_queue,
                adapter.rx_queue_generation,
            ),
            "network-stack-adapter->rx-queue",
            "live",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "packet-queue",
                adapter.tx_queue,
                adapter.tx_queue_generation,
            ),
            "network-stack-adapter->tx-queue",
            "live",
            Some(adapter.recorded_at_event),
        ));
    }
    for socket in &package.semantic.socket_objects {
        if socket.state != "created" {
            continue;
        }
        let from = object_ref_json("socket-object", socket.id, socket.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-stack-adapter",
                socket.adapter,
                socket.adapter_generation,
            ),
            "socket-object->network-stack-adapter",
            "live",
            Some(socket.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("store", socket.owner_store, socket.owner_store_generation),
            "socket-object->owner-store",
            "live",
            Some(socket.created_at_event),
        ));
    }
    for endpoint in &package.semantic.endpoint_objects {
        if endpoint.state != "allocated" {
            continue;
        }
        let from = object_ref_json("endpoint-object", endpoint.id, endpoint.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("socket-object", endpoint.socket, endpoint.socket_generation),
            "endpoint-object->socket-object",
            "live",
            Some(endpoint.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-stack-adapter",
                endpoint.adapter,
                endpoint.adapter_generation,
            ),
            "endpoint-object->network-stack-adapter",
            "live",
            Some(endpoint.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "store",
                endpoint.owner_store,
                endpoint.owner_store_generation,
            ),
            "endpoint-object->owner-store",
            "live",
            Some(endpoint.created_at_event),
        ));
    }
    for wait in &package.semantic.socket_waits {
        if wait.state != "pending" {
            continue;
        }
        let from = object_ref_json("socket-wait", wait.id, wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "socket-wait->wait-token",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("endpoint-object", wait.endpoint, wait.endpoint_generation),
            "socket-wait->endpoint-object",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("socket-object", wait.socket, wait.socket_generation),
            "socket-wait->socket-object",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-stack-adapter",
                wait.adapter,
                wait.adapter_generation,
            ),
            "socket-wait->network-stack-adapter",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", wait.owner_store, wait.owner_store_generation),
            "socket-wait->owner-store",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&wait.blocker),
            "socket-wait->blocker",
            if wait.blocker.kind == "external" {
                "external"
            } else {
                "live"
            },
            Some(wait.created_at_event),
        ));
    }
    for rx in &package.semantic.network_rx_interrupts {
        if rx.state != "recorded" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("network-rx-interrupt", rx.id, rx.generation),
            object_ref_json(
                "virtio-net-backend",
                rx.virtio_net_backend,
                rx.virtio_net_backend_generation,
            ),
            "network-rx-interrupt->virtio-net-backend",
            "live",
            Some(rx.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("network-rx-interrupt", rx.id, rx.generation),
            object_ref_json("packet-queue", rx.rx_queue, rx.rx_queue_generation),
            "network-rx-interrupt->rx-queue",
            "live",
            Some(rx.recorded_at_event),
        ));
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
    for device in &package.semantic.device_objects {
        if device.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("device", device.id, device.generation),
            object_ref_json("resource", device.resource, device.resource_generation),
            "device-resource",
            "live",
            Some(device.recorded_at_event),
        ));
    }
    for queue in &package.semantic.queue_objects {
        if queue.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("queue", queue.id, queue.generation),
            object_ref_json("device", queue.device, queue.device_generation),
            "queue-device",
            "live",
            Some(queue.recorded_at_event),
        ));
    }
    for descriptor in &package.semantic.descriptor_objects {
        if descriptor.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("descriptor", descriptor.id, descriptor.generation),
            object_ref_json("queue", descriptor.queue, descriptor.queue_generation),
            "descriptor-queue",
            "live",
            Some(descriptor.recorded_at_event),
        ));
    }
    for dma_buffer in &package.semantic.dma_buffer_objects {
        if dma_buffer.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("dma-buffer", dma_buffer.id, dma_buffer.generation),
            object_ref_json(
                "descriptor",
                dma_buffer.descriptor,
                dma_buffer.descriptor_generation,
            ),
            "dma-buffer-descriptor",
            "live",
            Some(dma_buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("dma-buffer", dma_buffer.id, dma_buffer.generation),
            object_ref_json(
                "resource",
                dma_buffer.resource,
                dma_buffer.resource_generation,
            ),
            "dma-buffer-resource",
            "live",
            Some(dma_buffer.recorded_at_event),
        ));
    }
    for mmio_region in &package.semantic.mmio_region_objects {
        if mmio_region.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("mmio-region", mmio_region.id, mmio_region.generation),
            object_ref_json("device", mmio_region.device, mmio_region.device_generation),
            "mmio-region-device",
            "live",
            Some(mmio_region.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("mmio-region", mmio_region.id, mmio_region.generation),
            object_ref_json(
                "resource",
                mmio_region.resource,
                mmio_region.resource_generation,
            ),
            "mmio-region-resource",
            "live",
            Some(mmio_region.recorded_at_event),
        ));
    }
    for irq_line in &package.semantic.irq_line_objects {
        if irq_line.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("irq-line", irq_line.id, irq_line.generation),
            object_ref_json("device", irq_line.device, irq_line.device_generation),
            "irq-line-device",
            "live",
            Some(irq_line.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("irq-line", irq_line.id, irq_line.generation),
            object_ref_json("resource", irq_line.resource, irq_line.resource_generation),
            "irq-line-resource",
            "live",
            Some(irq_line.recorded_at_event),
        ));
    }
    for device_capability in &package.semantic.device_capabilities {
        if device_capability.state != "active" {
            continue;
        }
        let from = object_ref_json(
            "device-capability",
            device_capability.id,
            device_capability.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                device_capability.driver_store,
                device_capability.driver_store_generation,
            ),
            "device-capability-driver-store",
            "live",
            Some(device_capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&device_capability.target),
            "device-capability-target",
            "live",
            Some(device_capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "capability",
                device_capability.capability,
                device_capability.capability_generation,
            ),
            "device-capability-ledger",
            "live",
            Some(device_capability.recorded_at_event),
        ));
    }
    for binding in &package.semantic.driver_store_bindings {
        if binding.state != "bound" {
            continue;
        }
        let from = object_ref_json("driver-store-binding", binding.id, binding.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                binding.driver_store,
                binding.driver_store_generation,
            ),
            "driver-store-binding-store",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", binding.device, binding.device_generation),
            "driver-store-binding-device",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "device-capability",
                binding.device_capability,
                binding.device_capability_generation,
            ),
            "driver-store-binding-device-capability",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "capability",
                binding.capability,
                binding.capability_generation,
            ),
            "driver-store-binding-ledger",
            "live",
            Some(binding.recorded_at_event),
        ));
    }
    for io_wait in &package.semantic.io_waits {
        if io_wait.state != "pending" {
            continue;
        }
        let from = object_ref_json("io-wait", io_wait.id, io_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", io_wait.wait, io_wait.wait_generation),
            "io-wait-token",
            "live",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                io_wait.driver_store,
                io_wait.driver_store_generation,
            ),
            "io-wait-driver-store",
            "live",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", io_wait.device, io_wait.device_generation),
            "io-wait-device",
            "live",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                io_wait.driver_binding,
                io_wait.driver_binding_generation,
            ),
            "io-wait-driver-binding",
            "live",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&io_wait.blocker),
            "io-wait-blocker",
            "live",
            Some(io_wait.created_at_event),
        ));
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
                object_ref_json("task", task, wait.owner_task_generation.unwrap_or(0)),
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
    for activation_wait in &package.semantic.activation_waits {
        if activation_wait.state != "pending" {
            continue;
        }
        let from = object_ref_json(
            "activation-wait",
            activation_wait.id,
            activation_wait.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                activation_wait.activation,
                activation_wait.activation_generation_after_block,
            ),
            "parks",
            "live",
            Some(activation_wait.blocked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "wait-token",
                activation_wait.wait,
                activation_wait.wait_generation,
            ),
            "waits-on",
            "live",
            Some(activation_wait.blocked_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "task",
                activation_wait.owner_task,
                activation_wait.owner_task_generation,
            ),
            "blocks-task",
            "live",
            Some(activation_wait.blocked_at_event),
        ));
    }
    edges
}

fn history_graph_edges(package: &MigrationPackageManifest) -> Vec<serde_json::Value> {
    let mut edges = Vec::new();
    for completion in &package.semantic.block_completion_objects {
        if completion.state != "recorded" {
            continue;
        }
        let from = object_ref_json("block-completion", completion.id, completion.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                completion.block_request,
                completion.block_request_generation,
            ),
            "block-completion->block-request",
            "historical",
            Some(completion.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                completion.block_device,
                completion.block_device_generation,
            ),
            "block-completion->block-device",
            "historical",
            Some(completion.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-range",
                completion.block_range,
                completion.block_range_generation,
            ),
            "block-completion->block-range",
            "historical",
            Some(completion.recorded_at_event),
        ));
    }
    for block_wait in &package.semantic.block_waits {
        if block_wait.state == "pending" {
            continue;
        }
        let event = block_wait
            .completed_at_event
            .or(Some(block_wait.created_at_event));
        let from = object_ref_json("block-wait", block_wait.id, block_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", block_wait.wait, block_wait.wait_generation),
            "block-wait->wait-token",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                block_wait.block_request,
                block_wait.block_request_generation,
            ),
            "block-wait->block-request",
            "historical",
            event,
        ));
        if let (Some(completion), Some(generation)) =
            (block_wait.completion, block_wait.completion_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("block-completion", completion, generation),
                "block-wait->block-completion",
                "historical",
                event,
            ));
        }
    }
    for wait in &package.semantic.fs_waits {
        if wait.state == "pending" {
            continue;
        }
        let event = wait.completed_at_event.or(Some(wait.created_at_event));
        let from = object_ref_json("fs-wait", wait.id, wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "fs-wait->wait-token",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "file-handle-capability",
                wait.file_handle_capability,
                wait.file_handle_capability_generation,
            ),
            "fs-wait->file-handle-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("file-object", wait.file_object, wait.file_object_generation),
            "fs-wait->file-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&wait.blocker),
            "fs-wait->blocker",
            "historical",
            event,
        ));
    }
    for cleanup in &package.semantic.block_driver_cleanups {
        let event = cleanup
            .completed_at_event
            .or(Some(cleanup.started_at_event));
        let from = object_ref_json("block-driver-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "io-cleanup",
                cleanup.io_cleanup,
                cleanup.io_cleanup_generation,
            ),
            "block-driver-cleanup->io-cleanup",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "block-driver-cleanup->driver-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", cleanup.device, cleanup.device_generation),
            "block-driver-cleanup->device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation,
            ),
            "block-driver-cleanup->driver-binding",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                cleanup.block_device,
                cleanup.block_device_generation,
            ),
            "block-driver-cleanup->block-device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&cleanup.backend),
            "block-driver-cleanup->backend",
            "historical",
            event,
        ));
        for target in &cleanup.cancelled_block_waits {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                "block-driver-cleanup->cancelled-block-wait",
                "historical",
                event,
            ));
        }
        for target in &cleanup.cancelled_wait_tokens {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                "block-driver-cleanup->cancelled-wait-token",
                "historical",
                event,
            ));
        }
        for target in &cleanup.released_dma_buffers {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                "block-driver-cleanup->released-dma-buffer",
                "historical",
                event,
            ));
        }
        for target in &cleanup.revoked_device_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                "block-driver-cleanup->revoked-device-capability",
                "historical",
                event,
            ));
        }
    }
    for policy in &package.semantic.block_pending_io_policies {
        let event = Some(policy.recorded_at_event);
        let from = object_ref_json("block-pending-io-policy", policy.id, policy.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-wait",
                policy.block_wait,
                policy.block_wait_generation,
            ),
            "block-pending-io-policy->block-wait",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", policy.wait, policy.wait_generation),
            "block-pending-io-policy->wait-token",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                policy.block_request,
                policy.block_request_generation,
            ),
            "block-pending-io-policy->block-request",
            "historical",
            event,
        ));
        if let (Some(retry), Some(generation)) =
            (policy.retry_request, policy.retry_request_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("block-request", retry, generation),
                "block-pending-io-policy->retry-request",
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                policy.block_device,
                policy.block_device_generation,
            ),
            "block-pending-io-policy->block-device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-range",
                policy.block_range,
                policy.block_range_generation,
            ),
            "block-pending-io-policy->block-range",
            "historical",
            event,
        ));
    }
    for audit in &package.semantic.block_request_generation_audits {
        let event = Some(audit.recorded_at_event);
        let from = object_ref_json("block-request-generation-audit", audit.id, audit.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                audit.block_device,
                audit.block_device_generation,
            ),
            "block-request-generation-audit->block-device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-range",
                audit.block_range,
                audit.block_range_generation,
            ),
            "block-request-generation-audit->block-range",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                audit.block_request,
                audit.block_request_generation,
            ),
            "block-request-generation-audit->block-request",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&audit.backend),
            "block-request-generation-audit->backend",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&audit.dma_buffer),
            "block-request-generation-audit->dma-buffer",
            "historical",
            event,
        ));
    }
    for benchmark in &package.semantic.block_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json("block-benchmark", benchmark.id, benchmark.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&benchmark.backend),
            "block-benchmark->backend",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "block-benchmark->block-device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-range",
                benchmark.block_range,
                benchmark.block_range_generation,
            ),
            "block-benchmark->block-range",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-read-path",
                benchmark.read_path,
                benchmark.read_path_generation,
            ),
            "block-benchmark->read-path",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-write-path",
                benchmark.write_path,
                benchmark.write_path_generation,
            ),
            "block-benchmark->write-path",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request-queue",
                benchmark.request_queue,
                benchmark.request_queue_generation,
            ),
            "block-benchmark->request-queue",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-dma-buffer",
                benchmark.block_dma_buffer,
                benchmark.block_dma_buffer_generation,
            ),
            "block-benchmark->block-dma-buffer",
            "historical",
            event,
        ));
    }
    for benchmark in &package.semantic.block_recovery_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json(
            "block-recovery-benchmark",
            benchmark.id,
            benchmark.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-driver-cleanup",
                benchmark.cleanup,
                benchmark.cleanup_generation,
            ),
            "block-recovery-benchmark->block-driver-cleanup",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "io-cleanup",
                benchmark.io_cleanup,
                benchmark.io_cleanup_generation,
            ),
            "block-recovery-benchmark->io-cleanup",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&benchmark.backend),
            "block-recovery-benchmark->backend",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "block-recovery-benchmark->block-device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
            "block-recovery-benchmark->driver-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", benchmark.device, benchmark.device_generation),
            "block-recovery-benchmark->device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "driver-store-binding",
                benchmark.driver_binding,
                benchmark.driver_binding_generation,
            ),
            "block-recovery-benchmark->driver-binding",
            "historical",
            event,
        ));
    }
    for feature in &package.semantic.target_feature_sets {
        let event = Some(feature.recorded_at_event);
        edges.push(graph_edge(
            object_ref_json("target-feature-set", feature.id, feature.generation),
            object_ref_json("event", feature.recorded_at_event, 1),
            "target-feature-set->event",
            "historical",
            event,
        ));
    }
    for vector_state in &package.semantic.vector_states {
        let event = Some(vector_state.recorded_at_event);
        let from = object_ref_json("vector-state", vector_state.id, vector_state.generation);
        for (target, label, mode) in [
            (
                &vector_state.owner_activation,
                "vector-state->activation",
                if vector_state.state == "reserved" {
                    "live"
                } else {
                    "historical"
                },
            ),
            (
                &vector_state.owner_store,
                "vector-state->store",
                if vector_state.state == "reserved" {
                    "live"
                } else {
                    "historical"
                },
            ),
            (
                &vector_state.code_object,
                "vector-state->code-object",
                if vector_state.state == "reserved" {
                    "live"
                } else {
                    "historical"
                },
            ),
            (
                &vector_state.target_feature_set,
                "vector-state->target-feature-set",
                if vector_state.state == "reserved" {
                    "live"
                } else {
                    "historical"
                },
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                mode,
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", vector_state.recorded_at_event, 1),
            "vector-state->event",
            "historical",
            event,
        ));
    }
    for injection in &package.semantic.simd_fault_injections {
        let event = Some(injection.recorded_at_event);
        let from = object_ref_json("simd-fault-injection", injection.id, injection.generation);
        for (target, label) in [
            (&injection.activation, "simd-fault-injection->activation"),
            (&injection.code_object, "simd-fault-injection->code-object"),
            (&injection.trap, "simd-fault-injection->trap"),
            (
                &injection.target_feature_set,
                "simd-fault-injection->target-feature-set",
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                "historical",
                event,
            ));
        }
        if let Some(vector_state) = &injection.vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(vector_state),
                "simd-fault-injection->vector-state",
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", injection.recorded_at_event, 1),
            "simd-fault-injection->event",
            "historical",
            event,
        ));
    }
    for benchmark in &package.semantic.simd_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json("simd-benchmark", benchmark.id, benchmark.generation);
        for (target, label) in [
            (
                &benchmark.target_feature_set,
                "simd-benchmark->target-feature-set",
            ),
            (
                &benchmark.scalar_code_object,
                "simd-benchmark->scalar-code-object",
            ),
            (
                &benchmark.vector_code_object,
                "simd-benchmark->vector-code-object",
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", benchmark.recorded_at_event, 1),
            "simd-benchmark->event",
            "historical",
            event,
        ));
    }
    for benchmark in &package.semantic.simd_context_switch_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json(
            "simd-context-switch-benchmark",
            benchmark.id,
            benchmark.generation,
        );
        for (target, label) in [
            (
                &benchmark.preemption,
                "simd-context-switch-benchmark->preemption",
            ),
            (
                &benchmark.activation_resume,
                "simd-context-switch-benchmark->activation-resume",
            ),
            (
                &benchmark.saved_vector_state,
                "simd-context-switch-benchmark->saved-vector-state",
            ),
            (
                &benchmark.restored_vector_state,
                "simd-context-switch-benchmark->restored-vector-state",
            ),
            (
                &benchmark.target_feature_set,
                "simd-context-switch-benchmark->target-feature-set",
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", benchmark.recorded_at_event, 1),
            "simd-context-switch-benchmark->event",
            "historical",
            event,
        ));
    }
    for framebuffer in &package.semantic.framebuffer_objects {
        let event = Some(framebuffer.recorded_at_event);
        let from = object_ref_json("framebuffer-object", framebuffer.id, framebuffer.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "resource",
                framebuffer.resource,
                framebuffer.resource_generation,
            ),
            "framebuffer-object->resource",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", framebuffer.recorded_at_event, 1),
            "framebuffer-object->event",
            "historical",
            event,
        ));
    }
    for display in &package.semantic.display_objects {
        let event = Some(display.recorded_at_event);
        let from = object_ref_json("display-object", display.id, display.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                display.framebuffer,
                display.framebuffer_generation,
            ),
            "display-object->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", display.recorded_at_event, 1),
            "display-object->event",
            "historical",
            event,
        ));
    }
    for capability in &package.semantic.display_capabilities {
        let event = Some(capability.recorded_at_event);
        let from = object_ref_json("display-capability", capability.id, capability.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                capability.owner_store,
                capability.owner_store_generation,
            ),
            "display-capability->owner-store",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-object",
                capability.display,
                capability.display_generation,
            ),
            "display-capability->display-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                capability.framebuffer,
                capability.framebuffer_generation,
            ),
            "display-capability->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "capability",
                capability.capability,
                capability.capability_generation,
            ),
            "display-capability->capability",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", capability.recorded_at_event, 1),
            "display-capability->event",
            "historical",
            event,
        ));
    }
    for lease in &package.semantic.framebuffer_window_leases {
        let event = Some(lease.recorded_at_event);
        let from = object_ref_json("framebuffer-window-lease", lease.id, lease.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", lease.owner_store, lease.owner_store_generation),
            "framebuffer-window-lease->owner-store",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                lease.display_capability,
                lease.display_capability_generation,
            ),
            "framebuffer-window-lease->display-capability",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", lease.display, lease.display_generation),
            "framebuffer-window-lease->display-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                lease.framebuffer,
                lease.framebuffer_generation,
            ),
            "framebuffer-window-lease->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", lease.recorded_at_event, 1),
            "framebuffer-window-lease->event",
            "historical",
            event,
        ));
    }
    for mapping in &package.semantic.framebuffer_mappings {
        let event = Some(mapping.recorded_at_event);
        let from = object_ref_json("framebuffer-mapping", mapping.id, mapping.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", mapping.owner_store, mapping.owner_store_generation),
            "framebuffer-mapping->owner-store",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-window-lease",
                mapping.framebuffer_window_lease,
                mapping.framebuffer_window_lease_generation,
            ),
            "framebuffer-mapping->framebuffer-window-lease",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                mapping.display_capability,
                mapping.display_capability_generation,
            ),
            "framebuffer-mapping->display-capability",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-object",
                mapping.display,
                mapping.display_generation,
            ),
            "framebuffer-mapping->display-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                mapping.framebuffer,
                mapping.framebuffer_generation,
            ),
            "framebuffer-mapping->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", mapping.recorded_at_event, 1),
            "framebuffer-mapping->event",
            "historical",
            event,
        ));
    }
    for write in &package.semantic.framebuffer_writes {
        let event = Some(write.recorded_at_event);
        let from = object_ref_json("framebuffer-write", write.id, write.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", write.owner_store, write.owner_store_generation),
            "framebuffer-write->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-mapping",
                write.framebuffer_mapping,
                write.framebuffer_mapping_generation,
            ),
            "framebuffer-write->framebuffer-mapping",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-window-lease",
                write.framebuffer_window_lease,
                write.framebuffer_window_lease_generation,
            ),
            "framebuffer-write->framebuffer-window-lease",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                write.display_capability,
                write.display_capability_generation,
            ),
            "framebuffer-write->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", write.display, write.display_generation),
            "framebuffer-write->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                write.framebuffer,
                write.framebuffer_generation,
            ),
            "framebuffer-write->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", write.recorded_at_event, 1),
            "framebuffer-write->event",
            "historical",
            event,
        ));
    }
    for flush in &package.semantic.framebuffer_flush_regions {
        let event = Some(flush.recorded_at_event);
        let from = object_ref_json("framebuffer-flush-region", flush.id, flush.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", flush.owner_store, flush.owner_store_generation),
            "framebuffer-flush-region->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-write",
                flush.framebuffer_write,
                flush.framebuffer_write_generation,
            ),
            "framebuffer-flush-region->framebuffer-write",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                flush.display_capability,
                flush.display_capability_generation,
            ),
            "framebuffer-flush-region->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", flush.display, flush.display_generation),
            "framebuffer-flush-region->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                flush.framebuffer,
                flush.framebuffer_generation,
            ),
            "framebuffer-flush-region->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", flush.recorded_at_event, 1),
            "framebuffer-flush-region->event",
            "historical",
            event,
        ));
    }
    for dirty in &package.semantic.framebuffer_dirty_regions {
        let event = Some(dirty.recorded_at_event);
        let from = object_ref_json("framebuffer-dirty-region", dirty.id, dirty.generation);
        let owner_mode = if dirty.state == "dirty" {
            "live"
        } else {
            "historical"
        };
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", dirty.owner_store, dirty.owner_store_generation),
            "framebuffer-dirty-region->owner-store",
            owner_mode,
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-write",
                dirty.framebuffer_write,
                dirty.framebuffer_write_generation,
            ),
            "framebuffer-dirty-region->framebuffer-write",
            "historical",
            event,
        ));
        if let (Some(flush), Some(generation)) = (
            dirty.framebuffer_flush_region,
            dirty.framebuffer_flush_region_generation,
        ) {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("framebuffer-flush-region", flush, generation),
                "framebuffer-dirty-region->framebuffer-flush-region",
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                dirty.display_capability,
                dirty.display_capability_generation,
            ),
            "framebuffer-dirty-region->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", dirty.display, dirty.display_generation),
            "framebuffer-dirty-region->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                dirty.framebuffer,
                dirty.framebuffer_generation,
            ),
            "framebuffer-dirty-region->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", dirty.recorded_at_event, 1),
            "framebuffer-dirty-region->event",
            "historical",
            event,
        ));
    }
    for log in &package.semantic.display_event_logs {
        let event = Some(log.recorded_at_event);
        let from = object_ref_json("display-event-log", log.id, log.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", log.owner_store, log.owner_store_generation),
            "display-event-log->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-dirty-region",
                log.framebuffer_dirty_region,
                log.framebuffer_dirty_region_generation,
            ),
            "display-event-log->framebuffer-dirty-region",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                log.display_capability,
                log.display_capability_generation,
            ),
            "display-event-log->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", log.display, log.display_generation),
            "display-event-log->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                log.framebuffer,
                log.framebuffer_generation,
            ),
            "display-event-log->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", log.recorded_at_event, 1),
            "display-event-log->event",
            "historical",
            event,
        ));
    }
    for cleanup in &package.semantic.display_cleanups {
        let event = Some(cleanup.completed_at_event);
        let from = object_ref_json("display-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.owner_store, cleanup.owner_store_generation),
            "display-cleanup->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                cleanup.display_capability,
                cleanup.display_capability_generation,
            ),
            "display-cleanup->display-capability",
            "cleanup-effect",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-object",
                cleanup.display,
                cleanup.display_generation,
            ),
            "display-cleanup->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                cleanup.framebuffer,
                cleanup.framebuffer_generation,
            ),
            "display-cleanup->framebuffer-object",
            "historical",
            event,
        ));
        for mapping in &cleanup.unmapped_framebuffer_mappings {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(&mapping.kind, mapping.id, mapping.generation),
                "display-cleanup->unmapped-framebuffer-mapping",
                "cleanup-effect",
                event,
            ));
        }
        for lease in &cleanup.released_framebuffer_window_leases {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(&lease.kind, lease.id, lease.generation),
                "display-cleanup->released-framebuffer-window-lease",
                "cleanup-effect",
                event,
            ));
        }
        for display_capability in &cleanup.revoked_display_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    &display_capability.kind,
                    display_capability.id,
                    display_capability.generation,
                ),
                "display-cleanup->revoked-display-capability",
                "cleanup-effect",
                event,
            ));
        }
        for capability in &cleanup.revoked_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(&capability.kind, capability.id, capability.generation),
                "display-cleanup->revoked-capability",
                "cleanup-effect",
                event,
            ));
        }
    }
    for barrier in &package.semantic.display_snapshot_barriers {
        let event = Some(barrier.validated_at_event);
        let from = object_ref_json("display-snapshot-barrier", barrier.id, barrier.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", barrier.owner_store, barrier.owner_store_generation),
            "display-snapshot-barrier->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-object",
                barrier.display,
                barrier.display_generation,
            ),
            "display-snapshot-barrier->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                barrier.framebuffer,
                barrier.framebuffer_generation,
            ),
            "display-snapshot-barrier->framebuffer-object",
            "historical",
            event,
        ));
        if let (Some(cleanup), Some(cleanup_generation)) =
            (barrier.display_cleanup, barrier.display_cleanup_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("display-cleanup", cleanup, cleanup_generation),
                "display-snapshot-barrier->display-cleanup",
                "historical",
                event,
            ));
        }
    }
    for frame in &package.semantic.display_panic_last_frames {
        let event = Some(frame.recorded_at_event);
        let from = object_ref_json("display-panic-last-frame", frame.id, frame.generation);
        for (relation, to) in [
            (
                "display-panic-last-frame->owner-store",
                object_ref_json("store", frame.owner_store, frame.owner_store_generation),
            ),
            (
                "display-panic-last-frame->display-object",
                object_ref_json("display-object", frame.display, frame.display_generation),
            ),
            (
                "display-panic-last-frame->framebuffer-object",
                object_ref_json(
                    "framebuffer-object",
                    frame.framebuffer,
                    frame.framebuffer_generation,
                ),
            ),
            (
                "display-panic-last-frame->snapshot-barrier",
                object_ref_json(
                    "display-snapshot-barrier",
                    frame.display_snapshot_barrier,
                    frame.display_snapshot_barrier_generation,
                ),
            ),
            (
                "display-panic-last-frame->display-event-log",
                object_ref_json(
                    "display-event-log",
                    frame.display_event_log,
                    frame.display_event_log_generation,
                ),
            ),
            (
                "display-panic-last-frame->framebuffer-write",
                object_ref_json(
                    "framebuffer-write",
                    frame.framebuffer_write,
                    frame.framebuffer_write_generation,
                ),
            ),
            (
                "display-panic-last-frame->framebuffer-flush-region",
                object_ref_json(
                    "framebuffer-flush-region",
                    frame.framebuffer_flush_region,
                    frame.framebuffer_flush_region_generation,
                ),
            ),
        ] {
            edges.push(graph_edge(from.clone(), to, relation, "historical", event));
        }
    }
    for benchmark in &package.semantic.framebuffer_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json("framebuffer-benchmark", benchmark.id, benchmark.generation);
        for (relation, to) in [
            (
                "framebuffer-benchmark->owner-store",
                object_ref_json(
                    "store",
                    benchmark.owner_store,
                    benchmark.owner_store_generation,
                ),
            ),
            (
                "framebuffer-benchmark->display-object",
                object_ref_json(
                    "display-object",
                    benchmark.display,
                    benchmark.display_generation,
                ),
            ),
            (
                "framebuffer-benchmark->framebuffer-object",
                object_ref_json(
                    "framebuffer-object",
                    benchmark.framebuffer,
                    benchmark.framebuffer_generation,
                ),
            ),
            (
                "framebuffer-benchmark->display-capability",
                object_ref_json(
                    "display-capability",
                    benchmark.display_capability,
                    benchmark.display_capability_generation,
                ),
            ),
            (
                "framebuffer-benchmark->framebuffer-write",
                object_ref_json(
                    "framebuffer-write",
                    benchmark.framebuffer_write,
                    benchmark.framebuffer_write_generation,
                ),
            ),
            (
                "framebuffer-benchmark->framebuffer-flush-region",
                object_ref_json(
                    "framebuffer-flush-region",
                    benchmark.framebuffer_flush_region,
                    benchmark.framebuffer_flush_region_generation,
                ),
            ),
            (
                "framebuffer-benchmark->display-event-log",
                object_ref_json(
                    "display-event-log",
                    benchmark.display_event_log,
                    benchmark.display_event_log_generation,
                ),
            ),
            (
                "framebuffer-benchmark->display-snapshot-barrier",
                object_ref_json(
                    "display-snapshot-barrier",
                    benchmark.display_snapshot_barrier,
                    benchmark.display_snapshot_barrier_generation,
                ),
            ),
        ] {
            edges.push(graph_edge(from.clone(), to, relation, "historical", event));
        }
    }
    for operation in &package.semantic.socket_operations {
        if operation.state != "applied" {
            continue;
        }
        let from = object_ref_json("socket-operation", operation.id, operation.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "endpoint-object",
                operation.endpoint,
                operation.endpoint_generation,
            ),
            "socket-operation->endpoint-object",
            "historical",
            Some(operation.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "socket-object",
                operation.socket,
                operation.socket_generation,
            ),
            "socket-operation->socket-object",
            "historical",
            Some(operation.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-stack-adapter",
                operation.adapter,
                operation.adapter_generation,
            ),
            "socket-operation->network-stack-adapter",
            "historical",
            Some(operation.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "store",
                operation.owner_store,
                operation.owner_store_generation,
            ),
            "socket-operation->owner-store",
            "historical",
            Some(operation.recorded_at_event),
        ));
    }
    for wait in &package.semantic.socket_waits {
        if wait.state == "pending" {
            continue;
        }
        let event = wait.completed_at_event.or(Some(wait.created_at_event));
        let from = object_ref_json("socket-wait", wait.id, wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "socket-wait->wait-token",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("endpoint-object", wait.endpoint, wait.endpoint_generation),
            "socket-wait->endpoint-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("socket-object", wait.socket, wait.socket_generation),
            "socket-wait->socket-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-stack-adapter",
                wait.adapter,
                wait.adapter_generation,
            ),
            "socket-wait->network-stack-adapter",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", wait.owner_store, wait.owner_store_generation),
            "socket-wait->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&wait.blocker),
            "socket-wait->blocker",
            if wait.blocker.kind == "external" {
                "external"
            } else {
                "historical"
            },
            event,
        ));
    }
    for backpressure in &package.semantic.network_backpressures {
        let from = object_ref_json(
            "network-backpressure",
            backpressure.id,
            backpressure.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-stack-adapter",
                backpressure.adapter,
                backpressure.adapter_generation,
            ),
            "network-backpressure->network-stack-adapter",
            "historical",
            Some(backpressure.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-device",
                backpressure.packet_device,
                backpressure.packet_device_generation,
            ),
            "network-backpressure->packet-device",
            "historical",
            Some(backpressure.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-queue",
                backpressure.packet_queue,
                backpressure.packet_queue_generation,
            ),
            "network-backpressure->packet-queue",
            "historical",
            Some(backpressure.recorded_at_event),
        ));
        if let (Some(endpoint), Some(endpoint_generation)) =
            (backpressure.endpoint, backpressure.endpoint_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("endpoint-object", endpoint, endpoint_generation),
                "network-backpressure->endpoint-object",
                "historical",
                Some(backpressure.recorded_at_event),
            ));
        }
        if let (Some(socket), Some(socket_generation)) =
            (backpressure.socket, backpressure.socket_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("socket-object", socket, socket_generation),
                "network-backpressure->socket-object",
                "historical",
                Some(backpressure.recorded_at_event),
            ));
        }
        if let (Some(store), Some(store_generation)) = (
            backpressure.owner_store,
            backpressure.owner_store_generation,
        ) {
            edges.push(graph_edge(
                from,
                object_ref_json("store", store, store_generation),
                "network-backpressure->owner-store",
                "historical",
                Some(backpressure.recorded_at_event),
            ));
        }
    }
    for cleanup in &package.semantic.network_driver_cleanups {
        let from = object_ref_json("network-driver-cleanup", cleanup.id, cleanup.generation);
        let event = cleanup
            .completed_at_event
            .or(Some(cleanup.started_at_event));
        for (target, relation) in [
            (
                object_ref_json(
                    "io-cleanup",
                    cleanup.io_cleanup,
                    cleanup.io_cleanup_generation,
                ),
                "network-driver-cleanup->io-cleanup",
            ),
            (
                object_ref_json(
                    "store",
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                ),
                "network-driver-cleanup->driver-store",
            ),
            (
                object_ref_json("device", cleanup.device, cleanup.device_generation),
                "network-driver-cleanup->device",
            ),
            (
                object_ref_json(
                    "driver-store-binding",
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                ),
                "network-driver-cleanup->driver-binding",
            ),
            (
                object_ref_json(
                    "packet-device",
                    cleanup.packet_device,
                    cleanup.packet_device_generation,
                ),
                "network-driver-cleanup->packet-device",
            ),
            (
                object_ref_json(
                    "network-stack-adapter",
                    cleanup.adapter,
                    cleanup.adapter_generation,
                ),
                "network-driver-cleanup->network-stack-adapter",
            ),
            (
                object_ref_manifest_json(&cleanup.backend),
                "network-driver-cleanup->backend",
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                target,
                relation,
                "historical",
                event,
            ));
        }
        for socket_wait in &cleanup.cancelled_socket_waits {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(socket_wait),
                "network-driver-cleanup->cancelled-socket-wait",
                "cleanup-effect",
                event,
            ));
        }
        for wait in &cleanup.cancelled_wait_tokens {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(wait),
                "network-driver-cleanup->cancelled-wait-token",
                "cleanup-effect",
                event,
            ));
        }
        for capability in &cleanup.revoked_packet_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(capability),
                "network-driver-cleanup->revoked-packet-capability",
                "cleanup-effect",
                event,
            ));
        }
    }
    for audit in &package.semantic.network_generation_audits {
        let from = object_ref_json("network-generation-audit", audit.id, audit.generation);
        let event = Some(audit.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json(
                    "network-stack-adapter",
                    audit.adapter,
                    audit.adapter_generation,
                ),
                "network-generation-audit->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    audit.packet_device,
                    audit.packet_device_generation,
                ),
                "network-generation-audit->packet-device",
            ),
            (
                object_ref_json(
                    "packet-queue",
                    audit.packet_queue,
                    audit.packet_queue_generation,
                ),
                "network-generation-audit->packet-queue",
            ),
            (
                object_ref_json(
                    "packet-descriptor",
                    audit.packet_descriptor,
                    audit.packet_descriptor_generation,
                ),
                "network-generation-audit->packet-descriptor",
            ),
            (
                object_ref_json(
                    "packet-buffer",
                    audit.packet_buffer,
                    audit.packet_buffer_generation,
                ),
                "network-generation-audit->packet-buffer",
            ),
            (
                object_ref_manifest_json(&audit.dma_buffer),
                "network-generation-audit->dma-buffer",
            ),
            (
                object_ref_manifest_json(&audit.device_capability),
                "network-generation-audit->device-capability",
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                target,
                relation,
                "historical",
                event,
            ));
        }
    }
    for injection in &package.semantic.network_fault_injections {
        let from = object_ref_json(
            "network-fault-injection",
            injection.id,
            injection.generation,
        );
        let event = Some(injection.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json(
                    "network-stack-adapter",
                    injection.adapter,
                    injection.adapter_generation,
                ),
                "network-fault-injection->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    injection.packet_device,
                    injection.packet_device_generation,
                ),
                "network-fault-injection->packet-device",
            ),
            (
                object_ref_json(
                    "packet-queue",
                    injection.packet_queue,
                    injection.packet_queue_generation,
                ),
                "network-fault-injection->packet-queue",
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                target,
                relation,
                "historical",
                event,
            ));
        }
        if let (Some(packet_descriptor), Some(packet_descriptor_generation)) = (
            injection.packet_descriptor,
            injection.packet_descriptor_generation,
        ) {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "packet-descriptor",
                    packet_descriptor,
                    packet_descriptor_generation,
                ),
                "network-fault-injection->packet-descriptor",
                "historical",
                event,
            ));
        }
        if let (Some(packet_buffer), Some(packet_buffer_generation)) =
            (injection.packet_buffer, injection.packet_buffer_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("packet-buffer", packet_buffer, packet_buffer_generation),
                "network-fault-injection->packet-buffer",
                "historical",
                event,
            ));
        }
        if let (Some(endpoint), Some(endpoint_generation)) =
            (injection.endpoint, injection.endpoint_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("endpoint-object", endpoint, endpoint_generation),
                "network-fault-injection->endpoint-object",
                "historical",
                event,
            ));
        }
        if let (Some(socket), Some(socket_generation)) =
            (injection.socket, injection.socket_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("socket-object", socket, socket_generation),
                "network-fault-injection->socket-object",
                "historical",
                event,
            ));
        }
        if let (Some(owner_store), Some(owner_store_generation)) =
            (injection.owner_store, injection.owner_store_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("store", owner_store, owner_store_generation),
                "network-fault-injection->owner-store",
                "historical",
                event,
            ));
        }
    }
    for benchmark in &package.semantic.network_benchmarks {
        let from = object_ref_json("network-benchmark", benchmark.id, benchmark.generation);
        let event = Some(benchmark.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json(
                    "network-stack-adapter",
                    benchmark.adapter,
                    benchmark.adapter_generation,
                ),
                "network-benchmark->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    benchmark.packet_device,
                    benchmark.packet_device_generation,
                ),
                "network-benchmark->packet-device",
            ),
            (
                object_ref_json(
                    "packet-queue",
                    benchmark.tx_queue,
                    benchmark.tx_queue_generation,
                ),
                "network-benchmark->tx-queue",
            ),
            (
                object_ref_json(
                    "packet-queue",
                    benchmark.rx_queue,
                    benchmark.rx_queue_generation,
                ),
                "network-benchmark->rx-queue",
            ),
            (
                object_ref_json(
                    "network-tx-completion",
                    benchmark.tx_completion,
                    benchmark.tx_completion_generation,
                ),
                "network-benchmark->tx-completion",
            ),
            (
                object_ref_json(
                    "network-rx-wait-resolution",
                    benchmark.rx_wait_resolution,
                    benchmark.rx_wait_resolution_generation,
                ),
                "network-benchmark->rx-wait-resolution",
            ),
            (
                object_ref_json(
                    "endpoint-object",
                    benchmark.endpoint,
                    benchmark.endpoint_generation,
                ),
                "network-benchmark->endpoint-object",
            ),
            (
                object_ref_json(
                    "socket-object",
                    benchmark.socket,
                    benchmark.socket_generation,
                ),
                "network-benchmark->socket-object",
            ),
            (
                object_ref_json(
                    "store",
                    benchmark.owner_store,
                    benchmark.owner_store_generation,
                ),
                "network-benchmark->owner-store",
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                target,
                relation,
                "historical",
                event,
            ));
        }
        if let (Some(backpressure), Some(backpressure_generation)) =
            (benchmark.backpressure, benchmark.backpressure_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "network-backpressure",
                    backpressure,
                    backpressure_generation,
                ),
                "network-benchmark->network-backpressure",
                "historical",
                event,
            ));
        }
    }
    for benchmark in &package.semantic.network_recovery_benchmarks {
        let from = object_ref_json(
            "network-recovery-benchmark",
            benchmark.id,
            benchmark.generation,
        );
        let event = Some(benchmark.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json(
                    "network-driver-cleanup",
                    benchmark.cleanup,
                    benchmark.cleanup_generation,
                ),
                "network-recovery-benchmark->network-driver-cleanup",
            ),
            (
                object_ref_json(
                    "io-cleanup",
                    benchmark.io_cleanup,
                    benchmark.io_cleanup_generation,
                ),
                "network-recovery-benchmark->io-cleanup",
            ),
            (
                object_ref_json(
                    "network-stack-adapter",
                    benchmark.adapter,
                    benchmark.adapter_generation,
                ),
                "network-recovery-benchmark->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    benchmark.packet_device,
                    benchmark.packet_device_generation,
                ),
                "network-recovery-benchmark->packet-device",
            ),
            (
                object_ref_manifest_json(&benchmark.backend),
                "network-recovery-benchmark->backend",
            ),
            (
                object_ref_json(
                    "store",
                    benchmark.driver_store,
                    benchmark.driver_store_generation,
                ),
                "network-recovery-benchmark->driver-store",
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                target,
                relation,
                "historical",
                event,
            ));
        }
        if let (Some(fault_injection), Some(fault_injection_generation)) = (
            benchmark.fault_injection,
            benchmark.fault_injection_generation,
        ) {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "network-fault-injection",
                    fault_injection,
                    fault_injection_generation,
                ),
                "network-recovery-benchmark->network-fault-injection",
                "historical",
                event,
            ));
        }
    }
    for rx in &package.semantic.network_rx_interrupts {
        edges.push(graph_edge(
            object_ref_json("network-rx-interrupt", rx.id, rx.generation),
            object_ref_json("irq-event", rx.irq_event, rx.irq_event_generation),
            "network-rx-interrupt->irq-event",
            "historical",
            Some(rx.recorded_at_event),
        ));
    }
    for resolution in &package.semantic.network_rx_wait_resolutions {
        edges.push(graph_edge(
            object_ref_json(
                "network-rx-wait-resolution",
                resolution.id,
                resolution.generation,
            ),
            object_ref_json("io-wait", resolution.io_wait, resolution.io_wait_generation),
            "network-rx-wait-resolution->io-wait",
            "historical",
            Some(resolution.resolved_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json(
                "network-rx-wait-resolution",
                resolution.id,
                resolution.generation,
            ),
            object_ref_json(
                "network-rx-interrupt",
                resolution.rx_interrupt,
                resolution.rx_interrupt_generation,
            ),
            "network-rx-wait-resolution->rx-interrupt",
            "historical",
            Some(resolution.resolved_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json(
                "network-rx-wait-resolution",
                resolution.id,
                resolution.generation,
            ),
            object_ref_json(
                "packet-queue",
                resolution.rx_queue,
                resolution.rx_queue_generation,
            ),
            "network-rx-wait-resolution->rx-queue",
            "historical",
            Some(resolution.resolved_at_event),
        ));
    }
    for gate in &package.semantic.network_tx_capability_gates {
        let from = object_ref_json("network-tx-capability-gate", gate.id, gate.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-descriptor",
                gate.packet_descriptor,
                gate.packet_descriptor_generation,
            ),
            "network-tx-capability-gate->packet-descriptor",
            "historical",
            Some(gate.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-device",
                gate.packet_device,
                gate.packet_device_generation,
            ),
            "network-tx-capability-gate->packet-device",
            "historical",
            Some(gate.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "device-capability",
                gate.device_capability,
                gate.device_capability_generation,
            ),
            "network-tx-capability-gate->device-capability",
            "historical",
            Some(gate.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("capability", gate.capability, gate.capability_generation),
            "network-tx-capability-gate->capability",
            "historical",
            Some(gate.recorded_at_event),
        ));
    }
    for completion in &package.semantic.network_tx_completions {
        let from = object_ref_json(
            "network-tx-completion",
            completion.id,
            completion.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-tx-capability-gate",
                completion.tx_gate,
                completion.tx_gate_generation,
            ),
            "network-tx-completion->tx-gate",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&completion.backend_kind),
                completion.backend,
                completion.backend_generation,
            ),
            "network-tx-completion->backend",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-descriptor",
                completion.packet_descriptor,
                completion.packet_descriptor_generation,
            ),
            "network-tx-completion->packet-descriptor",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-buffer",
                completion.packet_buffer,
                completion.packet_buffer_generation,
            ),
            "network-tx-completion->packet-buffer",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "packet-device",
                completion.packet_device,
                completion.packet_device_generation,
            ),
            "network-tx-completion->packet-device",
            "historical",
            Some(completion.completed_at_event),
        ));
    }
    for interrupt in &package.semantic.timer_interrupts {
        let from = object_ref_json("timer-interrupt", interrupt.id, interrupt.generation);
        if let Some(hart_generation) = interrupt.hart_generation {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", interrupt.hart, hart_generation),
                "recorded-on-hart",
                "historical",
                Some(interrupt.recorded_at_event),
            ));
        }
        if let (Some(activation), Some(generation)) = (
            interrupt.target_activation,
            interrupt.target_activation_generation,
        ) {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("activation", activation, generation),
                "recorded-target",
                "historical",
                Some(interrupt.recorded_at_event),
            ));
        }
        if let (Some(task), Some(generation)) =
            (interrupt.target_task, interrupt.target_task_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("task", task, generation),
                "recorded-task",
                "historical",
                Some(interrupt.recorded_at_event),
            ));
        }
    }
    for ipi in &package.semantic.ipi_events {
        let from = object_ref_json("ipi-event", ipi.id, ipi.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", ipi.source_hart, ipi.source_hart_generation),
            "ipi-source-hart",
            "historical",
            Some(ipi.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("hart", ipi.target_hart, ipi.target_hart_generation),
            "ipi-target-hart",
            "historical",
            Some(ipi.recorded_at_event),
        ));
    }
    for remote in &package.semantic.remote_preempts {
        let from = object_ref_json("remote-preempt", remote.id, remote.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("ipi-event", remote.ipi, remote.ipi_generation),
            "caused-by-ipi",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", remote.source_hart, remote.source_hart_generation),
            "source-hart",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                remote.target_hart,
                remote.target_hart_generation_before,
            ),
            "target-hart-before",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                remote.target_hart,
                remote.target_hart_generation_after,
            ),
            "target-hart-after",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                remote.activation,
                remote.activation_generation_before,
            ),
            "activation-before",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                remote.activation,
                remote.activation_generation_after,
            ),
            "activation-after",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("runnable-queue", remote.queue, remote.queue_generation),
            "target-runnable-queue",
            "historical",
            Some(remote.preempted_at_event),
        ));
    }
    for remote in &package.semantic.remote_parks {
        let from = object_ref_json("remote-park", remote.id, remote.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("ipi-event", remote.ipi, remote.ipi_generation),
            "caused-by-ipi",
            "historical",
            Some(remote.parked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", remote.source_hart, remote.source_hart_generation),
            "source-hart",
            "historical",
            Some(remote.parked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                remote.target_hart,
                remote.target_hart_generation_before,
            ),
            "target-hart-before",
            "historical",
            Some(remote.parked_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "hart",
                remote.target_hart,
                remote.target_hart_generation_after,
            ),
            "target-hart-after",
            "historical",
            Some(remote.parked_at_event),
        ));
    }
    for attribution in &package.semantic.hart_event_attributions {
        let from = object_ref_json(
            "hart-event-attribution",
            attribution.id,
            attribution.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", attribution.hart, attribution.hart_generation),
            "attributed-to-hart",
            "historical",
            Some(attribution.event),
        ));
        if let (Some(activation), Some(generation)) =
            (attribution.activation, attribution.activation_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("activation", activation, generation),
                "attributed-activation",
                "historical",
                Some(attribution.event),
            ));
        }
        if let (Some(task), Some(generation)) = (attribution.task, attribution.task_generation) {
            edges.push(graph_edge(
                from,
                object_ref_json("task", task, generation),
                "attributed-task",
                "historical",
                Some(attribution.event),
            ));
        }
    }
    for preemption in &package.semantic.preemptions {
        let from = object_ref_json("preemption", preemption.id, preemption.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                preemption.activation,
                preemption.activation_generation_before,
            ),
            "preempted-from",
            "historical",
            Some(preemption.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                preemption.activation,
                preemption.activation_generation_after,
            ),
            "preempted-to",
            "historical",
            Some(preemption.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "timer-interrupt",
                preemption.timer_interrupt,
                preemption.timer_interrupt_generation,
            ),
            "caused-by",
            "historical",
            Some(preemption.preempted_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "runnable-queue",
                preemption.queue,
                preemption.queue_generation,
            ),
            "queued-into",
            "historical",
            Some(preemption.preempted_at_event),
        ));
    }
    for saved in &package.semantic.saved_contexts {
        if let (Some(preemption), Some(preemption_generation)) =
            (saved.source_preemption, saved.source_preemption_generation)
        {
            edges.push(graph_edge(
                object_ref_json("saved-context", saved.id, saved.generation),
                object_ref_json("preemption", preemption, preemption_generation),
                "captured-from-preemption",
                "historical",
                Some(saved.saved_at_event),
            ));
        }
        if let Some(vector_state) = &saved.vector_state {
            edges.push(graph_edge(
                object_ref_json("saved-context", saved.id, saved.generation),
                object_ref_manifest_json(vector_state),
                "saved-vector-state",
                "historical",
                saved.vector_saved_at_event.or(Some(saved.saved_at_event)),
            ));
        }
    }
    for decision in &package.semantic.scheduler_decisions {
        let from = object_ref_json("scheduler-decision", decision.id, decision.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("runnable-queue", decision.queue, decision.queue_generation),
            "selected-from",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                decision.selected_activation,
                decision.selected_activation_generation,
            ),
            "selected",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("task", decision.owner_task, decision.owner_task_generation),
            "owned-by-task",
            "historical",
            Some(decision.decided_at_event),
        ));
    }
    for decision in &package.semantic.cross_hart_scheduler_decisions {
        let from = object_ref_json(
            "cross-hart-scheduler-decision",
            decision.id,
            decision.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "scheduler-decision",
                decision.scheduler_decision,
                decision.scheduler_decision_generation,
            ),
            "extends-scheduler-decision",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                decision.deciding_hart,
                decision.deciding_hart_generation,
            ),
            "deciding-hart",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                decision.target_hart,
                decision.target_hart_generation,
            ),
            "target-hart",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("runnable-queue", decision.queue, decision.queue_generation),
            "target-runnable-queue",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "activation",
                decision.selected_activation,
                decision.selected_activation_generation,
            ),
            "selected-activation",
            "historical",
            Some(decision.decided_at_event),
        ));
    }
    for migration in &package.semantic.activation_migrations {
        let from = object_ref_json("activation-migration", migration.id, migration.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                migration.activation,
                migration.activation_generation_before,
            ),
            "migrated-from",
            "historical",
            Some(migration.migrated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                migration.activation,
                migration.activation_generation_after,
            ),
            "migrated-to",
            "historical",
            Some(migration.migrated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                migration.source_hart,
                migration.source_hart_generation,
            ),
            "source-hart",
            "historical",
            Some(migration.migrated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                migration.target_hart,
                migration.target_hart_generation,
            ),
            "target-hart",
            "historical",
            Some(migration.migrated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "runnable-queue",
                migration.source_queue,
                migration.source_queue_generation,
            ),
            "source-runnable-queue",
            "historical",
            Some(migration.migrated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "runnable-queue",
                migration.target_queue,
                migration.target_queue_generation,
            ),
            "target-runnable-queue",
            "historical",
            Some(migration.migrated_at_event),
        ));
        if let Some(source_vector_state) = &migration.source_vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(source_vector_state),
                "source-vector-state",
                "historical",
                migration
                    .vector_migrated_at_event
                    .or(Some(migration.migrated_at_event)),
            ));
        }
        if let Some(migrated_vector_state) = &migration.migrated_vector_state {
            edges.push(graph_edge(
                from,
                object_ref_manifest_json(migrated_vector_state),
                "migrated-vector-state",
                "historical",
                migration
                    .vector_migrated_at_event
                    .or(Some(migration.migrated_at_event)),
            ));
        }
    }
    for safe_point in &package.semantic.smp_safe_points {
        let from = object_ref_json("smp-safe-point", safe_point.id, safe_point.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                safe_point.coordinator_hart,
                safe_point.coordinator_hart_generation,
            ),
            "coordinator-hart",
            "historical",
            Some(safe_point.recorded_at_event),
        ));
        for participant in &safe_point.participants {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", participant.hart, participant.hart_generation),
                "participant-hart",
                "historical",
                Some(safe_point.recorded_at_event),
            ));
        }
    }
    for rendezvous in &package.semantic.stop_the_world_rendezvous {
        let from = object_ref_json(
            "stop-the-world-rendezvous",
            rendezvous.id,
            rendezvous.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "smp-safe-point",
                rendezvous.safe_point,
                rendezvous.safe_point_generation,
            ),
            "rendezvous-safe-point",
            "historical",
            Some(rendezvous.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                rendezvous.coordinator_hart,
                rendezvous.coordinator_hart_generation,
            ),
            "coordinator-hart",
            "historical",
            Some(rendezvous.completed_at_event),
        ));
        for participant in &rendezvous.participants {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", participant.hart, participant.hart_generation),
                "participant-hart",
                "historical",
                Some(rendezvous.completed_at_event),
            ));
        }
    }
    for barrier in &package.semantic.smp_code_publish_barriers {
        let from = object_ref_json("smp-code-publish-barrier", barrier.id, barrier.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "stop-the-world-rendezvous",
                barrier.rendezvous,
                barrier.rendezvous_generation,
            ),
            "publish-rendezvous",
            "historical",
            Some(barrier.validated_at_event),
        ));
        for participant in &barrier.participants {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", participant.hart, participant.hart_generation),
                "participant-hart",
                "historical",
                Some(barrier.validated_at_event),
            ));
        }
    }
    for quiescence in &package.semantic.smp_cleanup_quiescence {
        let from = object_ref_json(
            "smp-cleanup-quiescence",
            quiescence.id,
            quiescence.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation-cleanup",
                quiescence.cleanup,
                quiescence.cleanup_generation,
            ),
            "cleanup",
            "historical",
            Some(quiescence.validated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                quiescence.store,
                quiescence.result_store_generation,
            ),
            "dead-store",
            "historical",
            Some(quiescence.validated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "stop-the-world-rendezvous",
                quiescence.rendezvous,
                quiescence.rendezvous_generation,
            ),
            "cleanup-rendezvous",
            "historical",
            Some(quiescence.validated_at_event),
        ));
        for participant in &quiescence.participants {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", participant.hart, participant.hart_generation),
                "participant-hart",
                "historical",
                Some(quiescence.validated_at_event),
            ));
        }
    }
    for barrier in &package.semantic.smp_snapshot_barriers {
        let from = object_ref_json("smp-snapshot-barrier", barrier.id, barrier.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "stop-the-world-rendezvous",
                barrier.rendezvous,
                barrier.rendezvous_generation,
            ),
            "snapshot-rendezvous",
            "historical",
            Some(barrier.validated_at_event),
        ));
        for participant in &barrier.participants {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", participant.hart, participant.hart_generation),
                "participant-hart",
                "historical",
                Some(barrier.validated_at_event),
            ));
        }
    }
    for run in &package.semantic.smp_stress_runs {
        let from = object_ref_json("smp-stress-run", run.id, run.generation);
        let stress_edges = [
            (
                "last-safe-point",
                "smp-safe-point",
                run.last_safe_point,
                run.last_safe_point_generation,
            ),
            (
                "last-rendezvous",
                "stop-the-world-rendezvous",
                run.last_rendezvous,
                run.last_rendezvous_generation,
            ),
            (
                "last-code-publish-barrier",
                "smp-code-publish-barrier",
                run.last_code_publish_barrier,
                run.last_code_publish_barrier_generation,
            ),
            (
                "last-cleanup-quiescence",
                "smp-cleanup-quiescence",
                run.last_cleanup_quiescence,
                run.last_cleanup_quiescence_generation,
            ),
            (
                "last-snapshot-barrier",
                "smp-snapshot-barrier",
                run.last_snapshot_barrier,
                run.last_snapshot_barrier_generation,
            ),
            (
                "last-activation-migration",
                "activation-migration",
                run.last_activation_migration,
                run.last_activation_migration_generation,
            ),
            (
                "last-remote-preempt",
                "remote-preempt",
                run.last_remote_preempt,
                run.last_remote_preempt_generation,
            ),
            (
                "last-remote-park",
                "remote-park",
                run.last_remote_park,
                run.last_remote_park_generation,
            ),
        ];
        for (label, kind, id, generation) in stress_edges {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(kind, id, generation),
                label,
                "historical",
                Some(run.recorded_at_event),
            ));
        }
    }
    for benchmark in &package.semantic.smp_scaling_benchmarks {
        edges.push(graph_edge(
            object_ref_json("smp-scaling-benchmark", benchmark.id, benchmark.generation),
            object_ref_json(
                "smp-stress-run",
                benchmark.stress_run,
                benchmark.stress_run_generation,
            ),
            "scaling-stress-run",
            "historical",
            Some(benchmark.recorded_at_event),
        ));
    }
    for record in &package.semantic.integrated_smp_preemption_cleanups {
        let from = object_ref_json(
            "integrated-smp-preemption-cleanup",
            record.id,
            record.generation,
        );
        for (label, kind, id, generation) in [
            (
                "integrated-stress-run",
                "smp-stress-run",
                record.stress_run,
                record.stress_run_generation,
            ),
            (
                "integrated-preemption",
                "preemption",
                record.preemption,
                record.preemption_generation,
            ),
            (
                "integrated-timer-interrupt",
                "timer-interrupt",
                record.timer_interrupt,
                record.timer_interrupt_generation,
            ),
            (
                "integrated-saved-context",
                "saved-context",
                record.saved_context,
                record.saved_context_generation,
            ),
            (
                "integrated-remote-preempt",
                "remote-preempt",
                record.remote_preempt,
                record.remote_preempt_generation,
            ),
            (
                "integrated-activation-cleanup",
                "activation-cleanup",
                record.activation_cleanup,
                record.activation_cleanup_generation,
            ),
            (
                "integrated-cleanup-quiescence",
                "smp-cleanup-quiescence",
                record.smp_cleanup_quiescence,
                record.smp_cleanup_quiescence_generation,
            ),
            (
                "integrated-cleanup-store",
                "store",
                record.cleanup_store,
                record.target_store_generation,
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(kind, id, generation),
                label,
                "historical",
                Some(record.recorded_at_event),
            ));
        }
    }
    for device in &package.semantic.device_objects {
        edges.push(graph_edge(
            object_ref_json("device", device.id, device.generation),
            object_ref_json("resource", device.resource, device.resource_generation),
            "device-resource",
            "live",
            Some(device.recorded_at_event),
        ));
    }
    for queue in &package.semantic.queue_objects {
        edges.push(graph_edge(
            object_ref_json("queue", queue.id, queue.generation),
            object_ref_json("device", queue.device, queue.device_generation),
            "queue-device",
            "live",
            Some(queue.recorded_at_event),
        ));
    }
    for descriptor in &package.semantic.descriptor_objects {
        edges.push(graph_edge(
            object_ref_json("descriptor", descriptor.id, descriptor.generation),
            object_ref_json("queue", descriptor.queue, descriptor.queue_generation),
            "descriptor-queue",
            "live",
            Some(descriptor.recorded_at_event),
        ));
    }
    for dma_buffer in &package.semantic.dma_buffer_objects {
        edges.push(graph_edge(
            object_ref_json("dma-buffer", dma_buffer.id, dma_buffer.generation),
            object_ref_json(
                "descriptor",
                dma_buffer.descriptor,
                dma_buffer.descriptor_generation,
            ),
            "dma-buffer-descriptor",
            "live",
            Some(dma_buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("dma-buffer", dma_buffer.id, dma_buffer.generation),
            object_ref_json(
                "resource",
                dma_buffer.resource,
                dma_buffer.resource_generation,
            ),
            "dma-buffer-resource",
            "live",
            Some(dma_buffer.recorded_at_event),
        ));
    }
    for mmio_region in &package.semantic.mmio_region_objects {
        edges.push(graph_edge(
            object_ref_json("mmio-region", mmio_region.id, mmio_region.generation),
            object_ref_json("device", mmio_region.device, mmio_region.device_generation),
            "mmio-region-device",
            "live",
            Some(mmio_region.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("mmio-region", mmio_region.id, mmio_region.generation),
            object_ref_json(
                "resource",
                mmio_region.resource,
                mmio_region.resource_generation,
            ),
            "mmio-region-resource",
            "live",
            Some(mmio_region.recorded_at_event),
        ));
    }
    for irq_line in &package.semantic.irq_line_objects {
        edges.push(graph_edge(
            object_ref_json("irq-line", irq_line.id, irq_line.generation),
            object_ref_json("device", irq_line.device, irq_line.device_generation),
            "irq-line-device",
            "live",
            Some(irq_line.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("irq-line", irq_line.id, irq_line.generation),
            object_ref_json("resource", irq_line.resource, irq_line.resource_generation),
            "irq-line-resource",
            "live",
            Some(irq_line.recorded_at_event),
        ));
    }
    for irq_event in &package.semantic.irq_events {
        let from = object_ref_json("irq-event", irq_event.id, irq_event.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "irq-line",
                irq_event.irq_line,
                irq_event.irq_line_generation,
            ),
            "irq-event-line",
            "historical",
            Some(irq_event.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", irq_event.device, irq_event.device_generation),
            "irq-event-device",
            "historical",
            Some(irq_event.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "store",
                irq_event.driver_store,
                irq_event.driver_store_generation,
            ),
            "irq-event-driver-store",
            "historical",
            Some(irq_event.recorded_at_event),
        ));
    }
    for device_capability in &package.semantic.device_capabilities {
        let from = object_ref_json(
            "device-capability",
            device_capability.id,
            device_capability.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                device_capability.driver_store,
                device_capability.driver_store_generation,
            ),
            "device-capability-driver-store",
            "live",
            Some(device_capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&device_capability.target),
            "device-capability-target",
            "live",
            Some(device_capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "capability",
                device_capability.capability,
                device_capability.capability_generation,
            ),
            "device-capability-ledger",
            "live",
            Some(device_capability.recorded_at_event),
        ));
    }
    for binding in &package.semantic.driver_store_bindings {
        let from = object_ref_json("driver-store-binding", binding.id, binding.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                binding.driver_store,
                binding.driver_store_generation,
            ),
            "driver-store-binding-store",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", binding.device, binding.device_generation),
            "driver-store-binding-device",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "device-capability",
                binding.device_capability,
                binding.device_capability_generation,
            ),
            "driver-store-binding-device-capability",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "capability",
                binding.capability,
                binding.capability_generation,
            ),
            "driver-store-binding-ledger",
            "live",
            Some(binding.recorded_at_event),
        ));
    }
    for io_wait in &package.semantic.io_waits {
        let from = object_ref_json("io-wait", io_wait.id, io_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", io_wait.wait, io_wait.wait_generation),
            "io-wait-token",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                io_wait.driver_store,
                io_wait.driver_store_generation,
            ),
            "io-wait-driver-store",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", io_wait.device, io_wait.device_generation),
            "io-wait-device",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                io_wait.driver_binding,
                io_wait.driver_binding_generation,
            ),
            "io-wait-driver-binding",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&io_wait.blocker),
            "io-wait-blocker",
            "historical",
            Some(io_wait.created_at_event),
        ));
        if let (Some(irq_event), Some(irq_event_generation)) = (
            io_wait.completion_irq_event,
            io_wait.completion_irq_event_generation,
        ) {
            edges.push(graph_edge(
                from,
                object_ref_json("irq-event", irq_event, irq_event_generation),
                "io-wait-completion-irq",
                "historical",
                io_wait.completed_at_event,
            ));
        }
    }
    for cleanup in &package.semantic.io_cleanups {
        let from = object_ref_json("io-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "io-cleanup-driver-store",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", cleanup.device, cleanup.device_generation),
            "io-cleanup-device",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation,
            ),
            "io-cleanup-driver-binding",
            "historical",
            Some(cleanup.started_at_event),
        ));
        for io_wait in &cleanup.cancelled_io_waits {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(io_wait),
                "cancelled-io-wait",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for device_capability in &cleanup.revoked_device_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(device_capability),
                "revoked-device-capability",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for capability in &cleanup.revoked_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(capability),
                "revoked-capability",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for dma_buffer in &cleanup.released_dma_buffers {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(dma_buffer),
                "released-dma-buffer",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for mmio_region in &cleanup.released_mmio_regions {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(mmio_region),
                "released-mmio-region",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for irq_line in &cleanup.released_irq_lines {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(irq_line),
                "released-irq-line",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
    }
    for fault in &package.semantic.io_fault_injections {
        let from = object_ref_json("io-fault-injection", fault.id, fault.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", fault.driver_store, fault.driver_store_generation),
            "io-fault-driver-store",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", fault.device, fault.device_generation),
            "io-fault-device",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                fault.driver_binding,
                fault.driver_binding_generation,
            ),
            "io-fault-driver-binding",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&fault.target),
            "io-fault-target",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("io-cleanup", fault.cleanup, fault.cleanup_generation),
            "triggered-cleanup",
            "cleanup-effect",
            Some(fault.injected_at_event),
        ));
    }
    for report in &package.semantic.io_validation_reports {
        let from = object_ref_json("io-validation-report", report.id, report.generation);
        for violation in &report.violations {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(&violation.subject),
                &violation.relation,
                "historical",
                Some(report.validated_at_event),
            ));
        }
    }
    for resume in &package.semantic.activation_resumes {
        let from = object_ref_json("activation-resume", resume.id, resume.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "scheduler-decision",
                resume.scheduler_decision,
                resume.scheduler_decision_generation,
            ),
            "consumed-decision",
            "historical",
            Some(resume.resumed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                resume.activation,
                resume.activation_generation_before,
            ),
            "resumed-from",
            "historical",
            Some(resume.resumed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                resume.activation,
                resume.activation_generation_after,
            ),
            "resumed-to",
            "historical",
            Some(resume.resumed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("runnable-queue", resume.queue, resume.queue_generation),
            "dequeued-from",
            "historical",
            Some(resume.resumed_at_event),
        ));
        if let (Some(context), Some(generation)) = (resume.context, resume.context_generation_after)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("activation-context", context, generation),
                "restored-context",
                "historical",
                Some(resume.resumed_at_event),
            ));
        }
        if let (Some(saved), Some(generation)) =
            (resume.saved_context, resume.saved_context_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("saved-context", saved, generation),
                "restored-saved-context",
                "historical",
                Some(resume.resumed_at_event),
            ));
        }
        if let Some(saved_vector_state) = &resume.saved_vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(saved_vector_state),
                "restores-saved-vector-state",
                "historical",
                resume
                    .vector_restored_at_event
                    .or(Some(resume.resumed_at_event)),
            ));
        }
        if let Some(restored_vector_state) = &resume.restored_vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(restored_vector_state),
                "restored-vector-state",
                "historical",
                resume
                    .vector_restored_at_event
                    .or(Some(resume.resumed_at_event)),
            ));
        }
    }
    for activation_wait in &package.semantic.activation_waits {
        let from = object_ref_json(
            "activation-wait",
            activation_wait.id,
            activation_wait.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                activation_wait.activation,
                activation_wait.activation_generation_before,
            ),
            "blocked-from",
            "historical",
            Some(activation_wait.blocked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                activation_wait.activation,
                activation_wait.activation_generation_after_block,
            ),
            "blocked-to",
            "historical",
            Some(activation_wait.blocked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "wait-token",
                activation_wait.wait,
                activation_wait.wait_generation,
            ),
            "created-wait",
            "historical",
            Some(activation_wait.blocked_at_event),
        ));
        if let Some(cancel_generation) = activation_wait.activation_generation_after_cancel {
            edges.push(graph_edge(
                from,
                object_ref_json("activation", activation_wait.activation, cancel_generation),
                "cancelled-to",
                "historical",
                activation_wait.completed_at_event,
            ));
        }
    }
    for cleanup in &package.semantic.activation_cleanups {
        let from = object_ref_json("activation-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.store, cleanup.target_store_generation),
            "cleanup-target",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.store, cleanup.result_store_generation),
            "marked-dead",
            "cleanup-effect",
            Some(cleanup.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                cleanup.activation,
                cleanup.activation_generation_before,
            ),
            "sealed-from",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                cleanup.activation,
                cleanup.activation_generation_after,
            ),
            "sealed-to",
            "cleanup-effect",
            Some(cleanup.completed_at_event),
        ));
        if let (Some(wait), Some(wait_generation)) = (cleanup.wait, cleanup.wait_generation) {
            edges.push(graph_edge(
                from,
                object_ref_json("wait-token", wait, wait_generation),
                "cancelled-wait",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
    }
    for sample in &package.semantic.preemption_latency_samples {
        let from = object_ref_json("preemption-latency", sample.id, sample.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "timer-interrupt",
                sample.timer_interrupt,
                sample.timer_interrupt_generation,
            ),
            "measured-from-timer",
            "historical",
            Some(sample.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "preemption",
                sample.preemption,
                sample.preemption_generation,
            ),
            "measured-preemption",
            "historical",
            Some(sample.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "scheduler-decision",
                sample.scheduler_decision,
                sample.scheduler_decision_generation,
            ),
            "measured-decision",
            "historical",
            Some(sample.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "activation-resume",
                sample.activation_resume,
                sample.activation_resume_generation,
            ),
            "measured-resume",
            "historical",
            Some(sample.recorded_at_event),
        ));
    }
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

fn optional_object_ref_json(
    kind: &str,
    id: Option<u64>,
    generation: Option<u64>,
) -> serde_json::Value {
    match (id, generation) {
        (Some(id), Some(generation)) => object_ref_json(kind, id, generation),
        _ => serde_json::Value::Null,
    }
}

fn osctl_kind_from_contract_kind(kind: &str) -> &str {
    match kind {
        "fake-block-backend-object" => "fake-block-backend",
        "fake-net-backend-object" => "fake-net-backend",
        "virtio-blk-backend-object" => "virtio-blk-backend",
        "virtio-net-backend-object" => "virtio-net-backend",
        other => other,
    }
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
        "block-driver-cleanup" | "disk-driver-cleanup" | "disk-cleanup" => {
            println!(
                "inspect block-driver-cleanup package={} count={}",
                package.package_id, package.semantic.block_driver_cleanup_count
            );
            for cleanup in &package.semantic.block_driver_cleanups {
                let line = format!(
                    "block-driver-cleanup id={} io_cleanup={}@{} driver_store={}@{} device={}@{} driver_binding={}@{} block_device={}@{} backend={}:{}@{} state={} generation={} cancelled_block_waits={} cancelled_wait_tokens={} released_dma_buffers={} revoked_device_capabilities={} reason={}",
                    cleanup.id,
                    cleanup.io_cleanup,
                    cleanup.io_cleanup_generation,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                    cleanup.device,
                    cleanup.device_generation,
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                    cleanup.block_device,
                    cleanup.block_device_generation,
                    cleanup.backend.kind,
                    cleanup.backend.id,
                    cleanup.backend.generation,
                    cleanup.state,
                    cleanup.generation,
                    cleanup.cancelled_block_waits.len(),
                    cleanup.cancelled_wait_tokens.len(),
                    cleanup.released_dma_buffers.len(),
                    cleanup.revoked_device_capabilities.len(),
                    cleanup.reason
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.block_driver_cleanups.is_empty() {
                print_roots_filtered(
                    "block-driver-cleanup",
                    &package.semantic.roots.block_driver_cleanup_roots,
                    filter,
                );
            }
        }
        "block-pending-io-policy" | "pending-block-io" | "pending-io-policy" => {
            println!(
                "inspect block-pending-io-policy package={} count={}",
                package.package_id, package.semantic.block_pending_io_policy_count
            );
            for policy in &package.semantic.block_pending_io_policies {
                let retry = policy
                    .retry_request
                    .zip(policy.retry_request_generation)
                    .map(|(id, generation)| format!("{id}@{generation}"))
                    .unwrap_or_else(|| "none".to_owned());
                let line = format!(
                    "block-pending-io-policy id={} block_wait={}@{} wait={}@{} block_request={}@{} retry_request={} block_device={}@{} block_range={}@{} action={} errno={} retry_attempt={} max_retries={} state={} generation={}",
                    policy.id,
                    policy.block_wait,
                    policy.block_wait_generation,
                    policy.wait,
                    policy.wait_generation,
                    policy.block_request,
                    policy.block_request_generation,
                    retry,
                    policy.block_device,
                    policy.block_device_generation,
                    policy.block_range,
                    policy.block_range_generation,
                    policy.action,
                    policy.errno,
                    policy.retry_attempt,
                    policy.max_retries,
                    policy.state,
                    policy.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.block_pending_io_policies.is_empty() {
                print_roots_filtered(
                    "block-pending-io-policy",
                    &package.semantic.roots.block_pending_io_policy_roots,
                    filter,
                );
            }
        }
        "block-request-generation-audit"
        | "stale-block-request-generation"
        | "block-generation-audit" => {
            println!(
                "inspect block-request-generation-audit package={} count={}",
                package.package_id, package.semantic.block_request_generation_audit_count
            );
            for audit in &package.semantic.block_request_generation_audits {
                let line = format!(
                    "block-request-generation-audit id={} block_device={}@{} block_range={}@{} block_request={}@{} backend={}:{}@{} dma_buffer={}:{}@{} rejected_completion_generation_probes={} rejected_wait_generation_probes={} rejected_dma_generation_probes={} rejected_queue_generation_probes={} state={} generation={}",
                    audit.id,
                    audit.block_device,
                    audit.block_device_generation,
                    audit.block_range,
                    audit.block_range_generation,
                    audit.block_request,
                    audit.block_request_generation,
                    audit.backend.kind,
                    audit.backend.id,
                    audit.backend.generation,
                    audit.dma_buffer.kind,
                    audit.dma_buffer.id,
                    audit.dma_buffer.generation,
                    audit.rejected_completion_generation_probes,
                    audit.rejected_wait_generation_probes,
                    audit.rejected_dma_generation_probes,
                    audit.rejected_queue_generation_probes,
                    audit.state,
                    audit.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.block_request_generation_audits.is_empty() {
                print_roots_filtered(
                    "block-request-generation-audit",
                    &package.semantic.roots.block_request_generation_audit_roots,
                    filter,
                );
            }
        }
        "block-benchmark" | "disk-benchmark" | "block-iops" => {
            println!(
                "inspect block-benchmark package={} count={}",
                package.package_id, package.semantic.block_benchmark_count
            );
            for benchmark in &package.semantic.block_benchmarks {
                let line = format!(
                    "block-benchmark id={} scenario={} backend={}:{}@{} block_device={}@{} block_range={}@{} read_path={}@{} write_path={}@{} request_queue={}@{} block_dma_buffer={}@{} sample_requests={} sample_bytes={} iops={} throughput_bytes_per_sec={} p50_latency_nanos={} p99_latency_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.backend.kind,
                    benchmark.backend.id,
                    benchmark.backend.generation,
                    benchmark.block_device,
                    benchmark.block_device_generation,
                    benchmark.block_range,
                    benchmark.block_range_generation,
                    benchmark.read_path,
                    benchmark.read_path_generation,
                    benchmark.write_path,
                    benchmark.write_path_generation,
                    benchmark.request_queue,
                    benchmark.request_queue_generation,
                    benchmark.block_dma_buffer,
                    benchmark.block_dma_buffer_generation,
                    benchmark.sample_requests,
                    benchmark.sample_bytes,
                    benchmark.iops,
                    benchmark.throughput_bytes_per_sec,
                    benchmark.p50_latency_nanos,
                    benchmark.p99_latency_nanos,
                    benchmark.state,
                    benchmark.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.block_benchmarks.is_empty() {
                print_roots_filtered(
                    "block-benchmark",
                    &package.semantic.roots.block_benchmark_roots,
                    filter,
                );
            }
        }
        "block-recovery-benchmark" | "disk-recovery-benchmark" | "disk-recovery" => {
            println!(
                "inspect block-recovery-benchmark package={} count={}",
                package.package_id, package.semantic.block_recovery_benchmark_count
            );
            for benchmark in &package.semantic.block_recovery_benchmarks {
                let line = format!(
                    "block-recovery-benchmark id={} scenario={} cleanup={}@{} io_cleanup={}@{} backend={}:{}@{} block_device={}@{} driver_store={}@{} device={}@{} driver_binding={}@{} recovery_start_event={} recovery_complete_event={} cancelled_block_waits={} cancelled_wait_tokens={} released_dma_buffers={} revoked_device_capabilities={} recovery_nanos={} budget_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.cleanup,
                    benchmark.cleanup_generation,
                    benchmark.io_cleanup,
                    benchmark.io_cleanup_generation,
                    benchmark.backend.kind,
                    benchmark.backend.id,
                    benchmark.backend.generation,
                    benchmark.block_device,
                    benchmark.block_device_generation,
                    benchmark.driver_store,
                    benchmark.driver_store_generation,
                    benchmark.device,
                    benchmark.device_generation,
                    benchmark.driver_binding,
                    benchmark.driver_binding_generation,
                    benchmark.recovery_start_event,
                    benchmark.recovery_complete_event,
                    benchmark.cancelled_block_waits,
                    benchmark.cancelled_wait_tokens,
                    benchmark.released_dma_buffers,
                    benchmark.revoked_device_capabilities,
                    benchmark.recovery_nanos,
                    benchmark.budget_nanos,
                    benchmark.state,
                    benchmark.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.block_recovery_benchmarks.is_empty() {
                print_roots_filtered(
                    "block-recovery-benchmark",
                    &package.semantic.roots.block_recovery_benchmark_roots,
                    filter,
                );
            }
        }
        "target-feature-set" | "target-feature" | "target-feature-set-object" => {
            println!(
                "inspect target-feature-set package={} count={}",
                package.package_id, package.semantic.target_feature_set_count
            );
            for feature in &package.semantic.target_feature_sets {
                let line = format!(
                    "target-feature-set id={} name={} source={} profile={} arch={} base_isa={} simd_abi={} simd_supported={} vector_register_count={} vector_register_bits={} scalar_fallback={} state={} generation={}",
                    feature.id,
                    feature.name,
                    feature.discovery_source,
                    feature.target_profile,
                    feature.target_arch,
                    feature.base_isa,
                    feature.simd_abi,
                    feature.simd_supported,
                    feature.vector_register_count,
                    feature.vector_register_bits,
                    feature.scalar_fallback,
                    feature.state,
                    feature.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.target_feature_sets.is_empty() {
                print_roots_filtered(
                    "target-feature-set",
                    &package.semantic.roots.target_feature_set_roots,
                    filter,
                );
            }
        }
        "vector-state" | "vector" | "simd-vector-state" => {
            println!(
                "inspect vector-state package={} count={}",
                package.package_id, package.semantic.vector_state_count
            );
            for vector_state in &package.semantic.vector_states {
                let line = format!(
                    "vector-state id={} activation={}@{} store={}@{} code_object={}@{} target_feature_set={}@{} simd_abi={} vector_register_count={} vector_register_bits={} register_bytes={} state={} generation={}",
                    vector_state.id,
                    vector_state.owner_activation.id,
                    vector_state.owner_activation.generation,
                    vector_state.owner_store.id,
                    vector_state.owner_store.generation,
                    vector_state.code_object.id,
                    vector_state.code_object.generation,
                    vector_state.target_feature_set.id,
                    vector_state.target_feature_set.generation,
                    vector_state.simd_abi,
                    vector_state.vector_register_count,
                    vector_state.vector_register_bits,
                    vector_state.register_bytes,
                    vector_state.state,
                    vector_state.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.vector_states.is_empty() {
                print_roots_filtered(
                    "vector-state",
                    &package.semantic.roots.vector_state_roots,
                    filter,
                );
            }
        }
        "simd-fault-injection" | "simd-fault" => {
            println!(
                "inspect simd-fault-injection package={} count={}",
                package.package_id, package.semantic.simd_fault_injection_count
            );
            for injection in &package.semantic.simd_fault_injections {
                let vector_state = injection
                    .vector_state
                    .as_ref()
                    .map(|reference| {
                        format!(
                            "{}:{}@{}",
                            reference.kind, reference.id, reference.generation
                        )
                    })
                    .unwrap_or_else(|| "none".to_owned());
                let line = format!(
                    "simd-fault-injection id={} activation={}@{} code_object={}@{} trap={}@{} target_feature_set={}@{} vector_state={} kind={} effect={} required_abi={} vector_register_count={} vector_register_bits={} injected_faults={} state={} generation={}",
                    injection.id,
                    injection.activation.id,
                    injection.activation.generation,
                    injection.code_object.id,
                    injection.code_object.generation,
                    injection.trap.id,
                    injection.trap.generation,
                    injection.target_feature_set.id,
                    injection.target_feature_set.generation,
                    vector_state,
                    injection.kind,
                    injection.effect,
                    injection.required_abi,
                    injection.vector_register_count,
                    injection.vector_register_bits,
                    injection.injected_faults,
                    injection.state,
                    injection.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.simd_fault_injections.is_empty() {
                print_roots_filtered(
                    "simd-fault-injection",
                    &package.semantic.roots.simd_fault_injection_roots,
                    filter,
                );
            }
        }
        "simd-benchmark" | "simd-scalar-vector-benchmark" => {
            println!(
                "inspect simd-benchmark package={} count={}",
                package.package_id, package.semantic.simd_benchmark_count
            );
            for benchmark in &package.semantic.simd_benchmarks {
                let line = format!(
                    "simd-benchmark id={} target_feature_set={}@{} scalar_code_object={}@{} vector_code_object={}@{} simd_abi={} vector_register_count={} vector_register_bits={} workload_units={} scalar_nanos={} vector_nanos={} speedup_milli={} context_overhead_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.target_feature_set.id,
                    benchmark.target_feature_set.generation,
                    benchmark.scalar_code_object.id,
                    benchmark.scalar_code_object.generation,
                    benchmark.vector_code_object.id,
                    benchmark.vector_code_object.generation,
                    benchmark.simd_abi,
                    benchmark.vector_register_count,
                    benchmark.vector_register_bits,
                    benchmark.workload_units,
                    benchmark.scalar_nanos,
                    benchmark.vector_nanos,
                    benchmark.speedup_milli,
                    benchmark.context_overhead_nanos,
                    benchmark.state,
                    benchmark.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.simd_benchmarks.is_empty() {
                print_roots_filtered(
                    "simd-benchmark",
                    &package.semantic.roots.simd_benchmark_roots,
                    filter,
                );
            }
        }
        "simd-context-switch-benchmark" | "simd-context-switch" | "simd-switch-benchmark" => {
            println!(
                "inspect simd-context-switch-benchmark package={} count={}",
                package.package_id, package.semantic.simd_context_switch_benchmark_count
            );
            for benchmark in &package.semantic.simd_context_switch_benchmarks {
                let line = format!(
                    "simd-context-switch-benchmark id={} preemption={}@{} activation_resume={}@{} saved_vector_state={}@{} restored_vector_state={}@{} target_feature_set={}@{} simd_abi={} vector_register_count={} vector_register_bits={} sample_count={} scalar_context_switch_nanos={} vector_context_switch_nanos={} overhead_nanos={} budget_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.preemption.id,
                    benchmark.preemption.generation,
                    benchmark.activation_resume.id,
                    benchmark.activation_resume.generation,
                    benchmark.saved_vector_state.id,
                    benchmark.saved_vector_state.generation,
                    benchmark.restored_vector_state.id,
                    benchmark.restored_vector_state.generation,
                    benchmark.target_feature_set.id,
                    benchmark.target_feature_set.generation,
                    benchmark.simd_abi,
                    benchmark.vector_register_count,
                    benchmark.vector_register_bits,
                    benchmark.sample_count,
                    benchmark.scalar_context_switch_nanos,
                    benchmark.vector_context_switch_nanos,
                    benchmark.overhead_nanos,
                    benchmark.budget_nanos,
                    benchmark.state,
                    benchmark.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.simd_context_switch_benchmarks.is_empty() {
                print_roots_filtered(
                    "simd-context-switch-benchmark",
                    &package.semantic.roots.simd_context_switch_benchmark_roots,
                    filter,
                );
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
        "framebuffer-object" | "framebuffer" | "fb" => {
            println!(
                "inspect framebuffer-object package={} count={}",
                package.package_id, package.semantic.framebuffer_object_count
            );
            for framebuffer in &package.semantic.framebuffer_objects {
                let line = format!(
                    "framebuffer-object id={} name={} resource={}@{} width={} height={} stride_bytes={} pixel_format={} byte_len={} state={} generation={}",
                    framebuffer.id,
                    framebuffer.name,
                    framebuffer.resource,
                    framebuffer.resource_generation,
                    framebuffer.width,
                    framebuffer.height,
                    framebuffer.stride_bytes,
                    framebuffer.pixel_format,
                    framebuffer.byte_len,
                    framebuffer.state,
                    framebuffer.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_objects.is_empty() {
                print_roots_filtered(
                    "framebuffer-object",
                    &package.semantic.roots.framebuffer_object_roots,
                    filter,
                );
            }
        }
        "display-object" | "display" | "display-mode" => {
            println!(
                "inspect display-object package={} count={}",
                package.package_id, package.semantic.display_object_count
            );
            for display in &package.semantic.display_objects {
                let line = format!(
                    "display-object id={} name={} framebuffer={}@{} mode_name={} width={} height={} refresh_millihz={} state={} generation={}",
                    display.id,
                    display.name,
                    display.framebuffer,
                    display.framebuffer_generation,
                    display.mode_name,
                    display.width,
                    display.height,
                    display.refresh_millihz,
                    display.state,
                    display.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_objects.is_empty() {
                print_roots_filtered(
                    "display-object",
                    &package.semantic.roots.display_object_roots,
                    filter,
                );
            }
        }
        "display-capability" | "display-cap" => {
            println!(
                "inspect display-capability package={} count={}",
                package.package_id, package.semantic.display_capability_count
            );
            for capability in &package.semantic.display_capabilities {
                let line = format!(
                    "display-capability id={} owner_store={}@{} display={}@{} framebuffer={}@{} capability={}@{} handle_slot={} handle_generation={} operations={} state={} generation={}",
                    capability.id,
                    capability.owner_store,
                    capability.owner_store_generation,
                    capability.display,
                    capability.display_generation,
                    capability.framebuffer,
                    capability.framebuffer_generation,
                    capability.capability,
                    capability.capability_generation,
                    capability.handle_slot,
                    capability.handle_generation,
                    capability.operations.join("|"),
                    capability.state,
                    capability.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_capabilities.is_empty() {
                print_roots_filtered(
                    "display-capability",
                    &package.semantic.roots.display_capability_roots,
                    filter,
                );
            }
        }
        "framebuffer-window-lease" | "fb-window-lease" | "display-lease" => {
            println!(
                "inspect framebuffer-window-lease package={} count={}",
                package.package_id, package.semantic.framebuffer_window_lease_count
            );
            for lease in &package.semantic.framebuffer_window_leases {
                let line = format!(
                    "framebuffer-window-lease id={} owner_store={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} window={},{} {}x{} byte_range={}+{} access={} state={} generation={}",
                    lease.id,
                    lease.owner_store,
                    lease.owner_store_generation,
                    lease.display_capability,
                    lease.display_capability_generation,
                    lease.display,
                    lease.display_generation,
                    lease.framebuffer,
                    lease.framebuffer_generation,
                    lease.x,
                    lease.y,
                    lease.width,
                    lease.height,
                    lease.byte_offset,
                    lease.byte_len,
                    lease.access,
                    lease.state,
                    lease.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_window_leases.is_empty() {
                print_roots_filtered(
                    "framebuffer-window-lease",
                    &package.semantic.roots.framebuffer_window_lease_roots,
                    filter,
                );
            }
        }
        "framebuffer-mapping" | "fb-mapping" | "display-mapping" => {
            println!(
                "inspect framebuffer-mapping package={} count={}",
                package.package_id, package.semantic.framebuffer_mapping_count
            );
            for mapping in &package.semantic.framebuffer_mappings {
                let line = format!(
                    "framebuffer-mapping id={} owner_store={}@{} framebuffer_window_lease={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} map_handle_slot={} map_handle_generation={} window={},{} {}x{} byte_range={}+{} access={} mode={} state={} generation={}",
                    mapping.id,
                    mapping.owner_store,
                    mapping.owner_store_generation,
                    mapping.framebuffer_window_lease,
                    mapping.framebuffer_window_lease_generation,
                    mapping.display_capability,
                    mapping.display_capability_generation,
                    mapping.display,
                    mapping.display_generation,
                    mapping.framebuffer,
                    mapping.framebuffer_generation,
                    mapping.map_handle_slot,
                    mapping.map_handle_generation,
                    mapping.x,
                    mapping.y,
                    mapping.width,
                    mapping.height,
                    mapping.byte_offset,
                    mapping.byte_len,
                    mapping.access,
                    mapping.mode,
                    mapping.state,
                    mapping.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_mappings.is_empty() {
                print_roots_filtered(
                    "framebuffer-mapping",
                    &package.semantic.roots.framebuffer_mapping_roots,
                    filter,
                );
            }
        }
        "framebuffer-write" | "fb-write" | "display-write" => {
            println!(
                "inspect framebuffer-write package={} count={}",
                package.package_id, package.semantic.framebuffer_write_count
            );
            for write in &package.semantic.framebuffer_writes {
                let line = format!(
                    "framebuffer-write id={} owner_store={}@{} framebuffer_mapping={}@{} framebuffer_window_lease={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} map_handle_slot={} map_handle_generation={} region={},{} {}x{} byte_range={}+{} pixel_format={} payload_digest={} state={} generation={}",
                    write.id,
                    write.owner_store,
                    write.owner_store_generation,
                    write.framebuffer_mapping,
                    write.framebuffer_mapping_generation,
                    write.framebuffer_window_lease,
                    write.framebuffer_window_lease_generation,
                    write.display_capability,
                    write.display_capability_generation,
                    write.display,
                    write.display_generation,
                    write.framebuffer,
                    write.framebuffer_generation,
                    write.map_handle_slot,
                    write.map_handle_generation,
                    write.x,
                    write.y,
                    write.width,
                    write.height,
                    write.byte_offset,
                    write.byte_len,
                    write.pixel_format,
                    write.payload_digest,
                    write.state,
                    write.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_writes.is_empty() {
                print_roots_filtered(
                    "framebuffer-write",
                    &package.semantic.roots.framebuffer_write_roots,
                    filter,
                );
            }
        }
        "framebuffer-flush-region" | "flush-region" | "display-flush" => {
            println!(
                "inspect framebuffer-flush-region package={} count={}",
                package.package_id, package.semantic.framebuffer_flush_region_count
            );
            for flush in &package.semantic.framebuffer_flush_regions {
                let line = format!(
                    "framebuffer-flush-region id={} owner_store={}@{} framebuffer_write={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} region={},{} {}x{} byte_range={}+{} pixel_format={} payload_digest={} state={} generation={}",
                    flush.id,
                    flush.owner_store,
                    flush.owner_store_generation,
                    flush.framebuffer_write,
                    flush.framebuffer_write_generation,
                    flush.display_capability,
                    flush.display_capability_generation,
                    flush.display,
                    flush.display_generation,
                    flush.framebuffer,
                    flush.framebuffer_generation,
                    flush.x,
                    flush.y,
                    flush.width,
                    flush.height,
                    flush.byte_offset,
                    flush.byte_len,
                    flush.pixel_format,
                    flush.payload_digest,
                    flush.state,
                    flush.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_flush_regions.is_empty() {
                print_roots_filtered(
                    "framebuffer-flush-region",
                    &package.semantic.roots.framebuffer_flush_region_roots,
                    filter,
                );
            }
        }
        "framebuffer-dirty-region" | "dirty-region" | "display-dirty" => {
            println!(
                "inspect framebuffer-dirty-region package={} count={}",
                package.package_id, package.semantic.framebuffer_dirty_region_count
            );
            for dirty in &package.semantic.framebuffer_dirty_regions {
                let line = format!(
                    "framebuffer-dirty-region id={} owner_store={}@{} framebuffer_write={}@{} framebuffer_flush_region={}:{} display_capability={}@{} display={}@{} framebuffer={}@{} region={},{} {}x{} byte_range={}+{} pixel_format={} payload_digest={} dirty_at_event={} cleaned_at_event={} state={} generation={}",
                    dirty.id,
                    dirty.owner_store,
                    dirty.owner_store_generation,
                    dirty.framebuffer_write,
                    dirty.framebuffer_write_generation,
                    dirty
                        .framebuffer_flush_region
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    dirty
                        .framebuffer_flush_region_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    dirty.display_capability,
                    dirty.display_capability_generation,
                    dirty.display,
                    dirty.display_generation,
                    dirty.framebuffer,
                    dirty.framebuffer_generation,
                    dirty.x,
                    dirty.y,
                    dirty.width,
                    dirty.height,
                    dirty.byte_offset,
                    dirty.byte_len,
                    dirty.pixel_format,
                    dirty.payload_digest,
                    dirty.dirty_at_event,
                    dirty
                        .cleaned_at_event
                        .map(|event| event.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    dirty.state,
                    dirty.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_dirty_regions.is_empty() {
                print_roots_filtered(
                    "framebuffer-dirty-region",
                    &package.semantic.roots.framebuffer_dirty_region_roots,
                    filter,
                );
            }
        }
        "display-event-log" | "display-log" => {
            println!(
                "inspect display-event-log package={} count={}",
                package.package_id, package.semantic.display_event_log_count
            );
            for log in &package.semantic.display_event_logs {
                let line = format!(
                    "display-event-log id={} owner_store={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} framebuffer_dirty_region={}@{} events={}..{} event_count={} flush_count={} dirty_region_count={} state={} generation={}",
                    log.id,
                    log.owner_store,
                    log.owner_store_generation,
                    log.display_capability,
                    log.display_capability_generation,
                    log.display,
                    log.display_generation,
                    log.framebuffer,
                    log.framebuffer_generation,
                    log.framebuffer_dirty_region,
                    log.framebuffer_dirty_region_generation,
                    log.first_event,
                    log.last_event,
                    log.event_count,
                    log.flush_count,
                    log.dirty_region_count,
                    log.state,
                    log.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_event_logs.is_empty() {
                print_roots_filtered(
                    "display-event-log",
                    &package.semantic.roots.display_event_log_roots,
                    filter,
                );
            }
        }
        "display-cleanup" => {
            println!(
                "inspect display-cleanup package={} count={}",
                package.package_id, package.semantic.display_cleanup_count
            );
            for cleanup in &package.semantic.display_cleanups {
                let line = format!(
                    "display-cleanup id={} owner_store={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} unmapped_mappings={} released_leases={} revoked_display_capabilities={} state={} generation={}",
                    cleanup.id,
                    cleanup.owner_store,
                    cleanup.owner_store_generation,
                    cleanup.display_capability,
                    cleanup.display_capability_generation,
                    cleanup.display,
                    cleanup.display_generation,
                    cleanup.framebuffer,
                    cleanup.framebuffer_generation,
                    cleanup.unmapped_framebuffer_mappings.len(),
                    cleanup.released_framebuffer_window_leases.len(),
                    cleanup.revoked_display_capabilities.len(),
                    cleanup.state,
                    cleanup.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_cleanups.is_empty() {
                print_roots_filtered(
                    "display-cleanup",
                    &package.semantic.roots.display_cleanup_roots,
                    filter,
                );
            }
        }
        "display-snapshot-barrier" | "display-snapshot" => {
            println!(
                "inspect display-snapshot-barrier package={} count={}",
                package.package_id, package.semantic.display_snapshot_barrier_count
            );
            for barrier in &package.semantic.display_snapshot_barriers {
                let line = format!(
                    "display-snapshot-barrier id={} owner_store={}@{} display={}@{} framebuffer={}@{} cleanup={}:{} active_leases={} active_mappings={} dirty_regions={} snapshot_ok={} state={} generation={}",
                    barrier.id,
                    barrier.owner_store,
                    barrier.owner_store_generation,
                    barrier.display,
                    barrier.display_generation,
                    barrier.framebuffer,
                    barrier.framebuffer_generation,
                    barrier
                        .display_cleanup
                        .map(|cleanup| cleanup.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    barrier
                        .display_cleanup_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    barrier.active_framebuffer_window_lease_count,
                    barrier.active_framebuffer_mapping_count,
                    barrier.dirty_framebuffer_region_count,
                    barrier.snapshot_validation_ok,
                    barrier.state,
                    barrier.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_snapshot_barriers.is_empty() {
                print_roots_filtered(
                    "display-snapshot-barrier",
                    &package.semantic.roots.display_snapshot_barrier_roots,
                    filter,
                );
            }
        }
        "display-panic-last-frame" | "panic-last-frame" => {
            println!(
                "inspect display-panic-last-frame package={} count={}",
                package.package_id, package.semantic.display_panic_last_frame_count
            );
            for frame in &package.semantic.display_panic_last_frames {
                let line = format!(
                    "display-panic-last-frame id={} owner_store={}@{} display={}@{} framebuffer={}@{} barrier={}@{} display_event_log={}@{} framebuffer_write={}@{} framebuffer_flush_region={}@{} payload_digest={} summary_digest={} summary_record_bytes={} panic_epoch={} panic_cpu={} panic_reason_code={} raw_framebuffer_bytes_exported={} state={} generation={}",
                    frame.id,
                    frame.owner_store,
                    frame.owner_store_generation,
                    frame.display,
                    frame.display_generation,
                    frame.framebuffer,
                    frame.framebuffer_generation,
                    frame.display_snapshot_barrier,
                    frame.display_snapshot_barrier_generation,
                    frame.display_event_log,
                    frame.display_event_log_generation,
                    frame.framebuffer_write,
                    frame.framebuffer_write_generation,
                    frame.framebuffer_flush_region,
                    frame.framebuffer_flush_region_generation,
                    frame.payload_digest,
                    frame.summary_digest,
                    frame.summary_record_bytes,
                    frame.panic_epoch,
                    frame.panic_cpu,
                    frame.panic_reason_code,
                    frame.raw_framebuffer_bytes_exported,
                    frame.state,
                    frame.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.display_panic_last_frames.is_empty() {
                print_roots_filtered(
                    "display-panic-last-frame",
                    &package.semantic.roots.display_panic_last_frame_roots,
                    filter,
                );
            }
        }
        "framebuffer-benchmark" | "fb-benchmark" | "display-benchmark" => {
            println!(
                "inspect framebuffer-benchmark package={} count={}",
                package.package_id, package.semantic.framebuffer_benchmark_count
            );
            for benchmark in &package.semantic.framebuffer_benchmarks {
                let line = format!(
                    "framebuffer-benchmark id={} scenario={} owner_store={}@{} display={}@{} framebuffer={}@{} display_capability={}@{} framebuffer_write={}@{} framebuffer_flush_region={}@{} display_event_log={}@{} display_snapshot_barrier={}@{} sample_frames={} sample_bytes={} measured_nanos={} budget_nanos={} throughput_bytes_per_sec={} flushes_per_sec_milli={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.owner_store,
                    benchmark.owner_store_generation,
                    benchmark.display,
                    benchmark.display_generation,
                    benchmark.framebuffer,
                    benchmark.framebuffer_generation,
                    benchmark.display_capability,
                    benchmark.display_capability_generation,
                    benchmark.framebuffer_write,
                    benchmark.framebuffer_write_generation,
                    benchmark.framebuffer_flush_region,
                    benchmark.framebuffer_flush_region_generation,
                    benchmark.display_event_log,
                    benchmark.display_event_log_generation,
                    benchmark.display_snapshot_barrier,
                    benchmark.display_snapshot_barrier_generation,
                    benchmark.sample_frames,
                    benchmark.sample_bytes,
                    benchmark.measured_nanos,
                    benchmark.budget_nanos,
                    benchmark.throughput_bytes_per_sec,
                    benchmark.flushes_per_sec_milli,
                    benchmark.state,
                    benchmark.generation
                );
                print_if_matches(&line, filter);
            }
            if package.semantic.framebuffer_benchmarks.is_empty() {
                print_roots_filtered(
                    "framebuffer-benchmark",
                    &package.semantic.roots.framebuffer_benchmark_roots,
                    filter,
                );
            }
        }
        "integrated-smp-preemption-cleanup"
        | "integrated-smp-cleanup"
        | "smp-preemption-cleanup" => {
            println!(
                "inspect integrated-smp-preemption-cleanup package={} count={}",
                package.package_id, package.semantic.integrated_smp_preemption_cleanup_count
            );
            for record in &package.semantic.integrated_smp_preemption_cleanups {
                let line = format!(
                    "integrated-smp-preemption-cleanup id={} scenario={} stress_run={}@{} preemption={}@{} timer_interrupt={}@{} saved_context={}@{} remote_preempt={}@{} activation_cleanup={}@{} smp_cleanup_quiescence={}@{} cleanup_store={}@{}->{} cleanup_activation={}@{} harts={} invariants={} state={} generation={}",
                    record.id,
                    record.scenario,
                    record.stress_run,
                    record.stress_run_generation,
                    record.preemption,
                    record.preemption_generation,
                    record.timer_interrupt,
                    record.timer_interrupt_generation,
                    record.saved_context,
                    record.saved_context_generation,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                    record.activation_cleanup,
                    record.activation_cleanup_generation,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                    record.cleanup_store,
                    record.target_store_generation,
                    record.result_store_generation,
                    record.cleanup_activation,
                    record.cleanup_activation_generation_after,
                    record.hart_count,
                    record.invariant_checks,
                    record.state,
                    record.generation
                );
                print_if_matches(&line, filter);
            }
            if package
                .semantic
                .integrated_smp_preemption_cleanups
                .is_empty()
            {
                print_roots_filtered(
                    "integrated-smp-preemption-cleanup",
                    &package
                        .semantic
                        .roots
                        .integrated_smp_preemption_cleanup_roots,
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
        "file-handle-capability" | "file-handle" => (
            "file-handle-capability",
            package.semantic.file_handle_capability_count,
            package
                .semantic
                .file_handle_capabilities
                .iter()
                .map(file_handle_capability_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.file_handle_capability_roots.len() }),
        ),
        "fs-wait" | "filesystem-wait" | "file-wait" => (
            "fs-wait",
            package.semantic.fs_wait_count,
            package
                .semantic
                .fs_waits
                .iter()
                .map(fs_wait_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.fs_wait_roots.len() }),
        ),
        "block-driver-cleanup" | "disk-driver-cleanup" | "disk-cleanup" => (
            "block-driver-cleanup",
            package.semantic.block_driver_cleanup_count,
            package
                .semantic
                .block_driver_cleanups
                .iter()
                .map(block_driver_cleanup_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.block_driver_cleanup_roots.len() }),
        ),
        "block-pending-io-policy" | "pending-block-io" | "pending-io-policy" => (
            "block-pending-io-policy",
            package.semantic.block_pending_io_policy_count,
            package
                .semantic
                .block_pending_io_policies
                .iter()
                .map(block_pending_io_policy_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.block_pending_io_policy_roots.len() }),
        ),
        "block-request-generation-audit"
        | "stale-block-request-generation"
        | "block-generation-audit" => (
            "block-request-generation-audit",
            package.semantic.block_request_generation_audit_count,
            package
                .semantic
                .block_request_generation_audits
                .iter()
                .map(block_request_generation_audit_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.block_request_generation_audit_roots.len() }),
        ),
        "block-benchmark" | "disk-benchmark" | "block-iops" => (
            "block-benchmark",
            package.semantic.block_benchmark_count,
            package
                .semantic
                .block_benchmarks
                .iter()
                .map(block_benchmark_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.block_benchmark_roots.len() }),
        ),
        "block-recovery-benchmark" | "disk-recovery-benchmark" | "disk-recovery" => (
            "block-recovery-benchmark",
            package.semantic.block_recovery_benchmark_count,
            package
                .semantic
                .block_recovery_benchmarks
                .iter()
                .map(block_recovery_benchmark_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.block_recovery_benchmark_roots.len() }),
        ),
        "target-feature-set" | "target-feature" | "target-feature-set-object" => (
            "target-feature-set",
            package.semantic.target_feature_set_count,
            package
                .semantic
                .target_feature_sets
                .iter()
                .map(target_feature_set_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.target_feature_set_roots.len() }),
        ),
        "vector-state" | "vector" | "simd-vector-state" => (
            "vector-state",
            package.semantic.vector_state_count,
            package
                .semantic
                .vector_states
                .iter()
                .map(vector_state_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.vector_state_roots.len() }),
        ),
        "simd-fault-injection" | "simd-fault" => (
            "simd-fault-injection",
            package.semantic.simd_fault_injection_count,
            package
                .semantic
                .simd_fault_injections
                .iter()
                .map(simd_fault_injection_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.simd_fault_injection_roots.len() }),
        ),
        "simd-benchmark" | "simd-scalar-vector-benchmark" => (
            "simd-benchmark",
            package.semantic.simd_benchmark_count,
            package
                .semantic
                .simd_benchmarks
                .iter()
                .map(simd_benchmark_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({ "root_count": package.semantic.roots.simd_benchmark_roots.len() }),
        ),
        "simd-context-switch-benchmark" | "simd-context-switch" | "simd-switch-benchmark" => (
            "simd-context-switch-benchmark",
            package.semantic.simd_context_switch_benchmark_count,
            package
                .semantic
                .simd_context_switch_benchmarks
                .iter()
                .map(simd_context_switch_benchmark_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .simd_context_switch_benchmark_roots
                    .len()
            }),
        ),
        "framebuffer-object" | "framebuffer" | "fb" => (
            "framebuffer-object",
            package.semantic.framebuffer_object_count,
            package
                .semantic
                .framebuffer_objects
                .iter()
                .map(framebuffer_object_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_object_roots.len()
            }),
        ),
        "display-object" | "display" | "display-mode" => (
            "display-object",
            package.semantic.display_object_count,
            package
                .semantic
                .display_objects
                .iter()
                .map(display_object_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_object_roots.len()
            }),
        ),
        "display-capability" | "display-cap" => (
            "display-capability",
            package.semantic.display_capability_count,
            package
                .semantic
                .display_capabilities
                .iter()
                .map(display_capability_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_capability_roots.len()
            }),
        ),
        "framebuffer-window-lease" | "fb-window-lease" | "display-lease" => (
            "framebuffer-window-lease",
            package.semantic.framebuffer_window_lease_count,
            package
                .semantic
                .framebuffer_window_leases
                .iter()
                .map(framebuffer_window_lease_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_window_lease_roots.len()
            }),
        ),
        "framebuffer-mapping" | "fb-mapping" | "display-mapping" => (
            "framebuffer-mapping",
            package.semantic.framebuffer_mapping_count,
            package
                .semantic
                .framebuffer_mappings
                .iter()
                .map(framebuffer_mapping_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_mapping_roots.len()
            }),
        ),
        "framebuffer-write" | "fb-write" | "display-write" => (
            "framebuffer-write",
            package.semantic.framebuffer_write_count,
            package
                .semantic
                .framebuffer_writes
                .iter()
                .map(framebuffer_write_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_write_roots.len()
            }),
        ),
        "framebuffer-flush-region" | "flush-region" | "display-flush" => (
            "framebuffer-flush-region",
            package.semantic.framebuffer_flush_region_count,
            package
                .semantic
                .framebuffer_flush_regions
                .iter()
                .map(framebuffer_flush_region_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_flush_region_roots.len()
            }),
        ),
        "framebuffer-dirty-region" | "dirty-region" | "display-dirty" => (
            "framebuffer-dirty-region",
            package.semantic.framebuffer_dirty_region_count,
            package
                .semantic
                .framebuffer_dirty_regions
                .iter()
                .map(framebuffer_dirty_region_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_dirty_region_roots.len()
            }),
        ),
        "display-event-log" | "display-log" => (
            "display-event-log",
            package.semantic.display_event_log_count,
            package
                .semantic
                .display_event_logs
                .iter()
                .map(display_event_log_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_event_log_roots.len()
            }),
        ),
        "display-cleanup" => (
            "display-cleanup",
            package.semantic.display_cleanup_count,
            package
                .semantic
                .display_cleanups
                .iter()
                .map(display_cleanup_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_cleanup_roots.len()
            }),
        ),
        "display-snapshot-barrier" | "display-snapshot" => (
            "display-snapshot-barrier",
            package.semantic.display_snapshot_barrier_count,
            package
                .semantic
                .display_snapshot_barriers
                .iter()
                .map(display_snapshot_barrier_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_snapshot_barrier_roots.len()
            }),
        ),
        "display-panic-last-frame" | "panic-last-frame" => (
            "display-panic-last-frame",
            package.semantic.display_panic_last_frame_count,
            package
                .semantic
                .display_panic_last_frames
                .iter()
                .map(display_panic_last_frame_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.display_panic_last_frame_roots.len()
            }),
        ),
        "framebuffer-benchmark" | "fb-benchmark" | "display-benchmark" => (
            "framebuffer-benchmark",
            package.semantic.framebuffer_benchmark_count,
            package
                .semantic
                .framebuffer_benchmarks
                .iter()
                .map(framebuffer_benchmark_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package.semantic.roots.framebuffer_benchmark_roots.len()
            }),
        ),
        "integrated-smp-preemption-cleanup"
        | "integrated-smp-cleanup"
        | "smp-preemption-cleanup" => (
            "integrated-smp-preemption-cleanup",
            package.semantic.integrated_smp_preemption_cleanup_count,
            package
                .semantic
                .integrated_smp_preemption_cleanups
                .iter()
                .map(integrated_smp_preemption_cleanup_view_v1)
                .collect::<Vec<_>>(),
            serde_json::json!({
                "root_count": package
                    .semantic
                    .roots
                    .integrated_smp_preemption_cleanup_roots
                    .len()
            }),
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
        "replay roots: harts={} tasks={} resources={} authorities={} stores={} caps={} target_stores={} target_caps={} boundaries={} artifacts={} activations={} executor_transitions={} target_artifacts={} code_objects={} activation_records={} traps={} hostcalls={} migration_objects={} smp_cleanup_quiescence={} smp_snapshot_barriers={} smp_stress_runs={} smp_scaling_benchmarks={} devices={} queues={} descriptors={} dma_buffers={} mmio_regions={} irq_lines={} irq_events={} device_capabilities={} driver_store_bindings={} io_waits={} io_cleanups={} io_fault_injections={} io_validation_reports={} packet_devices={} packet_buffers={} packet_queues={} packet_descriptors={} fake_net_backends={} virtio_net_backends={} network_tx_completions={} network_stack_adapters={} socket_objects={} endpoint_objects={} socket_operations={} socket_waits={} network_backpressures={} network_driver_cleanups={} network_generation_audits={} network_fault_injections={} network_benchmarks={} network_recovery_benchmarks={} block_devices={} block_ranges={} block_requests={} block_completions={} block_waits={} fake_block_backends={} virtio_blk_backends={} block_read_paths={} block_write_paths={} block_request_queues={} block_dma_buffers={} block_page_objects={} buffer_cache_objects={} file_objects={} directory_objects={} fat_adapter_objects={} ext4_adapter_objects={} file_handle_capabilities={} fs_waits={} block_driver_cleanups={} block_recovery_benchmarks={} target_feature_sets={} substrate_events={} command_results={} interface_events={} event_tail={}",
        package.semantic.roots.hart_roots.len(),
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
        package.semantic.roots.smp_cleanup_quiescence_roots.len(),
        package.semantic.roots.smp_snapshot_barrier_roots.len(),
        package.semantic.roots.smp_stress_run_roots.len(),
        package.semantic.roots.smp_scaling_benchmark_roots.len(),
        package.semantic.roots.device_object_roots.len(),
        package.semantic.roots.queue_object_roots.len(),
        package.semantic.roots.descriptor_object_roots.len(),
        package.semantic.roots.dma_buffer_object_roots.len(),
        package.semantic.roots.mmio_region_object_roots.len(),
        package.semantic.roots.irq_line_object_roots.len(),
        package.semantic.roots.irq_event_roots.len(),
        package.semantic.roots.device_capability_roots.len(),
        package.semantic.roots.driver_store_binding_roots.len(),
        package.semantic.roots.io_wait_roots.len(),
        package.semantic.roots.io_cleanup_roots.len(),
        package.semantic.roots.io_fault_injection_roots.len(),
        package.semantic.roots.io_validation_report_roots.len(),
        package.semantic.roots.packet_device_object_roots.len(),
        package.semantic.roots.packet_buffer_object_roots.len(),
        package.semantic.roots.packet_queue_object_roots.len(),
        package.semantic.roots.packet_descriptor_object_roots.len(),
        package.semantic.roots.fake_net_backend_object_roots.len(),
        package.semantic.roots.virtio_net_backend_object_roots.len(),
        package.semantic.roots.network_tx_completion_roots.len(),
        package.semantic.roots.network_stack_adapter_roots.len(),
        package.semantic.roots.socket_object_roots.len(),
        package.semantic.roots.endpoint_object_roots.len(),
        package.semantic.roots.socket_operation_roots.len(),
        package.semantic.roots.socket_wait_roots.len(),
        package.semantic.roots.network_backpressure_roots.len(),
        package.semantic.roots.network_driver_cleanup_roots.len(),
        package.semantic.roots.network_generation_audit_roots.len(),
        package.semantic.roots.network_fault_injection_roots.len(),
        package.semantic.roots.network_benchmark_roots.len(),
        package
            .semantic
            .roots
            .network_recovery_benchmark_roots
            .len(),
        package.semantic.roots.block_device_object_roots.len(),
        package.semantic.roots.block_range_object_roots.len(),
        package.semantic.roots.block_request_object_roots.len(),
        package.semantic.roots.block_completion_object_roots.len(),
        package.semantic.roots.block_wait_roots.len(),
        package.semantic.roots.fake_block_backend_object_roots.len(),
        package.semantic.roots.virtio_blk_backend_object_roots.len(),
        package.semantic.roots.block_read_path_roots.len(),
        package.semantic.roots.block_write_path_roots.len(),
        package.semantic.roots.block_request_queue_roots.len(),
        package.semantic.roots.block_dma_buffer_roots.len(),
        package.semantic.roots.block_page_object_roots.len(),
        package.semantic.roots.buffer_cache_object_roots.len(),
        package.semantic.roots.file_object_roots.len(),
        package.semantic.roots.directory_object_roots.len(),
        package.semantic.roots.fat_adapter_object_roots.len(),
        package.semantic.roots.ext4_adapter_object_roots.len(),
        package.semantic.roots.file_handle_capability_roots.len(),
        package.semantic.roots.fs_wait_roots.len(),
        package.semantic.roots.block_driver_cleanup_roots.len(),
        package.semantic.roots.block_recovery_benchmark_roots.len(),
        package.semantic.roots.target_feature_set_roots.len(),
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
    for quiescence in &package.semantic.roots.smp_cleanup_quiescence_roots {
        println!("replay smp-cleanup-quiescence {quiescence}");
    }
    for barrier in &package.semantic.roots.smp_snapshot_barrier_roots {
        println!("replay smp-snapshot-barrier {barrier}");
    }
    for run in &package.semantic.roots.smp_stress_run_roots {
        println!("replay smp-stress-run {run}");
    }
    for benchmark in &package.semantic.roots.smp_scaling_benchmark_roots {
        println!("replay smp-scaling-benchmark {benchmark}");
    }
    for integrated in &package
        .semantic
        .roots
        .integrated_smp_preemption_cleanup_roots
    {
        println!("replay integrated-smp-preemption-cleanup {integrated}");
    }
    for device in &package.semantic.roots.device_object_roots {
        println!("replay device {device}");
    }
    for queue in &package.semantic.roots.queue_object_roots {
        println!("replay queue {queue}");
    }
    for descriptor in &package.semantic.roots.descriptor_object_roots {
        println!("replay descriptor {descriptor}");
    }
    for dma_buffer in &package.semantic.roots.dma_buffer_object_roots {
        println!("replay dma-buffer {dma_buffer}");
    }
    for mmio_region in &package.semantic.roots.mmio_region_object_roots {
        println!("replay mmio-region {mmio_region}");
    }
    for irq_line in &package.semantic.roots.irq_line_object_roots {
        println!("replay irq-line {irq_line}");
    }
    for irq_event in &package.semantic.roots.irq_event_roots {
        println!("replay irq-event {irq_event}");
    }
    for device_capability in &package.semantic.roots.device_capability_roots {
        println!("replay device-capability {device_capability}");
    }
    for binding in &package.semantic.roots.driver_store_binding_roots {
        println!("replay driver-store-binding {binding}");
    }
    for io_wait in &package.semantic.roots.io_wait_roots {
        println!("replay io-wait {io_wait}");
    }
    for cleanup in &package.semantic.roots.io_cleanup_roots {
        println!("replay io-cleanup {cleanup}");
    }
    for fault in &package.semantic.roots.io_fault_injection_roots {
        println!("replay io-fault-injection {fault}");
    }
    for report in &package.semantic.roots.io_validation_report_roots {
        println!("replay io-validation-report {report}");
    }
    for packet_device in &package.semantic.roots.packet_device_object_roots {
        println!("replay packet-device {packet_device}");
    }
    for block_device in &package.semantic.roots.block_device_object_roots {
        println!("replay block-device {block_device}");
    }
    for block_range in &package.semantic.roots.block_range_object_roots {
        println!("replay block-range {block_range}");
    }
    for request in &package.semantic.roots.block_request_object_roots {
        println!("replay block-request {request}");
    }
    for completion in &package.semantic.roots.block_completion_object_roots {
        println!("replay block-completion {completion}");
    }
    for block_wait in &package.semantic.roots.block_wait_roots {
        println!("replay block-wait {block_wait}");
    }
    for backend in &package.semantic.roots.fake_block_backend_object_roots {
        println!("replay fake-block-backend {backend}");
    }
    for backend in &package.semantic.roots.virtio_blk_backend_object_roots {
        println!("replay virtio-blk-backend {backend}");
    }
    for path in &package.semantic.roots.block_read_path_roots {
        println!("replay block-read-path {path}");
    }
    for path in &package.semantic.roots.block_write_path_roots {
        println!("replay block-write-path {path}");
    }
    for queue in &package.semantic.roots.block_request_queue_roots {
        println!("replay block-request-queue {queue}");
    }
    for buffer in &package.semantic.roots.block_dma_buffer_roots {
        println!("replay block-dma-buffer {buffer}");
    }
    for page in &package.semantic.roots.block_page_object_roots {
        println!("replay block-page-object {page}");
    }
    for cache in &package.semantic.roots.buffer_cache_object_roots {
        println!("replay buffer-cache-object {cache}");
    }
    for file in &package.semantic.roots.file_object_roots {
        println!("replay file-object {file}");
    }
    for directory in &package.semantic.roots.directory_object_roots {
        println!("replay directory-object {directory}");
    }
    for adapter in &package.semantic.roots.fat_adapter_object_roots {
        println!("replay fat-adapter-object {adapter}");
    }
    for adapter in &package.semantic.roots.ext4_adapter_object_roots {
        println!("replay ext4-adapter-object {adapter}");
    }
    for capability in &package.semantic.roots.file_handle_capability_roots {
        println!("replay file-handle-capability {capability}");
    }
    for wait in &package.semantic.roots.fs_wait_roots {
        println!("replay fs-wait {wait}");
    }
    for cleanup in &package.semantic.roots.block_driver_cleanup_roots {
        println!("replay block-driver-cleanup {cleanup}");
    }
    for policy in &package.semantic.roots.block_pending_io_policy_roots {
        println!("replay block-pending-io-policy {policy}");
    }
    for audit in &package.semantic.roots.block_request_generation_audit_roots {
        println!("replay block-request-generation-audit {audit}");
    }
    for benchmark in &package.semantic.roots.block_benchmark_roots {
        println!("replay block-benchmark {benchmark}");
    }
    for benchmark in &package.semantic.roots.block_recovery_benchmark_roots {
        println!("replay block-recovery-benchmark {benchmark}");
    }
    for feature in &package.semantic.roots.target_feature_set_roots {
        println!("replay target-feature-set {feature}");
    }
    for packet_buffer in &package.semantic.roots.packet_buffer_object_roots {
        println!("replay packet-buffer {packet_buffer}");
    }
    for packet_queue in &package.semantic.roots.packet_queue_object_roots {
        println!("replay packet-queue {packet_queue}");
    }
    for packet_descriptor in &package.semantic.roots.packet_descriptor_object_roots {
        println!("replay packet-descriptor {packet_descriptor}");
    }
    for backend in &package.semantic.roots.fake_net_backend_object_roots {
        println!("replay fake-net-backend {backend}");
    }
    for backend in &package.semantic.roots.virtio_net_backend_object_roots {
        println!("replay virtio-net-backend {backend}");
    }
    for rx in &package.semantic.roots.network_rx_interrupt_roots {
        println!("replay network-rx-interrupt {rx}");
    }
    for resolution in &package.semantic.roots.network_rx_wait_resolution_roots {
        println!("replay network-rx-wait-resolution {resolution}");
    }
    for gate in &package.semantic.roots.network_tx_capability_gate_roots {
        println!("replay network-tx-capability-gate {gate}");
    }
    for completion in &package.semantic.roots.network_tx_completion_roots {
        println!("replay network-tx-completion {completion}");
    }
    for adapter in &package.semantic.roots.network_stack_adapter_roots {
        println!("replay network-stack-adapter {adapter}");
    }
    for socket in &package.semantic.roots.socket_object_roots {
        println!("replay socket-object {socket}");
    }
    for endpoint in &package.semantic.roots.endpoint_object_roots {
        println!("replay endpoint-object {endpoint}");
    }
    for operation in &package.semantic.roots.socket_operation_roots {
        println!("replay socket-operation {operation}");
    }
    for wait in &package.semantic.roots.socket_wait_roots {
        println!("replay socket-wait {wait}");
    }
    for backpressure in &package.semantic.roots.network_backpressure_roots {
        println!("replay network-backpressure {backpressure}");
    }
    for cleanup in &package.semantic.roots.network_driver_cleanup_roots {
        println!("replay network-driver-cleanup {cleanup}");
    }
    for audit in &package.semantic.roots.network_generation_audit_roots {
        println!("replay network-generation-audit {audit}");
    }
    for injection in &package.semantic.roots.network_fault_injection_roots {
        println!("replay network-fault-injection {injection}");
    }
    for benchmark in &package.semantic.roots.network_benchmark_roots {
        println!("replay network-benchmark {benchmark}");
    }
    for benchmark in &package.semantic.roots.network_recovery_benchmark_roots {
        println!("replay network-recovery-benchmark {benchmark}");
    }
    Ok(())
}

fn print_replay_json(
    cursor: u64,
    package: &MigrationPackageManifest,
) -> Result<(), Box<dyn Error>> {
    let mut roots = serde_json::Map::new();
    roots.insert(
        "tasks".to_owned(),
        serde_json::json!(package.semantic.roots.task_roots.len()),
    );
    roots.insert(
        "timer_interrupts".to_owned(),
        serde_json::json!(package.semantic.roots.timer_interrupt_roots.len()),
    );
    roots.insert(
        "ipi_events".to_owned(),
        serde_json::json!(package.semantic.roots.ipi_event_roots.len()),
    );
    roots.insert(
        "remote_preempts".to_owned(),
        serde_json::json!(package.semantic.roots.remote_preempt_roots.len()),
    );
    roots.insert(
        "remote_parks".to_owned(),
        serde_json::json!(package.semantic.roots.remote_park_roots.len()),
    );
    roots.insert(
        "cross_hart_scheduler_decisions".to_owned(),
        serde_json::json!(
            package
                .semantic
                .roots
                .cross_hart_scheduler_decision_roots
                .len()
        ),
    );
    roots.insert(
        "activation_migrations".to_owned(),
        serde_json::json!(package.semantic.roots.activation_migration_roots.len()),
    );
    roots.insert(
        "smp_safe_points".to_owned(),
        serde_json::json!(package.semantic.roots.smp_safe_point_roots.len()),
    );
    roots.insert(
        "stop_the_world_rendezvous".to_owned(),
        serde_json::json!(package.semantic.roots.stop_the_world_rendezvous_roots.len()),
    );
    roots.insert(
        "smp_code_publish_barriers".to_owned(),
        serde_json::json!(package.semantic.roots.smp_code_publish_barrier_roots.len()),
    );
    roots.insert(
        "smp_cleanup_quiescence".to_owned(),
        serde_json::json!(package.semantic.roots.smp_cleanup_quiescence_roots.len()),
    );
    roots.insert(
        "smp_snapshot_barriers".to_owned(),
        serde_json::json!(package.semantic.roots.smp_snapshot_barrier_roots.len()),
    );
    roots.insert(
        "smp_stress_runs".to_owned(),
        serde_json::json!(package.semantic.roots.smp_stress_run_roots.len()),
    );
    roots.insert(
        "smp_scaling_benchmarks".to_owned(),
        serde_json::json!(package.semantic.roots.smp_scaling_benchmark_roots.len()),
    );
    roots.insert(
        "devices".to_owned(),
        serde_json::json!(package.semantic.roots.device_object_roots.len()),
    );
    roots.insert(
        "queues".to_owned(),
        serde_json::json!(package.semantic.roots.queue_object_roots.len()),
    );
    roots.insert(
        "descriptors".to_owned(),
        serde_json::json!(package.semantic.roots.descriptor_object_roots.len()),
    );
    roots.insert(
        "dma_buffers".to_owned(),
        serde_json::json!(package.semantic.roots.dma_buffer_object_roots.len()),
    );
    roots.insert(
        "mmio_regions".to_owned(),
        serde_json::json!(package.semantic.roots.mmio_region_object_roots.len()),
    );
    roots.insert(
        "irq_lines".to_owned(),
        serde_json::json!(package.semantic.roots.irq_line_object_roots.len()),
    );
    roots.insert(
        "irq_events".to_owned(),
        serde_json::json!(package.semantic.roots.irq_event_roots.len()),
    );
    roots.insert(
        "device_capabilities".to_owned(),
        serde_json::json!(package.semantic.roots.device_capability_roots.len()),
    );
    roots.insert(
        "driver_store_bindings".to_owned(),
        serde_json::json!(package.semantic.roots.driver_store_binding_roots.len()),
    );
    roots.insert(
        "io_waits".to_owned(),
        serde_json::json!(package.semantic.roots.io_wait_roots.len()),
    );
    roots.insert(
        "io_cleanups".to_owned(),
        serde_json::json!(package.semantic.roots.io_cleanup_roots.len()),
    );
    roots.insert(
        "io_fault_injections".to_owned(),
        serde_json::json!(package.semantic.roots.io_fault_injection_roots.len()),
    );
    roots.insert(
        "io_validation_reports".to_owned(),
        serde_json::json!(package.semantic.roots.io_validation_report_roots.len()),
    );
    roots.insert(
        "packet_devices".to_owned(),
        serde_json::json!(package.semantic.roots.packet_device_object_roots.len()),
    );
    roots.insert(
        "packet_buffers".to_owned(),
        serde_json::json!(package.semantic.roots.packet_buffer_object_roots.len()),
    );
    roots.insert(
        "packet_queues".to_owned(),
        serde_json::json!(package.semantic.roots.packet_queue_object_roots.len()),
    );
    roots.insert(
        "packet_descriptors".to_owned(),
        serde_json::json!(package.semantic.roots.packet_descriptor_object_roots.len()),
    );
    roots.insert(
        "fake_net_backends".to_owned(),
        serde_json::json!(package.semantic.roots.fake_net_backend_object_roots.len()),
    );
    roots.insert(
        "virtio_net_backends".to_owned(),
        serde_json::json!(package.semantic.roots.virtio_net_backend_object_roots.len()),
    );
    roots.insert(
        "network_rx_interrupts".to_owned(),
        serde_json::json!(package.semantic.roots.network_rx_interrupt_roots.len()),
    );
    roots.insert(
        "network_rx_wait_resolutions".to_owned(),
        serde_json::json!(
            package
                .semantic
                .roots
                .network_rx_wait_resolution_roots
                .len()
        ),
    );
    roots.insert(
        "network_tx_capability_gates".to_owned(),
        serde_json::json!(
            package
                .semantic
                .roots
                .network_tx_capability_gate_roots
                .len()
        ),
    );
    roots.insert(
        "network_tx_completions".to_owned(),
        serde_json::json!(package.semantic.roots.network_tx_completion_roots.len()),
    );
    roots.insert(
        "network_stack_adapters".to_owned(),
        serde_json::json!(package.semantic.roots.network_stack_adapter_roots.len()),
    );
    roots.insert(
        "socket_objects".to_owned(),
        serde_json::json!(package.semantic.roots.socket_object_roots.len()),
    );
    roots.insert(
        "endpoint_objects".to_owned(),
        serde_json::json!(package.semantic.roots.endpoint_object_roots.len()),
    );
    roots.insert(
        "socket_operations".to_owned(),
        serde_json::json!(package.semantic.roots.socket_operation_roots.len()),
    );
    roots.insert(
        "socket_waits".to_owned(),
        serde_json::json!(package.semantic.roots.socket_wait_roots.len()),
    );
    roots.insert(
        "network_backpressures".to_owned(),
        serde_json::json!(package.semantic.roots.network_backpressure_roots.len()),
    );
    roots.insert(
        "network_driver_cleanups".to_owned(),
        serde_json::json!(package.semantic.roots.network_driver_cleanup_roots.len()),
    );
    roots.insert(
        "network_generation_audits".to_owned(),
        serde_json::json!(package.semantic.roots.network_generation_audit_roots.len()),
    );
    roots.insert(
        "network_fault_injections".to_owned(),
        serde_json::json!(package.semantic.roots.network_fault_injection_roots.len()),
    );
    roots.insert(
        "network_benchmarks".to_owned(),
        serde_json::json!(package.semantic.roots.network_benchmark_roots.len()),
    );
    roots.insert(
        "network_recovery_benchmarks".to_owned(),
        serde_json::json!(
            package
                .semantic
                .roots
                .network_recovery_benchmark_roots
                .len()
        ),
    );
    roots.insert(
        "block_devices".to_owned(),
        serde_json::json!(package.semantic.roots.block_device_object_roots.len()),
    );
    roots.insert(
        "block_ranges".to_owned(),
        serde_json::json!(package.semantic.roots.block_range_object_roots.len()),
    );
    roots.insert(
        "block_requests".to_owned(),
        serde_json::json!(package.semantic.roots.block_request_object_roots.len()),
    );
    roots.insert(
        "block_completions".to_owned(),
        serde_json::json!(package.semantic.roots.block_completion_object_roots.len()),
    );
    roots.insert(
        "block_waits".to_owned(),
        serde_json::json!(package.semantic.roots.block_wait_roots.len()),
    );
    roots.insert(
        "fake_block_backends".to_owned(),
        serde_json::json!(package.semantic.roots.fake_block_backend_object_roots.len()),
    );
    roots.insert(
        "virtio_blk_backends".to_owned(),
        serde_json::json!(package.semantic.roots.virtio_blk_backend_object_roots.len()),
    );
    roots.insert(
        "block_read_paths".to_owned(),
        serde_json::json!(package.semantic.roots.block_read_path_roots.len()),
    );
    roots.insert(
        "block_write_paths".to_owned(),
        serde_json::json!(package.semantic.roots.block_write_path_roots.len()),
    );
    roots.insert(
        "block_request_queues".to_owned(),
        serde_json::json!(package.semantic.roots.block_request_queue_roots.len()),
    );
    roots.insert(
        "block_dma_buffers".to_owned(),
        serde_json::json!(package.semantic.roots.block_dma_buffer_roots.len()),
    );
    roots.insert(
        "block_page_objects".to_owned(),
        serde_json::json!(package.semantic.roots.block_page_object_roots.len()),
    );
    roots.insert(
        "buffer_cache_objects".to_owned(),
        serde_json::json!(package.semantic.roots.buffer_cache_object_roots.len()),
    );
    roots.insert(
        "file_objects".to_owned(),
        serde_json::json!(package.semantic.roots.file_object_roots.len()),
    );
    roots.insert(
        "directory_objects".to_owned(),
        serde_json::json!(package.semantic.roots.directory_object_roots.len()),
    );
    roots.insert(
        "fat_adapter_objects".to_owned(),
        serde_json::json!(package.semantic.roots.fat_adapter_object_roots.len()),
    );
    roots.insert(
        "ext4_adapter_objects".to_owned(),
        serde_json::json!(package.semantic.roots.ext4_adapter_object_roots.len()),
    );
    roots.insert(
        "file_handle_capabilities".to_owned(),
        serde_json::json!(package.semantic.roots.file_handle_capability_roots.len()),
    );
    roots.insert(
        "fs_waits".to_owned(),
        serde_json::json!(package.semantic.roots.fs_wait_roots.len()),
    );
    roots.insert(
        "block_driver_cleanups".to_owned(),
        serde_json::json!(package.semantic.roots.block_driver_cleanup_roots.len()),
    );
    roots.insert(
        "block_pending_io_policies".to_owned(),
        serde_json::json!(package.semantic.roots.block_pending_io_policy_roots.len()),
    );
    roots.insert(
        "block_request_generation_audits".to_owned(),
        serde_json::json!(
            package
                .semantic
                .roots
                .block_request_generation_audit_roots
                .len()
        ),
    );
    roots.insert(
        "block_benchmarks".to_owned(),
        serde_json::json!(package.semantic.roots.block_benchmark_roots.len()),
    );
    roots.insert(
        "block_recovery_benchmarks".to_owned(),
        serde_json::json!(package.semantic.roots.block_recovery_benchmark_roots.len()),
    );
    roots.insert(
        "target_feature_sets".to_owned(),
        serde_json::json!(package.semantic.roots.target_feature_set_roots.len()),
    );
    roots.insert(
        "resources".to_owned(),
        serde_json::json!(package.semantic.roots.resource_roots.len()),
    );
    roots.insert(
        "authorities".to_owned(),
        serde_json::json!(package.semantic.roots.authority_roots.len()),
    );
    roots.insert(
        "stores".to_owned(),
        serde_json::json!(package.semantic.roots.store_roots.len()),
    );
    roots.insert(
        "capabilities".to_owned(),
        serde_json::json!(package.semantic.roots.capability_roots.len()),
    );
    roots.insert(
        "target_stores".to_owned(),
        serde_json::json!(package.semantic.roots.target_store_record_roots.len()),
    );
    roots.insert(
        "target_capabilities".to_owned(),
        serde_json::json!(package.semantic.roots.target_capability_record_roots.len()),
    );
    roots.insert(
        "boundaries".to_owned(),
        serde_json::json!(package.semantic.roots.boundary_roots.len()),
    );
    roots.insert(
        "artifacts".to_owned(),
        serde_json::json!(package.semantic.roots.artifact_verification_roots.len()),
    );
    roots.insert(
        "activations".to_owned(),
        serde_json::json!(package.semantic.roots.store_activation_roots.len()),
    );
    roots.insert(
        "executor_transitions".to_owned(),
        serde_json::json!(package.semantic.roots.executor_transition_roots.len()),
    );
    roots.insert(
        "target_artifacts".to_owned(),
        serde_json::json!(package.semantic.roots.target_artifact_roots.len()),
    );
    roots.insert(
        "code_objects".to_owned(),
        serde_json::json!(package.semantic.roots.code_object_roots.len()),
    );
    roots.insert(
        "activation_records".to_owned(),
        serde_json::json!(package.semantic.roots.activation_record_roots.len()),
    );
    roots.insert(
        "traps".to_owned(),
        serde_json::json!(package.semantic.roots.trap_roots.len()),
    );
    roots.insert(
        "hostcalls".to_owned(),
        serde_json::json!(package.semantic.roots.hostcall_trace_roots.len()),
    );
    roots.insert(
        "migration_objects".to_owned(),
        serde_json::json!(package.semantic.roots.migration_object_roots.len()),
    );
    roots.insert(
        "tombstones".to_owned(),
        serde_json::json!(package.semantic.roots.tombstone_roots.len()),
    );
    roots.insert(
        "contract_violations".to_owned(),
        serde_json::json!(package.semantic.roots.contract_violation_roots.len()),
    );
    roots.insert(
        "cleanup".to_owned(),
        serde_json::json!(package.semantic.roots.cleanup_roots.len()),
    );
    roots.insert(
        "activation_cleanup".to_owned(),
        serde_json::json!(package.semantic.roots.activation_cleanup_roots.len()),
    );
    roots.insert(
        "preemption_latency".to_owned(),
        serde_json::json!(package.semantic.roots.preemption_latency_roots.len()),
    );
    roots.insert(
        "hart_event_attribution".to_owned(),
        serde_json::json!(package.semantic.roots.hart_event_attribution_roots.len()),
    );
    roots.insert(
        "memory_policies".to_owned(),
        serde_json::json!(package.semantic.roots.memory_policy_roots.len()),
    );
    roots.insert(
        "snapshot_validation".to_owned(),
        serde_json::json!(package.semantic.roots.snapshot_validation_roots.len()),
    );
    roots.insert(
        "replay_validation".to_owned(),
        serde_json::json!(package.semantic.roots.replay_validation_roots.len()),
    );
    roots.insert(
        "substrate_events".to_owned(),
        serde_json::json!(package.semantic.roots.substrate_event_roots.len()),
    );
    roots.insert(
        "command_results".to_owned(),
        serde_json::json!(package.semantic.roots.command_result_roots.len()),
    );
    roots.insert(
        "interface_events".to_owned(),
        serde_json::json!(package.semantic.roots.interface_event_roots.len()),
    );
    roots.insert(
        "event_tail".to_owned(),
        serde_json::json!(package.semantic.roots.event_log_tail.len()),
    );
    roots.insert(
        "boundary_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.boundary_roots),
    );
    roots.insert(
        "artifact_verification_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.artifact_verification_roots),
    );
    roots.insert(
        "store_activation_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.store_activation_roots),
    );
    roots.insert(
        "executor_transition_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.executor_transition_roots),
    );
    roots.insert(
        "target_artifact_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.target_artifact_roots),
    );
    roots.insert(
        "target_store_record_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.target_store_record_roots),
    );
    roots.insert(
        "target_capability_record_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.target_capability_record_roots),
    );
    roots.insert(
        "code_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.code_object_roots),
    );
    roots.insert(
        "activation_record_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.activation_record_roots),
    );
    roots.insert(
        "trap_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.trap_roots),
    );
    roots.insert(
        "hostcall_trace_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.hostcall_trace_roots),
    );
    roots.insert(
        "migration_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.migration_object_roots),
    );
    roots.insert(
        "tombstone_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.tombstone_roots),
    );
    roots.insert(
        "contract_violation_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.contract_violation_roots),
    );
    roots.insert(
        "timer_interrupt_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.timer_interrupt_roots),
    );
    roots.insert(
        "ipi_event_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.ipi_event_roots),
    );
    roots.insert(
        "remote_preempt_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.remote_preempt_roots),
    );
    roots.insert(
        "remote_park_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.remote_park_roots),
    );
    roots.insert(
        "cross_hart_scheduler_decision_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.cross_hart_scheduler_decision_roots),
    );
    roots.insert(
        "activation_migration_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.activation_migration_roots),
    );
    roots.insert(
        "smp_safe_point_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_safe_point_roots),
    );
    roots.insert(
        "stop_the_world_rendezvous_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.stop_the_world_rendezvous_roots),
    );
    roots.insert(
        "smp_code_publish_barrier_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_code_publish_barrier_roots),
    );
    roots.insert(
        "smp_cleanup_quiescence_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_cleanup_quiescence_roots),
    );
    roots.insert(
        "smp_snapshot_barrier_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_snapshot_barrier_roots),
    );
    roots.insert(
        "smp_stress_run_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_stress_run_roots),
    );
    roots.insert(
        "smp_scaling_benchmark_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_scaling_benchmark_roots),
    );
    roots.insert(
        "device_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.device_object_roots),
    );
    roots.insert(
        "queue_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.queue_object_roots),
    );
    roots.insert(
        "descriptor_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.descriptor_object_roots),
    );
    roots.insert(
        "dma_buffer_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.dma_buffer_object_roots),
    );
    roots.insert(
        "mmio_region_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.mmio_region_object_roots),
    );
    roots.insert(
        "irq_line_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.irq_line_object_roots),
    );
    roots.insert(
        "irq_event_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.irq_event_roots),
    );
    roots.insert(
        "device_capability_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.device_capability_roots),
    );
    roots.insert(
        "driver_store_binding_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.driver_store_binding_roots),
    );
    roots.insert(
        "cleanup_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.cleanup_roots),
    );
    roots.insert(
        "activation_cleanup_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.activation_cleanup_roots),
    );
    roots.insert(
        "preemption_latency_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.preemption_latency_roots),
    );
    roots.insert(
        "hart_event_attribution_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.hart_event_attribution_roots),
    );
    roots.insert(
        "memory_policy_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.memory_policy_roots),
    );
    roots.insert(
        "snapshot_validation_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.snapshot_validation_roots),
    );
    roots.insert(
        "replay_validation_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.replay_validation_roots),
    );
    roots.insert(
        "substrate_event_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.substrate_event_roots),
    );
    roots.insert(
        "command_result_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.command_result_roots),
    );
    roots.insert(
        "interface_event_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.interface_event_roots),
    );
    roots.insert(
        "socket_operation_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.socket_operation_roots),
    );
    roots.insert(
        "socket_wait_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.socket_wait_roots),
    );
    roots.insert(
        "network_backpressure_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_backpressure_roots),
    );
    roots.insert(
        "network_driver_cleanup_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_driver_cleanup_roots),
    );
    roots.insert(
        "network_generation_audit_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_generation_audit_roots),
    );
    roots.insert(
        "network_fault_injection_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_fault_injection_roots),
    );
    roots.insert(
        "network_benchmark_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_benchmark_roots),
    );
    roots.insert(
        "network_recovery_benchmark_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_recovery_benchmark_roots),
    );
    roots.insert(
        "block_device_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_device_object_roots),
    );
    roots.insert(
        "block_range_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_range_object_roots),
    );
    roots.insert(
        "block_request_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_request_object_roots),
    );
    roots.insert(
        "block_completion_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_completion_object_roots),
    );
    roots.insert(
        "block_wait_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_wait_roots),
    );
    roots.insert(
        "fake_block_backend_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.fake_block_backend_object_roots),
    );
    roots.insert(
        "virtio_blk_backend_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.virtio_blk_backend_object_roots),
    );
    roots.insert(
        "block_read_path_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_read_path_roots),
    );
    roots.insert(
        "block_write_path_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_write_path_roots),
    );
    roots.insert(
        "block_request_queue_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_request_queue_roots),
    );
    roots.insert(
        "block_dma_buffer_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_dma_buffer_roots),
    );
    roots.insert(
        "block_page_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_page_object_roots),
    );
    roots.insert(
        "buffer_cache_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.buffer_cache_object_roots),
    );
    roots.insert(
        "file_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.file_object_roots),
    );
    roots.insert(
        "directory_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.directory_object_roots),
    );
    roots.insert(
        "fat_adapter_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.fat_adapter_object_roots),
    );
    roots.insert(
        "ext4_adapter_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.ext4_adapter_object_roots),
    );
    roots.insert(
        "file_handle_capability_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.file_handle_capability_roots),
    );
    roots.insert(
        "fs_wait_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.fs_wait_roots),
    );
    roots.insert(
        "block_driver_cleanup_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_driver_cleanup_roots),
    );
    roots.insert(
        "block_pending_io_policy_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_pending_io_policy_roots),
    );
    roots.insert(
        "block_request_generation_audit_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_request_generation_audit_roots),
    );
    roots.insert(
        "block_benchmark_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_benchmark_roots),
    );
    roots.insert(
        "block_recovery_benchmark_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_recovery_benchmark_roots),
    );
    roots.insert(
        "target_feature_set_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.target_feature_set_roots),
    );

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
        "roots": serde_json::Value::Object(roots)
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
        package
            .substrate_boundary
            .active_packet_device_authority_count,
        package
            .substrate_boundary
            .active_virtio_queue_authority_count,
        package.substrate_boundary.cow_epoch,
        package.substrate_boundary.background_copy_pages
    );
    print_roots("hart", &package.semantic.roots.hart_roots);
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
    print_roots("socket-wait", &package.semantic.roots.socket_wait_roots);
    print_roots(
        "network-backpressure",
        &package.semantic.roots.network_backpressure_roots,
    );
    print_roots(
        "network-driver-cleanup",
        &package.semantic.roots.network_driver_cleanup_roots,
    );
    print_roots(
        "fat-adapter-object",
        &package.semantic.roots.fat_adapter_object_roots,
    );
    print_roots(
        "ext4-adapter-object",
        &package.semantic.roots.ext4_adapter_object_roots,
    );
    print_roots(
        "file-handle-capability",
        &package.semantic.roots.file_handle_capability_roots,
    );
    print_roots("fs-wait", &package.semantic.roots.fs_wait_roots);
    print_roots(
        "block-driver-cleanup",
        &package.semantic.roots.block_driver_cleanup_roots,
    );
    print_roots(
        "block-pending-io-policy",
        &package.semantic.roots.block_pending_io_policy_roots,
    );
    print_roots(
        "block-request-generation-audit",
        &package.semantic.roots.block_request_generation_audit_roots,
    );
    print_roots(
        "block-benchmark",
        &package.semantic.roots.block_benchmark_roots,
    );
    print_roots(
        "block-recovery-benchmark",
        &package.semantic.roots.block_recovery_benchmark_roots,
    );
    print_roots(
        "target-feature-set",
        &package.semantic.roots.target_feature_set_roots,
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
            owner_task_generation: Some(3),
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
        assert_eq!(view["owner"]["task_generation"], 3);
        assert_eq!(view["owner"]["store_generation"], 1);
        assert_eq!(view["references"]["blockers"][0]["kind"], "capability");
        assert_eq!(view["cancel_reason"], "capability-revoked");
        assert_eq!(view["restart_policy"], "restart-if-allowed");
    }

    #[test]
    fn io_cleanup_view_v1_exposes_steps_effects_and_generations() {
        let view = io_cleanup_view_v1(&IoCleanupManifest {
            id: 47,
            driver_store: 1,
            driver_store_generation: 2,
            device: 35,
            device_generation: 1,
            driver_binding: 44,
            driver_binding_generation: 1,
            generation: 1,
            state: "completed".to_owned(),
            reason: "device-fault".to_owned(),
            started_at_event: 51,
            completed_at_event: 57,
            cancelled_io_waits: vec![ContractObjectRefManifest {
                kind: "io-wait".to_owned(),
                id: 46,
                generation: 1,
            }],
            revoked_device_capabilities: vec![ContractObjectRefManifest {
                kind: "device-capability".to_owned(),
                id: 42,
                generation: 1,
            }],
            revoked_capabilities: vec![ContractObjectRefManifest {
                kind: "capability".to_owned(),
                id: 7,
                generation: 1,
            }],
            released_dma_buffers: vec![ContractObjectRefManifest {
                kind: "dma-buffer-object".to_owned(),
                id: 38,
                generation: 1,
            }],
            released_mmio_regions: vec![ContractObjectRefManifest {
                kind: "mmio-region-object".to_owned(),
                id: 39,
                generation: 1,
            }],
            released_irq_lines: vec![ContractObjectRefManifest {
                kind: "irq-line-object".to_owned(),
                id: 40,
                generation: 1,
            }],
            steps: vec![artifact_manifest::IoCleanupStepManifest {
                kind: "cancel-io-waits".to_owned(),
                target: ContractObjectRefManifest {
                    kind: "store".to_owned(),
                    id: 1,
                    generation: 2,
                },
                observed_generation: 2,
                status: "done".to_owned(),
                event: Some(52),
            }],
            note: "io cleanup".to_owned(),
        });
        assert_eq!(view["kind"], "io-cleanup");
        assert_eq!(view["owner"]["driver_store"]["generation"], 2);
        assert_eq!(
            view["references"]["cancelled_io_waits"][0]["kind"],
            "io-wait"
        );
        assert_eq!(
            view["references"]["released_dma_buffers"][0]["generation"],
            1
        );
        assert_eq!(view["steps"][0]["kind"], "cancel-io-waits");
        assert_eq!(view["last_transition"]["completed_at_event"], 57);
    }

    #[test]
    fn io_fault_injection_view_v1_exposes_target_cleanup_and_generations() {
        let view = io_fault_injection_view_v1(&IoFaultInjectionManifest {
            id: 48,
            driver_store: 1,
            driver_store_generation: 2,
            device: 35,
            device_generation: 1,
            driver_binding: 44,
            driver_binding_generation: 1,
            target: ContractObjectRefManifest {
                kind: "irq-line-object".to_owned(),
                id: 40,
                generation: 1,
            },
            cleanup: 47,
            cleanup_generation: 1,
            generation: 1,
            kind: "device-fault".to_owned(),
            state: "completed".to_owned(),
            injected_at_event: 58,
            note: "io fault".to_owned(),
        });
        assert_eq!(view["kind"], "io-fault-injection");
        assert_eq!(view["owner"]["driver_store"]["generation"], 2);
        assert_eq!(view["references"]["target"]["kind"], "irq-line-object");
        assert_eq!(view["references"]["cleanup"]["id"], 47);
        assert_eq!(view["fault"]["kind"], "device-fault");
        assert_eq!(view["last_transition"]["injected_at_event"], 58);
    }

    #[test]
    fn io_validation_report_view_v1_exposes_counts_and_violations() {
        let view = io_validation_report_view_v1(&IoValidationReportManifest {
            id: 49,
            generation: 1,
            state: "failed".to_owned(),
            validated_at_event: 59,
            event_log_cursor: 58,
            observed_device_count: 1,
            observed_queue_count: 1,
            observed_descriptor_count: 1,
            observed_dma_buffer_count: 1,
            observed_mmio_region_count: 1,
            observed_irq_line_count: 1,
            observed_irq_event_count: 1,
            observed_device_capability_count: 1,
            observed_driver_binding_count: 1,
            observed_io_wait_count: 1,
            observed_io_cleanup_count: 1,
            observed_io_fault_injection_count: 1,
            violation_count: 1,
            violations: vec![artifact_manifest::IoValidationViolationManifest {
                code: "stale-generation".to_owned(),
                subject: ContractObjectRefManifest {
                    kind: "io-wait".to_owned(),
                    id: 41,
                    generation: 1,
                },
                relation: "io-wait->driver-binding".to_owned(),
                message: "bad generation".to_owned(),
            }],
            note: "io validator".to_owned(),
        });
        assert_eq!(view["kind"], "io-validation-report");
        assert_eq!(view["observed"]["devices"], 1);
        assert_eq!(view["observed"]["io_fault_injections"], 1);
        assert_eq!(view["validation"]["ok"], false);
        assert_eq!(view["validation"]["violation_count"], 1);
        assert_eq!(
            view["validation"]["violations"][0]["subject"]["kind"],
            "io-wait"
        );
        assert_eq!(view["last_transition"]["validated_at_event"], 59);
    }

    #[test]
    fn packet_device_view_v1_exposes_contract_and_device_generation() {
        let view = packet_device_object_view_v1(&PacketDeviceObjectManifest {
            id: 51,
            name: "net0".to_owned(),
            device: 17,
            device_generation: 2,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
            frame_format_version: 2,
            max_payload_len: 512,
            generation: 1,
            state: "registered".to_owned(),
            recorded_at_event: 60,
            note: "packet device".to_owned(),
        });
        assert_eq!(view["kind"], "packet-device");
        assert_eq!(view["owner"]["device"]["kind"], "device");
        assert_eq!(view["owner"]["device"]["generation"], 2);
        assert_eq!(view["contract"]["mtu"], 1500);
        assert_eq!(view["contract"]["rx_queue_depth"], 4);
        assert_eq!(view["contract"]["max_payload_len"], 512);
        assert_eq!(view["identity"]["mac"][5], 1);
        assert_eq!(view["last_transition"]["recorded_at_event"], 60);
    }

    #[test]
    fn packet_buffer_view_v1_exposes_contract_and_packet_device_generation() {
        let view = packet_buffer_object_view_v1(&PacketBufferObjectManifest {
            id: 52,
            packet_device: 51,
            packet_device_generation: 3,
            direction: "rx".to_owned(),
            frame_format_version: 2,
            capacity: 512,
            payload_len: 64,
            sequence: 9,
            generation: 1,
            state: "filled".to_owned(),
            recorded_at_event: 61,
            note: "packet buffer".to_owned(),
        });
        assert_eq!(view["kind"], "packet-buffer");
        assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
        assert_eq!(view["owner"]["packet_device"]["generation"], 3);
        assert_eq!(view["contract"]["direction"], "rx");
        assert_eq!(view["contract"]["capacity"], 512);
        assert_eq!(view["contract"]["payload_len"], 64);
        assert_eq!(view["contract"]["sequence"], 9);
        assert_eq!(view["last_transition"]["recorded_at_event"], 61);
    }

    #[test]
    fn packet_queue_view_v1_exposes_role_depth_and_packet_device_generation() {
        let view = packet_queue_object_view_v1(&PacketQueueObjectManifest {
            id: 53,
            name: "net0-rx0".to_owned(),
            packet_device: 51,
            packet_device_generation: 3,
            role: "rx".to_owned(),
            queue_index: 0,
            depth: 4,
            generation: 1,
            state: "registered".to_owned(),
            recorded_at_event: 62,
            note: "packet queue".to_owned(),
        });
        assert_eq!(view["kind"], "packet-queue");
        assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
        assert_eq!(view["owner"]["packet_device"]["generation"], 3);
        assert_eq!(view["identity"]["name"], "net0-rx0");
        assert_eq!(view["identity"]["role"], "rx");
        assert_eq!(view["identity"]["queue_index"], 0);
        assert_eq!(view["contract"]["depth"], 4);
        assert_eq!(view["last_transition"]["recorded_at_event"], 62);
    }

    #[test]
    fn packet_descriptor_view_v1_exposes_queue_buffer_and_length() {
        let view = packet_descriptor_object_view_v1(&PacketDescriptorObjectManifest {
            id: 54,
            packet_queue: 53,
            packet_queue_generation: 2,
            packet_buffer: 52,
            packet_buffer_generation: 3,
            slot: 1,
            length: 64,
            generation: 1,
            state: "registered".to_owned(),
            recorded_at_event: 63,
            note: "packet descriptor".to_owned(),
        });
        assert_eq!(view["kind"], "packet-descriptor");
        assert_eq!(view["owner"]["packet_queue"]["kind"], "packet-queue");
        assert_eq!(view["owner"]["packet_queue"]["generation"], 2);
        assert_eq!(view["owner"]["packet_buffer"]["kind"], "packet-buffer");
        assert_eq!(view["owner"]["packet_buffer"]["generation"], 3);
        assert_eq!(view["identity"]["slot"], 1);
        assert_eq!(view["contract"]["length"], 64);
        assert_eq!(view["last_transition"]["recorded_at_event"], 63);
    }

    #[test]
    fn fake_net_backend_view_v1_exposes_packet_device_and_profile_contract() {
        let view = fake_net_backend_object_view_v1(&FakeNetBackendObjectManifest {
            id: 55,
            name: "fake-net0".to_owned(),
            packet_device: 51,
            packet_device_generation: 4,
            provider: "service_core".to_owned(),
            profile: "fake-net-v1".to_owned(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 7,
            generation: 1,
            state: "bound".to_owned(),
            recorded_at_event: 64,
            note: "fake backend".to_owned(),
        });
        assert_eq!(view["kind"], "fake-net-backend");
        assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
        assert_eq!(view["owner"]["packet_device"]["generation"], 4);
        assert_eq!(view["identity"]["provider"], "service_core");
        assert_eq!(view["identity"]["profile"], "fake-net-v1");
        assert_eq!(view["contract"]["mtu"], 1500);
        assert_eq!(view["contract"]["mac"][5], 1);
        assert_eq!(view["last_transition"]["recorded_at_event"], 64);
    }

    #[test]
    fn virtio_net_backend_view_v1_exposes_driver_binding_and_profile_contract() {
        let view = virtio_net_backend_object_view_v1(&VirtioNetBackendObjectManifest {
            id: 56,
            name: "virtio-net0-backend".to_owned(),
            packet_device: 51,
            packet_device_generation: 4,
            driver_binding: 57,
            driver_binding_generation: 2,
            device: 50,
            device_generation: 4,
            provider: "substrate_virtio".to_owned(),
            profile: "virtio-net-backend-skeleton-v1".to_owned(),
            model: "virtio-net".to_owned(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            generation: 1,
            state: "skeleton-ready".to_owned(),
            recorded_at_event: 65,
            note: "virtio backend".to_owned(),
        });
        assert_eq!(view["kind"], "virtio-net-backend");
        assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
        assert_eq!(
            view["owner"]["driver_binding"]["kind"],
            "driver-store-binding"
        );
        assert_eq!(view["owner"]["driver_binding"]["generation"], 2);
        assert_eq!(view["identity"]["provider"], "substrate_virtio");
        assert_eq!(
            view["identity"]["profile"],
            "virtio-net-backend-skeleton-v1"
        );
        assert_eq!(view["contract"]["negotiated_features"], 32);
        assert_eq!(view["contract"]["queue_size"], 4);
        assert_eq!(view["last_transition"]["recorded_at_event"], 65);
    }

    #[test]
    fn network_rx_interrupt_view_v1_exposes_irq_and_rx_queue_generations() {
        let view = network_rx_interrupt_view_v1(&NetworkRxInterruptManifest {
            id: 58,
            virtio_net_backend: 56,
            virtio_net_backend_generation: 1,
            irq_event: 59,
            irq_event_generation: 2,
            packet_device: 51,
            packet_device_generation: 4,
            rx_queue: 53,
            rx_queue_generation: 3,
            ready_descriptors: 1,
            sequence: 9,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 66,
            note: "rx interrupt".to_owned(),
        });
        assert_eq!(view["kind"], "network-rx-interrupt");
        assert_eq!(
            view["owner"]["virtio_net_backend"]["kind"],
            "virtio-net-backend"
        );
        assert_eq!(view["owner"]["packet_device"]["generation"], 4);
        assert_eq!(view["references"]["irq_event"]["kind"], "irq-event");
        assert_eq!(view["references"]["irq_event"]["generation"], 2);
        assert_eq!(view["references"]["rx_queue"]["generation"], 3);
        assert_eq!(view["readiness"]["ready_descriptors"], 1);
        assert_eq!(view["readiness"]["sequence"], 9);
        assert_eq!(view["last_transition"]["recorded_at_event"], 66);
    }

    #[test]
    fn network_rx_wait_resolution_view_v1_exposes_wait_and_interrupt_generations() {
        let view = network_rx_wait_resolution_view_v1(&NetworkRxWaitResolutionManifest {
            id: 60,
            io_wait: 61,
            io_wait_generation: 2,
            wait: 62,
            wait_generation: 3,
            rx_interrupt: 58,
            rx_interrupt_generation: 1,
            irq_event: 59,
            irq_event_generation: 2,
            packet_device: 51,
            packet_device_generation: 4,
            rx_queue: 53,
            rx_queue_generation: 3,
            ready_descriptors: 1,
            sequence: 9,
            generation: 1,
            state: "resolved".to_owned(),
            resolved_at_event: 67,
            note: "rx wait resolution".to_owned(),
        });
        assert_eq!(view["kind"], "network-rx-wait-resolution");
        assert_eq!(view["owner"]["io_wait"]["kind"], "io-wait");
        assert_eq!(view["owner"]["io_wait"]["generation"], 2);
        assert_eq!(view["references"]["wait"]["kind"], "wait-token");
        assert_eq!(view["references"]["wait"]["generation"], 3);
        assert_eq!(
            view["references"]["rx_interrupt"]["kind"],
            "network-rx-interrupt"
        );
        assert_eq!(view["references"]["rx_queue"]["generation"], 3);
        assert_eq!(view["readiness"]["sequence"], 9);
        assert_eq!(view["last_transition"]["resolved_at_event"], 67);
    }

    #[test]
    fn network_tx_capability_gate_view_v1_exposes_capability_and_descriptor_generations() {
        let view = network_tx_capability_gate_view_v1(&NetworkTxCapabilityGateManifest {
            id: 68,
            driver_store: 7,
            driver_store_generation: 2,
            packet_device: 51,
            packet_device_generation: 4,
            tx_queue: 53,
            tx_queue_generation: 3,
            packet_descriptor: 54,
            packet_descriptor_generation: 2,
            packet_buffer: 52,
            packet_buffer_generation: 3,
            device_capability: 69,
            device_capability_generation: 1,
            capability: 70,
            capability_generation: 5,
            handle_slot: 4,
            handle_generation: 5,
            handle_tag: 99,
            operation: "tx".to_owned(),
            byte_len: 64,
            sequence: 9,
            generation: 1,
            state: "allowed".to_owned(),
            recorded_at_event: 68,
            note: "tx gate".to_owned(),
        });
        assert_eq!(view["kind"], "network-tx-capability-gate");
        assert_eq!(view["owner"]["driver_store"]["kind"], "store");
        assert_eq!(view["owner"]["driver_store"]["generation"], 2);
        assert_eq!(
            view["references"]["packet_descriptor"]["kind"],
            "packet-descriptor"
        );
        assert_eq!(view["references"]["packet_descriptor"]["generation"], 2);
        assert_eq!(
            view["references"]["device_capability"]["kind"],
            "device-capability"
        );
        assert_eq!(view["references"]["capability"]["generation"], 5);
        assert_eq!(view["authority"]["operation"], "tx");
        assert_eq!(view["authority"]["handle_slot"], 4);
        assert_eq!(view["tx"]["byte_len"], 64);
        assert_eq!(view["last_transition"]["recorded_at_event"], 68);
    }

    #[test]
    fn network_tx_completion_view_v1_exposes_gate_backend_and_descriptor_generations() {
        let view = network_tx_completion_view_v1(&NetworkTxCompletionManifest {
            id: 71,
            tx_gate: 68,
            tx_gate_generation: 2,
            backend_kind: "virtio-net-backend-object".to_owned(),
            backend: 72,
            backend_generation: 3,
            driver_store: 7,
            driver_store_generation: 4,
            packet_device: 51,
            packet_device_generation: 5,
            tx_queue: 53,
            tx_queue_generation: 6,
            packet_descriptor: 54,
            packet_descriptor_generation: 7,
            packet_buffer: 52,
            packet_buffer_generation: 8,
            byte_len: 64,
            sequence: 9,
            completion_sequence: 10,
            generation: 1,
            state: "completed".to_owned(),
            completed_at_event: 73,
            note: "tx completion".to_owned(),
        });
        assert_eq!(view["kind"], "network-tx-completion");
        assert_eq!(view["owner"]["backend"]["kind"], "virtio-net-backend");
        assert_eq!(view["owner"]["backend"]["generation"], 3);
        assert_eq!(
            view["references"]["tx_gate"]["kind"],
            "network-tx-capability-gate"
        );
        assert_eq!(view["references"]["tx_gate"]["generation"], 2);
        assert_eq!(
            view["references"]["packet_descriptor"]["kind"],
            "packet-descriptor"
        );
        assert_eq!(view["references"]["packet_descriptor"]["generation"], 7);
        assert_eq!(view["references"]["packet_buffer"]["generation"], 8);
        assert_eq!(view["tx"]["completion_sequence"], 10);
        assert_eq!(view["last_transition"]["completed_at_event"], 73);
    }

    #[test]
    fn network_stack_adapter_view_v1_exposes_smoltcp_profile_and_queue_generations() {
        let view = network_stack_adapter_view_v1(&NetworkStackAdapterManifest {
            id: 74,
            implementation: "smoltcp".to_owned(),
            implementation_version: "0.13.0".to_owned(),
            profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_owned(),
            medium: "ethernet".to_owned(),
            backend_kind: "virtio-net-backend-object".to_owned(),
            backend: 72,
            backend_generation: 3,
            packet_device: 51,
            packet_device_generation: 5,
            rx_queue: 53,
            rx_queue_generation: 6,
            tx_queue: 54,
            tx_queue_generation: 7,
            mac: [2, 0x76, 0x6d, 0x6f, 0x73, 1],
            ipv4_addr: [10, 0, 2, 15],
            ipv4_prefix_len: 24,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            max_payload_len: 512,
            socket_capacity: 0,
            generation: 1,
            state: "bound".to_owned(),
            recorded_at_event: 75,
            note: "smoltcp adapter".to_owned(),
        });
        assert_eq!(view["kind"], "network-stack-adapter");
        assert_eq!(view["owner"]["backend"]["kind"], "virtio-net-backend");
        assert_eq!(view["owner"]["backend"]["generation"], 3);
        assert_eq!(view["references"]["packet_device"]["generation"], 5);
        assert_eq!(view["references"]["rx_queue"]["generation"], 6);
        assert_eq!(view["references"]["tx_queue"]["generation"], 7);
        assert_eq!(view["adapter"]["implementation"], "smoltcp");
        assert_eq!(view["adapter"]["socket_capacity"], 0);
        assert_eq!(view["network"]["ipv4_prefix_len"], 24);
        assert_eq!(view["last_transition"]["recorded_at_event"], 75);
    }

    #[test]
    fn socket_object_view_v1_exposes_adapter_store_and_socket_contract() {
        let view = socket_object_view_v1(&SocketObjectManifest {
            id: 76,
            adapter: 74,
            adapter_generation: 1,
            owner_store: 7,
            owner_store_generation: 3,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            canonical_protocol: 6,
            family: "inet".to_owned(),
            transport: "tcp".to_owned(),
            generation: 1,
            state: "created".to_owned(),
            created_at_event: 77,
            note: "socket object".to_owned(),
        });
        assert_eq!(view["kind"], "socket-object");
        assert_eq!(view["owner"]["store"]["kind"], "store");
        assert_eq!(view["owner"]["store"]["generation"], 3);
        assert_eq!(
            view["references"]["adapter"]["kind"],
            "network-stack-adapter"
        );
        assert_eq!(view["references"]["adapter"]["generation"], 1);
        assert_eq!(view["socket"]["domain"], 2);
        assert_eq!(view["socket"]["type"], 1);
        assert_eq!(view["socket"]["canonical_protocol"], 6);
        assert_eq!(view["socket"]["family"], "inet");
        assert_eq!(view["socket"]["transport"], "tcp");
        assert_eq!(view["last_transition"]["created_at_event"], 77);
    }

    #[test]
    fn endpoint_object_view_v1_exposes_socket_store_and_endpoint_contract() {
        let view = endpoint_object_view_v1(&EndpointObjectManifest {
            id: 78,
            socket: 76,
            socket_generation: 1,
            adapter: 74,
            adapter_generation: 1,
            owner_store: 7,
            owner_store_generation: 3,
            family: "inet".to_owned(),
            transport: "tcp".to_owned(),
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            generation: 1,
            state: "allocated".to_owned(),
            created_at_event: 79,
            note: "endpoint object".to_owned(),
        });
        assert_eq!(view["kind"], "endpoint-object");
        assert_eq!(view["owner"]["store"]["kind"], "store");
        assert_eq!(view["owner"]["store"]["generation"], 3);
        assert_eq!(view["owner"]["socket"]["kind"], "socket-object");
        assert_eq!(view["references"]["socket"]["generation"], 1);
        assert_eq!(
            view["references"]["adapter"]["kind"],
            "network-stack-adapter"
        );
        assert_eq!(view["endpoint"]["family"], "inet");
        assert_eq!(view["endpoint"]["transport"], "tcp");
        assert_eq!(view["endpoint"]["local_port"], 0);
        assert_eq!(view["endpoint"]["remote_port"], 0);
        assert_eq!(view["last_transition"]["created_at_event"], 79);
    }

    #[test]
    fn socket_operation_view_v1_exposes_endpoint_operation_and_generations() {
        let view = socket_operation_view_v1(&SocketOperationManifest {
            id: 80,
            endpoint: 78,
            endpoint_generation: 1,
            socket: 76,
            socket_generation: 2,
            adapter: 74,
            adapter_generation: 3,
            owner_store: 7,
            owner_store_generation: 4,
            operation: "connect".to_owned(),
            local_addr: [10, 0, 2, 15],
            local_port: 40000,
            remote_addr: [10, 0, 2, 2],
            remote_port: 80,
            backlog: 0,
            byte_len: 0,
            sequence: 2,
            generation: 1,
            state: "applied".to_owned(),
            recorded_at_event: 81,
            note: "socket operation".to_owned(),
        });
        assert_eq!(view["kind"], "socket-operation");
        assert_eq!(view["owner"]["endpoint"]["kind"], "endpoint-object");
        assert_eq!(view["owner"]["endpoint"]["generation"], 1);
        assert_eq!(view["references"]["socket"]["kind"], "socket-object");
        assert_eq!(view["references"]["socket"]["generation"], 2);
        assert_eq!(view["references"]["adapter"]["generation"], 3);
        assert_eq!(view["references"]["owner_store"]["generation"], 4);
        assert_eq!(view["operation"]["name"], "connect");
        assert_eq!(view["operation"]["sequence"], 2);
        assert_eq!(view["operation"]["local_port"], 40000);
        assert_eq!(view["operation"]["remote_port"], 80);
        assert_eq!(view["last_transition"]["recorded_at_event"], 81);
    }

    #[test]
    fn socket_wait_view_v1_exposes_wait_endpoint_and_readiness_generations() {
        let view = socket_wait_view_v1(&SocketWaitManifest {
            id: 82,
            wait: 900,
            wait_generation: 2,
            endpoint: 78,
            endpoint_generation: 3,
            socket: 76,
            socket_generation: 4,
            adapter: 74,
            adapter_generation: 5,
            owner_store: 7,
            owner_store_generation: 6,
            wait_kind: "socket-readable".to_owned(),
            blocker: ContractObjectRefManifest {
                kind: "endpoint-object".to_owned(),
                id: 78,
                generation: 3,
            },
            generation: 1,
            state: "resolved".to_owned(),
            created_at_event: 83,
            completed_at_event: Some(84),
            cancel_reason: None,
            ready_sequence: Some(9),
            byte_len: Some(19),
            note: "socket wait".to_owned(),
        });
        assert_eq!(view["kind"], "socket-wait");
        assert_eq!(view["owner"]["wait"]["kind"], "wait-token");
        assert_eq!(view["owner"]["wait"]["generation"], 2);
        assert_eq!(view["owner"]["endpoint"]["kind"], "endpoint-object");
        assert_eq!(view["owner"]["endpoint"]["generation"], 3);
        assert_eq!(view["references"]["socket"]["generation"], 4);
        assert_eq!(view["references"]["adapter"]["generation"], 5);
        assert_eq!(view["references"]["owner_store"]["generation"], 6);
        assert_eq!(view["references"]["blocker"]["kind"], "endpoint-object");
        assert_eq!(view["wait"]["kind"], "socket-readable");
        assert_eq!(view["wait"]["ready_sequence"], 9);
        assert_eq!(view["wait"]["byte_len"], 19);
        assert_eq!(view["last_transition"]["completed_at_event"], 84);
    }

    #[test]
    fn network_backpressure_view_v1_exposes_policy_refs_and_drops() {
        let view = network_backpressure_view_v1(&NetworkBackpressureManifest {
            id: 85,
            adapter: 74,
            adapter_generation: 5,
            packet_device: 51,
            packet_device_generation: 6,
            packet_queue: 53,
            packet_queue_generation: 7,
            endpoint: Some(76),
            endpoint_generation: Some(8),
            socket: Some(75),
            socket_generation: Some(9),
            owner_store: Some(7),
            owner_store_generation: Some(10),
            direction: "tx".to_owned(),
            reason: "queue-full".to_owned(),
            action: "reject-send".to_owned(),
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 11,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 86,
            note: "backpressure".to_owned(),
        });
        assert_eq!(view["kind"], "network-backpressure");
        assert_eq!(view["owner"]["adapter"]["kind"], "network-stack-adapter");
        assert_eq!(view["owner"]["adapter"]["generation"], 5);
        assert_eq!(view["references"]["packet_queue"]["generation"], 7);
        assert_eq!(view["references"]["endpoint"]["kind"], "endpoint-object");
        assert_eq!(view["references"]["socket"]["generation"], 9);
        assert_eq!(view["references"]["owner_store"]["generation"], 10);
        assert_eq!(view["policy"]["direction"], "tx");
        assert_eq!(view["policy"]["reason"], "queue-full");
        assert_eq!(view["policy"]["action"], "reject-send");
        assert_eq!(view["policy"]["queue_depth"], 4);
        assert_eq!(view["policy"]["dropped_packets"], 0);
        assert_eq!(view["last_transition"]["recorded_at_event"], 86);
    }

    #[test]
    fn network_driver_cleanup_view_v1_exposes_cleanup_effects_and_generations() {
        let view = network_driver_cleanup_view_v1(&NetworkDriverCleanupManifest {
            id: 87,
            io_cleanup: 70,
            io_cleanup_generation: 1,
            driver_store: 7,
            driver_store_generation: 3,
            device: 35,
            device_generation: 1,
            driver_binding: 44,
            driver_binding_generation: 2,
            packet_device: 51,
            packet_device_generation: 4,
            adapter: 74,
            adapter_generation: 5,
            backend: ContractObjectRefManifest {
                kind: "virtio-net-backend-object".to_owned(),
                id: 85,
                generation: 6,
            },
            cancelled_socket_waits: vec![ContractObjectRefManifest {
                kind: "socket-wait".to_owned(),
                id: 90,
                generation: 1,
            }],
            cancelled_wait_tokens: vec![ContractObjectRefManifest {
                kind: "wait-token".to_owned(),
                id: 91,
                generation: 1,
            }],
            revoked_packet_capabilities: vec![ContractObjectRefManifest {
                kind: "device-capability".to_owned(),
                id: 92,
                generation: 1,
            }],
            generation: 1,
            state: "completed".to_owned(),
            started_at_event: 88,
            completed_at_event: Some(89),
            reason: "device-fault".to_owned(),
            note: "network cleanup".to_owned(),
        });
        assert_eq!(view["kind"], "network-driver-cleanup");
        assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
        assert_eq!(view["owner"]["packet_device"]["generation"], 4);
        assert_eq!(view["references"]["io_cleanup"]["kind"], "io-cleanup");
        assert_eq!(view["references"]["driver_binding"]["generation"], 2);
        assert_eq!(
            view["references"]["backend"]["kind"],
            "virtio-net-backend-object"
        );
        assert_eq!(view["references"]["cancelled_socket_waits"][0]["id"], 90);
        assert_eq!(view["references"]["cancelled_wait_tokens"][0]["id"], 91);
        assert_eq!(
            view["references"]["revoked_packet_capabilities"][0]["id"],
            92
        );
        assert_eq!(view["cleanup"]["reason"], "device-fault");
        assert_eq!(view["cleanup"]["cancelled_socket_wait_count"], 1);
        assert_eq!(view["last_transition"]["completed_at_event"], 89);
    }

    #[test]
    fn network_generation_audit_view_v1_exposes_exact_generation_refs() {
        let view = network_generation_audit_view_v1(&NetworkGenerationAuditManifest {
            id: 93,
            adapter: 74,
            adapter_generation: 5,
            packet_device: 51,
            packet_device_generation: 4,
            packet_queue: 89,
            packet_queue_generation: 7,
            packet_descriptor: 90,
            packet_descriptor_generation: 8,
            packet_buffer: 91,
            packet_buffer_generation: 9,
            dma_buffer: ContractObjectRefManifest {
                kind: "dma-buffer-object".to_owned(),
                id: 92,
                generation: 10,
            },
            device_capability: ContractObjectRefManifest {
                kind: "device-capability".to_owned(),
                id: 94,
                generation: 11,
            },
            rejected_packet_generation_probes: 2,
            rejected_dma_generation_probes: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 95,
            note: "generation audit".to_owned(),
        });
        assert_eq!(view["kind"], "network-generation-audit");
        assert_eq!(view["owner"]["adapter"]["kind"], "network-stack-adapter");
        assert_eq!(view["owner"]["adapter"]["generation"], 5);
        assert_eq!(view["references"]["packet_descriptor"]["generation"], 8);
        assert_eq!(view["references"]["packet_buffer"]["generation"], 9);
        assert_eq!(
            view["references"]["dma_buffer"]["kind"],
            "dma-buffer-object"
        );
        assert_eq!(view["references"]["dma_buffer"]["generation"], 10);
        assert_eq!(
            view["references"]["device_capability"]["kind"],
            "device-capability"
        );
        assert_eq!(view["audit"]["rejected_packet_generation_probes"], 2);
        assert_eq!(view["audit"]["rejected_dma_generation_probes"], 1);
        assert_eq!(view["last_transition"]["recorded_at_event"], 95);
    }

    #[test]
    fn network_fault_injection_view_v1_exposes_packet_loss_and_error_evidence() {
        let view = network_fault_injection_view_v1(&NetworkFaultInjectionManifest {
            id: 96,
            adapter: 74,
            adapter_generation: 5,
            packet_device: 51,
            packet_device_generation: 4,
            packet_queue: 89,
            packet_queue_generation: 7,
            packet_descriptor: Some(90),
            packet_descriptor_generation: Some(8),
            packet_buffer: Some(91),
            packet_buffer_generation: Some(9),
            endpoint: Some(92),
            endpoint_generation: Some(10),
            socket: Some(93),
            socket_generation: Some(11),
            owner_store: Some(94),
            owner_store_generation: Some(12),
            direction: "tx".to_owned(),
            kind: "packet-error".to_owned(),
            effect: "report-error".to_owned(),
            injected_packets: 1,
            dropped_packets: 0,
            error_packets: 1,
            error_code: "injected-checksum-error".to_owned(),
            sequence: 18,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 97,
            note: "packet error injection".to_owned(),
        });
        assert_eq!(view["kind"], "network-fault-injection");
        assert_eq!(view["owner"]["adapter"]["kind"], "network-stack-adapter");
        assert_eq!(view["references"]["packet_queue"]["generation"], 7);
        assert_eq!(view["references"]["packet_descriptor"]["generation"], 8);
        assert_eq!(view["references"]["packet_buffer"]["generation"], 9);
        assert_eq!(view["references"]["endpoint"]["generation"], 10);
        assert_eq!(view["injection"]["kind"], "packet-error");
        assert_eq!(view["injection"]["effect"], "report-error");
        assert_eq!(view["injection"]["error_code"], "injected-checksum-error");
        assert_eq!(view["last_transition"]["recorded_at_event"], 97);
    }

    #[test]
    fn network_benchmark_view_v1_exposes_throughput_latency_metrics() {
        let view = network_benchmark_view_v1(&NetworkBenchmarkManifest {
            id: 98,
            scenario: "host-validation-network-throughput-latency".to_owned(),
            adapter: 74,
            adapter_generation: 5,
            packet_device: 51,
            packet_device_generation: 4,
            tx_queue: 89,
            tx_queue_generation: 7,
            rx_queue: 88,
            rx_queue_generation: 6,
            tx_completion: 99,
            tx_completion_generation: 1,
            rx_wait_resolution: 100,
            rx_wait_resolution_generation: 1,
            endpoint: 92,
            endpoint_generation: 10,
            socket: 93,
            socket_generation: 11,
            owner_store: 94,
            owner_store_generation: 12,
            backpressure: Some(96),
            backpressure_generation: Some(1),
            sample_packets: 3,
            sample_bytes: 6000,
            tx_completed_packets: 1,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 120_000,
            budget_nanos: 250_000,
            throughput_bytes_per_sec: 50_000_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 101,
            note: "network benchmark".to_owned(),
        });
        assert_eq!(view["kind"], "network-benchmark");
        assert_eq!(view["owner"]["adapter"]["generation"], 5);
        assert_eq!(
            view["references"]["tx_completion"]["kind"],
            "network-tx-completion"
        );
        assert_eq!(
            view["references"]["rx_wait_resolution"]["kind"],
            "network-rx-wait-resolution"
        );
        assert_eq!(view["references"]["backpressure"]["generation"], 1);
        assert_eq!(view["benchmark"]["sample_packets"], 3);
        assert_eq!(view["benchmark"]["throughput_bytes_per_sec"], 50_000_000);
        assert_eq!(view["benchmark"]["p99_latency_nanos"], 48_000);
        assert_eq!(view["last_transition"]["recorded_at_event"], 101);
    }

    #[test]
    fn network_recovery_benchmark_view_v1_exposes_recovery_metrics() {
        let view = network_recovery_benchmark_view_v1(&NetworkRecoveryBenchmarkManifest {
            id: 99,
            scenario: "host-validation-network-driver-recovery".to_owned(),
            cleanup: 100,
            cleanup_generation: 1,
            io_cleanup: 70,
            io_cleanup_generation: 2,
            adapter: 74,
            adapter_generation: 5,
            packet_device: 51,
            packet_device_generation: 4,
            backend: ContractObjectRefManifest {
                kind: "virtio-net-backend-object".to_owned(),
                id: 85,
                generation: 3,
            },
            driver_store: 7,
            driver_store_generation: 8,
            fault_injection: Some(102),
            fault_injection_generation: Some(1),
            recovery_start_event: 33,
            recovery_complete_event: 34,
            cancelled_socket_waits: 1,
            revoked_packet_capabilities: 1,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 103,
            note: "network recovery benchmark".to_owned(),
        });
        assert_eq!(view["kind"], "network-recovery-benchmark");
        assert_eq!(view["owner"]["driver_store"]["generation"], 8);
        assert_eq!(
            view["references"]["cleanup"]["kind"],
            "network-driver-cleanup"
        );
        assert_eq!(
            view["references"]["backend"]["kind"],
            "virtio-net-backend-object"
        );
        assert_eq!(
            view["references"]["fault_injection"]["kind"],
            "network-fault-injection"
        );
        assert_eq!(view["benchmark"]["recovery_nanos"], 90_000);
        assert_eq!(view["benchmark"]["within_budget"], true);
        assert_eq!(view["last_transition"]["recorded_at_event"], 103);
    }

    #[test]
    fn block_device_view_v1_exposes_device_and_sector_contract() {
        let view = block_device_object_view_v1(&BlockDeviceObjectManifest {
            id: 104,
            name: "blk0".to_owned(),
            device: 35,
            device_generation: 1,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            generation: 1,
            state: "registered".to_owned(),
            recorded_at_event: 104,
            note: "block device".to_owned(),
        });
        assert_eq!(view["kind"], "block-device");
        assert_eq!(view["owner"]["device"]["kind"], "device");
        assert_eq!(view["references"]["device"]["generation"], 1);
        assert_eq!(view["identity"]["name"], "blk0");
        assert_eq!(view["contract"]["sector_size"], 512);
        assert_eq!(view["contract"]["sector_count"], 4096);
        assert_eq!(view["contract"]["read_only"], false);
        assert_eq!(view["contract"]["max_transfer_sectors"], 128);
        assert_eq!(view["last_transition"]["recorded_at_event"], 104);
    }

    #[test]
    fn block_range_view_v1_exposes_sector_and_byte_ranges() {
        let view = block_range_object_view_v1(&BlockRangeObjectManifest {
            id: 105,
            block_device: 104,
            block_device_generation: 1,
            start_sector: 64,
            sector_count: 8,
            byte_offset: 32768,
            byte_len: 4096,
            generation: 1,
            state: "registered".to_owned(),
            recorded_at_event: 105,
            note: "block range".to_owned(),
        });
        assert_eq!(view["kind"], "block-range");
        assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
        assert_eq!(view["references"]["block_device"]["generation"], 1);
        assert_eq!(view["sector_range"]["start_sector"], 64);
        assert_eq!(view["sector_range"]["sector_count"], 8);
        assert_eq!(view["byte_range"]["byte_offset"], 32768);
        assert_eq!(view["byte_range"]["byte_len"], 4096);
        assert_eq!(view["last_transition"]["recorded_at_event"], 105);
    }

    #[test]
    fn block_request_view_v1_exposes_range_and_operation_contract() {
        let view = block_request_object_view_v1(&BlockRequestObjectManifest {
            id: 106,
            block_device: 104,
            block_device_generation: 1,
            block_range: 105,
            block_range_generation: 1,
            operation: "read".to_owned(),
            sequence: 1,
            byte_len: 4096,
            generation: 1,
            state: "submitted".to_owned(),
            recorded_at_event: 106,
            note: "block request".to_owned(),
        });
        assert_eq!(view["kind"], "block-request");
        assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
        assert_eq!(view["references"]["block_range"]["kind"], "block-range");
        assert_eq!(view["references"]["block_range"]["generation"], 1);
        assert_eq!(view["request"]["operation"], "read");
        assert_eq!(view["request"]["sequence"], 1);
        assert_eq!(view["request"]["byte_len"], 4096);
        assert_eq!(view["last_transition"]["recorded_at_event"], 106);
    }

    #[test]
    fn block_completion_view_v1_exposes_request_and_result_contract() {
        let view = block_completion_object_view_v1(&BlockCompletionObjectManifest {
            id: 107,
            block_request: 106,
            block_request_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            block_range: 105,
            block_range_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: "success".to_owned(),
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 107,
            note: "block completion".to_owned(),
        });
        assert_eq!(view["kind"], "block-completion");
        assert_eq!(view["owner"]["block_request"]["kind"], "block-request");
        assert_eq!(view["references"]["block_request"]["generation"], 1);
        assert_eq!(view["references"]["block_range"]["kind"], "block-range");
        assert_eq!(view["completion"]["sequence"], 1);
        assert_eq!(view["completion"]["completed_bytes"], 4096);
        assert_eq!(view["completion"]["status"], "success");
        assert_eq!(view["last_transition"]["recorded_at_event"], 107);
    }

    #[test]
    fn block_wait_view_v1_exposes_wait_token_and_completion_contract() {
        let view = block_wait_view_v1(&BlockWaitManifest {
            id: 108,
            wait: 109,
            wait_generation: 1,
            block_request: 106,
            block_request_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            block_range: 105,
            block_range_generation: 1,
            operation: "read".to_owned(),
            sequence: 1,
            byte_len: 4096,
            generation: 1,
            state: "resolved".to_owned(),
            created_at_event: 108,
            completed_at_event: Some(110),
            completion: Some(107),
            completion_generation: Some(1),
            cancel_reason: None,
            note: "block wait".to_owned(),
        });
        assert_eq!(view["kind"], "block-wait");
        assert_eq!(view["owner"]["wait"]["kind"], "wait-token");
        assert_eq!(view["references"]["block_request"]["generation"], 1);
        assert_eq!(view["references"]["completion"]["kind"], "block-completion");
        assert_eq!(view["wait"]["operation"], "read");
        assert_eq!(view["wait"]["sequence"], 1);
        assert_eq!(view["wait"]["byte_len"], 4096);
        assert_eq!(view["last_transition"]["completed_at_event"], 110);
    }

    #[test]
    fn fake_block_backend_view_v1_exposes_block_device_and_profile_contract() {
        let view = fake_block_backend_object_view_v1(&FakeBlockBackendObjectManifest {
            id: 111,
            name: "fake-block0".to_owned(),
            block_device: 104,
            block_device_generation: 1,
            provider: "service_core".to_owned(),
            profile: "fake-block-v1".to_owned(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            deterministic_seed: 0x766d_6f73_626c_6b31,
            generation: 1,
            state: "bound".to_owned(),
            recorded_at_event: 111,
            note: "fake block backend".to_owned(),
        });
        assert_eq!(view["kind"], "fake-block-backend");
        assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
        assert_eq!(view["owner"]["block_device"]["generation"], 1);
        assert_eq!(view["identity"]["provider"], "service_core");
        assert_eq!(view["identity"]["profile"], "fake-block-v1");
        assert_eq!(view["contract"]["sector_size"], 512);
        assert_eq!(view["contract"]["sector_count"], 4096);
        assert_eq!(view["contract"]["max_transfer_sectors"], 128);
        assert_eq!(view["last_transition"]["recorded_at_event"], 111);
    }

    #[test]
    fn virtio_blk_backend_view_v1_exposes_driver_binding_and_profile_contract() {
        let view = virtio_blk_backend_object_view_v1(&VirtioBlkBackendObjectManifest {
            id: 112,
            name: "virtio-blk0-backend".to_owned(),
            block_device: 104,
            block_device_generation: 1,
            driver_binding: 130,
            driver_binding_generation: 1,
            device: 35,
            device_generation: 1,
            provider: "substrate_virtio".to_owned(),
            profile: "virtio-blk-backend-skeleton-v1".to_owned(),
            model: "virtio-blk".to_owned(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 0x40,
            driver_features: 0x40,
            negotiated_features: 0x40,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            generation: 1,
            state: "skeleton-ready".to_owned(),
            recorded_at_event: 112,
            note: "virtio block backend".to_owned(),
        });
        assert_eq!(view["kind"], "virtio-blk-backend");
        assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
        assert_eq!(
            view["owner"]["driver_binding"]["kind"],
            "driver-store-binding"
        );
        assert_eq!(view["references"]["device"]["kind"], "device");
        assert_eq!(view["identity"]["provider"], "substrate_virtio");
        assert_eq!(
            view["identity"]["profile"],
            "virtio-blk-backend-skeleton-v1"
        );
        assert_eq!(view["identity"]["model"], "virtio-blk");
        assert_eq!(view["contract"]["sector_size"], 512);
        assert_eq!(view["contract"]["queue_size"], 8);
        assert_eq!(view["contract"]["irq_vector"], 6);
        assert_eq!(view["last_transition"]["recorded_at_event"], 112);
    }

    #[test]
    fn block_read_path_view_v1_exposes_backend_request_completion_and_digest() {
        let view = block_read_path_view_v1(&BlockReadPathManifest {
            id: 113,
            backend_kind: "fake-block-backend".to_owned(),
            backend: 111,
            backend_generation: 1,
            block_request: 106,
            block_request_generation: 1,
            block_completion: 107,
            block_completion_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            block_range: 105,
            block_range_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            data_digest: 0xfeed,
            generation: 1,
            state: "completed".to_owned(),
            recorded_at_event: 113,
            note: "block read path".to_owned(),
        });
        assert_eq!(view["kind"], "block-read-path");
        assert_eq!(view["owner"]["block_request"]["kind"], "block-request");
        assert_eq!(view["references"]["backend"]["kind"], "fake-block-backend");
        assert_eq!(
            view["references"]["block_completion"]["kind"],
            "block-completion"
        );
        assert_eq!(view["references"]["block_device"]["generation"], 1);
        assert_eq!(view["read"]["completed_bytes"], 4096);
        assert_eq!(view["read"]["data_digest"], 0xfeed);
        assert_eq!(view["last_transition"]["recorded_at_event"], 113);
    }

    #[test]
    fn block_write_path_view_v1_exposes_backend_request_completion_and_payload_digest() {
        let view = block_write_path_view_v1(&BlockWritePathManifest {
            id: 114,
            backend_kind: "fake-block-backend".to_owned(),
            backend: 111,
            backend_generation: 1,
            block_request: 106,
            block_request_generation: 1,
            block_completion: 107,
            block_completion_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            block_range: 105,
            block_range_generation: 1,
            sequence: 2,
            completed_bytes: 4096,
            payload_digest: 0xbeef,
            generation: 1,
            state: "completed".to_owned(),
            recorded_at_event: 114,
            note: "block write path".to_owned(),
        });
        assert_eq!(view["kind"], "block-write-path");
        assert_eq!(view["owner"]["block_request"]["kind"], "block-request");
        assert_eq!(view["references"]["backend"]["kind"], "fake-block-backend");
        assert_eq!(
            view["references"]["block_completion"]["kind"],
            "block-completion"
        );
        assert_eq!(view["references"]["block_device"]["generation"], 1);
        assert_eq!(view["write"]["completed_bytes"], 4096);
        assert_eq!(view["write"]["payload_digest"], 0xbeef);
        assert_eq!(view["last_transition"]["recorded_at_event"], 114);
    }

    #[test]
    fn block_request_queue_view_v1_exposes_entries_depth_and_generations() {
        let view = block_request_queue_view_v1(&BlockRequestQueueManifest {
            id: 115,
            backend_kind: "fake-block-backend-object".to_owned(),
            backend: 111,
            backend_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            depth: 4,
            entries: vec![
                artifact_manifest::BlockRequestQueueEntryManifest {
                    request: 106,
                    request_generation: 1,
                    completion: Some(107),
                    completion_generation: Some(1),
                    sequence: 1,
                    operation: "read".to_owned(),
                    byte_len: 4096,
                    state: "completed".to_owned(),
                },
                artifact_manifest::BlockRequestQueueEntryManifest {
                    request: 108,
                    request_generation: 1,
                    completion: None,
                    completion_generation: None,
                    sequence: 2,
                    operation: "write".to_owned(),
                    byte_len: 4096,
                    state: "pending".to_owned(),
                },
            ],
            pending_count: 1,
            completed_count: 1,
            first_sequence: 1,
            last_sequence: 2,
            generation: 1,
            state: "active".to_owned(),
            recorded_at_event: 115,
            note: "block request queue".to_owned(),
        });
        assert_eq!(view["kind"], "block-request-queue");
        assert_eq!(view["owner"]["backend"]["kind"], "fake-block-backend");
        assert_eq!(
            view["references"]["entries"][0]["request"]["kind"],
            "block-request"
        );
        assert_eq!(
            view["references"]["entries"][0]["completion"]["kind"],
            "block-completion"
        );
        assert_eq!(
            view["references"]["entries"][1]["completion"],
            serde_json::Value::Null
        );
        assert_eq!(view["queue"]["depth"], 4);
        assert_eq!(view["queue"]["pending_count"], 1);
        assert_eq!(view["queue"]["completed_count"], 1);
        assert_eq!(view["last_transition"]["recorded_at_event"], 115);
    }

    #[test]
    fn block_dma_buffer_view_v1_exposes_request_dma_and_buffer_contract() {
        let view = block_dma_buffer_view_v1(&BlockDmaBufferManifest {
            id: 116,
            backend_kind: "fake-block-backend-object".to_owned(),
            backend: 111,
            backend_generation: 1,
            block_request: 108,
            block_request_generation: 1,
            dma_buffer: 210,
            dma_buffer_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            block_range: 105,
            block_range_generation: 1,
            descriptor: 209,
            descriptor_generation: 1,
            queue: 208,
            queue_generation: 1,
            operation: "write".to_owned(),
            access: "read-write".to_owned(),
            byte_len: 4096,
            buffer_len: 4096,
            buffer_digest: 0xb10,
            generation: 1,
            state: "bound".to_owned(),
            recorded_at_event: 116,
            note: "block dma buffer".to_owned(),
        });
        assert_eq!(view["kind"], "block-dma-buffer");
        assert_eq!(view["owner"]["backend"]["kind"], "fake-block-backend");
        assert_eq!(view["owner"]["block_request"]["generation"], 1);
        assert_eq!(view["references"]["dma_buffer"]["kind"], "dma-buffer");
        assert_eq!(view["references"]["descriptor"]["id"], 209);
        assert_eq!(view["references"]["queue"]["generation"], 1);
        assert_eq!(view["buffer"]["operation"], "write");
        assert_eq!(view["buffer"]["buffer_digest"], 0xb10);
        assert_eq!(view["last_transition"]["dma_buffer_generation"], 1);
    }

    #[test]
    fn block_page_object_view_v1_exposes_page_and_block_dma_contract() {
        let view = block_page_object_view_v1(&BlockPageObjectManifest {
            id: 117,
            block_dma_buffer: 116,
            block_dma_buffer_generation: 1,
            block_request: 108,
            block_request_generation: 1,
            block_completion: 109,
            block_completion_generation: 1,
            dma_buffer: 210,
            dma_buffer_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            block_range: 105,
            block_range_generation: 1,
            aspace: ContractObjectRefManifest {
                kind: "guest-address-space".to_owned(),
                id: 301,
                generation: 1,
            },
            vma_region: ContractObjectRefManifest {
                kind: "vma-region".to_owned(),
                id: 302,
                generation: 1,
            },
            page: ContractObjectRefManifest {
                kind: "page-object".to_owned(),
                id: 303,
                generation: 1,
            },
            page_dirty_generation: 2,
            page_backing: "file-backed".to_owned(),
            cow_state: "none".to_owned(),
            page_state: "live".to_owned(),
            page_offset: 0,
            byte_len: 4096,
            operation: "write".to_owned(),
            generation: 1,
            state: "integrated".to_owned(),
            recorded_at_event: 117,
            note: "block page object".to_owned(),
        });
        assert_eq!(view["kind"], "block-page-object");
        assert_eq!(view["owner"]["page"]["kind"], "page-object");
        assert_eq!(
            view["owner"]["block_dma_buffer"]["kind"],
            "block-dma-buffer"
        );
        assert_eq!(view["references"]["aspace"]["id"], 301);
        assert_eq!(view["references"]["vma_region"]["generation"], 1);
        assert_eq!(view["references"]["block_completion"]["id"], 109);
        assert_eq!(view["page"]["dirty_generation"], 2);
        assert_eq!(view["page"]["backing"], "file-backed");
        assert_eq!(view["page"]["byte_len"], 4096);
        assert_eq!(view["last_transition"]["recorded_at_event"], 117);
    }

    #[test]
    fn buffer_cache_object_view_v1_exposes_page_and_block_range_contract() {
        let view = buffer_cache_object_view_v1(&BufferCacheObjectManifest {
            id: 118,
            block_page_object: 117,
            block_page_object_generation: 1,
            block_dma_buffer: 116,
            block_dma_buffer_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            block_range: 105,
            block_range_generation: 1,
            aspace: ContractObjectRefManifest {
                kind: "guest-address-space".to_owned(),
                id: 301,
                generation: 1,
            },
            vma_region: ContractObjectRefManifest {
                kind: "vma-region".to_owned(),
                id: 302,
                generation: 1,
            },
            page: ContractObjectRefManifest {
                kind: "page-object".to_owned(),
                id: 303,
                generation: 1,
            },
            page_dirty_generation: 2,
            page_offset: 0,
            block_offset: 0,
            byte_len: 4096,
            operation: "write".to_owned(),
            cache_state: "dirty".to_owned(),
            coherency_epoch: 7,
            generation: 1,
            state: "dirty".to_owned(),
            recorded_at_event: 118,
            note: "buffer cache object".to_owned(),
        });
        assert_eq!(view["kind"], "buffer-cache-object");
        assert_eq!(view["owner"]["page"]["kind"], "page-object");
        assert_eq!(view["owner"]["block_range"]["kind"], "block-range");
        assert_eq!(
            view["references"]["block_page_object"]["kind"],
            "block-page-object"
        );
        assert_eq!(view["references"]["block_dma_buffer"]["generation"], 1);
        assert_eq!(view["references"]["aspace"]["id"], 301);
        assert_eq!(view["cache"]["page_dirty_generation"], 2);
        assert_eq!(view["cache"]["cache_state"], "dirty");
        assert_eq!(view["cache"]["coherency_epoch"], 7);
        assert_eq!(view["last_transition"]["recorded_at_event"], 118);
    }

    #[test]
    fn file_object_view_v1_exposes_cache_file_and_page_contract() {
        let view = file_object_view_v1(&FileObjectManifest {
            id: 119,
            buffer_cache_object: 118,
            buffer_cache_object_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            block_range: 105,
            block_range_generation: 1,
            page: ContractObjectRefManifest {
                kind: "page-object".to_owned(),
                id: 303,
                generation: 1,
            },
            page_dirty_generation: 2,
            namespace: "rootfs".to_owned(),
            file_key: "demo-file".to_owned(),
            path: "/demo/file.txt".to_owned(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            cache_state: "dirty".to_owned(),
            generation: 1,
            state: "dirty".to_owned(),
            recorded_at_event: 119,
            note: "file object".to_owned(),
        });
        assert_eq!(view["kind"], "file-object");
        assert_eq!(view["owner"]["namespace"], "rootfs");
        assert_eq!(view["owner"]["file_key"], "demo-file");
        assert_eq!(
            view["references"]["buffer_cache_object"]["kind"],
            "buffer-cache-object"
        );
        assert_eq!(view["references"]["block_range"]["generation"], 1);
        assert_eq!(view["references"]["page"]["id"], 303);
        assert_eq!(view["file"]["content_digest"], 0xB13);
        assert_eq!(view["file"]["cache_state"], "dirty");
        assert_eq!(view["last_transition"]["recorded_at_event"], 119);
    }

    #[test]
    fn directory_object_view_v1_exposes_file_entry_contract() {
        let view = directory_object_view_v1(&DirectoryObjectManifest {
            id: 120,
            file_object: 119,
            file_object_generation: 1,
            namespace: "rootfs".to_owned(),
            directory_key: "demo-dir".to_owned(),
            directory_path: "/demo".to_owned(),
            entry_name: "file.txt".to_owned(),
            child_file_key: "demo-file".to_owned(),
            child_path: "/demo/file.txt".to_owned(),
            entry_kind: "file".to_owned(),
            file_size: 4096,
            content_digest: 0xB13,
            generation: 1,
            state: "cached".to_owned(),
            recorded_at_event: 120,
            note: "directory object".to_owned(),
        });
        assert_eq!(view["kind"], "directory-object");
        assert_eq!(view["owner"]["namespace"], "rootfs");
        assert_eq!(view["owner"]["directory_key"], "demo-dir");
        assert_eq!(view["owner"]["entry_name"], "file.txt");
        assert_eq!(view["references"]["file_object"]["kind"], "file-object");
        assert_eq!(view["references"]["file_object"]["id"], 119);
        assert_eq!(view["directory"]["entry_kind"], "file");
        assert_eq!(view["directory"]["child_path"], "/demo/file.txt");
        assert_eq!(view["directory"]["content_digest"], 0xB13);
        assert_eq!(view["last_transition"]["recorded_at_event"], 120);
    }

    #[test]
    fn fat_adapter_object_view_v1_exposes_read_write_adapter_contract() {
        let view = fat_adapter_object_view_v1(&FatAdapterObjectManifest {
            id: 121,
            directory_object: 120,
            directory_object_generation: 1,
            file_object: 119,
            file_object_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            implementation: "fatfs".to_owned(),
            version: "0.3.6".to_owned(),
            profile: "fatfs-read-write-demo-v1".to_owned(),
            volume_label: "VMOSFAT".to_owned(),
            image_bytes: 1_048_576,
            adapter_path: "DEMO.TXT".to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x1234,
            read_digest: 0x1234,
            file_content_digest: 0xB13,
            generation: 1,
            state: "verified".to_owned(),
            recorded_at_event: 121,
            note: "fat adapter object".to_owned(),
        });
        assert_eq!(view["kind"], "fat-adapter-object");
        assert_eq!(view["owner"]["implementation"], "fatfs");
        assert_eq!(view["owner"]["profile"], "fatfs-read-write-demo-v1");
        assert_eq!(
            view["references"]["directory_object"]["kind"],
            "directory-object"
        );
        assert_eq!(view["references"]["file_object"]["id"], 119);
        assert_eq!(view["references"]["block_device"]["generation"], 1);
        assert_eq!(view["fat"]["bytes_written"], 35);
        assert_eq!(view["fat"]["read_digest"], 0x1234);
        assert_eq!(view["fat"]["file_content_digest"], 0xB13);
        assert_eq!(view["last_transition"]["recorded_at_event"], 121);
    }

    #[test]
    fn ext4_adapter_object_view_v1_exposes_read_only_adapter_contract() {
        let view = ext4_adapter_object_view_v1(&Ext4AdapterObjectManifest {
            id: 122,
            directory_object: 120,
            directory_object_generation: 1,
            file_object: 119,
            file_object_generation: 1,
            block_device: 104,
            block_device_generation: 1,
            implementation: "ext4-view".to_owned(),
            version: "0.9.3".to_owned(),
            profile: "ext4-read-only-demo-v1".to_owned(),
            volume_label: "VMOSEXT4".to_owned(),
            image_bytes: 32 * 1024,
            adapter_path: "/demo.txt".to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_read: 34,
            read_digest: 0x6121,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: true,
            generation: 1,
            state: "verified".to_owned(),
            recorded_at_event: 122,
            note: "ext4 adapter object".to_owned(),
        });
        assert_eq!(view["kind"], "ext4-adapter-object");
        assert_eq!(view["owner"]["implementation"], "ext4-view");
        assert_eq!(view["owner"]["profile"], "ext4-read-only-demo-v1");
        assert_eq!(
            view["references"]["directory_object"]["kind"],
            "directory-object"
        );
        assert_eq!(view["references"]["file_object"]["id"], 119);
        assert_eq!(view["references"]["block_device"]["generation"], 1);
        assert_eq!(view["ext4"]["bytes_read"], 34);
        assert_eq!(view["ext4"]["read_digest"], 0x6121);
        assert_eq!(view["ext4"]["file_content_digest"], 0xB13);
        assert_eq!(view["ext4"]["directory_entries"], 1);
        assert_eq!(view["ext4"]["read_only_enforced"], true);
        assert_eq!(view["last_transition"]["recorded_at_event"], 122);
    }

    #[test]
    fn file_handle_capability_view_v1_exposes_file_and_capability_gate() {
        let view = file_handle_capability_view_v1(&FileHandleCapabilityManifest {
            id: 123,
            owner_store: 7,
            owner_store_generation: 3,
            file_object: 119,
            file_object_generation: 1,
            directory_object: 120,
            directory_object_generation: 1,
            capability: 44,
            capability_generation: 5,
            handle_slot: 9,
            handle_generation: 5,
            handle_tag: 0xFEED,
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            generation: 1,
            state: "allowed".to_owned(),
            recorded_at_event: 123,
            note: "file handle capability".to_owned(),
        });
        assert_eq!(view["kind"], "file-handle-capability");
        assert_eq!(view["owner"]["store"]["id"], 7);
        assert_eq!(view["owner"]["operation"], "read");
        assert_eq!(view["references"]["file_object"]["kind"], "file-object");
        assert_eq!(view["references"]["file_object"]["id"], 119);
        assert_eq!(view["references"]["directory_object"]["id"], 120);
        assert_eq!(view["references"]["capability"]["generation"], 5);
        assert_eq!(view["handle"]["slot"], 9);
        assert_eq!(view["handle"]["generation"], 5);
        assert_eq!(view["handle"]["tag"], 0xFEED);
        assert_eq!(view["file_access"]["byte_len"], 512);
        assert_eq!(view["file_access"]["content_digest"], 0xB13);
        assert_eq!(view["last_transition"]["recorded_at_event"], 123);
    }

    #[test]
    fn fs_wait_view_v1_exposes_file_handle_wait_contract() {
        let view = fs_wait_view_v1(&FsWaitManifest {
            id: 124,
            wait: 55,
            wait_generation: 1,
            owner_store: 7,
            owner_store_generation: 3,
            file_object: 119,
            file_object_generation: 1,
            directory_object: 120,
            directory_object_generation: 1,
            file_handle_capability: 123,
            file_handle_capability_generation: 1,
            operation: "read".to_owned(),
            blocker: ContractObjectRefManifest {
                kind: "file-handle-capability".to_owned(),
                id: 123,
                generation: 1,
            },
            sequence: 9,
            byte_len: 512,
            generation: 1,
            state: "cancelled".to_owned(),
            created_at_event: 124,
            completed_at_event: Some(125),
            cancel_reason: Some("close-fd".to_owned()),
            note: "fs wait".to_owned(),
        });
        assert_eq!(view["kind"], "fs-wait");
        assert_eq!(view["owner"]["store"]["id"], 7);
        assert_eq!(view["owner"]["operation"], "read");
        assert_eq!(view["references"]["wait"]["kind"], "wait-token");
        assert_eq!(
            view["references"]["file_handle_capability"]["kind"],
            "file-handle-capability"
        );
        assert_eq!(view["references"]["file_object"]["id"], 119);
        assert_eq!(view["references"]["blocker"]["id"], 123);
        assert_eq!(view["wait"]["sequence"], 9);
        assert_eq!(view["wait"]["cancel_reason"], "close-fd");
        assert_eq!(view["last_error"]["cancel_reason"], "close-fd");
        assert_eq!(view["last_transition"]["completed_at_event"], 125);
    }

    #[test]
    fn block_driver_cleanup_view_v1_exposes_cleanup_effects_and_generations() {
        let view = block_driver_cleanup_view_v1(&BlockDriverCleanupManifest {
            id: 126,
            io_cleanup: 44,
            io_cleanup_generation: 1,
            driver_store: 7,
            driver_store_generation: 3,
            device: 30,
            device_generation: 1,
            driver_binding: 33,
            driver_binding_generation: 1,
            block_device: 31,
            block_device_generation: 1,
            backend: ContractObjectRefManifest {
                kind: "virtio-blk-backend-object".to_owned(),
                id: 34,
                generation: 1,
            },
            cancelled_block_waits: vec![ContractObjectRefManifest {
                kind: "block-wait".to_owned(),
                id: 103,
                generation: 1,
            }],
            cancelled_wait_tokens: vec![ContractObjectRefManifest {
                kind: "wait-token".to_owned(),
                id: 102,
                generation: 1,
            }],
            revoked_device_capabilities: vec![ContractObjectRefManifest {
                kind: "device-capability".to_owned(),
                id: 32,
                generation: 1,
            }],
            released_dma_buffers: vec![ContractObjectRefManifest {
                kind: "dma-buffer-object".to_owned(),
                id: 106,
                generation: 1,
            }],
            generation: 1,
            state: "completed".to_owned(),
            started_at_event: 126,
            completed_at_event: Some(127),
            reason: "virtio-blk-device-fault".to_owned(),
            note: "block driver cleanup".to_owned(),
        });
        assert_eq!(view["kind"], "block-driver-cleanup");
        assert_eq!(view["owner"]["driver_store"]["generation"], 3);
        assert_eq!(view["owner"]["block_device"]["id"], 31);
        assert_eq!(view["references"]["io_cleanup"]["id"], 44);
        assert_eq!(
            view["references"]["backend"]["kind"],
            "virtio-blk-backend-object"
        );
        assert_eq!(view["references"]["cancelled_block_waits"][0]["id"], 103);
        assert_eq!(view["references"]["cancelled_wait_tokens"][0]["id"], 102);
        assert_eq!(
            view["references"]["revoked_device_capabilities"][0]["id"],
            32
        );
        assert_eq!(view["references"]["released_dma_buffers"][0]["id"], 106);
        assert_eq!(view["cleanup"]["reason"], "virtio-blk-device-fault");
        assert_eq!(view["cleanup"]["cancelled_block_wait_count"], 1);
        assert_eq!(view["cleanup"]["released_dma_buffer_count"], 1);
        assert_eq!(view["cleanup"]["revoked_device_capability_count"], 1);
        assert_eq!(view["last_transition"]["completed_at_event"], 127);
    }

    #[test]
    fn block_pending_io_policy_view_v1_exposes_retry_and_eio_policy() {
        let retry_policy = BlockPendingIoPolicyManifest {
            id: 127,
            block_wait: 103,
            block_wait_generation: 1,
            wait: 102,
            wait_generation: 1,
            block_request: 101,
            block_request_generation: 1,
            retry_request: Some(112),
            retry_request_generation: Some(1),
            block_device: 31,
            block_device_generation: 1,
            block_range: 100,
            block_range_generation: 1,
            operation: "read".to_owned(),
            sequence: 2,
            byte_len: 4096,
            action: "retry".to_owned(),
            errno: 11,
            retry_attempt: 1,
            max_retries: 2,
            generation: 1,
            state: "retry-scheduled".to_owned(),
            recorded_at_event: 128,
            note: "pending io retry policy".to_owned(),
        };
        let view = block_pending_io_policy_view_v1(&retry_policy);
        assert_eq!(view["kind"], "block-pending-io-policy");
        assert_eq!(view["owner"]["block_wait"]["id"], 103);
        assert_eq!(view["references"]["wait"]["kind"], "wait-token");
        assert_eq!(view["references"]["retry_request"]["id"], 112);
        assert_eq!(view["policy"]["action"], "retry");
        assert_eq!(view["policy"]["retry_attempt"], 1);
        assert_eq!(view["last_transition"]["recorded_at_event"], 128);
        assert!(view["last_error"].is_null());

        let eio = block_pending_io_policy_view_v1(&BlockPendingIoPolicyManifest {
            id: 129,
            retry_request: None,
            retry_request_generation: None,
            action: "eio".to_owned(),
            errno: 5,
            retry_attempt: 0,
            max_retries: 0,
            state: "eio-returned".to_owned(),
            recorded_at_event: 130,
            note: "pending io eio policy".to_owned(),
            ..retry_policy
        });
        assert_eq!(eio["last_error"]["errno"], 5);
    }

    #[test]
    fn block_request_generation_audit_view_v1_exposes_exact_generation_refs() {
        let view = block_request_generation_audit_view_v1(&BlockRequestGenerationAuditManifest {
            id: 131,
            block_device: 2,
            block_device_generation: 3,
            block_range: 5,
            block_range_generation: 7,
            block_request: 11,
            block_request_generation: 13,
            backend: ContractObjectRefManifest {
                kind: "fake-block-backend-object".to_owned(),
                id: 17,
                generation: 19,
            },
            dma_buffer: ContractObjectRefManifest {
                kind: "dma-buffer-object".to_owned(),
                id: 23,
                generation: 29,
            },
            rejected_completion_generation_probes: 1,
            rejected_wait_generation_probes: 2,
            rejected_dma_generation_probes: 3,
            rejected_queue_generation_probes: 4,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 31,
            note: "stale request generation audit".to_owned(),
        });
        assert_eq!(view["kind"], "block-request-generation-audit");
        assert_eq!(view["owner"]["block_request"]["generation"], 13);
        assert_eq!(
            view["references"]["backend"]["kind"],
            "fake-block-backend-object"
        );
        assert_eq!(view["references"]["backend"]["generation"], 19);
        assert_eq!(
            view["references"]["dma_buffer"]["kind"],
            "dma-buffer-object"
        );
        assert_eq!(view["references"]["dma_buffer"]["generation"], 29);
        assert_eq!(view["audit"]["rejected_completion_generation_probes"], 1);
        assert_eq!(view["audit"]["rejected_wait_generation_probes"], 2);
        assert_eq!(view["audit"]["rejected_dma_generation_probes"], 3);
        assert_eq!(view["audit"]["rejected_queue_generation_probes"], 4);
        assert_eq!(view["last_transition"]["recorded_at_event"], 31);
    }

    #[test]
    fn block_benchmark_view_v1_exposes_iops_latency_and_exact_refs() {
        let view = block_benchmark_view_v1(&BlockBenchmarkManifest {
            id: 132,
            scenario: "fake-block-read-write-iops-latency-v1".to_owned(),
            backend: ContractObjectRefManifest {
                kind: "fake-block-backend-object".to_owned(),
                id: 26,
                generation: 1,
            },
            block_device: 2,
            block_device_generation: 1,
            block_range: 5,
            block_range_generation: 1,
            read_path: 39,
            read_path_generation: 1,
            write_path: 48,
            write_path_generation: 1,
            request_queue: 53,
            request_queue_generation: 1,
            block_dma_buffer: 61,
            block_dma_buffer_generation: 1,
            sample_requests: 2,
            sample_bytes: 8192,
            read_completed_requests: 1,
            write_completed_requests: 1,
            queue_completed_requests: 2,
            measured_nanos: 40_000,
            budget_nanos: 80_000,
            iops: 50_000,
            throughput_bytes_per_sec: 204_800_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 35_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 487,
            note: "disk benchmark".to_owned(),
        });
        assert_eq!(view["kind"], "block-benchmark");
        assert_eq!(
            view["references"]["backend"]["kind"],
            "fake-block-backend-object"
        );
        assert_eq!(view["references"]["block_device"]["generation"], 1);
        assert_eq!(view["references"]["read_path"]["id"], 39);
        assert_eq!(view["references"]["write_path"]["id"], 48);
        assert_eq!(view["references"]["request_queue"]["id"], 53);
        assert_eq!(view["references"]["block_dma_buffer"]["id"], 61);
        assert_eq!(view["benchmark"]["sample_requests"], 2);
        assert_eq!(view["benchmark"]["iops"], 50_000);
        assert_eq!(view["benchmark"]["throughput_bytes_per_sec"], 204_800_000);
        assert_eq!(view["benchmark"]["p99_latency_nanos"], 35_000);
        assert_eq!(view["last_transition"]["recorded_at_event"], 487);
    }

    #[test]
    fn block_recovery_benchmark_view_v1_exposes_cleanup_latency_and_effects() {
        let view = block_recovery_benchmark_view_v1(&BlockRecoveryBenchmarkManifest {
            id: 135,
            scenario: "host-validation-disk-driver-recovery".to_owned(),
            cleanup: 107,
            cleanup_generation: 1,
            io_cleanup: 108,
            io_cleanup_generation: 1,
            backend: ContractObjectRefManifest {
                kind: "virtio-blk-backend-object".to_owned(),
                id: 34,
                generation: 1,
            },
            block_device: 31,
            block_device_generation: 1,
            driver_store: 7,
            driver_store_generation: 3,
            device: 30,
            device_generation: 1,
            driver_binding: 33,
            driver_binding_generation: 1,
            recovery_start_event: 125,
            recovery_complete_event: 126,
            cancelled_block_waits: 1,
            cancelled_wait_tokens: 1,
            released_dma_buffers: 1,
            revoked_device_capabilities: 1,
            recovery_nanos: 70_000,
            budget_nanos: 150_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 488,
            note: "disk recovery benchmark".to_owned(),
        });
        assert_eq!(view["kind"], "block-recovery-benchmark");
        assert_eq!(
            view["references"]["cleanup"]["kind"],
            "block-driver-cleanup"
        );
        assert_eq!(view["references"]["io_cleanup"]["id"], 108);
        assert_eq!(
            view["references"]["backend"]["kind"],
            "virtio-blk-backend-object"
        );
        assert_eq!(view["references"]["block_device"]["id"], 31);
        assert_eq!(view["references"]["driver_store"]["generation"], 3);
        assert_eq!(view["benchmark"]["cancelled_block_waits"], 1);
        assert_eq!(view["benchmark"]["released_dma_buffers"], 1);
        assert_eq!(view["benchmark"]["recovery_nanos"], 70_000);
        assert_eq!(view["last_transition"]["recorded_at_event"], 488);
    }

    #[test]
    fn target_feature_set_view_v1_exposes_simd_discovery() {
        let view = target_feature_set_view_v1(&TargetFeatureSetManifest {
            id: 21_000,
            name: "riscv64-qemu-virt-research-target".to_owned(),
            discovery_source: "target-runtime-default-profile".to_owned(),
            target_profile: "riscv64-qemu-virt-research".to_owned(),
            target_arch: "riscv64".to_owned(),
            base_isa: "rv64imac".to_owned(),
            simd_abi: "riscv-v".to_owned(),
            simd_supported: false,
            vector_register_count: 0,
            vector_register_bits: 0,
            scalar_fallback: true,
            unsupported_reason: "default profile does not declare RVV/SIMD".to_owned(),
            generation: 1,
            state: "discovered".to_owned(),
            recorded_at_event: 489,
            note: "target feature discovery".to_owned(),
        });
        assert_eq!(view["kind"], "target-feature-set");
        assert_eq!(
            view["owner"]["target_profile"],
            "riscv64-qemu-virt-research"
        );
        assert_eq!(view["features"]["base_isa"], "rv64imac");
        assert_eq!(view["features"]["simd"]["abi"], "riscv-v");
        assert_eq!(view["features"]["simd"]["supported"], false);
        assert_eq!(view["features"]["simd"]["scalar_fallback"], true);
        assert_eq!(view["last_transition"]["recorded_at_event"], 489);
    }

    #[test]
    fn vector_state_view_v1_exposes_owner_and_simd_shape() {
        let view = vector_state_view_v1(&VectorStateManifest {
            id: 22_000,
            owner_activation: ContractObjectRefManifest {
                kind: "activation".to_owned(),
                id: 7,
                generation: 3,
            },
            owner_store: ContractObjectRefManifest {
                kind: "store".to_owned(),
                id: 2,
                generation: 5,
            },
            code_object: ContractObjectRefManifest {
                kind: "code-object".to_owned(),
                id: 9,
                generation: 4,
            },
            target_feature_set: ContractObjectRefManifest {
                kind: "target-feature-set".to_owned(),
                id: 21_000,
                generation: 1,
            },
            simd_abi: "riscv-v".to_owned(),
            vector_register_count: 32,
            vector_register_bits: 128,
            register_bytes: 512,
            generation: 1,
            state: "unavailable".to_owned(),
            recorded_at_event: 490,
            note: "v4 vector state".to_owned(),
        });
        assert_eq!(view["kind"], "vector-state");
        assert_eq!(view["owner"]["activation"]["generation"], 3);
        assert_eq!(view["owner"]["store"]["generation"], 5);
        assert_eq!(view["references"]["code_object"]["id"], 9);
        assert_eq!(view["references"]["target_feature_set"]["generation"], 1);
        assert_eq!(view["simd"]["register_bytes"], 512);
        assert_eq!(view["last_error"], "simd-unavailable");
    }

    #[test]
    fn simd_fault_injection_view_v1_exposes_fault_and_exact_refs() {
        let view = simd_fault_injection_view_v1(&SimdFaultInjectionManifest {
            id: 22_010,
            activation: ContractObjectRefManifest {
                kind: "activation".to_owned(),
                id: 11,
                generation: 4,
            },
            code_object: ContractObjectRefManifest {
                kind: "code-object".to_owned(),
                id: 9,
                generation: 4,
            },
            trap: ContractObjectRefManifest {
                kind: "trap".to_owned(),
                id: 33,
                generation: 1,
            },
            target_feature_set: ContractObjectRefManifest {
                kind: "target-feature-set".to_owned(),
                id: 21_010,
                generation: 1,
            },
            vector_state: None,
            kind: "unsupported-feature".to_owned(),
            effect: "activation-trapped".to_owned(),
            required_abi: "riscv-v".to_owned(),
            vector_register_count: 32,
            vector_register_bits: 128,
            injected_faults: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 491,
            note: "v10 SIMD fault injection".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "simd-fault-injection");
        assert_eq!(view["owner"]["activation"]["generation"], 4);
        assert_eq!(view["references"]["code_object"]["id"], 9);
        assert_eq!(view["references"]["trap"]["generation"], 1);
        assert_eq!(view["references"]["target_feature_set"]["id"], 21_010);
        assert!(view["references"]["vector_state"].is_null());
        assert_eq!(view["fault"]["kind"], "unsupported-feature");
        assert_eq!(view["fault"]["effect"], "activation-trapped");
        assert_eq!(view["fault"]["required_abi"], "riscv-v");
        assert_eq!(view["fault"]["vector_register_count"], 32);
        assert_eq!(view["fault"]["vector_register_bits"], 128);
        assert_eq!(view["fault"]["injected_faults"], 1);
        assert_eq!(view["last_transition"]["recorded_at_event"], 491);
    }

    #[test]
    fn simd_benchmark_view_v1_exposes_scalar_vector_metrics_and_refs() {
        let view = simd_benchmark_view_v1(&SimdBenchmarkManifest {
            id: 22_011,
            target_feature_set: ContractObjectRefManifest {
                kind: "target-feature-set".to_owned(),
                id: 21_011,
                generation: 1,
            },
            scalar_code_object: ContractObjectRefManifest {
                kind: "code-object".to_owned(),
                id: 41,
                generation: 4,
            },
            vector_code_object: ContractObjectRefManifest {
                kind: "code-object".to_owned(),
                id: 42,
                generation: 5,
            },
            simd_abi: "riscv-v".to_owned(),
            vector_register_count: 32,
            vector_register_bits: 128,
            workload_units: 4096,
            scalar_nanos: 120_000,
            vector_nanos: 40_000,
            speedup_milli: 3000,
            context_overhead_nanos: 80_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 492,
            note: "v11 SIMD benchmark".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "simd-benchmark");
        assert_eq!(view["owner"]["target_feature_set"]["id"], 21_011);
        assert_eq!(view["references"]["scalar_code_object"]["generation"], 4);
        assert_eq!(view["references"]["vector_code_object"]["generation"], 5);
        assert_eq!(view["simd"]["abi"], "riscv-v");
        assert_eq!(view["simd"]["vector_register_count"], 32);
        assert_eq!(view["metrics"]["workload_units"], 4096);
        assert_eq!(view["metrics"]["scalar_nanos"], 120_000);
        assert_eq!(view["metrics"]["vector_nanos"], 40_000);
        assert_eq!(view["metrics"]["speedup_milli"], 3000);
        assert_eq!(view["metrics"]["context_overhead_nanos"], 80_000);
        assert_eq!(view["last_transition"]["recorded_at_event"], 492);
    }

    #[test]
    fn simd_context_switch_benchmark_view_v1_exposes_overhead_and_refs() {
        let view = simd_context_switch_benchmark_view_v1(&SimdContextSwitchBenchmarkManifest {
            id: 22_012,
            preemption: ContractObjectRefManifest {
                kind: "preemption".to_owned(),
                id: 9_070,
                generation: 1,
            },
            activation_resume: ContractObjectRefManifest {
                kind: "activation-resume".to_owned(),
                id: 9_071,
                generation: 1,
            },
            saved_vector_state: ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 22_002,
                generation: 1,
            },
            restored_vector_state: ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 22_003,
                generation: 1,
            },
            target_feature_set: ContractObjectRefManifest {
                kind: "target-feature-set".to_owned(),
                id: 21_002,
                generation: 1,
            },
            simd_abi: "riscv-v".to_owned(),
            vector_register_count: 32,
            vector_register_bits: 128,
            sample_count: 64,
            scalar_context_switch_nanos: 30_000,
            vector_context_switch_nanos: 46_384,
            overhead_nanos: 16_384,
            budget_nanos: 50_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 493,
            note: "v12 SIMD context switch benchmark".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "simd-context-switch-benchmark");
        assert_eq!(view["owner"]["activation_resume"]["id"], 9_071);
        assert_eq!(view["references"]["preemption"]["generation"], 1);
        assert_eq!(view["references"]["saved_vector_state"]["id"], 22_002);
        assert_eq!(view["references"]["restored_vector_state"]["id"], 22_003);
        assert_eq!(view["simd"]["abi"], "riscv-v");
        assert_eq!(view["metrics"]["sample_count"], 64);
        assert_eq!(view["metrics"]["scalar_context_switch_nanos"], 30_000);
        assert_eq!(view["metrics"]["vector_context_switch_nanos"], 46_384);
        assert_eq!(view["metrics"]["overhead_nanos"], 16_384);
        assert_eq!(view["metrics"]["budget_nanos"], 50_000);
        assert_eq!(view["last_transition"]["recorded_at_event"], 493);
    }

    #[test]
    fn framebuffer_object_view_v1_exposes_geometry_and_authority_boundary() {
        let view = framebuffer_object_view_v1(&FramebufferObjectManifest {
            id: 23_001,
            name: "fb0".to_owned(),
            resource: 101,
            resource_generation: 2,
            width: 800,
            height: 600,
            stride_bytes: 3200,
            pixel_format: "xrgb8888".to_owned(),
            byte_len: 1_920_000,
            generation: 1,
            state: "registered".to_owned(),
            recorded_at_event: 494,
            note: "g0 framebuffer object".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "framebuffer-object");
        assert_eq!(view["owner"]["resource"]["id"], 101);
        assert_eq!(view["references"]["resource"]["generation"], 2);
        assert_eq!(view["geometry"]["width"], 800);
        assert_eq!(view["geometry"]["height"], 600);
        assert_eq!(view["geometry"]["stride_bytes"], 3200);
        assert_eq!(view["geometry"]["pixel_format"], "xrgb8888");
        assert_eq!(view["geometry"]["byte_len"], 1_920_000);
        assert_eq!(
            view["authority"]["write_requires"],
            "display-capability-and-framebuffer-window-lease"
        );
        assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
        assert_eq!(view["last_transition"]["recorded_at_event"], 494);
    }

    #[test]
    fn display_object_view_v1_exposes_mode_and_framebuffer_ref() {
        let view = display_object_view_v1(&DisplayObjectManifest {
            id: 23_101,
            name: "display0".to_owned(),
            framebuffer: 23_001,
            framebuffer_generation: 1,
            mode_name: "800x600@60".to_owned(),
            width: 800,
            height: 600,
            refresh_millihz: 60_000,
            generation: 1,
            state: "registered".to_owned(),
            recorded_at_event: 495,
            note: "g1 display object".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "display-object");
        assert_eq!(view["owner"]["framebuffer"]["id"], 23_001);
        assert_eq!(view["references"]["framebuffer"]["generation"], 1);
        assert_eq!(view["mode"]["name"], "800x600@60");
        assert_eq!(view["mode"]["width"], 800);
        assert_eq!(view["mode"]["height"], 600);
        assert_eq!(view["mode"]["refresh_millihz"], 60_000);
        assert_eq!(
            view["authority"]["write_requires"],
            "display-capability-and-framebuffer-window-lease"
        );
        assert_eq!(view["authority"]["flush_requires"], "display-capability");
        assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
        assert_eq!(view["last_transition"]["recorded_at_event"], 495);
    }

    #[test]
    fn display_capability_view_v1_exposes_handle_and_generation_refs() {
        let view = display_capability_view_v1(&DisplayCapabilityManifest {
            id: 23_201,
            owner_store: 12,
            owner_store_generation: 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            capability: 25,
            capability_generation: 1,
            handle_slot: 8,
            handle_generation: 1,
            handle_tag: 99,
            operations: vec!["flush".to_owned(), "lease".to_owned()],
            generation: 1,
            state: "active".to_owned(),
            recorded_at_event: 496,
            note: "g2 display capability".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "display-capability");
        assert_eq!(view["owner"]["store"]["id"], 12);
        assert_eq!(view["references"]["display"]["id"], 23_101);
        assert_eq!(view["references"]["framebuffer"]["generation"], 1);
        assert_eq!(view["references"]["capability"]["id"], 25);
        assert_eq!(view["authority"]["class"], "display");
        assert_eq!(view["authority"]["operations"][0], "flush");
        assert_eq!(view["authority"]["operations"][1], "lease");
        assert_eq!(view["authority"]["handle"]["slot"], 8);
        assert_eq!(
            view["authority"]["write_requires_framebuffer_window_lease"],
            true
        );
        assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
        assert_eq!(view["last_transition"]["recorded_at_event"], 496);
    }

    #[test]
    fn framebuffer_window_lease_view_v1_exposes_window_and_authority_refs() {
        let view = framebuffer_window_lease_view_v1(&FramebufferWindowLeaseManifest {
            id: 23_301,
            owner_store: 12,
            owner_store_generation: 2,
            display_capability: 23_201,
            display_capability_generation: 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            byte_offset: 0,
            byte_len: 1_920_000,
            access: "write".to_owned(),
            generation: 1,
            state: "active".to_owned(),
            recorded_at_event: 497,
            note: "g3 framebuffer window lease".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "framebuffer-window-lease");
        assert_eq!(view["owner"]["store"]["generation"], 2);
        assert_eq!(view["references"]["display_capability"]["id"], 23_201);
        assert_eq!(view["references"]["display"]["generation"], 1);
        assert_eq!(view["references"]["framebuffer"]["id"], 23_001);
        assert_eq!(view["window"]["width"], 800);
        assert_eq!(view["window"]["byte_len"], 1_920_000);
        assert_eq!(
            view["authority"]["requires_display_capability_operation"],
            "lease"
        );
        assert_eq!(view["authority"]["write_requires_this_lease"], true);
        assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
        assert_eq!(view["last_transition"]["recorded_at_event"], 497);
    }

    #[test]
    fn framebuffer_mapping_view_v1_exposes_handle_mode_mapping_refs() {
        let view = framebuffer_mapping_view_v1(&FramebufferMappingManifest {
            id: 23_401,
            owner_store: 12,
            owner_store_generation: 2,
            framebuffer_window_lease: 23_301,
            framebuffer_window_lease_generation: 1,
            display_capability: 23_201,
            display_capability_generation: 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            map_handle_slot: 3,
            map_handle_generation: 1,
            map_handle_tag: 0x4d41505f4642,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            byte_offset: 0,
            byte_len: 1_920_000,
            access: "write".to_owned(),
            mode: "handle-mode".to_owned(),
            generation: 1,
            state: "active".to_owned(),
            recorded_at_event: 498,
            note: "g4 framebuffer mapping".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "framebuffer-mapping");
        assert_eq!(view["owner"]["store"]["generation"], 2);
        assert_eq!(view["references"]["framebuffer_window_lease"]["id"], 23_301);
        assert_eq!(view["references"]["display_capability"]["id"], 23_201);
        assert_eq!(view["references"]["framebuffer"]["id"], 23_001);
        assert_eq!(view["map_handle"]["slot"], 3);
        assert_eq!(view["map_handle"]["mode"], "handle-mode");
        assert_eq!(view["window"]["byte_len"], 1_920_000);
        assert_eq!(view["authority"]["requires_framebuffer_window_lease"], true);
        assert_eq!(view["authority"]["raw_pointer_exposed"], false);
        assert_eq!(view["authority"]["pixel_write_allowed"], false);
        assert_eq!(view["authority"]["flush_allowed"], false);
        assert_eq!(view["last_transition"]["recorded_at_event"], 498);
    }

    #[test]
    fn framebuffer_write_view_v1_exposes_semantic_pixel_write_refs() {
        let view = framebuffer_write_view_v1(&FramebufferWriteManifest {
            id: 23_501,
            owner_store: 12,
            owner_store_generation: 2,
            framebuffer_mapping: 23_401,
            framebuffer_mapping_generation: 1,
            framebuffer_window_lease: 23_301,
            framebuffer_window_lease_generation: 1,
            display_capability: 23_201,
            display_capability_generation: 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            map_handle_slot: 3,
            map_handle_generation: 1,
            map_handle_tag: 0x4d41505f4642,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3200,
            pixel_format: "xrgb8888".to_owned(),
            payload_digest: 12_345,
            generation: 1,
            state: "applied".to_owned(),
            recorded_at_event: 499,
            note: "g5 framebuffer write".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "framebuffer-write");
        assert_eq!(view["owner"]["store"]["generation"], 2);
        assert_eq!(view["references"]["framebuffer_mapping"]["id"], 23_401);
        assert_eq!(view["references"]["framebuffer_window_lease"]["id"], 23_301);
        assert_eq!(view["map_handle"]["slot"], 3);
        assert_eq!(view["write"]["byte_len"], 3200);
        assert_eq!(view["write"]["pixel_format"], "xrgb8888");
        assert_eq!(view["authority"]["requires_framebuffer_mapping"], true);
        assert_eq!(view["authority"]["raw_pointer_exposed"], false);
        assert_eq!(view["authority"]["flush_allowed"], false);
        assert_eq!(view["last_transition"]["recorded_at_event"], 499);
    }

    #[test]
    fn framebuffer_flush_region_view_v1_exposes_flush_refs() {
        let view = framebuffer_flush_region_view_v1(&FramebufferFlushRegionManifest {
            id: 23_601,
            owner_store: 12,
            owner_store_generation: 2,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            display_capability: 23_201,
            display_capability_generation: 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3200,
            pixel_format: "xrgb8888".to_owned(),
            payload_digest: 12_345,
            generation: 1,
            state: "applied".to_owned(),
            recorded_at_event: 500,
            note: "g6 framebuffer flush".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "framebuffer-flush-region");
        assert_eq!(view["owner"]["store"]["generation"], 2);
        assert_eq!(view["references"]["framebuffer_write"]["id"], 23_501);
        assert_eq!(view["references"]["display_capability"]["id"], 23_201);
        assert_eq!(view["flush"]["byte_len"], 3200);
        assert_eq!(view["flush"]["pixel_format"], "xrgb8888");
        assert_eq!(view["authority"]["requires_display_capability_flush"], true);
        assert_eq!(view["authority"]["requires_framebuffer_write"], true);
        assert_eq!(view["authority"]["raw_pointer_exposed"], false);
        assert_eq!(view["authority"]["real_present_executed"], false);
        assert_eq!(view["last_transition"]["recorded_at_event"], 500);
    }

    #[test]
    fn framebuffer_dirty_region_view_v1_exposes_dirty_tracking_refs() {
        let view = framebuffer_dirty_region_view_v1(&FramebufferDirtyRegionManifest {
            id: 23_701,
            owner_store: 12,
            owner_store_generation: 2,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: Some(23_601),
            framebuffer_flush_region_generation: Some(1),
            display_capability: 23_201,
            display_capability_generation: 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3200,
            pixel_format: "xrgb8888".to_owned(),
            payload_digest: 12_345,
            generation: 1,
            state: "clean".to_owned(),
            dirty_at_event: 499,
            cleaned_at_event: Some(500),
            recorded_at_event: 501,
            note: "g7 framebuffer dirty region".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "framebuffer-dirty-region");
        assert_eq!(view["owner"]["store"]["generation"], 2);
        assert_eq!(view["references"]["framebuffer_write"]["id"], 23_501);
        assert_eq!(view["references"]["framebuffer_flush_region"]["id"], 23_601);
        assert_eq!(view["region"]["byte_len"], 3200);
        assert_eq!(view["region"]["pixel_format"], "xrgb8888");
        assert_eq!(view["authority"]["requires_framebuffer_write"], true);
        assert_eq!(view["authority"]["clean_state_requires_flush_region"], true);
        assert_eq!(view["authority"]["raw_pointer_exposed"], false);
        assert_eq!(view["authority"]["real_present_executed"], false);
        assert_eq!(view["last_transition"]["recorded_at_event"], 501);
    }

    #[test]
    fn display_event_log_view_v1_exposes_event_window_refs() {
        let view = display_event_log_view_v1(&DisplayEventLogManifest {
            id: 23_801,
            owner_store: 12,
            owner_store_generation: 2,
            display_capability: 23_201,
            display_capability_generation: 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            framebuffer_dirty_region: 23_701,
            framebuffer_dirty_region_generation: 1,
            first_event: 494,
            last_event: 501,
            event_count: 8,
            flush_count: 1,
            dirty_region_count: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 502,
            note: "g8 display event log".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "display-event-log");
        assert_eq!(view["owner"]["store"]["generation"], 2);
        assert_eq!(view["references"]["framebuffer_dirty_region"]["id"], 23_701);
        assert_eq!(view["window"]["first_event"], 494);
        assert_eq!(view["window"]["last_event"], 501);
        assert_eq!(view["window"]["event_count"], 8);
        assert_eq!(view["window"]["flush_count"], 1);
        assert_eq!(view["window"]["dirty_region_count"], 1);
        assert_eq!(view["authority"]["read_only_control_plane"], true);
        assert_eq!(view["authority"]["raw_event_storage_exposed"], false);
        assert_eq!(view["authority"]["real_present_executed"], false);
        assert_eq!(view["last_transition"]["recorded_at_event"], 502);
    }

    #[test]
    fn display_cleanup_view_v1_exposes_cleanup_effects_and_generations() {
        let view = display_cleanup_view_v1(&DisplayCleanupManifest {
            id: 23_901,
            owner_store: 12,
            owner_store_generation: 2,
            display_capability: 23_201,
            display_capability_generation: 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            generation: 1,
            state: "completed".to_owned(),
            reason: "display-window-cleanup".to_owned(),
            started_at_event: 503,
            completed_at_event: 505,
            unmapped_framebuffer_mappings: vec![ContractObjectRefManifest {
                kind: "framebuffer-mapping".to_owned(),
                id: 23_401,
                generation: 1,
            }],
            released_framebuffer_window_leases: vec![ContractObjectRefManifest {
                kind: "framebuffer-window-lease".to_owned(),
                id: 23_301,
                generation: 1,
            }],
            revoked_display_capabilities: vec![ContractObjectRefManifest {
                kind: "display-capability".to_owned(),
                id: 23_201,
                generation: 1,
            }],
            revoked_capabilities: vec![ContractObjectRefManifest {
                kind: "capability".to_owned(),
                id: 77,
                generation: 2,
            }],
            steps: Vec::new(),
            note: "g9 display cleanup".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "display-cleanup");
        assert_eq!(view["owner"]["store"]["generation"], 2);
        assert_eq!(view["references"]["display_capability"]["id"], 23_201);
        assert_eq!(view["cleanup"]["reason"], "display-window-cleanup");
        assert_eq!(
            view["cleanup"]["unmapped_framebuffer_mappings"][0]["kind"],
            "framebuffer-mapping"
        );
        assert_eq!(
            view["cleanup"]["released_framebuffer_window_leases"][0]["id"],
            23_301
        );
        assert_eq!(
            view["cleanup"]["revoked_display_capabilities"][0]["generation"],
            1
        );
        assert_eq!(view["cleanup"]["revoked_capabilities"][0]["generation"], 2);
        assert_eq!(view["authority"]["releases_handle_mode_mappings"], true);
        assert_eq!(view["authority"]["real_present_executed"], false);
        assert_eq!(view["last_transition"]["completed_at_event"], 505);
    }

    #[test]
    fn display_snapshot_barrier_view_v1_exposes_quiescent_display_boundary() {
        let view = display_snapshot_barrier_view_v1(&DisplaySnapshotBarrierManifest {
            id: 24_001,
            owner_store: 12,
            owner_store_generation: 2,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            display_cleanup: Some(23_901),
            display_cleanup_generation: Some(1),
            active_framebuffer_window_lease_count: 0,
            active_framebuffer_mapping_count: 0,
            dirty_framebuffer_region_count: 0,
            snapshot_validation_ok: true,
            generation: 1,
            state: "validated".to_owned(),
            validated_at_event: 506,
            reason: "display-snapshot-barrier".to_owned(),
            note: "g10 display snapshot".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "display-snapshot-barrier");
        assert_eq!(view["owner"]["store"]["generation"], 2);
        assert_eq!(view["references"]["display_cleanup"]["id"], 23_901);
        assert_eq!(view["snapshot"]["snapshot_validation_ok"], true);
        assert_eq!(view["snapshot"]["active_framebuffer_window_lease_count"], 0);
        assert_eq!(
            view["authority"]["requires_no_active_framebuffer_lease"],
            true
        );
        assert_eq!(view["authority"]["real_snapshot_cow_executed"], false);
        assert_eq!(view["last_transition"]["validated_at_event"], 506);
    }

    #[test]
    fn display_panic_last_frame_view_v1_exposes_panic_safe_summary() {
        let view = display_panic_last_frame_view_v1(&DisplayPanicLastFrameManifest {
            id: 25_001,
            owner_store: 12,
            owner_store_generation: 2,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            display_snapshot_barrier: 24_001,
            display_snapshot_barrier_generation: 1,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3200,
            pixel_format: "xrgb8888".to_owned(),
            payload_digest: 12_345,
            summary_digest: 54_321,
            summary_record_bytes: 512,
            panic_epoch: 1,
            panic_cpu: 0,
            panic_reason_code: 1,
            panic_record_kind: "contract-panic-summary-v1".to_owned(),
            raw_framebuffer_bytes_exported: false,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 507,
            note: "g11 display panic last-frame".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "display-panic-last-frame");
        assert_eq!(view["owner"]["store"]["generation"], 2);
        assert_eq!(view["references"]["display_snapshot_barrier"]["id"], 24_001);
        assert_eq!(view["references"]["display_event_log"]["id"], 23_801);
        assert_eq!(view["frame"]["payload_digest"], 12_345);
        assert_eq!(view["frame"]["summary_digest"], 54_321);
        assert_eq!(view["panic"]["record_kind"], "contract-panic-summary-v1");
        assert_eq!(view["panic"]["summary_record_bytes"], 512);
        assert_eq!(view["panic"]["raw_framebuffer_bytes_exported"], false);
        assert_eq!(view["authority"]["panic_path_allocates"], false);
        assert_eq!(view["authority"]["real_panic_ring_write_executed"], false);
        assert_eq!(view["last_transition"]["recorded_at_event"], 507);
    }

    #[test]
    fn framebuffer_benchmark_view_v1_exposes_semantic_display_metrics() {
        let view = framebuffer_benchmark_view_v1(&FramebufferBenchmarkManifest {
            id: 25_101,
            scenario: "display-g12-single-flush".to_owned(),
            owner_store: 12,
            owner_store_generation: 2,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            display_capability: 23_201,
            display_capability_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            display_snapshot_barrier: 24_001,
            display_snapshot_barrier_generation: 1,
            sample_frames: 1,
            sample_bytes: 3200,
            frame_area_pixels: 800,
            write_nanos: 40_000,
            flush_nanos: 60_000,
            measured_nanos: 100_000,
            budget_nanos: 200_000,
            throughput_bytes_per_sec: 32_000_000,
            flushes_per_sec_milli: 10_000_000,
            p50_latency_nanos: 100_000,
            p99_latency_nanos: 100_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 508,
            note: "g12 framebuffer benchmark".to_owned(),
        });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "framebuffer-benchmark");
        assert_eq!(view["owner"]["store"]["generation"], 2);
        assert_eq!(view["references"]["framebuffer_write"]["id"], 23_501);
        assert_eq!(view["references"]["framebuffer_flush_region"]["id"], 23_601);
        assert_eq!(view["references"]["display_snapshot_barrier"]["id"], 24_001);
        assert_eq!(view["benchmark"]["sample_bytes"], 3200);
        assert_eq!(view["benchmark"]["throughput_bytes_per_sec"], 32_000_000);
        assert_eq!(view["benchmark"]["flushes_per_sec_milli"], 10_000_000);
        assert_eq!(view["authority"]["real_scanout_measured"], false);
        assert_eq!(
            view["authority"]["uses_semantic_write_flush_evidence"],
            true
        );
        assert_eq!(view["last_transition"]["recorded_at_event"], 508);
    }

    #[test]
    fn integrated_smp_preemption_cleanup_view_v1_exposes_runtime_closure_refs() {
        let view =
            integrated_smp_preemption_cleanup_view_v1(&IntegratedSmpPreemptionCleanupManifest {
                id: 26_001,
                scenario: "x0-smp-preemption-cleanup".to_owned(),
                stress_run: 9_501,
                stress_run_generation: 1,
                preemption: 9_001,
                preemption_generation: 1,
                timer_interrupt: 9_001,
                timer_interrupt_generation: 1,
                saved_context: 9_002,
                saved_context_generation: 1,
                remote_preempt: 9_001,
                remote_preempt_generation: 1,
                activation_cleanup: 9_001,
                activation_cleanup_generation: 1,
                smp_cleanup_quiescence: 9_301,
                smp_cleanup_quiescence_generation: 1,
                cleanup_store: 14,
                target_store_generation: 2,
                result_store_generation: 3,
                cleanup_activation: 77,
                cleanup_activation_generation_after: 4,
                hart_count: 2,
                invariant_checks: 7,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 570,
                note: "x0 integrated runtime".to_owned(),
            });

        assert_eq!(view["schema"], VIEW_SCHEMA_V1);
        assert_eq!(view["kind"], "integrated-smp-preemption-cleanup");
        assert_eq!(view["owner"]["cleanup_store"]["generation"], 2);
        assert_eq!(view["owner"]["runtime_activation"]["id"], 77);
        assert_eq!(
            view["owner"]["runtime_activation"]["generation_after_cleanup"],
            4
        );
        assert_eq!(
            view["owner"]["runtime_activation"]["note"],
            "runtime-preemptive-activation-not-target-executor-object"
        );
        assert_eq!(view["references"]["smp_stress_run"]["id"], 9_501);
        assert_eq!(view["references"]["remote_preempt"]["generation"], 1);
        assert_eq!(view["references"]["activation_cleanup"]["id"], 9_001);
        assert_eq!(view["references"]["smp_cleanup_quiescence"]["id"], 9_301);
        assert_eq!(view["closure"]["hart_count"], 2);
        assert_eq!(view["closure"]["result_store_generation"], 3);
        assert_eq!(view["closure"]["invariant_checks"], 7);
        assert_eq!(view["authority"]["real_smp_preemption_executed"], false);
        assert_eq!(
            view["authority"]["uses_semantic_preemption_cleanup_evidence"],
            true
        );
        assert_eq!(view["last_transition"]["recorded_at_event"], 570);
    }

    #[test]
    fn activation_context_view_v1_exposes_vector_clean_dirty_state() {
        let view = activation_context_view_v1(&ActivationContextManifest {
            id: 12,
            activation: 11,
            activation_generation: 3,
            owner_task: 7,
            owner_task_generation: 1,
            owner_store: Some(2),
            owner_store_generation: Some(5),
            generation: 4,
            state: "current".to_owned(),
            current_saved_context: None,
            current_saved_context_generation: None,
            vector_state: Some(ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 22_000,
                generation: 1,
            }),
            vector_status: "dirty".to_owned(),
            vector_state_event: Some(42),
            last_event: Some(42),
        });

        assert_eq!(view["kind"], "activation-context");
        assert_eq!(view["vector_context"]["status"], "dirty");
        assert_eq!(
            view["vector_context"]["vector_state"]["kind"],
            "vector-state"
        );
        assert_eq!(view["vector_context"]["vector_state"]["generation"], 1);
        assert_eq!(view["references"]["vector_state"]["id"], 22_000);
        assert_eq!(view["vector_context"]["last_event"], 42);
    }

    #[test]
    fn saved_context_view_v1_exposes_preempted_vector_state() {
        let view = saved_context_view_v1(&SavedContextManifest {
            id: 13,
            context: 12,
            context_generation: 4,
            activation: 11,
            activation_generation: 4,
            owner_task: 7,
            owner_task_generation: 1,
            source_preemption: Some(6),
            source_preemption_generation: Some(1),
            generation: 2,
            state: "captured".to_owned(),
            reason: "timer-preempt".to_owned(),
            pc: 0x2000,
            sp: 0x9000,
            flags: 0,
            integer_registers: 33,
            vector_state: Some(ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 22_002,
                generation: 1,
            }),
            vector_status: "clean".to_owned(),
            vector_saved_at_event: Some(77),
            saved_at_event: 41,
            note: "preempted vector frame".to_owned(),
        });

        assert_eq!(view["kind"], "saved-context");
        assert_eq!(view["references"]["vector_state"]["kind"], "vector-state");
        assert_eq!(view["references"]["vector_state"]["id"], 22_002);
        assert_eq!(view["vector_context"]["status"], "clean");
        assert_eq!(view["vector_context"]["saved_at_event"], 77);
    }

    #[test]
    fn activation_resume_view_v1_exposes_vector_restore_refs() {
        let view = activation_resume_view_v1(&ActivationResumeManifest {
            id: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation_before: 4,
            activation_generation_after: 5,
            owner_task: 7,
            owner_task_generation: 1,
            queue: 1,
            queue_generation: 1,
            context: Some(12),
            context_generation_before: Some(4),
            context_generation_after: Some(5),
            saved_context: Some(13),
            saved_context_generation: Some(3),
            saved_vector_state: Some(ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 22_002,
                generation: 1,
            }),
            restored_vector_state: Some(ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 22_003,
                generation: 1,
            }),
            vector_status: "clean".to_owned(),
            vector_restored_at_event: Some(88),
            generation: 1,
            state: "applied".to_owned(),
            resumed_at_event: 87,
            note: "resume restores vector state".to_owned(),
        });

        assert_eq!(view["kind"], "activation-resume");
        assert_eq!(view["vector_restore"]["status"], "clean");
        assert_eq!(view["references"]["saved_vector_state"]["id"], 22_002);
        assert_eq!(view["references"]["restored_vector_state"]["id"], 22_003);
        assert_eq!(view["vector_restore"]["restored_at_event"], 88);
    }

    #[test]
    fn activation_migration_view_v1_exposes_vector_migration_refs() {
        let view = activation_migration_view_v1(&ActivationMigrationManifest {
            id: 71,
            activation: 11,
            activation_generation_before: 4,
            activation_generation_after: 5,
            owner_task: 7,
            owner_task_generation: 1,
            source_hart: 2,
            source_hart_generation: 4,
            target_hart: 1,
            target_hart_generation: 2,
            source_queue: 2,
            source_queue_generation: 2,
            source_queue_owner_hart_generation: 4,
            target_queue: 3,
            target_queue_generation: 2,
            target_queue_owner_hart_generation: 2,
            context: Some(12),
            context_generation_before: Some(2),
            context_generation_after: Some(3),
            source_vector_state: Some(ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 22_004,
                generation: 1,
            }),
            migrated_vector_state: Some(ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 22_005,
                generation: 1,
            }),
            vector_status: "clean".to_owned(),
            vector_migrated_at_event: Some(99),
            generation: 1,
            state: "applied".to_owned(),
            migrated_at_event: 98,
            reason: "vector-rebalance".to_owned(),
            note: "cross-hart migration rehomes vector state".to_owned(),
        });

        assert_eq!(view["kind"], "activation-migration");
        assert_eq!(view["vector_migration"]["status"], "clean");
        assert_eq!(view["references"]["context"]["id"], 12);
        assert_eq!(view["references"]["source_vector_state"]["id"], 22_004);
        assert_eq!(view["references"]["migrated_vector_state"]["id"], 22_005);
        assert_eq!(view["vector_migration"]["event"], 99);
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
        package.semantic.hart_count = 2;
        package.semantic.task_record_count = 1;
        package.semantic.runtime_activation_count = 1;
        package.semantic.runnable_queue_count = 1;
        package.semantic.activation_context_count = 1;
        package.semantic.saved_context_count = 1;
        package.semantic.timer_interrupt_count = 1;
        package.semantic.ipi_event_count = 1;
        package.semantic.remote_preempt_count = 1;
        package.semantic.remote_park_count = 1;
        package.semantic.preemption_count = 1;
        package.semantic.scheduler_decision_count = 1;
        package.semantic.cross_hart_scheduler_decision_count = 1;
        package.semantic.activation_migration_count = 1;
        package.semantic.smp_safe_point_count = 1;
        package.semantic.stop_the_world_rendezvous_count = 1;
        package.semantic.smp_code_publish_barrier_count = 1;
        package.semantic.smp_cleanup_quiescence_count = 1;
        package.semantic.smp_snapshot_barrier_count = 1;
        package.semantic.smp_stress_run_count = 1;
        package.semantic.smp_scaling_benchmark_count = 1;
        package.semantic.device_object_count = 1;
        package.semantic.queue_object_count = 1;
        package.semantic.descriptor_object_count = 1;
        package.semantic.dma_buffer_object_count = 1;
        package.semantic.mmio_region_object_count = 1;
        package.semantic.irq_line_object_count = 1;
        package.semantic.irq_event_count = 1;
        package.semantic.device_capability_count = 2;
        package.semantic.driver_store_binding_count = 1;
        package.semantic.io_wait_count = 1;
        package.semantic.wait_token_count = 1;
        package.semantic.wait_record_count = 1;
        package.semantic.activation_resume_count = 1;
        package.semantic.activation_wait_count = 1;
        package.semantic.activation_cleanup_count = 1;
        package.semantic.preemption_latency_sample_count = 1;
        package.semantic.hart_event_attribution_count = 1;
        package.substrate_boundary.timer_epoch = 3;
        package.semantic.hart_records.push(HartRecordManifest {
            id: 1,
            hardware_id: 0,
            label: "boot-hart0".to_owned(),
            state: "idle".to_owned(),
            generation: 2,
            boot: true,
            current_activation: None,
            current_activation_generation: None,
            current_task: None,
            current_task_generation: None,
            current_store: None,
            current_store_generation: None,
            last_event: Some(2),
            last_current_event: None,
            note: "s0 hart object".to_owned(),
        });
        package.semantic.hart_records.push(HartRecordManifest {
            id: 2,
            hardware_id: 1,
            label: "hart1".to_owned(),
            state: "idle".to_owned(),
            generation: 2,
            boot: false,
            current_activation: None,
            current_activation_generation: None,
            current_task: None,
            current_task_generation: None,
            current_store: None,
            current_store_generation: None,
            last_event: Some(4),
            last_current_event: None,
            note: "s5 target hart".to_owned(),
        });
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
                owner_hart: Some(1),
                owner_hart_generation: Some(2),
                entries: vec![artifact_manifest::RunnableQueueEntryManifest {
                    activation: 11,
                    activation_generation: 2,
                    enqueued_at: 9,
                }],
            });
        package
            .semantic
            .activation_contexts
            .push(ActivationContextManifest {
                id: 12,
                activation: 11,
                activation_generation: 2,
                owner_task: 7,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                generation: 2,
                state: "saved".to_owned(),
                current_saved_context: Some(13),
                current_saved_context_generation: Some(1),
                vector_state: None,
                vector_status: "absent".to_owned(),
                vector_state_event: None,
                last_event: Some(10),
            });
        package.semantic.saved_contexts.push(SavedContextManifest {
            id: 13,
            context: 12,
            context_generation: 2,
            activation: 11,
            activation_generation: 2,
            owner_task: 7,
            owner_task_generation: 1,
            source_preemption: Some(15),
            source_preemption_generation: Some(1),
            generation: 1,
            state: "captured".to_owned(),
            reason: "timer-preempt".to_owned(),
            pc: 0x1000,
            sp: 0x8000,
            flags: 0,
            integer_registers: 33,
            vector_state: None,
            vector_status: "absent".to_owned(),
            vector_saved_at_event: None,
            saved_at_event: 10,
            note: "preempted frame".to_owned(),
        });
        package
            .semantic
            .timer_interrupts
            .push(TimerInterruptManifest {
                id: 14,
                timer_epoch: 3,
                hart: 1,
                hart_generation: Some(2),
                hardware_hart: Some(0),
                target_activation: Some(11),
                target_activation_generation: Some(2),
                target_task: Some(7),
                target_task_generation: Some(1),
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 11,
                note: "timer tick".to_owned(),
            });
        package.semantic.ipi_events.push(IpiEventManifest {
            id: 23,
            source_hart: 1,
            source_hart_generation: 2,
            source_hardware_hart: 0,
            target_hart: 2,
            target_hart_generation: 2,
            target_hardware_hart: 1,
            kind: "scheduler-kick".to_owned(),
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 12,
            reason: "s5-scheduler-kick".to_owned(),
            note: "hart0 kicks hart1".to_owned(),
        });
        package
            .semantic
            .remote_preempts
            .push(RemotePreemptManifest {
                id: 24,
                ipi: 23,
                ipi_generation: 1,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation_before: 2,
                target_hart_generation_after: 3,
                activation: 11,
                activation_generation_before: 2,
                activation_generation_after: 3,
                queue: 1,
                queue_generation: 1,
                generation: 1,
                state: "applied".to_owned(),
                preempted_at_event: 13,
                note: "remote preempt activation".to_owned(),
            });
        package.semantic.remote_parks.push(RemoteParkManifest {
            id: 25,
            ipi: 23,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation_before: 3,
            target_hart_generation_after: 4,
            generation: 1,
            state: "parked".to_owned(),
            parked_at_event: 14,
            reason: "remote-maintenance".to_owned(),
            note: "remote park hart".to_owned(),
        });
        package
            .semantic
            .hart_event_attributions
            .push(HartEventAttributionManifest {
                id: 22,
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                event: 11,
                event_source: "timer".to_owned(),
                event_kind: "TimerInterruptRecorded".to_owned(),
                activation: Some(11),
                activation_generation: Some(2),
                task: Some(7),
                task_generation: Some(1),
                store: None,
                store_generation: None,
                generation: 1,
                state: "recorded".to_owned(),
                note: "timer event attributed to hart".to_owned(),
            });
        package.semantic.preemptions.push(PreemptionManifest {
            id: 15,
            activation: 11,
            activation_generation_before: 2,
            activation_generation_after: 3,
            timer_interrupt: 14,
            timer_interrupt_generation: 1,
            queue: 1,
            queue_generation: 1,
            generation: 1,
            state: "applied".to_owned(),
            preempted_at_event: 12,
            note: "preempted".to_owned(),
        });
        package
            .semantic
            .scheduler_decisions
            .push(SchedulerDecisionManifest {
                id: 16,
                queue: 1,
                queue_generation: 1,
                selected_activation: 11,
                selected_activation_generation: 3,
                owner_task: 7,
                owner_task_generation: 1,
                generation: 1,
                state: "recorded".to_owned(),
                decided_at_event: 13,
                reason: "runnable-available".to_owned(),
                note: "select activation".to_owned(),
            });
        package
            .semantic
            .cross_hart_scheduler_decisions
            .push(CrossHartSchedulerDecisionManifest {
                id: 26,
                scheduler_decision: 16,
                scheduler_decision_generation: 1,
                deciding_hart: 2,
                deciding_hart_generation: 2,
                target_hart: 1,
                target_hart_generation: 2,
                queue: 1,
                queue_generation: 1,
                queue_owner_hart_generation: 2,
                selected_activation: 11,
                selected_activation_generation: 3,
                generation: 1,
                state: "recorded".to_owned(),
                decided_at_event: 20,
                reason: "remote-runnable".to_owned(),
                note: "cross hart decision".to_owned(),
            });
        package
            .semantic
            .activation_migrations
            .push(ActivationMigrationManifest {
                id: 27,
                activation: 11,
                activation_generation_before: 3,
                activation_generation_after: 4,
                owner_task: 7,
                owner_task_generation: 1,
                source_hart: 2,
                source_hart_generation: 2,
                target_hart: 1,
                target_hart_generation: 2,
                source_queue: 2,
                source_queue_generation: 1,
                source_queue_owner_hart_generation: 2,
                target_queue: 1,
                target_queue_generation: 1,
                target_queue_owner_hart_generation: 2,
                context: None,
                context_generation_before: None,
                context_generation_after: None,
                source_vector_state: None,
                migrated_vector_state: None,
                vector_status: "absent".to_owned(),
                vector_migrated_at_event: None,
                generation: 1,
                state: "applied".to_owned(),
                migrated_at_event: 21,
                reason: "rebalance".to_owned(),
                note: "activation migration".to_owned(),
            });
        package.semantic.smp_safe_points.push(SmpSafePointManifest {
            id: 28,
            coordinator_hart: 1,
            coordinator_hart_generation: 2,
            participants: vec![
                artifact_manifest::SmpSafePointParticipantManifest {
                    hart: 1,
                    hart_generation: 2,
                    hardware_hart: 0,
                    hart_state: "idle".to_owned(),
                    current_activation: None,
                    current_activation_generation: None,
                },
                artifact_manifest::SmpSafePointParticipantManifest {
                    hart: 2,
                    hart_generation: 2,
                    hardware_hart: 1,
                    hart_state: "parked".to_owned(),
                    current_activation: None,
                    current_activation_generation: None,
                },
            ],
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 22,
            reason: "quiescent-boundary".to_owned(),
            note: "smp safe point".to_owned(),
        });
        package
            .semantic
            .stop_the_world_rendezvous
            .push(StopTheWorldRendezvousManifest {
                id: 29,
                epoch: 1,
                safe_point: 28,
                safe_point_generation: 1,
                coordinator_hart: 1,
                coordinator_hart_generation: 2,
                participants: vec![
                    artifact_manifest::StopTheWorldRendezvousParticipantManifest {
                        hart: 1,
                        hart_generation: 2,
                        hardware_hart: 0,
                        hart_state: "idle".to_owned(),
                    },
                    artifact_manifest::StopTheWorldRendezvousParticipantManifest {
                        hart: 2,
                        hart_generation: 2,
                        hardware_hart: 1,
                        hart_state: "parked".to_owned(),
                    },
                ],
                stop_new_activations: true,
                generation: 1,
                state: "completed".to_owned(),
                completed_at_event: 23,
                reason: "code-publish-boundary".to_owned(),
                note: "stop the world".to_owned(),
            });
        package
            .semantic
            .smp_code_publish_barriers
            .push(SmpCodePublishBarrierManifest {
                id: 30,
                rendezvous: 29,
                rendezvous_generation: 1,
                rendezvous_epoch: 1,
                code_publish_epoch_before: 0,
                code_publish_epoch_after: 1,
                participants: vec![
                    artifact_manifest::SmpCodePublishBarrierParticipantManifest {
                        hart: 1,
                        hart_generation: 2,
                        hardware_hart: 0,
                        last_seen_code_epoch_before: 0,
                        last_seen_code_epoch_after: 1,
                        semantic_icache_sync: true,
                    },
                    artifact_manifest::SmpCodePublishBarrierParticipantManifest {
                        hart: 2,
                        hart_generation: 2,
                        hardware_hart: 1,
                        last_seen_code_epoch_before: 0,
                        last_seen_code_epoch_after: 1,
                        semantic_icache_sync: true,
                    },
                ],
                remote_icache_sync_required: true,
                code_publish_executed: false,
                generation: 1,
                state: "validated".to_owned(),
                validated_at_event: 24,
                reason: "semantic-code-publish-barrier".to_owned(),
                note: "smp publish barrier".to_owned(),
            });
        package
            .semantic
            .smp_cleanup_quiescence
            .push(SmpCleanupQuiescenceManifest {
                id: 31,
                cleanup: 20,
                cleanup_generation: 1,
                store: 5,
                target_store_generation: 2,
                result_store_generation: 4,
                activation: 11,
                activation_generation_after: 6,
                rendezvous: 29,
                rendezvous_generation: 1,
                rendezvous_epoch: 1,
                participants: vec![
                    artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                        hart: 1,
                        hart_generation: 2,
                        hardware_hart: 0,
                        hart_state: "idle".to_owned(),
                        current_activation: None,
                        current_activation_generation: None,
                        current_store: None,
                        current_store_generation: None,
                        quiesced: true,
                    },
                    artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                        hart: 2,
                        hart_generation: 2,
                        hardware_hart: 1,
                        hart_state: "parked".to_owned(),
                        current_activation: None,
                        current_activation_generation: None,
                        current_store: None,
                        current_store_generation: None,
                        quiesced: true,
                    },
                ],
                no_running_activation: true,
                no_pending_wait: true,
                no_live_capability: true,
                no_live_resource: true,
                generation: 1,
                state: "validated".to_owned(),
                validated_at_event: 25,
                reason: "smp-cleanup-quiescence".to_owned(),
                note: "cleanup quiesced".to_owned(),
            });
        package
            .semantic
            .smp_snapshot_barriers
            .push(SmpSnapshotBarrierManifest {
                id: 32,
                rendezvous: 29,
                rendezvous_generation: 1,
                rendezvous_epoch: 1,
                event_log_cursor: 25,
                participants: vec![
                    artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                        hart: 1,
                        hart_generation: 2,
                        hardware_hart: 0,
                        hart_state: "idle".to_owned(),
                        event_log_cursor_observed: 25,
                        snapshot_safe: true,
                    },
                    artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                        hart: 2,
                        hart_generation: 2,
                        hardware_hart: 1,
                        hart_state: "parked".to_owned(),
                        event_log_cursor_observed: 25,
                        snapshot_safe: true,
                    },
                ],
                pending_wait_count: 0,
                active_transaction_count: 0,
                active_dmw_lease_count: 0,
                active_nonconvertible_activation_count: 0,
                in_flight_dma_count: 0,
                unsealed_event_log: false,
                unflushed_trap_record_count: 0,
                pending_cleanup_count: 0,
                native_activation_stack_live: false,
                raw_dma_binding_count: 0,
                raw_mmio_binding_count: 0,
                snapshot_validation_ok: true,
                generation: 1,
                state: "validated".to_owned(),
                validated_at_event: 26,
                reason: "smp-snapshot-barrier".to_owned(),
                note: "snapshot barrier".to_owned(),
            });
        package.semantic.smp_stress_runs.push(SmpStressRunManifest {
            id: 33,
            scenario: "s15-smp-stress-property".to_owned(),
            iterations: 3,
            hart_count: 2,
            event_log_cursor: 26,
            observed_safe_point_count: 3,
            observed_rendezvous_count: 3,
            observed_code_publish_barrier_count: 1,
            observed_cleanup_quiescence_count: 1,
            observed_snapshot_barrier_count: 1,
            observed_activation_migration_count: 1,
            observed_remote_preempt_count: 1,
            observed_remote_park_count: 1,
            invariant_checks: 6,
            property_failures: 0,
            last_safe_point: 28,
            last_safe_point_generation: 1,
            last_rendezvous: 29,
            last_rendezvous_generation: 1,
            last_code_publish_barrier: 30,
            last_code_publish_barrier_generation: 1,
            last_cleanup_quiescence: 31,
            last_cleanup_quiescence_generation: 1,
            last_snapshot_barrier: 32,
            last_snapshot_barrier_generation: 1,
            last_activation_migration: 27,
            last_activation_migration_generation: 1,
            last_remote_preempt: 24,
            last_remote_preempt_generation: 1,
            last_remote_park: 25,
            last_remote_park_generation: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 27,
            reason: "smp-stress-property-tests".to_owned(),
            note: "stress run".to_owned(),
        });
        package
            .semantic
            .smp_scaling_benchmarks
            .push(SmpScalingBenchmarkManifest {
                id: 34,
                scenario: "s16-smp-scaling-benchmark".to_owned(),
                stress_run: 33,
                stress_run_generation: 1,
                hart_count: 2,
                workload_units: 6,
                baseline_single_hart_nanos: 120_000,
                measured_smp_nanos: 72_000,
                budget_nanos: 90_000,
                speedup_milli: 1_666,
                efficiency_milli: 833,
                event_log_cursor: 27,
                stress_safe_point_count: 3,
                stress_rendezvous_count: 3,
                stress_property_failures: 0,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 28,
                note: "scaling benchmark".to_owned(),
            });
        package.semantic.device_objects.push(DeviceObjectManifest {
            id: 35,
            name: "fake-io0".to_owned(),
            class: "fake-device".to_owned(),
            resource: 99,
            resource_generation: 1,
            backend: "fake-io-backend".to_owned(),
            bus: "semantic-harness".to_owned(),
            vendor: "vmos".to_owned(),
            model: "fake-io-v1".to_owned(),
            generation: 1,
            state: "registered".to_owned(),
            recorded_at_event: 29,
            note: "device object".to_owned(),
        });
        package.semantic.queue_objects.push(QueueObjectManifest {
            id: 36,
            name: "fake-io0-rx".to_owned(),
            role: "rx".to_owned(),
            queue_index: 0,
            depth: 64,
            device: 35,
            device_generation: 1,
            generation: 1,
            state: "registered".to_owned(),
            recorded_at_event: 30,
            note: "queue object".to_owned(),
        });
        package
            .semantic
            .descriptor_objects
            .push(DescriptorObjectManifest {
                id: 37,
                queue: 36,
                queue_generation: 1,
                slot: 0,
                access: "read-write".to_owned(),
                length: 2048,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 31,
                note: "descriptor object".to_owned(),
            });
        package
            .semantic
            .dma_buffer_objects
            .push(DmaBufferObjectManifest {
                id: 38,
                descriptor: 37,
                descriptor_generation: 1,
                resource: 100,
                resource_generation: 1,
                access: "read-write".to_owned(),
                length: 2048,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 32,
                note: "dma buffer object".to_owned(),
            });
        package
            .semantic
            .mmio_region_objects
            .push(MmioRegionObjectManifest {
                id: 39,
                device: 35,
                device_generation: 1,
                resource: 101,
                resource_generation: 1,
                region_index: 0,
                offset: 0x1000,
                length: 0x100,
                access: "read-write".to_owned(),
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 33,
                note: "mmio region object".to_owned(),
            });
        package
            .semantic
            .irq_line_objects
            .push(IrqLineObjectManifest {
                id: 40,
                device: 35,
                device_generation: 1,
                resource: 102,
                resource_generation: 1,
                irq_number: 5,
                trigger: "level".to_owned(),
                polarity: "active-high".to_owned(),
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 34,
                note: "irq line object".to_owned(),
            });
        package.semantic.irq_events.push(IrqEventManifest {
            id: 41,
            irq_line: 40,
            irq_line_generation: 1,
            device: 35,
            device_generation: 1,
            driver_store: 1,
            driver_store_generation: 2,
            irq_number: 5,
            sequence: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 35,
            note: "irq event".to_owned(),
        });
        package
            .semantic
            .device_capabilities
            .push(DeviceCapabilityManifest {
                id: 42,
                driver_store: 1,
                driver_store_generation: 2,
                target: ContractObjectRefManifest {
                    kind: "mmio-region-object".to_owned(),
                    id: 39,
                    generation: 1,
                },
                class: "mmio-region".to_owned(),
                operation: "write32".to_owned(),
                capability: 7,
                capability_generation: 1,
                handle_slot: 3,
                handle_generation: 1,
                handle_tag: 9001,
                generation: 1,
                state: "active".to_owned(),
                recorded_at_event: 36,
                note: "device capability".to_owned(),
            });
        package
            .semantic
            .device_capabilities
            .push(DeviceCapabilityManifest {
                id: 43,
                driver_store: 1,
                driver_store_generation: 2,
                target: ContractObjectRefManifest {
                    kind: "device-object".to_owned(),
                    id: 35,
                    generation: 1,
                },
                class: "device".to_owned(),
                operation: "probe".to_owned(),
                capability: 8,
                capability_generation: 1,
                handle_slot: 4,
                handle_generation: 1,
                handle_tag: 9002,
                generation: 1,
                state: "active".to_owned(),
                recorded_at_event: 37,
                note: "device capability".to_owned(),
            });
        package
            .semantic
            .driver_store_bindings
            .push(DriverStoreBindingManifest {
                id: 44,
                driver_store: 1,
                driver_store_generation: 2,
                device: 35,
                device_generation: 1,
                device_capability: 43,
                device_capability_generation: 1,
                capability: 8,
                capability_generation: 1,
                generation: 1,
                state: "bound".to_owned(),
                recorded_at_event: 38,
                note: "driver store binding".to_owned(),
            });
        package.semantic.wait_records.push(WaitRecordManifest {
            id: 45,
            owner_task: None,
            owner_task_generation: None,
            owner_store: Some(1),
            owner_store_generation: Some(2),
            kind: "device-irq".to_owned(),
            generation: 1,
            state: "resolved".to_owned(),
            blockers: vec![ContractObjectRefManifest {
                kind: "irq-line-object".to_owned(),
                id: 40,
                generation: 1,
            }],
            deadline: None,
            cancel_reason: None,
            restart_policy: "internal-only".to_owned(),
            saved_context: Some("fake-io0:rx-irq".to_owned()),
        });
        package.semantic.io_waits.push(IoWaitManifest {
            id: 46,
            wait: 45,
            wait_generation: 1,
            driver_store: 1,
            driver_store_generation: 2,
            device: 35,
            device_generation: 1,
            driver_binding: 44,
            driver_binding_generation: 1,
            blocker: ContractObjectRefManifest {
                kind: "irq-line-object".to_owned(),
                id: 40,
                generation: 1,
            },
            generation: 1,
            state: "resolved".to_owned(),
            created_at_event: 39,
            completed_at_event: Some(40),
            completion_irq_event: Some(41),
            completion_irq_event_generation: Some(1),
            cancel_reason: None,
            note: "io wait".to_owned(),
        });
        package
            .semantic
            .activation_resumes
            .push(ActivationResumeManifest {
                id: 17,
                scheduler_decision: 16,
                scheduler_decision_generation: 1,
                activation: 11,
                activation_generation_before: 3,
                activation_generation_after: 4,
                owner_task: 7,
                owner_task_generation: 1,
                queue: 1,
                queue_generation: 1,
                context: Some(12),
                context_generation_before: Some(2),
                context_generation_after: Some(3),
                saved_context: Some(13),
                saved_context_generation: Some(2),
                saved_vector_state: None,
                restored_vector_state: None,
                vector_status: "absent".to_owned(),
                vector_restored_at_event: None,
                generation: 1,
                state: "applied".to_owned(),
                resumed_at_event: 14,
                note: "resume activation".to_owned(),
            });
        package
            .semantic
            .activation_waits
            .push(ActivationWaitManifest {
                id: 18,
                activation: 11,
                activation_generation_before: 4,
                activation_generation_after_block: 5,
                activation_generation_after_cancel: Some(6),
                wait: 19,
                wait_generation: 1,
                owner_task: 7,
                owner_task_generation: 2,
                queue: None,
                queue_generation: None,
                generation: 1,
                state: "cancelled".to_owned(),
                blocked_at_event: 15,
                completed_at_event: Some(16),
                cancel_reason: Some("timeout".to_owned()),
                note: "activation wait".to_owned(),
            });
        package
            .semantic
            .activation_cleanups
            .push(ActivationCleanupManifest {
                id: 20,
                store: 3,
                target_store_generation: 2,
                result_store_generation: 4,
                activation: 11,
                activation_generation_before: 5,
                activation_generation_after: 6,
                wait: Some(19),
                wait_generation: Some(1),
                owner_task: 7,
                owner_task_generation_before: 2,
                owner_task_generation_after: 3,
                generation: 1,
                state: "completed".to_owned(),
                reason: "driver-store-fault".to_owned(),
                started_at_event: 17,
                completed_at_event: 18,
                steps: vec![artifact_manifest::ActivationCleanupStepManifest {
                    kind: "cancel-wait".to_owned(),
                    target: ContractObjectRefManifest {
                        kind: "wait-token".to_owned(),
                        id: 19,
                        generation: 1,
                    },
                    observed_generation: 1,
                    status: "done".to_owned(),
                    event: Some(17),
                }],
                note: "cleanup".to_owned(),
            });
        package
            .semantic
            .preemption_latency_samples
            .push(PreemptionLatencySampleManifest {
                id: 21,
                timer_interrupt: 14,
                timer_interrupt_generation: 1,
                preemption: 15,
                preemption_generation: 1,
                scheduler_decision: 16,
                scheduler_decision_generation: 1,
                activation_resume: 17,
                activation_resume_generation: 1,
                activation: 11,
                activation_generation_before: 2,
                activation_generation_after: 4,
                queue: 1,
                queue_generation: 1,
                interrupt_recorded_at_event: 11,
                preempted_at_event: 12,
                decided_at_event: 13,
                resumed_at_event: 14,
                interrupt_to_preempt_events: 1,
                preempt_to_decision_events: 1,
                decision_to_resume_events: 1,
                interrupt_to_resume_events: 3,
                measured_nanos: 8_500,
                budget_nanos: 50_000,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 19,
                note: "latency sample".to_owned(),
            });
        let hart = hart_view_v1(&package.semantic.hart_records[0]);
        assert_eq!(hart["kind"], "hart");
        assert_eq!(hart["owner"]["hardware_id"], 0);
        assert_eq!(hart["generation"], 2);
        assert_eq!(hart["state"], "idle");
        let current_hart = hart_view_v1(&HartRecordManifest {
            id: 2,
            hardware_id: 1,
            label: "hart1".to_owned(),
            state: "running".to_owned(),
            generation: 3,
            boot: false,
            current_activation: Some(11),
            current_activation_generation: Some(2),
            current_task: Some(7),
            current_task_generation: Some(1),
            current_store: None,
            current_store_generation: None,
            last_event: Some(21),
            last_current_event: Some(21),
            note: "current activation".to_owned(),
        });
        assert_eq!(
            current_hart["references"]["current_activation"]["generation"],
            2
        );
        assert_eq!(current_hart["references"]["current_task"]["id"], 7);
        let context = activation_context_view_v1(&package.semantic.activation_contexts[0]);
        assert_eq!(context["kind"], "activation-context");
        assert_eq!(context["references"]["activation"]["generation"], 2);
        assert_eq!(
            context["references"]["current_saved_context"]["generation"],
            1
        );
        let saved = saved_context_view_v1(&package.semantic.saved_contexts[0]);
        assert_eq!(saved["kind"], "saved-context");
        assert_eq!(saved["reason"], "timer-preempt");
        assert_eq!(saved["machine_frame"]["integer_registers"], 33);
        assert_eq!(saved["references"]["activation_context"]["generation"], 2);
        assert_eq!(saved["references"]["source_preemption"]["id"], 15);
        assert_eq!(saved["references"]["source_preemption"]["generation"], 1);
        assert_eq!(saved["vector_context"]["status"], "absent");
        let timer = timer_interrupt_view_v1(&package.semantic.timer_interrupts[0]);
        assert_eq!(timer["kind"], "timer-interrupt");
        assert_eq!(timer["owner"]["timer_epoch"], 3);
        assert_eq!(timer["owner"]["hart"]["id"], 1);
        assert_eq!(timer["owner"]["hart"]["generation"], 2);
        assert_eq!(timer["owner"]["hart"]["hardware_id"], 0);
        assert_eq!(timer["references"]["activation"]["generation"], 2);
        let ipi = ipi_event_view_v1(&package.semantic.ipi_events[0]);
        assert_eq!(ipi["kind"], "ipi-event");
        assert_eq!(ipi["owner"]["source_hart"]["generation"], 2);
        assert_eq!(ipi["owner"]["target_hart"]["hardware_id"], 1);
        assert_eq!(ipi["ipi_kind"], "scheduler-kick");
        let remote = remote_preempt_view_v1(&package.semantic.remote_preempts[0]);
        assert_eq!(remote["kind"], "remote-preempt");
        assert_eq!(remote["references"]["ipi"]["generation"], 1);
        assert_eq!(remote["references"]["activation"]["generation_after"], 3);
        let remote_park = remote_park_view_v1(&package.semantic.remote_parks[0]);
        assert_eq!(remote_park["kind"], "remote-park");
        assert_eq!(remote_park["references"]["ipi"]["id"], 23);
        assert_eq!(remote_park["owner"]["target_hart"]["generation_after"], 4);
        let hart_event =
            hart_event_attribution_view_v1(&package.semantic.hart_event_attributions[0]);
        assert_eq!(hart_event["kind"], "hart-event-attribution");
        assert_eq!(hart_event["owner"]["hart"]["generation"], 2);
        assert_eq!(
            hart_event["references"]["event"]["kind"],
            "TimerInterruptRecorded"
        );
        assert_eq!(hart_event["references"]["activation"]["id"], 11);
        let queue = runnable_queue_view_v1(&package.semantic.runnable_queues[0]);
        assert_eq!(queue["kind"], "runnable-queue");
        assert_eq!(queue["owner"]["hart"]["id"], 1);
        assert_eq!(queue["owner"]["hart"]["generation"], 2);
        let preemption = preemption_view_v1(&package.semantic.preemptions[0]);
        assert_eq!(preemption["kind"], "preemption");
        assert_eq!(
            preemption["references"]["activation"]["generation_before"],
            2
        );
        assert_eq!(
            preemption["references"]["activation"]["generation_after"],
            3
        );
        assert_eq!(preemption["references"]["timer_interrupt"]["generation"], 1);
        let decision = scheduler_decision_view_v1(&package.semantic.scheduler_decisions[0]);
        assert_eq!(decision["kind"], "scheduler-decision");
        assert_eq!(
            decision["references"]["selected_activation"]["generation"],
            3
        );
        assert_eq!(decision["references"]["queue"]["generation"], 1);
        assert_eq!(decision["reason"], "runnable-available");
        let cross_decision = cross_hart_scheduler_decision_view_v1(
            &package.semantic.cross_hart_scheduler_decisions[0],
        );
        assert_eq!(cross_decision["kind"], "cross-hart-scheduler-decision");
        assert_eq!(cross_decision["owner"]["deciding_hart"]["id"], 2);
        assert_eq!(cross_decision["owner"]["target_hart"]["id"], 1);
        assert_eq!(
            cross_decision["references"]["scheduler_decision"]["generation"],
            1
        );
        assert_eq!(
            cross_decision["references"]["queue"]["owner_hart_generation"],
            2
        );
        let migration = activation_migration_view_v1(&package.semantic.activation_migrations[0]);
        assert_eq!(migration["kind"], "activation-migration");
        assert_eq!(migration["owner"]["source_hart"]["id"], 2);
        assert_eq!(migration["owner"]["target_hart"]["id"], 1);
        assert_eq!(migration["references"]["activation"]["generation_after"], 4);
        assert_eq!(migration["references"]["target_queue"]["id"], 1);
        let safe_point = smp_safe_point_view_v1(&package.semantic.smp_safe_points[0]);
        assert_eq!(safe_point["kind"], "smp-safe-point");
        assert_eq!(safe_point["owner"]["coordinator_hart"]["id"], 1);
        assert_eq!(safe_point["references"]["participants"][0]["hart"]["id"], 1);
        assert_eq!(
            safe_point["references"]["participants"][0]["hart"]["generation"],
            2
        );
        assert_eq!(safe_point["last_transition"]["participant_count"], 2);
        let rendezvous =
            stop_the_world_rendezvous_view_v1(&package.semantic.stop_the_world_rendezvous[0]);
        assert_eq!(rendezvous["kind"], "stop-the-world-rendezvous");
        assert_eq!(rendezvous["epoch"], 1);
        assert_eq!(rendezvous["references"]["safe_point"]["id"], 28);
        assert_eq!(
            rendezvous["references"]["participants"][1]["hart"]["generation"],
            2
        );
        assert_eq!(rendezvous["stop_new_activations"], true);
        let barrier =
            smp_code_publish_barrier_view_v1(&package.semantic.smp_code_publish_barriers[0]);
        assert_eq!(barrier["kind"], "smp-code-publish-barrier");
        assert_eq!(barrier["references"]["rendezvous"]["id"], 29);
        assert_eq!(
            barrier["references"]["participants"][0]["semantic_icache_sync"],
            true
        );
        assert_eq!(barrier["last_transition"]["code_publish_epoch_after"], 1);
        assert_eq!(barrier["code_publish_executed"], false);
        let quiescence =
            smp_cleanup_quiescence_view_v1(&package.semantic.smp_cleanup_quiescence[0]);
        assert_eq!(quiescence["kind"], "smp-cleanup-quiescence");
        assert_eq!(quiescence["references"]["cleanup"]["id"], 20);
        assert_eq!(quiescence["references"]["store"]["target_generation"], 2);
        assert_eq!(quiescence["references"]["store"]["result_generation"], 4);
        assert_eq!(quiescence["references"]["rendezvous"]["id"], 29);
        assert_eq!(quiescence["postconditions"]["no_running_activation"], true);
        assert_eq!(
            quiescence["references"]["participants"][1]["quiesced"],
            true
        );
        let snapshot_barrier =
            smp_snapshot_barrier_view_v1(&package.semantic.smp_snapshot_barriers[0]);
        assert_eq!(snapshot_barrier["kind"], "smp-snapshot-barrier");
        assert_eq!(snapshot_barrier["references"]["rendezvous"]["id"], 29);
        assert_eq!(snapshot_barrier["last_transition"]["event_log_cursor"], 25);
        assert_eq!(
            snapshot_barrier["references"]["participants"][1]["snapshot_safe"],
            true
        );
        assert_eq!(
            snapshot_barrier["postconditions"]["snapshot_validation_ok"],
            true
        );
        let stress = smp_stress_run_view_v1(&package.semantic.smp_stress_runs[0]);
        assert_eq!(stress["kind"], "smp-stress-run");
        assert_eq!(stress["owner"]["scenario"], "s15-smp-stress-property");
        assert_eq!(stress["coverage"]["iterations"], 3);
        assert_eq!(stress["coverage"]["property_failures"], 0);
        assert_eq!(
            stress["references"]["last_snapshot_barrier"]["generation"],
            1
        );
        let scaling = smp_scaling_benchmark_view_v1(&package.semantic.smp_scaling_benchmarks[0]);
        assert_eq!(scaling["kind"], "smp-scaling-benchmark");
        assert_eq!(scaling["owner"]["scenario"], "s16-smp-scaling-benchmark");
        assert_eq!(scaling["references"]["stress_run"]["id"], 33);
        assert_eq!(scaling["metrics"]["workload_units"], 6);
        assert_eq!(scaling["metrics"]["measured_smp_nanos"], 72_000);
        assert_eq!(scaling["metrics"]["speedup_milli"], 1_666);
        assert_eq!(scaling["metrics"]["efficiency_milli"], 833);
        assert_eq!(scaling["coverage"]["stress_property_failures"], 0);
        let device = device_object_view_v1(&package.semantic.device_objects[0]);
        assert_eq!(device["kind"], "device");
        assert_eq!(device["owner"]["class"], "fake-device");
        assert_eq!(device["owner"]["backend"], "fake-io-backend");
        assert_eq!(device["references"]["resource"]["generation"], 1);
        assert_eq!(device["identity"]["model"], "fake-io-v1");
        let queue = queue_object_view_v1(&package.semantic.queue_objects[0]);
        assert_eq!(queue["kind"], "queue");
        assert_eq!(queue["owner"]["device"]["id"], 35);
        assert_eq!(queue["owner"]["device"]["generation"], 1);
        assert_eq!(queue["identity"]["role"], "rx");
        assert_eq!(queue["identity"]["queue_index"], 0);
        assert_eq!(queue["capacity"]["depth"], 64);
        let descriptor = descriptor_object_view_v1(&package.semantic.descriptor_objects[0]);
        assert_eq!(descriptor["kind"], "descriptor");
        assert_eq!(descriptor["owner"]["queue"]["id"], 36);
        assert_eq!(descriptor["owner"]["queue"]["generation"], 1);
        assert_eq!(descriptor["identity"]["slot"], 0);
        assert_eq!(descriptor["identity"]["access"], "read-write");
        assert_eq!(descriptor["capacity"]["length"], 2048);
        let dma_buffer = dma_buffer_object_view_v1(&package.semantic.dma_buffer_objects[0]);
        assert_eq!(dma_buffer["kind"], "dma-buffer");
        assert_eq!(dma_buffer["owner"]["descriptor"]["id"], 37);
        assert_eq!(dma_buffer["owner"]["descriptor"]["generation"], 1);
        assert_eq!(dma_buffer["references"]["resource"]["id"], 100);
        assert_eq!(dma_buffer["references"]["resource"]["generation"], 1);
        assert_eq!(dma_buffer["identity"]["access"], "read-write");
        assert_eq!(dma_buffer["capacity"]["length"], 2048);
        let mmio_region = mmio_region_object_view_v1(&package.semantic.mmio_region_objects[0]);
        assert_eq!(mmio_region["kind"], "mmio-region");
        assert_eq!(mmio_region["owner"]["device"]["id"], 35);
        assert_eq!(mmio_region["owner"]["device"]["generation"], 1);
        assert_eq!(mmio_region["references"]["resource"]["id"], 101);
        assert_eq!(mmio_region["references"]["resource"]["generation"], 1);
        assert_eq!(mmio_region["identity"]["region_index"], 0);
        assert_eq!(mmio_region["identity"]["offset"], 0x1000);
        assert_eq!(mmio_region["identity"]["access"], "read-write");
        assert_eq!(mmio_region["capacity"]["length"], 0x100);
        let irq_line = irq_line_object_view_v1(&package.semantic.irq_line_objects[0]);
        assert_eq!(irq_line["kind"], "irq-line");
        assert_eq!(irq_line["owner"]["device"]["id"], 35);
        assert_eq!(irq_line["owner"]["device"]["generation"], 1);
        assert_eq!(irq_line["references"]["resource"]["id"], 102);
        assert_eq!(irq_line["references"]["resource"]["generation"], 1);
        assert_eq!(irq_line["identity"]["irq_number"], 5);
        assert_eq!(irq_line["identity"]["trigger"], "level");
        assert_eq!(irq_line["identity"]["polarity"], "active-high");
        let irq_event = irq_event_view_v1(&package.semantic.irq_events[0]);
        assert_eq!(irq_event["kind"], "irq-event");
        assert_eq!(irq_event["owner"]["device"]["id"], 35);
        assert_eq!(irq_event["owner"]["driver_store"]["id"], 1);
        assert_eq!(irq_event["owner"]["driver_store"]["generation"], 2);
        assert_eq!(irq_event["references"]["irq_line"]["id"], 40);
        assert_eq!(irq_event["references"]["irq_line"]["generation"], 1);
        assert_eq!(irq_event["identity"]["irq_number"], 5);
        assert_eq!(irq_event["identity"]["sequence"], 1);
        let device_capability = device_capability_view_v1(&package.semantic.device_capabilities[0]);
        assert_eq!(device_capability["kind"], "device-capability");
        assert_eq!(device_capability["owner"]["driver_store"]["generation"], 2);
        assert_eq!(device_capability["references"]["target"]["id"], 39);
        assert_eq!(device_capability["references"]["target"]["generation"], 1);
        assert_eq!(device_capability["references"]["capability"]["id"], 7);
        assert_eq!(device_capability["authority"]["class"], "mmio-region");
        assert_eq!(device_capability["authority"]["operation"], "write32");
        assert_eq!(device_capability["authority"]["handle"]["slot"], 3);
        let binding = driver_store_binding_view_v1(&package.semantic.driver_store_bindings[0]);
        assert_eq!(binding["kind"], "driver-store-binding");
        assert_eq!(binding["owner"]["driver_store"]["generation"], 2);
        assert_eq!(binding["owner"]["device"]["id"], 35);
        assert_eq!(binding["references"]["device_capability"]["id"], 43);
        assert_eq!(binding["references"]["capability"]["generation"], 1);
        let io_wait = io_wait_view_v1(&package.semantic.io_waits[0]);
        assert_eq!(io_wait["kind"], "io-wait");
        assert_eq!(io_wait["owner"]["driver_store"]["generation"], 2);
        assert_eq!(io_wait["references"]["wait"]["id"], 45);
        assert_eq!(io_wait["references"]["blocker"]["kind"], "irq-line-object");
        assert_eq!(io_wait["references"]["completion_irq_event"]["id"], 41);
        assert_eq!(io_wait["last_transition"]["completed_at_event"], 40);
        let resume = activation_resume_view_v1(&package.semantic.activation_resumes[0]);
        assert_eq!(resume["kind"], "activation-resume");
        assert_eq!(resume["references"]["activation"]["generation_before"], 3);
        assert_eq!(resume["references"]["activation"]["generation_after"], 4);
        assert_eq!(resume["references"]["scheduler_decision"]["generation"], 1);
        assert_eq!(resume["references"]["saved_context"]["generation"], 2);
        let activation_wait = activation_wait_view_v1(&package.semantic.activation_waits[0]);
        assert_eq!(activation_wait["kind"], "activation-wait");
        assert_eq!(
            activation_wait["references"]["activation"]["generation_before"],
            4
        );
        assert_eq!(
            activation_wait["references"]["activation"]["generation_after_block"],
            5
        );
        assert_eq!(
            activation_wait["references"]["activation"]["generation_after_cancel"],
            6
        );
        assert_eq!(activation_wait["references"]["wait"]["generation"], 1);
        assert_eq!(activation_wait["cancel_reason"], "timeout");
        let activation_cleanup =
            activation_cleanup_view_v1(&package.semantic.activation_cleanups[0]);
        assert_eq!(activation_cleanup["kind"], "activation-cleanup");
        assert_eq!(activation_cleanup["owner"]["target_store_generation"], 2);
        assert_eq!(activation_cleanup["owner"]["result_store_generation"], 4);
        assert_eq!(
            activation_cleanup["references"]["activation"]["generation_after"],
            6
        );
        assert_eq!(
            activation_cleanup["references"]["steps"][0]["target"]["kind"],
            "wait-token"
        );
        let latency = preemption_latency_view_v1(&package.semantic.preemption_latency_samples[0]);
        assert_eq!(latency["kind"], "preemption-latency");
        assert_eq!(latency["references"]["timer_interrupt"]["generation"], 1);
        assert_eq!(latency["event_window"]["interrupt_to_resume_events"], 3);
        assert_eq!(latency["metrics"]["measured_nanos"], 8_500);
        assert_eq!(latency["metrics"]["within_budget"], true);
        let scheduler = scheduler_view_v1(&package);
        assert_eq!(scheduler["kind"], "scheduler");
        assert_eq!(scheduler["references"]["harts"][0]["hardware_id"], 0);
        assert_eq!(scheduler["last_transition"]["hart_count"], 2);
        assert_eq!(scheduler["references"]["queues"][0]["entries"], 1);
        assert_eq!(scheduler["references"]["queues"][0]["owner_hart"], 1);
        assert_eq!(
            scheduler["references"]["queues"][0]["owner_hart_generation"],
            2
        );
        assert_eq!(scheduler["references"]["preemptions"][0]["activation"], 11);
        assert_eq!(
            scheduler["references"]["scheduler_decisions"][0]["selected_activation_generation"],
            3
        );
        assert_eq!(scheduler["last_transition"]["activation_context_count"], 1);
        assert_eq!(scheduler["last_transition"]["saved_context_count"], 1);
        assert_eq!(scheduler["last_transition"]["timer_interrupt_count"], 1);
        assert_eq!(scheduler["last_transition"]["ipi_event_count"], 1);
        assert_eq!(scheduler["last_transition"]["remote_preempt_count"], 1);
        assert_eq!(scheduler["last_transition"]["remote_park_count"], 1);
        assert_eq!(scheduler["references"]["ipi_events"][0]["target_hart"], 2);
        assert_eq!(
            scheduler["references"]["remote_preempts"][0]["activation_generation_after"],
            3
        );
        assert_eq!(scheduler["references"]["remote_parks"][0]["target_hart"], 2);
        assert_eq!(
            scheduler["last_transition"]["hart_event_attribution_count"],
            1
        );
        assert_eq!(
            scheduler["references"]["hart_event_attributions"][0]["event_kind"],
            "TimerInterruptRecorded"
        );
        assert_eq!(scheduler["last_transition"]["preemption_count"], 1);
        assert_eq!(scheduler["last_transition"]["scheduler_decision_count"], 1);
        assert_eq!(
            scheduler["last_transition"]["cross_hart_scheduler_decision_count"],
            1
        );
        assert_eq!(
            scheduler["references"]["cross_hart_scheduler_decisions"][0]["target_hart"],
            1
        );
        assert_eq!(
            scheduler["last_transition"]["activation_migration_count"],
            1
        );
        assert_eq!(
            scheduler["references"]["activation_migrations"][0]["activation_generation_after"],
            4
        );
        assert_eq!(scheduler["last_transition"]["smp_safe_point_count"], 1);
        assert_eq!(
            scheduler["references"]["smp_safe_points"][0]["participant_count"],
            2
        );
        assert_eq!(
            scheduler["last_transition"]["stop_the_world_rendezvous_count"],
            1
        );
        assert_eq!(
            scheduler["references"]["stop_the_world_rendezvous"][0]["safe_point"],
            28
        );
        assert_eq!(
            scheduler["last_transition"]["smp_code_publish_barrier_count"],
            1
        );
        assert_eq!(
            scheduler["references"]["smp_code_publish_barriers"][0]["rendezvous"],
            29
        );
        assert_eq!(
            scheduler["last_transition"]["smp_cleanup_quiescence_count"],
            1
        );
        assert_eq!(
            scheduler["references"]["smp_cleanup_quiescence"][0]["cleanup"],
            20
        );
        assert_eq!(
            scheduler["last_transition"]["smp_snapshot_barrier_count"],
            1
        );
        assert_eq!(
            scheduler["references"]["smp_snapshot_barriers"][0]["rendezvous"],
            29
        );
        assert_eq!(scheduler["last_transition"]["smp_stress_run_count"], 1);
        assert_eq!(
            scheduler["references"]["smp_stress_runs"][0]["property_failures"],
            0
        );
        assert_eq!(
            scheduler["last_transition"]["smp_scaling_benchmark_count"],
            1
        );
        assert_eq!(
            scheduler["references"]["smp_scaling_benchmarks"][0]["efficiency_milli"],
            833
        );
        assert_eq!(scheduler["last_transition"]["activation_resume_count"], 1);
        assert_eq!(scheduler["last_transition"]["activation_wait_count"], 1);
        assert_eq!(scheduler["last_transition"]["activation_cleanup_count"], 1);
        assert_eq!(
            scheduler["last_transition"]["preemption_latency_sample_count"],
            1
        );
        assert_eq!(scheduler["last_transition"]["timer_epoch"], 3);
        assert_eq!(
            scheduler["last_transition"]["scheduler_decision_cursor"],
            12
        );

        let live_edges = live_graph_edges(&package);
        assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "task"
            && edge["from"]["generation"] == 1
            && edge["to"]["kind"] == "activation"
            && edge["to"]["generation"] == 2));
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "device"
                    && edge["to"]["kind"] == "resource"
                    && edge["to"]["id"] == 99
                    && edge["relation"] == "device-resource"
                    && edge["mode"] == "live")
        );
        assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "queue"
            && edge["to"]["kind"] == "device"
            && edge["to"]["id"] == 35
            && edge["to"]["generation"] == 1
            && edge["relation"] == "queue-device"
            && edge["mode"] == "live"));
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "descriptor"
                    && edge["to"]["kind"] == "queue"
                    && edge["to"]["id"] == 36
                    && edge["to"]["generation"] == 1
                    && edge["relation"] == "descriptor-queue"
                    && edge["mode"] == "live")
        );
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "dma-buffer"
                    && edge["to"]["kind"] == "descriptor"
                    && edge["to"]["id"] == 37
                    && edge["to"]["generation"] == 1
                    && edge["relation"] == "dma-buffer-descriptor"
                    && edge["mode"] == "live")
        );
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "dma-buffer"
                    && edge["to"]["kind"] == "resource"
                    && edge["to"]["id"] == 100
                    && edge["to"]["generation"] == 1
                    && edge["relation"] == "dma-buffer-resource"
                    && edge["mode"] == "live")
        );
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "mmio-region"
                    && edge["to"]["kind"] == "device"
                    && edge["to"]["id"] == 35
                    && edge["to"]["generation"] == 1
                    && edge["relation"] == "mmio-region-device"
                    && edge["mode"] == "live")
        );
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "mmio-region"
                    && edge["to"]["kind"] == "resource"
                    && edge["to"]["id"] == 101
                    && edge["to"]["generation"] == 1
                    && edge["relation"] == "mmio-region-resource"
                    && edge["mode"] == "live")
        );
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "irq-line"
                    && edge["to"]["kind"] == "device"
                    && edge["to"]["id"] == 35
                    && edge["to"]["generation"] == 1
                    && edge["relation"] == "irq-line-device"
                    && edge["mode"] == "live")
        );
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "irq-line"
                    && edge["to"]["kind"] == "resource"
                    && edge["to"]["id"] == 102
                    && edge["to"]["generation"] == 1
                    && edge["relation"] == "irq-line-resource"
                    && edge["mode"] == "live")
        );
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "activation"
                    && edge["to"]["kind"] == "runnable-queue"
                    && edge["to"]["generation"] == 1)
        );
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "activation"
                    && edge["to"]["kind"] == "activation-context"
                    && edge["to"]["generation"] == 2)
        );
        assert!(
            live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "activation-context"
                    && edge["to"]["kind"] == "saved-context"
                    && edge["to"]["generation"] == 1)
        );
        assert!(
            !live_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "timer-interrupt")
        );
        let history_edges = history_graph_edges(&package);
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "timer-interrupt"
                    && edge["to"]["kind"] == "activation"
                    && edge["to"]["generation"] == 2
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "preemption"
                    && edge["to"]["kind"] == "activation"
                    && edge["to"]["generation"] == 3
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "saved-context"
                    && edge["to"]["kind"] == "preemption"
                    && edge["to"]["generation"] == 1
                    && edge["relation"] == "captured-from-preemption"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "scheduler-decision"
                    && edge["to"]["kind"] == "activation"
                    && edge["to"]["generation"] == 3
                    && edge["relation"] == "selected"
                    && edge["mode"] == "historical")
        );
        assert!(history_edges.iter().any(|edge| edge["from"]["kind"]
            == "cross-hart-scheduler-decision"
            && edge["to"]["kind"] == "hart"
            && edge["to"]["id"] == 1
            && edge["relation"] == "target-hart"
            && edge["mode"] == "historical"));
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "activation-migration"
                    && edge["to"]["kind"] == "activation"
                    && edge["to"]["generation"] == 4
                    && edge["relation"] == "migrated-to"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "smp-safe-point"
                    && edge["to"]["kind"] == "hart"
                    && edge["to"]["id"] == 1
                    && edge["relation"] == "coordinator-hart"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "smp-safe-point"
                    && edge["to"]["kind"] == "hart"
                    && edge["to"]["id"] == 2
                    && edge["relation"] == "participant-hart"
                    && edge["mode"] == "historical")
        );
        assert!(history_edges.iter().any(|edge| edge["from"]["kind"]
            == "stop-the-world-rendezvous"
            && edge["to"]["kind"] == "smp-safe-point"
            && edge["to"]["id"] == 28
            && edge["relation"] == "rendezvous-safe-point"
            && edge["mode"] == "historical"));
        assert!(history_edges.iter().any(|edge| edge["from"]["kind"]
            == "stop-the-world-rendezvous"
            && edge["to"]["kind"] == "hart"
            && edge["to"]["id"] == 2
            && edge["relation"] == "participant-hart"
            && edge["mode"] == "historical"));
        assert!(history_edges.iter().any(|edge| edge["from"]["kind"]
            == "smp-code-publish-barrier"
            && edge["to"]["kind"] == "stop-the-world-rendezvous"
            && edge["to"]["id"] == 29
            && edge["relation"] == "publish-rendezvous"
            && edge["mode"] == "historical"));
        assert!(history_edges.iter().any(|edge| edge["from"]["kind"]
            == "smp-code-publish-barrier"
            && edge["to"]["kind"] == "hart"
            && edge["to"]["id"] == 2
            && edge["relation"] == "participant-hart"
            && edge["mode"] == "historical"));
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "smp-cleanup-quiescence"
                    && edge["to"]["kind"] == "activation-cleanup"
                    && edge["to"]["id"] == 20
                    && edge["relation"] == "cleanup"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "smp-cleanup-quiescence"
                    && edge["to"]["kind"] == "stop-the-world-rendezvous"
                    && edge["to"]["id"] == 29
                    && edge["relation"] == "cleanup-rendezvous"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "smp-snapshot-barrier"
                    && edge["to"]["kind"] == "stop-the-world-rendezvous"
                    && edge["to"]["id"] == 29
                    && edge["relation"] == "snapshot-rendezvous"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "smp-stress-run"
                    && edge["to"]["kind"] == "smp-snapshot-barrier"
                    && edge["to"]["id"] == 32
                    && edge["relation"] == "last-snapshot-barrier"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "smp-scaling-benchmark"
                    && edge["to"]["kind"] == "smp-stress-run"
                    && edge["to"]["id"] == 33
                    && edge["relation"] == "scaling-stress-run"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "device"
                    && edge["to"]["kind"] == "resource"
                    && edge["to"]["id"] == 99
                    && edge["relation"] == "device-resource"
                    && edge["mode"] == "live")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "queue"
                    && edge["to"]["kind"] == "device"
                    && edge["to"]["id"] == 35
                    && edge["relation"] == "queue-device"
                    && edge["mode"] == "live")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "descriptor"
                    && edge["to"]["kind"] == "queue"
                    && edge["to"]["id"] == 36
                    && edge["relation"] == "descriptor-queue"
                    && edge["mode"] == "live")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "dma-buffer"
                    && edge["to"]["kind"] == "descriptor"
                    && edge["to"]["id"] == 37
                    && edge["relation"] == "dma-buffer-descriptor"
                    && edge["mode"] == "live")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "dma-buffer"
                    && edge["to"]["kind"] == "resource"
                    && edge["to"]["id"] == 100
                    && edge["relation"] == "dma-buffer-resource"
                    && edge["mode"] == "live")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "mmio-region"
                    && edge["to"]["kind"] == "device"
                    && edge["to"]["id"] == 35
                    && edge["relation"] == "mmio-region-device"
                    && edge["mode"] == "live")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "mmio-region"
                    && edge["to"]["kind"] == "resource"
                    && edge["to"]["id"] == 101
                    && edge["relation"] == "mmio-region-resource"
                    && edge["mode"] == "live")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "irq-line"
                    && edge["to"]["kind"] == "device"
                    && edge["to"]["id"] == 35
                    && edge["relation"] == "irq-line-device"
                    && edge["mode"] == "live")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "irq-line"
                    && edge["to"]["kind"] == "resource"
                    && edge["to"]["id"] == 102
                    && edge["relation"] == "irq-line-resource"
                    && edge["mode"] == "live")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "irq-event"
                    && edge["to"]["kind"] == "irq-line"
                    && edge["to"]["id"] == 40
                    && edge["relation"] == "irq-event-line"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "irq-event"
                    && edge["to"]["kind"] == "device"
                    && edge["to"]["id"] == 35
                    && edge["relation"] == "irq-event-device"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "irq-event"
                    && edge["to"]["kind"] == "store"
                    && edge["to"]["id"] == 1
                    && edge["relation"] == "irq-event-driver-store"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "activation-resume"
                    && edge["to"]["kind"] == "activation"
                    && edge["to"]["generation"] == 4
                    && edge["relation"] == "resumed-to"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "activation-wait"
                    && edge["to"]["kind"] == "activation"
                    && edge["to"]["generation"] == 6
                    && edge["relation"] == "cancelled-to"
                    && edge["mode"] == "historical")
        );
        assert!(
            history_edges
                .iter()
                .any(|edge| edge["from"]["kind"] == "preemption-latency"
                    && edge["to"]["kind"] == "activation-resume"
                    && edge["to"]["generation"] == 1
                    && edge["relation"] == "measured-resume"
                    && edge["mode"] == "historical")
        );
    }

    #[test]
    fn scheduler_view_v1_exposes_current_activation_owners() {
        let mut package = minimal_graph_package();
        package.package_id = "s4-test".to_owned();
        package.semantic.hart_count = 1;
        package.semantic.hart_records.push(HartRecordManifest {
            id: 2,
            hardware_id: 1,
            label: "hart1".to_owned(),
            state: "running".to_owned(),
            generation: 3,
            boot: false,
            current_activation: Some(11),
            current_activation_generation: Some(4),
            current_task: Some(7),
            current_task_generation: Some(1),
            current_store: Some(5),
            current_store_generation: Some(2),
            last_event: Some(21),
            last_current_event: Some(21),
            note: "s4 current owner".to_owned(),
        });

        let scheduler = scheduler_view_v1(&package);
        assert_eq!(
            scheduler["references"]["current_activation_owners"][0]["hart"]["id"],
            2
        );
        assert_eq!(
            scheduler["references"]["current_activation_owners"][0]["activation"]["generation"],
            4
        );
        assert_eq!(
            scheduler["references"]["current_activation_owners"][0]["store"]["generation"],
            2
        );
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
            simd_requirement: artifact_manifest::CodeObjectSimdRequirementManifest {
                uses_simd: true,
                declared: true,
                required_abi: "riscv-v".to_owned(),
                min_vector_register_count: 32,
                min_vector_register_bits: 128,
                target_feature_set: Some(ContractObjectRefManifest {
                    kind: "target-feature-set".to_owned(),
                    id: 21_000,
                    generation: 1,
                }),
                status: "declared".to_owned(),
                note: "requires RVV".to_owned(),
            },
            ..CodeObjectManifest::default()
        });
        assert_eq!(code["kind"], "code-object");
        assert_eq!(code["generation"], 4);
        assert_eq!(code["references"]["bound_store"]["generation"], 7);
        assert_eq!(code["memory"]["text"]["permission"], "rx");
        assert_eq!(code["simd_requirement"]["uses_simd"], true);
        assert_eq!(code["simd_requirement"]["required_abi"], "riscv-v");
        assert_eq!(
            code["simd_requirement"]["target_feature_set"]["kind"],
            "target-feature-set"
        );
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
            trap_kind: Some("simd-unsupported".to_owned()),
            simd_attribution: Some(artifact_manifest::SimdTrapAttributionManifest {
                classification: "unsupported-target-profile".to_owned(),
                required_abi: "riscv-v".to_owned(),
                min_vector_register_count: 32,
                min_vector_register_bits: 128,
                target_feature_set: Some(ContractObjectRefManifest {
                    kind: "target-feature-set".to_owned(),
                    id: 21_000,
                    generation: 1,
                }),
                code_requirement_status: "declared".to_owned(),
                note: "SIMD trap attribution".to_owned(),
            }),
            fault_policy: "restart".to_owned(),
            effect: "cleanup".to_owned(),
            detail: "denied".to_owned(),
            ..TrapRecordManifest::default()
        });
        assert_eq!(trap["kind"], "trap");
        assert_eq!(trap["owner"]["activation_generation"], 6);
        assert_eq!(trap["references"]["code_object"]["generation"], 4);
        assert_eq!(
            trap["simd_attribution"]["classification"],
            "unsupported-target-profile"
        );
        assert_eq!(
            trap["simd_attribution"]["target_feature_set"]["generation"],
            1
        );
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
        package.semantic.io_cleanups.push(IoCleanupManifest {
            id: 70,
            driver_store: 1,
            driver_store_generation: 2,
            device: 35,
            device_generation: 1,
            driver_binding: 44,
            driver_binding_generation: 1,
            generation: 1,
            state: "completed".to_owned(),
            reason: "device-fault".to_owned(),
            started_at_event: 10,
            completed_at_event: 11,
            cancelled_io_waits: vec![ContractObjectRefManifest {
                kind: "io-wait".to_owned(),
                id: 46,
                generation: 1,
            }],
            revoked_device_capabilities: vec![ContractObjectRefManifest {
                kind: "device-capability".to_owned(),
                id: 42,
                generation: 1,
            }],
            revoked_capabilities: vec![ContractObjectRefManifest {
                kind: "capability".to_owned(),
                id: 20,
                generation: 1,
            }],
            released_dma_buffers: vec![ContractObjectRefManifest {
                kind: "dma-buffer-object".to_owned(),
                id: 38,
                generation: 1,
            }],
            released_mmio_regions: vec![ContractObjectRefManifest {
                kind: "mmio-region-object".to_owned(),
                id: 39,
                generation: 1,
            }],
            released_irq_lines: vec![ContractObjectRefManifest {
                kind: "irq-line-object".to_owned(),
                id: 40,
                generation: 1,
            }],
            steps: Vec::new(),
            note: "io cleanup graph".to_owned(),
        });
        package
            .semantic
            .io_fault_injections
            .push(IoFaultInjectionManifest {
                id: 71,
                driver_store: 1,
                driver_store_generation: 2,
                device: 35,
                device_generation: 1,
                driver_binding: 44,
                driver_binding_generation: 1,
                target: ContractObjectRefManifest {
                    kind: "irq-line-object".to_owned(),
                    id: 40,
                    generation: 1,
                },
                cleanup: 70,
                cleanup_generation: 1,
                generation: 1,
                kind: "device-fault".to_owned(),
                state: "completed".to_owned(),
                injected_at_event: 12,
                note: "io fault graph".to_owned(),
            });
        package
            .semantic
            .packet_buffer_objects
            .push(PacketBufferObjectManifest {
                id: 80,
                packet_device: 81,
                packet_device_generation: 1,
                direction: "rx".to_owned(),
                frame_format_version: 2,
                capacity: 512,
                payload_len: 64,
                sequence: 1,
                generation: 1,
                state: "filled".to_owned(),
                recorded_at_event: 13,
                note: "packet buffer graph".to_owned(),
            });
        package
            .semantic
            .packet_queue_objects
            .push(PacketQueueObjectManifest {
                id: 82,
                name: "net0-rx0".to_owned(),
                packet_device: 81,
                packet_device_generation: 1,
                role: "rx".to_owned(),
                queue_index: 0,
                depth: 4,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 14,
                note: "packet queue graph".to_owned(),
            });
        package
            .semantic
            .packet_descriptors
            .push(PacketDescriptorObjectManifest {
                id: 83,
                packet_queue: 82,
                packet_queue_generation: 1,
                packet_buffer: 80,
                packet_buffer_generation: 1,
                slot: 0,
                length: 64,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 15,
                note: "packet descriptor graph".to_owned(),
            });
        package
            .semantic
            .fake_net_backends
            .push(FakeNetBackendObjectManifest {
                id: 84,
                name: "fake-net0".to_owned(),
                packet_device: 81,
                packet_device_generation: 1,
                provider: "service_core".to_owned(),
                profile: "fake-net-v1".to_owned(),
                mtu: 1500,
                rx_queue_depth: 4,
                tx_queue_depth: 4,
                mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
                frame_format_version: 2,
                max_payload_len: 512,
                deterministic_seed: 7,
                generation: 1,
                state: "bound".to_owned(),
                recorded_at_event: 16,
                note: "fake net backend graph".to_owned(),
            });
        package
            .semantic
            .virtio_net_backends
            .push(VirtioNetBackendObjectManifest {
                id: 85,
                name: "virtio-net0-backend".to_owned(),
                packet_device: 81,
                packet_device_generation: 1,
                driver_binding: 70,
                driver_binding_generation: 1,
                device: 61,
                device_generation: 1,
                provider: "substrate_virtio".to_owned(),
                profile: "virtio-net-backend-skeleton-v1".to_owned(),
                model: "virtio-net".to_owned(),
                mtu: 1500,
                rx_queue_depth: 4,
                tx_queue_depth: 4,
                mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
                frame_format_version: 2,
                max_payload_len: 512,
                device_features: 32,
                driver_features: 32,
                negotiated_features: 32,
                rx_queue_index: 0,
                tx_queue_index: 1,
                queue_size: 4,
                irq_vector: 5,
                generation: 1,
                state: "skeleton-ready".to_owned(),
                recorded_at_event: 17,
                note: "virtio net backend graph".to_owned(),
            });
        package
            .semantic
            .network_rx_interrupts
            .push(NetworkRxInterruptManifest {
                id: 86,
                virtio_net_backend: 85,
                virtio_net_backend_generation: 1,
                irq_event: 41,
                irq_event_generation: 1,
                packet_device: 81,
                packet_device_generation: 1,
                rx_queue: 82,
                rx_queue_generation: 1,
                ready_descriptors: 1,
                sequence: 1,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 18,
                note: "network rx interrupt graph".to_owned(),
            });
        package
            .semantic
            .network_rx_wait_resolutions
            .push(NetworkRxWaitResolutionManifest {
                id: 87,
                io_wait: 50,
                io_wait_generation: 1,
                wait: 5,
                wait_generation: 1,
                rx_interrupt: 86,
                rx_interrupt_generation: 1,
                irq_event: 41,
                irq_event_generation: 1,
                packet_device: 81,
                packet_device_generation: 1,
                rx_queue: 82,
                rx_queue_generation: 1,
                ready_descriptors: 1,
                sequence: 1,
                generation: 1,
                state: "resolved".to_owned(),
                resolved_at_event: 19,
                note: "network rx wait resolution graph".to_owned(),
            });
        package
            .semantic
            .packet_buffer_objects
            .push(PacketBufferObjectManifest {
                id: 88,
                packet_device: 81,
                packet_device_generation: 1,
                direction: "tx".to_owned(),
                frame_format_version: 2,
                capacity: 512,
                payload_len: 64,
                sequence: 2,
                generation: 1,
                state: "filled".to_owned(),
                recorded_at_event: 20,
                note: "tx packet buffer graph".to_owned(),
            });
        package
            .semantic
            .packet_queue_objects
            .push(PacketQueueObjectManifest {
                id: 89,
                name: "net0-tx0".to_owned(),
                packet_device: 81,
                packet_device_generation: 1,
                role: "tx".to_owned(),
                queue_index: 1,
                depth: 4,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 21,
                note: "tx packet queue graph".to_owned(),
            });
        package
            .semantic
            .packet_descriptors
            .push(PacketDescriptorObjectManifest {
                id: 90,
                packet_queue: 89,
                packet_queue_generation: 1,
                packet_buffer: 88,
                packet_buffer_generation: 1,
                slot: 0,
                length: 64,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 22,
                note: "tx packet descriptor graph".to_owned(),
            });
        package
            .semantic
            .network_tx_capability_gates
            .push(NetworkTxCapabilityGateManifest {
                id: 91,
                driver_store: 1,
                driver_store_generation: 2,
                packet_device: 81,
                packet_device_generation: 1,
                tx_queue: 89,
                tx_queue_generation: 1,
                packet_descriptor: 90,
                packet_descriptor_generation: 1,
                packet_buffer: 88,
                packet_buffer_generation: 1,
                device_capability: 42,
                device_capability_generation: 1,
                capability: 1,
                capability_generation: 1,
                handle_slot: 1,
                handle_generation: 1,
                handle_tag: 9,
                operation: "tx".to_owned(),
                byte_len: 64,
                sequence: 2,
                generation: 1,
                state: "allowed".to_owned(),
                recorded_at_event: 23,
                note: "network tx capability gate graph".to_owned(),
            });
        package
            .semantic
            .network_tx_completions
            .push(NetworkTxCompletionManifest {
                id: 92,
                tx_gate: 91,
                tx_gate_generation: 1,
                backend_kind: "virtio-net-backend-object".to_owned(),
                backend: 85,
                backend_generation: 1,
                driver_store: 1,
                driver_store_generation: 2,
                packet_device: 81,
                packet_device_generation: 1,
                tx_queue: 89,
                tx_queue_generation: 1,
                packet_descriptor: 90,
                packet_descriptor_generation: 1,
                packet_buffer: 88,
                packet_buffer_generation: 1,
                byte_len: 64,
                sequence: 2,
                completion_sequence: 1,
                generation: 1,
                state: "completed".to_owned(),
                completed_at_event: 24,
                note: "network tx completion graph".to_owned(),
            });
        package
            .semantic
            .network_stack_adapters
            .push(NetworkStackAdapterManifest {
                id: 93,
                implementation: "smoltcp".to_owned(),
                implementation_version: "0.13.0".to_owned(),
                profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_owned(),
                medium: "ethernet".to_owned(),
                backend_kind: "virtio-net-backend-object".to_owned(),
                backend: 85,
                backend_generation: 1,
                packet_device: 81,
                packet_device_generation: 1,
                rx_queue: 82,
                rx_queue_generation: 1,
                tx_queue: 89,
                tx_queue_generation: 1,
                mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
                ipv4_addr: [10, 0, 2, 15],
                ipv4_prefix_len: 24,
                mtu: 1500,
                rx_queue_depth: 4,
                tx_queue_depth: 4,
                max_payload_len: 512,
                socket_capacity: 0,
                generation: 1,
                state: "bound".to_owned(),
                recorded_at_event: 25,
                note: "network stack adapter graph".to_owned(),
            });
        package.semantic.socket_objects.push(SocketObjectManifest {
            id: 94,
            adapter: 93,
            adapter_generation: 1,
            owner_store: 1,
            owner_store_generation: 2,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            canonical_protocol: 6,
            family: "inet".to_owned(),
            transport: "tcp".to_owned(),
            generation: 1,
            state: "created".to_owned(),
            created_at_event: 26,
            note: "socket object graph".to_owned(),
        });
        package
            .semantic
            .endpoint_objects
            .push(EndpointObjectManifest {
                id: 95,
                socket: 94,
                socket_generation: 1,
                adapter: 93,
                adapter_generation: 1,
                owner_store: 1,
                owner_store_generation: 2,
                family: "inet".to_owned(),
                transport: "tcp".to_owned(),
                local_addr: [0, 0, 0, 0],
                local_port: 0,
                remote_addr: [0, 0, 0, 0],
                remote_port: 0,
                generation: 1,
                state: "allocated".to_owned(),
                created_at_event: 27,
                note: "endpoint object graph".to_owned(),
            });
        package
            .semantic
            .socket_operations
            .push(SocketOperationManifest {
                id: 96,
                endpoint: 95,
                endpoint_generation: 1,
                socket: 94,
                socket_generation: 1,
                adapter: 93,
                adapter_generation: 1,
                owner_store: 1,
                owner_store_generation: 2,
                operation: "bind".to_owned(),
                local_addr: [10, 0, 2, 15],
                local_port: 8080,
                remote_addr: [0, 0, 0, 0],
                remote_port: 0,
                backlog: 0,
                byte_len: 0,
                sequence: 1,
                generation: 1,
                state: "applied".to_owned(),
                recorded_at_event: 28,
                note: "socket operation graph".to_owned(),
            });
        package.semantic.socket_waits.push(SocketWaitManifest {
            id: 97,
            wait: 45,
            wait_generation: 1,
            endpoint: 95,
            endpoint_generation: 1,
            socket: 94,
            socket_generation: 1,
            adapter: 93,
            adapter_generation: 1,
            owner_store: 1,
            owner_store_generation: 2,
            wait_kind: "socket-readable".to_owned(),
            blocker: ContractObjectRefManifest {
                kind: "endpoint-object".to_owned(),
                id: 95,
                generation: 1,
            },
            generation: 1,
            state: "pending".to_owned(),
            created_at_event: 29,
            completed_at_event: None,
            cancel_reason: None,
            ready_sequence: None,
            byte_len: None,
            note: "pending socket wait graph".to_owned(),
        });
        package.semantic.socket_waits.push(SocketWaitManifest {
            id: 98,
            wait: 46,
            wait_generation: 1,
            endpoint: 95,
            endpoint_generation: 1,
            socket: 94,
            socket_generation: 1,
            adapter: 93,
            adapter_generation: 1,
            owner_store: 1,
            owner_store_generation: 2,
            wait_kind: "socket-readable".to_owned(),
            blocker: ContractObjectRefManifest {
                kind: "endpoint-object".to_owned(),
                id: 95,
                generation: 1,
            },
            generation: 1,
            state: "resolved".to_owned(),
            created_at_event: 30,
            completed_at_event: Some(31),
            cancel_reason: None,
            ready_sequence: Some(1),
            byte_len: Some(19),
            note: "resolved socket wait graph".to_owned(),
        });
        package
            .semantic
            .network_backpressures
            .push(NetworkBackpressureManifest {
                id: 99,
                adapter: 93,
                adapter_generation: 1,
                packet_device: 81,
                packet_device_generation: 1,
                packet_queue: 89,
                packet_queue_generation: 1,
                endpoint: Some(95),
                endpoint_generation: Some(1),
                socket: Some(94),
                socket_generation: Some(1),
                owner_store: Some(1),
                owner_store_generation: Some(2),
                direction: "tx".to_owned(),
                reason: "queue-full".to_owned(),
                action: "reject-send".to_owned(),
                queue_depth: 4,
                queue_limit: 4,
                dropped_packets: 0,
                dropped_bytes: 0,
                sequence: 2,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 32,
                note: "network backpressure graph".to_owned(),
            });
        package
            .semantic
            .network_driver_cleanups
            .push(NetworkDriverCleanupManifest {
                id: 100,
                io_cleanup: 70,
                io_cleanup_generation: 1,
                driver_store: 1,
                driver_store_generation: 2,
                device: 35,
                device_generation: 1,
                driver_binding: 44,
                driver_binding_generation: 1,
                packet_device: 81,
                packet_device_generation: 1,
                adapter: 93,
                adapter_generation: 1,
                backend: ContractObjectRefManifest {
                    kind: "virtio-net-backend-object".to_owned(),
                    id: 85,
                    generation: 1,
                },
                cancelled_socket_waits: vec![ContractObjectRefManifest {
                    kind: "socket-wait".to_owned(),
                    id: 97,
                    generation: 1,
                }],
                cancelled_wait_tokens: vec![ContractObjectRefManifest {
                    kind: "wait-token".to_owned(),
                    id: 45,
                    generation: 1,
                }],
                revoked_packet_capabilities: vec![ContractObjectRefManifest {
                    kind: "device-capability".to_owned(),
                    id: 42,
                    generation: 1,
                }],
                generation: 1,
                state: "completed".to_owned(),
                started_at_event: 33,
                completed_at_event: Some(34),
                reason: "device-fault".to_owned(),
                note: "network driver cleanup graph".to_owned(),
            });
        package
            .semantic
            .network_generation_audits
            .push(NetworkGenerationAuditManifest {
                id: 101,
                adapter: 93,
                adapter_generation: 1,
                packet_device: 81,
                packet_device_generation: 1,
                packet_queue: 89,
                packet_queue_generation: 1,
                packet_descriptor: 88,
                packet_descriptor_generation: 1,
                packet_buffer: 87,
                packet_buffer_generation: 1,
                dma_buffer: ContractObjectRefManifest {
                    kind: "dma-buffer-object".to_owned(),
                    id: 50,
                    generation: 1,
                },
                device_capability: ContractObjectRefManifest {
                    kind: "device-capability".to_owned(),
                    id: 42,
                    generation: 1,
                },
                rejected_packet_generation_probes: 2,
                rejected_dma_generation_probes: 1,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 35,
                note: "network generation audit graph".to_owned(),
            });
        package
            .semantic
            .network_fault_injections
            .push(NetworkFaultInjectionManifest {
                id: 102,
                adapter: 93,
                adapter_generation: 1,
                packet_device: 81,
                packet_device_generation: 1,
                packet_queue: 89,
                packet_queue_generation: 1,
                packet_descriptor: Some(88),
                packet_descriptor_generation: Some(1),
                packet_buffer: Some(87),
                packet_buffer_generation: Some(1),
                endpoint: Some(95),
                endpoint_generation: Some(1),
                socket: Some(94),
                socket_generation: Some(1),
                owner_store: Some(7),
                owner_store_generation: Some(2),
                direction: "tx".to_owned(),
                kind: "packet-loss".to_owned(),
                effect: "drop-packet".to_owned(),
                injected_packets: 1,
                dropped_packets: 1,
                error_packets: 0,
                error_code: String::new(),
                sequence: 18,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 36,
                note: "network fault injection graph".to_owned(),
            });
        package
            .semantic
            .network_benchmarks
            .push(NetworkBenchmarkManifest {
                id: 103,
                scenario: "host-validation-network-throughput-latency".to_owned(),
                adapter: 93,
                adapter_generation: 1,
                packet_device: 81,
                packet_device_generation: 1,
                tx_queue: 89,
                tx_queue_generation: 1,
                rx_queue: 82,
                rx_queue_generation: 1,
                tx_completion: 92,
                tx_completion_generation: 1,
                rx_wait_resolution: 87,
                rx_wait_resolution_generation: 1,
                endpoint: 95,
                endpoint_generation: 1,
                socket: 94,
                socket_generation: 1,
                owner_store: 7,
                owner_store_generation: 2,
                backpressure: Some(99),
                backpressure_generation: Some(1),
                sample_packets: 3,
                sample_bytes: 6000,
                tx_completed_packets: 1,
                rx_resolved_packets: 1,
                dropped_packets: 1,
                measured_nanos: 120_000,
                budget_nanos: 250_000,
                throughput_bytes_per_sec: 50_000_000,
                p50_latency_nanos: 18_000,
                p99_latency_nanos: 48_000,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 37,
                note: "network benchmark graph".to_owned(),
            });
        package
            .semantic
            .network_recovery_benchmarks
            .push(NetworkRecoveryBenchmarkManifest {
                id: 104,
                scenario: "host-validation-network-driver-recovery".to_owned(),
                cleanup: 100,
                cleanup_generation: 1,
                io_cleanup: 70,
                io_cleanup_generation: 1,
                adapter: 93,
                adapter_generation: 1,
                packet_device: 81,
                packet_device_generation: 1,
                backend: ContractObjectRefManifest {
                    kind: "virtio-net-backend-object".to_owned(),
                    id: 85,
                    generation: 1,
                },
                driver_store: 1,
                driver_store_generation: 2,
                fault_injection: Some(102),
                fault_injection_generation: Some(1),
                recovery_start_event: 33,
                recovery_complete_event: 34,
                cancelled_socket_waits: 1,
                revoked_packet_capabilities: 1,
                recovery_nanos: 90_000,
                budget_nanos: 200_000,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 38,
                note: "network recovery benchmark graph".to_owned(),
            });
        package
            .semantic
            .block_device_objects
            .push(BlockDeviceObjectManifest {
                id: 105,
                name: "blk0".to_owned(),
                device: 35,
                device_generation: 1,
                sector_size: 512,
                sector_count: 4096,
                read_only: false,
                max_transfer_sectors: 128,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 39,
                note: "block device graph".to_owned(),
            });
        package
            .semantic
            .block_range_objects
            .push(BlockRangeObjectManifest {
                id: 106,
                block_device: 105,
                block_device_generation: 1,
                start_sector: 64,
                sector_count: 8,
                byte_offset: 32768,
                byte_len: 4096,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 40,
                note: "block range graph".to_owned(),
            });
        package
            .semantic
            .block_request_objects
            .push(BlockRequestObjectManifest {
                id: 107,
                block_device: 105,
                block_device_generation: 1,
                block_range: 106,
                block_range_generation: 1,
                operation: "read".to_owned(),
                sequence: 1,
                byte_len: 4096,
                generation: 1,
                state: "submitted".to_owned(),
                recorded_at_event: 41,
                note: "block request graph".to_owned(),
            });
        package
            .semantic
            .block_completion_objects
            .push(BlockCompletionObjectManifest {
                id: 108,
                block_request: 107,
                block_request_generation: 1,
                block_device: 105,
                block_device_generation: 1,
                block_range: 106,
                block_range_generation: 1,
                sequence: 1,
                completed_bytes: 4096,
                status: "success".to_owned(),
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 42,
                note: "block completion graph".to_owned(),
            });
        package.semantic.block_waits.push(BlockWaitManifest {
            id: 109,
            wait: 110,
            wait_generation: 1,
            block_request: 107,
            block_request_generation: 1,
            block_device: 105,
            block_device_generation: 1,
            block_range: 106,
            block_range_generation: 1,
            operation: "read".to_owned(),
            sequence: 1,
            byte_len: 4096,
            generation: 1,
            state: "resolved".to_owned(),
            created_at_event: 43,
            completed_at_event: Some(44),
            completion: Some(108),
            completion_generation: Some(1),
            cancel_reason: None,
            note: "block wait graph".to_owned(),
        });
        package
            .semantic
            .fake_block_backends
            .push(FakeBlockBackendObjectManifest {
                id: 111,
                name: "fake-block0".to_owned(),
                block_device: 105,
                block_device_generation: 1,
                provider: "service_core".to_owned(),
                profile: "fake-block-v1".to_owned(),
                sector_size: 512,
                sector_count: 4096,
                read_only: false,
                max_transfer_sectors: 128,
                deterministic_seed: 7,
                generation: 1,
                state: "bound".to_owned(),
                recorded_at_event: 45,
                note: "fake block backend graph".to_owned(),
            });
        package
            .semantic
            .virtio_blk_backends
            .push(VirtioBlkBackendObjectManifest {
                id: 112,
                name: "virtio-blk0-backend".to_owned(),
                block_device: 105,
                block_device_generation: 1,
                driver_binding: 113,
                driver_binding_generation: 1,
                device: 103,
                device_generation: 1,
                provider: "substrate_virtio".to_owned(),
                profile: "virtio-blk-backend-skeleton-v1".to_owned(),
                model: "virtio-blk".to_owned(),
                sector_size: 512,
                sector_count: 4096,
                read_only: false,
                max_transfer_sectors: 128,
                device_features: 0x40,
                driver_features: 0x40,
                negotiated_features: 0x40,
                request_queue_index: 0,
                queue_size: 8,
                irq_vector: 6,
                generation: 1,
                state: "skeleton-ready".to_owned(),
                recorded_at_event: 46,
                note: "virtio block backend graph".to_owned(),
            });

        let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "owns"
            && edge["to"]["kind"] == "activation"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "authorizes"
            && edge["to"]["kind"] == "resource"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "packet-descriptor->packet-queue"
            && edge["from"]["kind"] == "packet-descriptor"
            && edge["to"]["kind"] == "packet-queue"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "packet-descriptor->packet-buffer"
            && edge["from"]["kind"] == "packet-descriptor"
            && edge["to"]["kind"] == "packet-buffer"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "block-device->device"
            && edge["from"]["kind"] == "block-device"
            && edge["to"]["kind"] == "device"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "block-range->block-device"
            && edge["from"]["kind"] == "block-range"
            && edge["to"]["kind"] == "block-device"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "block-request->block-range"
            && edge["from"]["kind"] == "block-request"
            && edge["to"]["kind"] == "block-range"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "fake-block-backend->block-device"
            && edge["from"]["kind"] == "fake-block-backend"
            && edge["to"]["kind"] == "block-device"
            && edge["to"]["generation"] == 1));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "virtio-blk-backend->block-device"
            && edge["from"]["kind"] == "virtio-blk-backend"
            && edge["to"]["kind"] == "block-device"
            && edge["to"]["generation"] == 1));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "virtio-blk-backend->driver-binding"
            && edge["from"]["kind"] == "virtio-blk-backend"
            && edge["to"]["kind"] == "driver-store-binding"));
        let history = graph_edges_for_package(&package, GraphEdgeMode::History);
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "block-completion->block-request"
            && edge["from"]["kind"] == "block-completion"
            && edge["to"]["kind"] == "block-request"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "block-wait->block-completion"
            && edge["from"]["kind"] == "block-wait"
            && edge["to"]["kind"] == "block-completion"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "fake-net-backend->packet-device"
            && edge["from"]["kind"] == "fake-net-backend"
            && edge["to"]["kind"] == "packet-device"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "virtio-net-backend->packet-device"
            && edge["from"]["kind"] == "virtio-net-backend"
            && edge["to"]["kind"] == "packet-device"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "virtio-net-backend->driver-binding"
            && edge["from"]["kind"] == "virtio-net-backend"
            && edge["to"]["kind"] == "driver-store-binding"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "network-rx-interrupt->virtio-net-backend"
            && edge["from"]["kind"] == "network-rx-interrupt"
            && edge["to"]["kind"] == "virtio-net-backend"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "network-rx-interrupt->rx-queue"
            && edge["from"]["kind"] == "network-rx-interrupt"
            && edge["to"]["kind"] == "packet-queue"));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "network-stack-adapter->backend"
            && edge["from"]["kind"] == "network-stack-adapter"
            && edge["to"]["kind"] == "virtio-net-backend"
            && edge["to"]["generation"] == 1));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "network-stack-adapter->rx-queue"
            && edge["from"]["kind"] == "network-stack-adapter"
            && edge["to"]["kind"] == "packet-queue"
            && edge["to"]["id"] == 82));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "network-stack-adapter->tx-queue"
            && edge["from"]["kind"] == "network-stack-adapter"
            && edge["to"]["kind"] == "packet-queue"
            && edge["to"]["id"] == 89));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "socket-object->network-stack-adapter"
            && edge["from"]["kind"] == "socket-object"
            && edge["to"]["kind"] == "network-stack-adapter"
            && edge["to"]["id"] == 93));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "socket-object->owner-store"
            && edge["from"]["kind"] == "socket-object"
            && edge["to"]["kind"] == "store"
            && edge["to"]["generation"] == 2));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "endpoint-object->socket-object"
            && edge["from"]["kind"] == "endpoint-object"
            && edge["to"]["kind"] == "socket-object"
            && edge["to"]["id"] == 94));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "endpoint-object->network-stack-adapter"
            && edge["from"]["kind"] == "endpoint-object"
            && edge["to"]["kind"] == "network-stack-adapter"
            && edge["to"]["id"] == 93));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "endpoint-object->owner-store"
            && edge["from"]["kind"] == "endpoint-object"
            && edge["to"]["kind"] == "store"
            && edge["to"]["generation"] == 2));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "socket-wait->wait-token"
            && edge["from"]["kind"] == "socket-wait"
            && edge["from"]["id"] == 97
            && edge["to"]["kind"] == "wait-token"
            && edge["to"]["generation"] == 1));
        assert!(live.iter().any(|edge| edge["mode"] == "live"
            && edge["relation"] == "socket-wait->endpoint-object"
            && edge["from"]["kind"] == "socket-wait"
            && edge["from"]["id"] == 97
            && edge["to"]["kind"] == "endpoint-object"));
        assert!(
            !live
                .iter()
                .any(|edge| edge["from"]["kind"] == "network-backpressure")
        );
        assert!(
            !live
                .iter()
                .any(|edge| edge["from"]["kind"] == "network-driver-cleanup")
        );
        assert!(
            !live
                .iter()
                .any(|edge| edge["from"]["kind"] == "network-generation-audit")
        );
        assert!(
            !live
                .iter()
                .any(|edge| edge["from"]["kind"] == "network-fault-injection")
        );
        assert!(
            !live
                .iter()
                .any(|edge| edge["from"]["kind"] == "network-benchmark")
        );
        assert!(
            !live
                .iter()
                .any(|edge| edge["from"]["kind"] == "network-recovery-benchmark")
        );

        let history = graph_edges_for_package(&package, GraphEdgeMode::History);
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "socket-operation->endpoint-object"
            && edge["from"]["kind"] == "socket-operation"
            && edge["to"]["kind"] == "endpoint-object"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "socket-operation->socket-object"
            && edge["from"]["kind"] == "socket-operation"
            && edge["to"]["kind"] == "socket-object"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "socket-operation->network-stack-adapter"
            && edge["from"]["kind"] == "socket-operation"
            && edge["to"]["kind"] == "network-stack-adapter"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "socket-operation->owner-store"
            && edge["from"]["kind"] == "socket-operation"
            && edge["to"]["kind"] == "store"
            && edge["to"]["generation"] == 2));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "socket-wait->wait-token"
            && edge["from"]["kind"] == "socket-wait"
            && edge["from"]["id"] == 98
            && edge["to"]["kind"] == "wait-token"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "socket-wait->endpoint-object"
            && edge["from"]["kind"] == "socket-wait"
            && edge["from"]["id"] == 98
            && edge["to"]["kind"] == "endpoint-object"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-backpressure->packet-queue"
            && edge["from"]["kind"] == "network-backpressure"
            && edge["from"]["id"] == 99
            && edge["to"]["kind"] == "packet-queue"
            && edge["to"]["id"] == 89));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-backpressure->endpoint-object"
            && edge["from"]["kind"] == "network-backpressure"
            && edge["to"]["kind"] == "endpoint-object"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-driver-cleanup->io-cleanup"
            && edge["from"]["kind"] == "network-driver-cleanup"
            && edge["to"]["kind"] == "io-cleanup"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-driver-cleanup->backend"
            && edge["from"]["kind"] == "network-driver-cleanup"
            && edge["to"]["kind"] == "virtio-net-backend-object"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
            && edge["relation"] == "network-driver-cleanup->cancelled-socket-wait"
            && edge["from"]["kind"] == "network-driver-cleanup"
            && edge["to"]["kind"] == "socket-wait"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
            && edge["relation"] == "network-driver-cleanup->cancelled-wait-token"
            && edge["from"]["kind"] == "network-driver-cleanup"
            && edge["to"]["kind"] == "wait-token"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
            && edge["relation"] == "network-driver-cleanup->revoked-packet-capability"
            && edge["from"]["kind"] == "network-driver-cleanup"
            && edge["to"]["kind"] == "device-capability"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-generation-audit->packet-descriptor"
            && edge["from"]["kind"] == "network-generation-audit"
            && edge["to"]["kind"] == "packet-descriptor"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-generation-audit->dma-buffer"
            && edge["from"]["kind"] == "network-generation-audit"
            && edge["to"]["kind"] == "dma-buffer-object"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-generation-audit->device-capability"
            && edge["from"]["kind"] == "network-generation-audit"
            && edge["to"]["kind"] == "device-capability"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-fault-injection->packet-descriptor"
            && edge["from"]["kind"] == "network-fault-injection"
            && edge["to"]["kind"] == "packet-descriptor"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-fault-injection->endpoint-object"
            && edge["from"]["kind"] == "network-fault-injection"
            && edge["to"]["kind"] == "endpoint-object"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-fault-injection->owner-store"
            && edge["from"]["kind"] == "network-fault-injection"
            && edge["to"]["kind"] == "store"
            && edge["to"]["generation"] == 2));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-benchmark->tx-completion"
            && edge["from"]["kind"] == "network-benchmark"
            && edge["to"]["kind"] == "network-tx-completion"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-benchmark->rx-wait-resolution"
            && edge["from"]["kind"] == "network-benchmark"
            && edge["to"]["kind"] == "network-rx-wait-resolution"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-benchmark->network-backpressure"
            && edge["from"]["kind"] == "network-benchmark"
            && edge["to"]["kind"] == "network-backpressure"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-recovery-benchmark->network-driver-cleanup"
            && edge["from"]["kind"] == "network-recovery-benchmark"
            && edge["to"]["kind"] == "network-driver-cleanup"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-recovery-benchmark->network-fault-injection"
            && edge["from"]["kind"] == "network-recovery-benchmark"
            && edge["to"]["kind"] == "network-fault-injection"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-recovery-benchmark->backend"
            && edge["from"]["kind"] == "network-recovery-benchmark"
            && edge["to"]["kind"] == "virtio-net-backend-object"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-rx-interrupt->irq-event"
            && edge["from"]["kind"] == "network-rx-interrupt"
            && edge["to"]["kind"] == "irq-event"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-rx-wait-resolution->rx-interrupt"
            && edge["from"]["kind"] == "network-rx-wait-resolution"
            && edge["to"]["kind"] == "network-rx-interrupt"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-rx-wait-resolution->rx-queue"
            && edge["from"]["kind"] == "network-rx-wait-resolution"
            && edge["to"]["kind"] == "packet-queue"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-tx-capability-gate->packet-descriptor"
            && edge["from"]["kind"] == "network-tx-capability-gate"
            && edge["to"]["kind"] == "packet-descriptor"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-tx-capability-gate->capability"
            && edge["from"]["kind"] == "network-tx-capability-gate"
            && edge["to"]["kind"] == "capability"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-tx-completion->tx-gate"
            && edge["from"]["kind"] == "network-tx-completion"
            && edge["to"]["kind"] == "network-tx-capability-gate"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-tx-completion->backend"
            && edge["from"]["kind"] == "network-tx-completion"
            && edge["to"]["kind"] == "virtio-net-backend"
            && edge["to"]["generation"] == 1));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["relation"] == "network-tx-completion->packet-descriptor"
            && edge["from"]["kind"] == "network-tx-completion"
            && edge["to"]["kind"] == "packet-descriptor"
            && edge["to"]["generation"] == 1));
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
        assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
            && edge["from"]["kind"] == "io-cleanup"
            && edge["relation"] == "released-irq-line"
            && edge["to"]["kind"] == "irq-line-object"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["from"]["kind"] == "io-cleanup"
            && edge["relation"] == "io-cleanup-driver-store"
            && edge["to"]["generation"] == 2));
        assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
            && edge["from"]["kind"] == "io-fault-injection"
            && edge["relation"] == "triggered-cleanup"
            && edge["to"]["kind"] == "io-cleanup"));
        assert!(history.iter().any(|edge| edge["mode"] == "historical"
            && edge["from"]["kind"] == "io-fault-injection"
            && edge["relation"] == "io-fault-target"
            && edge["to"]["kind"] == "irq-line-object"));
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
