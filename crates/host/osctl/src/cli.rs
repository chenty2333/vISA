use super::*;

pub fn run() -> Result<(), Box<dyn Error>> {
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
        | "integrated-smp-network-fault"
        | "smp-network-fault"
        | "integrated-network-fault"
        | "integrated-disk-preempt-fault"
        | "disk-preempt-fault"
        | "integrated-block-preempt-fault"
        | "integrated-simd-migration"
        | "simd-migration"
        | "integrated-vector-migration"
        | "integrated-network-disk-io"
        | "network-disk-io"
        | "integrated-io-concurrency"
        | "integrated-display-scheduler-load"
        | "display-scheduler-load"
        | "integrated-display-load"
        | "integrated-snapshot-io-lease-barrier"
        | "snapshot-io-lease-barrier"
        | "snapshot-io-barrier"
        | "integrated-code-publish-smp-workload"
        | "code-publish-smp-workload"
        | "integrated-code-publish-workload"
        | "integrated-display-panic"
        | "display-panic"
        | "panic-ring-extraction"
        | "integrated-osctl-trace-replay"
        | "osctl-trace-replay"
        | "full-osctl-trace-replay"
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
            if collected.first().is_some_and(|arg| arg == "show" || arg == "list") {
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
            let cursor = args.next().ok_or("replay requires a cursor")?.parse::<u64>()?;
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
            replay_until(cursor, manifest_path.as_deref().map(Path::new), Path::new(&path), json)
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
    eprintln!("  osctl modes");
    eprintln!("  osctl caps [--subject <subject>] <manifest-or-migration.json>");
    eprintln!(
        "  osctl hart|task|activation|activation-context|saved-context|timer-interrupt|ipi-event|remote-preempt|remote-park|preemption|scheduler-decision|cross-hart-scheduler-decision|activation-migration|smp-safe-point|safepoint|stop-the-world-rendezvous|stop-the-world|stw|smp-code-publish-barrier|smp-cleanup-quiescence|smp-snapshot-barrier|smp-stress-run|smp-scaling-benchmark|integrated-smp-preemption-cleanup|integrated-smp-network-fault|integrated-disk-preempt-fault|integrated-simd-migration|integrated-network-disk-io|integrated-display-scheduler-load|integrated-snapshot-io-lease-barrier|integrated-code-publish-smp-workload|integrated-display-panic|integrated-osctl-trace-replay|device|queue|descriptor|dma-buffer|mmio-region|irq-line|irq-event|device-capability|driver-store-binding|io-wait|io-cleanup|io-fault-injection|io-validation-report|packet-device|packet-buffer|packet-queue|packet-descriptor|fake-net-backend|virtio-net-backend|network-rx-interrupt|network-rx-wait-resolution|network-tx-capability-gate|network-tx-completion|network-stack-adapter|socket-object|endpoint-object|socket-operation|socket-wait|network-backpressure|network-driver-cleanup|network-generation-audit|network-fault-injection|network-benchmark|network-recovery-benchmark|block-device|block-range|block-request|block-completion|block-wait|fake-block-backend|virtio-blk-backend|block-read-path|block-write-path|block-request-queue|block-dma-buffer|block-page-object|buffer-cache-object|fs-cache|file-object|file|directory-object|directory|fat-adapter-object|fat-adapter|ext4-adapter-object|ext4-adapter|file-handle-capability|file-handle|fs-wait|block-driver-cleanup|block-pending-io-policy|block-request-generation-audit|block-benchmark|block-recovery-benchmark|target-feature-set|vector-state|simd-fault-injection|simd-benchmark|simd-context-switch-benchmark|framebuffer-object|framebuffer|display-object|display|display-capability|display-cap|framebuffer-window-lease|fb-window-lease|display-lease|framebuffer-mapping|fb-mapping|display-mapping|framebuffer-write|fb-write|display-write|framebuffer-flush-region|flush-region|display-flush|framebuffer-dirty-region|dirty-region|display-dirty|display-event-log|display-log|display-cleanup|display-snapshot-barrier|display-panic-last-frame|framebuffer-benchmark|activation-resume|activation-wait|activation-cleanup|preemption-latency|hart-event|scheduler|runnable-queue|store|cap|wait|cleanup|command list --json <migration.json>"
    );
    eprintln!("  osctl store|cap|wait|cleanup|command show --json <migration.json> <id>");
    eprintln!("  osctl state <manifest-or-migration.json>");
    eprintln!("  osctl graph [--live|--history] [--json] <migration.json>");
    eprintln!("  osctl activation [--blocked] <migration.json>");
    eprintln!("  osctl event-log tail <migration.json>");
    eprintln!(
        "  osctl inspect artifact|code|store|activation|capability|wait|trap|hostcall|tombstone|contract|cleanup|file-handle-capability|fs-wait|block-driver-cleanup|block-pending-io-policy|block-request-generation-audit|block-benchmark|block-recovery-benchmark|target-feature-set|vector-state|simd-fault-injection|simd-benchmark|simd-context-switch-benchmark|framebuffer-object|display-object|display-capability|framebuffer-window-lease|framebuffer-mapping|framebuffer-write|framebuffer-flush-region|framebuffer-dirty-region|display-event-log|display-cleanup|display-snapshot-barrier|display-panic-last-frame|framebuffer-benchmark|integrated-smp-preemption-cleanup|integrated-smp-network-fault|integrated-disk-preempt-fault|integrated-simd-migration|integrated-network-disk-io|integrated-display-scheduler-load|integrated-snapshot-io-lease-barrier|integrated-code-publish-smp-workload|integrated-display-panic|integrated-osctl-trace-replay|memory-policy|snapshot-validation|replay-validation|event [--json] <manifest-or-migration.json> [filter]"
    );
    eprintln!("  osctl contract validate [--json] <migration.json>");
    eprintln!(
        "  osctl replay --until <event-cursor> [--manifest <manifest.json>] [--json] <migration.json>"
    );
}
