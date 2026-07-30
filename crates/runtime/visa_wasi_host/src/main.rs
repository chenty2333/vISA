use std::{
    env,
    path::{Path, PathBuf},
};

use visa_wasi_host::{
    CreateConfig, ImportFile, ProviderServer, RestoreConfig, create_provider, open_provider,
    restore_provider, send_admin,
};
use visa_wasi_protocol::{
    AdminCapability, AdminOperation, AdminRequest, BarrierReleaseAction, BarrierToken,
    GuestCapability, HostcallKind, HostcallPredicate, OutcomePredicate, PROTOCOL_VERSION,
    ResourceSelector, SessionId,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
visa_wasi_host create <database> <session-hex> <admin-capability-hex> <guest-capability-hex> <epoch> [<guest>=<host> ...]\n  \
visa_wasi_host restore <bundle> <database> <admin-capability-hex> <guest-capability-hex>\n  \
visa_wasi_host serve <database> <socket>\n  \
visa_wasi_host control <socket> <capability-hex> status\n  \
visa_wasi_host control <socket> <capability-hex> barrier-arm <barrier-hex> <kind> <any|fd:N|path:P> <any|success|errno:N> <occurrence>\n  \
visa_wasi_host control <socket> <capability-hex> barrier-release <barrier-hex> <continue|checkpoint>\n  \
visa_wasi_host control <socket> <capability-hex> freeze <barrier-hex> <handoff-hex> <destination-epoch>\n  \
visa_wasi_host control <socket> <capability-hex> export <bundle>\n  \
visa_wasi_host control <socket> <capability-hex> resume <handoff-hex> <source-epoch>\n  \
visa_wasi_host control <socket> <capability-hex> fence <handoff-hex> <committed-epoch>\n  \
visa_wasi_host control <socket> <capability-hex> activate <handoff-hex> <destination-epoch>\n  \
visa_wasi_host control <socket> <capability-hex> materialize <guest-path> <host-path>\n  \
visa_wasi_host control <socket> <capability-hex> snapshot-namespace <output>\n  \
visa_wasi_host control <socket> <capability-hex> shutdown"
    );
    std::process::exit(64);
}

fn parse_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{label} must contain exactly {} hexadecimal characters", N * 2));
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| format!("{label} is not hexadecimal"))?;
        bytes[index] =
            u8::from_str_radix(pair, 16).map_err(|_| format!("{label} is not hexadecimal"))?;
    }
    if bytes == [0; N] {
        return Err(format!("{label} must not be zero"));
    }
    Ok(bytes)
}

fn parse_epoch(value: &str) -> Result<u64, String> {
    let epoch = value.parse::<u64>().map_err(|_| format!("invalid authority epoch {value:?}"))?;
    if epoch == 0 || epoch > i64::MAX as u64 {
        Err("authority epoch is outside the durable range".to_owned())
    } else {
        Ok(epoch)
    }
}

fn parse_barrier_predicate(args: &[String]) -> Result<HostcallPredicate, String> {
    let kind = match args[0].as_str() {
        "any" => HostcallKind::Any,
        "fd-close" => HostcallKind::FdClose,
        "fd-datasync" => HostcallKind::FdDataSync,
        "fd-pread" => HostcallKind::FdPread,
        "fd-pwrite" => HostcallKind::FdPwrite,
        "fd-read" => HostcallKind::FdRead,
        "fd-sync" => HostcallKind::FdSync,
        "fd-write" => HostcallKind::FdWrite,
        "path-create-directory" => HostcallKind::PathCreateDirectory,
        "path-open" => HostcallKind::PathOpen,
        "path-remove-directory" => HostcallKind::PathRemoveDirectory,
        "path-rename" => HostcallKind::PathRename,
        "path-unlink-file" => HostcallKind::PathUnlinkFile,
        "vfs-lock" => HostcallKind::VfsLock,
        "vfs-unlock" => HostcallKind::VfsUnlock,
        value => return Err(format!("unsupported barrier hostcall kind {value:?}")),
    };
    let resource = if args[1] == "any" {
        ResourceSelector::Any
    } else if let Some(value) = args[1].strip_prefix("fd:") {
        ResourceSelector::Fd(value.parse().map_err(|_| format!("invalid barrier fd {value:?}"))?)
    } else if let Some(value) = args[1].strip_prefix("path:") {
        ResourceSelector::ExactPath(value.as_bytes().to_vec())
    } else {
        return Err(format!("unsupported barrier resource selector {:?}", args[1]));
    };
    let outcome = if args[2] == "any" {
        OutcomePredicate::Any
    } else if args[2] == "success" {
        OutcomePredicate::Success
    } else if let Some(value) = args[2].strip_prefix("errno:") {
        OutcomePredicate::Errno(
            value.parse().map_err(|_| format!("invalid barrier errno {value:?}"))?,
        )
    } else {
        return Err(format!("unsupported barrier outcome predicate {:?}", args[2]));
    };
    let occurrence =
        args[3].parse::<u64>().map_err(|_| format!("invalid barrier occurrence {:?}", args[3]))?;
    Ok(HostcallPredicate { kind, resource, outcome, occurrence })
}

fn create(args: &[String]) -> Result<(), String> {
    if args.len() < 7 {
        usage();
    }
    let imports = args[7..]
        .iter()
        .map(|value| {
            let (guest, host) = value
                .split_once('=')
                .ok_or_else(|| format!("import {value:?} must use <guest>=<host>"))?;
            if guest.is_empty() || host.is_empty() {
                return Err(format!("import {value:?} has an empty path"));
            }
            Ok(ImportFile { host_path: PathBuf::from(host), guest_path: guest.as_bytes().to_vec() })
        })
        .collect::<Result<Vec<_>, String>>()?;
    create_provider(&CreateConfig {
        database: PathBuf::from(&args[2]),
        session: SessionId(parse_hex(&args[3], "session")?),
        capability: AdminCapability(parse_hex(&args[4], "admin capability")?),
        guest_capability: GuestCapability(parse_hex(&args[5], "guest capability")?),
        authority_epoch: parse_epoch(&args[6])?,
        imports,
    })
    .map_err(|error| error.to_string())
}

fn restore(args: &[String]) -> Result<(), String> {
    if args.len() != 6 {
        usage();
    }
    restore_provider(&RestoreConfig {
        bundle: PathBuf::from(&args[2]),
        database: PathBuf::from(&args[3]),
        capability: AdminCapability(parse_hex(&args[4], "admin capability")?),
        guest_capability: GuestCapability(parse_hex(&args[5], "guest capability")?),
    })
    .map_err(|error| error.to_string())
}

fn serve(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        usage();
    }
    let provider = open_provider(&args[2]).map_err(|error| error.to_string())?;
    ProviderServer::serve(provider, Path::new(&args[3])).map_err(|error| error.to_string())
}

fn control(args: &[String]) -> Result<(), String> {
    if args.len() < 5 {
        usage();
    }
    let capability = AdminCapability(parse_hex(&args[3], "admin capability")?);
    let operation = match args[4].as_str() {
        "status" if args.len() == 5 => AdminOperation::Status,
        "barrier-arm" if args.len() == 10 => AdminOperation::BarrierArm {
            token: BarrierToken(parse_hex(&args[5], "barrier")?),
            predicate: parse_barrier_predicate(&args[6..10])?,
        },
        "barrier-release" if args.len() == 7 => AdminOperation::BarrierRelease {
            token: BarrierToken(parse_hex(&args[5], "barrier")?),
            action: match args[6].as_str() {
                "continue" => BarrierReleaseAction::Continue,
                "checkpoint" => BarrierReleaseAction::Checkpoint,
                _ => usage(),
            },
        },
        "freeze" if args.len() == 8 => AdminOperation::Freeze {
            barrier: BarrierToken(parse_hex(&args[5], "barrier")?),
            handoff: parse_hex(&args[6], "handoff")?,
            destination_epoch: parse_epoch(&args[7])?,
        },
        "export" if args.len() == 6 => AdminOperation::Export { bundle: args[5].clone() },
        "resume" if args.len() == 7 => AdminOperation::Resume {
            handoff: parse_hex(&args[5], "handoff")?,
            authority_epoch: parse_epoch(&args[6])?,
        },
        "fence" if args.len() == 7 => AdminOperation::Fence {
            handoff: parse_hex(&args[5], "handoff")?,
            committed_epoch: parse_epoch(&args[6])?,
        },
        "activate" if args.len() == 7 => AdminOperation::Activate {
            handoff: parse_hex(&args[5], "handoff")?,
            authority_epoch: parse_epoch(&args[6])?,
        },
        "materialize" if args.len() == 7 => AdminOperation::Materialize {
            guest_path: args[5].as_bytes().to_vec(),
            host_path: args[6].clone(),
        },
        "snapshot-namespace" if args.len() == 6 => {
            AdminOperation::SnapshotNamespace { output: args[5].clone() }
        }
        "shutdown" if args.len() == 5 => AdminOperation::Shutdown,
        _ => usage(),
    };
    let response = send_admin(
        Path::new(&args[2]),
        &AdminRequest { version: PROTOCOL_VERSION, capability, operation },
    )
    .map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response)
            .map_err(|error| format!("cannot encode control response: {error}"))?
    );
    if response.ok { Ok(()) } else { Err(response.message) }
}

fn run() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("create") => create(&args),
        Some("restore") => restore(&args),
        Some("serve") => serve(&args),
        Some("control") => control(&args),
        _ => usage(),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("visa_wasi_host: {error}");
        std::process::exit(1);
    }
}
