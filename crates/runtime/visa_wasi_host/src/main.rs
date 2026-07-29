use std::{
    env,
    path::{Path, PathBuf},
};

use visa_wasi_host::{
    CreateConfig, ImportFile, ProviderServer, RestoreConfig, create_provider, open_provider,
    restore_provider, send_admin,
};
use visa_wasi_protocol::{
    AdminCapability, AdminOperation, AdminRequest, GuestCapability, PROTOCOL_VERSION, SessionId,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
visa_wasi_host create <database> <session-hex> <admin-capability-hex> <guest-capability-hex> <epoch> [<guest>=<host> ...]\n  \
visa_wasi_host restore <bundle> <database> <admin-capability-hex> <guest-capability-hex>\n  \
visa_wasi_host serve <database> <socket>\n  \
visa_wasi_host control <socket> <capability-hex> status\n  \
visa_wasi_host control <socket> <capability-hex> freeze <handoff-hex> <destination-epoch>\n  \
visa_wasi_host control <socket> <capability-hex> export <bundle>\n  \
visa_wasi_host control <socket> <capability-hex> resume <handoff-hex> <source-epoch>\n  \
visa_wasi_host control <socket> <capability-hex> fence <handoff-hex> <committed-epoch>\n  \
visa_wasi_host control <socket> <capability-hex> activate <handoff-hex> <destination-epoch>\n  \
visa_wasi_host control <socket> <capability-hex> materialize <guest-path> <host-path>\n  \
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
        "freeze" if args.len() == 7 => AdminOperation::Freeze {
            handoff: parse_hex(&args[5], "handoff")?,
            destination_epoch: parse_epoch(&args[6])?,
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
