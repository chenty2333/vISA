use std::{
    env, fs,
    fs::OpenOptions,
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use visa_component_adapter::component_digest;
use visa_wanco_carrier::{
    CarrierProbeCase, CarrierRoute, RecordInput,
    canonical::{
        CanonicalEndpoint, CanonicalTransfer, CanonicalWorkload, DestinationEndpointConfig,
        ServiceExit, SourceEndpointConfig,
    },
    merge_carrier_probe, record_observation,
};

const CONFIG_SCHEMA: &str = "visa-wanco-canonical-endpoint-config-v1";

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
visa-wanco-carrier canonical-source <config.json> <socket> <transfer.json|-> <receipt.json>\n  \
visa-wanco-carrier canonical-destination <config.json> <transfer.json> <socket> <receipt.json>\n  \
visa-wanco-carrier canonical-control <socket> <SAFE_POINT|EXPORT|RESUME|SHUTDOWN>\n  \
visa-wanco-carrier record <mode> <artifact-root> <case> <source-events> \
<destination-events|-> <source-stdout> <destination-stdout|-> \
<source-status> <destination-status|-> <source-receipt> <destination-receipt|-> <subject-file> \
<checkpoint|-> <output.json>\n  \
visa-wanco-carrier merge-probe <read-write.json> <append.json> <output.json>"
    );
    std::process::exit(64);
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointConfigFile {
    schema: String,
    cell_id: String,
    route: String,
    workload: String,
    database: PathBuf,
    file_root: PathBuf,
    component_input: PathBuf,
    session_id: String,
    initial_content: Option<Vec<u8>>,
}

fn optional_path(value: &str) -> Option<&Path> {
    (value != "-").then(|| Path::new(value))
}

fn load_config(path: &Path) -> Result<(EndpointConfigFile, CanonicalWorkload), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read endpoint config {}: {error}", path.display()))?;
    let config: EndpointConfigFile = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot decode endpoint config {}: {error}", path.display()))?;
    if config.schema != CONFIG_SCHEMA {
        return Err(format!("endpoint config {} has an unknown schema", path.display()));
    }
    let workload = match config.workload.as_str() {
        "read-write-offset" => CanonicalWorkload::ReadWriteOffset,
        "append-continuity" => CanonicalWorkload::AppendContinuity,
        other => return Err(format!("unknown canonical endpoint workload {other:?}")),
    };
    if config.session_id.is_empty() {
        return Err("canonical endpoint session_id must not be empty".to_owned());
    }
    Ok((config, workload))
}

fn config_component_digest(config: &EndpointConfigFile) -> Result<contract_core::Digest, String> {
    let bytes = fs::read(&config.component_input).map_err(|error| {
        format!(
            "cannot read canonical endpoint component input {}: {error}",
            config.component_input.display()
        )
    })?;
    Ok(component_digest(&bytes))
}

fn write_new(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {label} {}: {error}", path.display()))?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("cannot publish {label} {}: {error}", path.display()))
}

fn run_source(
    config_path: &Path,
    socket: &Path,
    transfer_path: Option<&Path>,
    receipt_path: &Path,
) -> Result<(), String> {
    let (config, workload) = load_config(config_path)?;
    let component_digest = config_component_digest(&config)?;
    let initial_content = config
        .initial_content
        .clone()
        .ok_or_else(|| "source endpoint config lacks initial_content".to_owned())?;
    let mut endpoint = CanonicalEndpoint::initialize_source(SourceEndpointConfig {
        cell_id: config.cell_id,
        route: config.route,
        workload,
        database: config.database,
        file_root: config.file_root,
        component_digest,
        session_id: config.session_id,
        initial_content,
    })?;
    match endpoint.serve_unix(socket)? {
        ServiceExit::Exported(transfer) => {
            let transfer_path = transfer_path
                .ok_or_else(|| "source exported without a transfer output path".to_owned())?;
            write_new(transfer_path, &transfer.encode_json()?, "canonical endpoint transfer")?;
        }
        ServiceExit::Shutdown if transfer_path.is_none() => {}
        ServiceExit::Shutdown => {
            return Err("source shut down before publishing the required transfer".to_owned());
        }
    }
    endpoint.write_receipt(receipt_path)
}

fn run_destination(
    config_path: &Path,
    transfer_path: &Path,
    socket: &Path,
    receipt_path: &Path,
) -> Result<(), String> {
    let (config, workload) = load_config(config_path)?;
    if config.initial_content.is_some() {
        return Err("destination endpoint config must not carry initial_content".to_owned());
    }
    let component_digest = config_component_digest(&config)?;
    let transfer = CanonicalTransfer::decode_json(&fs::read(transfer_path).map_err(|error| {
        format!("cannot read canonical transfer {}: {error}", transfer_path.display())
    })?)?;
    let mut endpoint = CanonicalEndpoint::restore_destination(
        DestinationEndpointConfig {
            cell_id: config.cell_id,
            route: config.route,
            workload,
            database: config.database,
            file_root: config.file_root,
            component_digest,
            session_id: config.session_id,
        },
        &transfer,
    )?;
    match endpoint.serve_unix(socket)? {
        ServiceExit::Shutdown => endpoint.write_receipt(receipt_path),
        ServiceExit::Exported(_) => {
            Err("destination endpoint unexpectedly exported a source transfer".to_owned())
        }
    }
}

fn run_control(socket: &Path, command: &str) -> Result<(), String> {
    if !matches!(command, "SAFE_POINT" | "EXPORT" | "RESUME" | "SHUTDOWN") {
        return Err(format!("unknown canonical endpoint control command {command:?}"));
    }
    let mut stream = UnixStream::connect(socket)
        .map_err(|error| format!("cannot connect to endpoint {}: {error}", socket.display()))?;
    stream
        .write_all(format!("{command}\n").as_bytes())
        .and_then(|()| stream.shutdown(Shutdown::Write))
        .map_err(|error| format!("cannot send endpoint command {command}: {error}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("cannot read endpoint response: {error}"))?;
    let response = response.trim_end_matches(['\r', '\n']);
    if response.is_empty() || response.contains('\n') || response.starts_with("ERROR\t") {
        return Err(format!("endpoint rejected {command}: {response}"));
    }
    println!("{response}");
    Ok(())
}

fn run() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("canonical-source") if args.len() == 6 => run_source(
            Path::new(&args[2]),
            Path::new(&args[3]),
            optional_path(&args[4]),
            Path::new(&args[5]),
        ),
        Some("canonical-destination") if args.len() == 6 => run_destination(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
            Path::new(&args[5]),
        ),
        Some("canonical-control") if args.len() == 4 => run_control(Path::new(&args[2]), &args[3]),
        Some("record") if args.len() == 16 => {
            let input = RecordInput {
                route: CarrierRoute::parse(&args[2])?,
                artifact_root: Path::new(&args[3]),
                case: CarrierProbeCase::parse(&args[4])?,
                source_events: Path::new(&args[5]),
                destination_events: optional_path(&args[6]),
                source_stdout: Path::new(&args[7]),
                destination_stdout: optional_path(&args[8]),
                source_status: Path::new(&args[9]),
                destination_status: optional_path(&args[10]),
                source_receipt: Path::new(&args[11]),
                destination_receipt: optional_path(&args[12]),
                subject_file: Path::new(&args[13]),
                checkpoint: optional_path(&args[14]),
                output: Path::new(&args[15]),
            };
            record_observation(&input).map(|_| ())
        }
        Some("merge-probe") if args.len() == 5 => {
            merge_carrier_probe(Path::new(&args[2]), Path::new(&args[3]), Path::new(&args[4]))
                .map(|_| ())
        }
        _ => usage(),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("visa-wanco-carrier: {error}");
        std::process::exit(1);
    }
}
