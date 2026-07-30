//! Content-binding utility for a trusted local migration orchestrator.
//!
//! This utility verifies artifact and receipt bindings. It does not authenticate
//! a coordinator or turn local receipt bytes into an external authority claim.

use std::{
    env, fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use visa_wasi_migration::{
    BuildIdentity, CanonicalCommitProof, CanonicalFenceProof, FileRoles, MigrationIntent,
    MigrationManifest, PlatformIdentity,
};
use visa_wasi_protocol::{BarrierToken, ClientId, OwnerId, SessionId};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentDocument {
    files: FileRoles,
    session_hex: String,
    stable_owner_hex: String,
    handoff_hex: String,
    checkpoint_barrier_hex: String,
    source_epoch: u64,
    destination_epoch: u64,
    source_client_hex: String,
    source_restore_client_hex: String,
    destination_client_hex: String,
    application_build: BuildIdentity,
    source_platform: PlatformIdentity,
    destination_platform: PlatformIdentity,
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
visa-wasi-migration-bind seal <root> <intent-json> <manifest-json>\n  \
visa-wasi-migration-bind verify <root> <manifest-json>\n  \
visa-wasi-migration-bind bind-proofs <root> <manifest-json> \
<commit-receipt-semantic-path> <fence-receipt-semantic-path> \
<commit-proof-json> <fence-proof-json>\n  \
visa-wasi-migration-bind verify-proofs <root> <manifest-json> \
<commit-proof-json> <fence-proof-json>"
    );
    std::process::exit(64);
}

fn parse_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{label} must contain exactly {} hexadecimal characters", N * 2));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| format!("{label} is not hexadecimal"))?;
        output[index] =
            u8::from_str_radix(pair, 16).map_err(|_| format!("{label} is not hexadecimal"))?;
    }
    Ok(output)
}

fn read_manifest(path: &Path) -> Result<MigrationManifest, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read migration manifest {}: {error}", path.display()))?;
    MigrationManifest::decode_canonical(&bytes).map_err(|error| error.to_string())
}

fn read_canonical_commit(path: &Path) -> Result<CanonicalCommitProof, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read commit proof {}: {error}", path.display()))?;
    let proof: CanonicalCommitProof =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if proof.canonical_bytes().map_err(|error| error.to_string())? != bytes {
        return Err("ownership commit proof is not canonical RFC 8785 JSON".to_owned());
    }
    Ok(proof)
}

fn read_canonical_fence(path: &Path) -> Result<CanonicalFenceProof, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read fence proof {}: {error}", path.display()))?;
    let proof: CanonicalFenceProof =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if proof.canonical_bytes().map_err(|error| error.to_string())? != bytes {
        return Err("source fence proof is not canonical RFC 8785 JSON".to_owned());
    }
    Ok(proof)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or_else(|| format!("output path has no parent: {}", path.display()))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {}: {error}", parent.display()))
}

fn rooted(root: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() { path.to_owned() } else { root.join(path) }
}

fn seal(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        usage();
    }
    let root = Path::new(&args[2]);
    let bytes = fs::read(rooted(root, &args[3]))
        .map_err(|error| format!("cannot read migration intent {}: {error}", args[3]))?;
    let document: IntentDocument =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let intent = MigrationIntent {
        files: document.files,
        session: SessionId(parse_hex(&document.session_hex, "session")?),
        stable_owner: OwnerId(parse_hex(&document.stable_owner_hex, "stable owner")?),
        handoff: parse_hex(&document.handoff_hex, "handoff")?,
        checkpoint_barrier: BarrierToken(parse_hex(
            &document.checkpoint_barrier_hex,
            "checkpoint barrier",
        )?),
        source_epoch: document.source_epoch,
        destination_epoch: document.destination_epoch,
        source_client: ClientId(parse_hex(&document.source_client_hex, "source client")?),
        source_restore_client: ClientId(parse_hex(
            &document.source_restore_client_hex,
            "source restore client",
        )?),
        destination_client: ClientId(parse_hex(
            &document.destination_client_hex,
            "destination client",
        )?),
        application_build: document.application_build,
        source_platform: document.source_platform,
        destination_platform: document.destination_platform,
    };
    let manifest = MigrationManifest::seal(&intent, root).map_err(|error| error.to_string())?;
    manifest.write_new(&rooted(root, &args[4])).map_err(|error| error.to_string())?;
    println!("{}", manifest.digest().map_err(|error| error.to_string())?);
    Ok(())
}

fn verify(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        usage();
    }
    let root = Path::new(&args[2]);
    let manifest = read_manifest(&rooted(root, &args[3]))?;
    manifest.verify_at(root).map_err(|error| error.to_string())?;
    println!("{}", manifest.digest().map_err(|error| error.to_string())?);
    Ok(())
}

fn bind_proofs(args: &[String]) -> Result<(), String> {
    if args.len() != 8 {
        usage();
    }
    let root = Path::new(&args[2]);
    let manifest = read_manifest(&rooted(root, &args[3]))?;
    manifest.verify_at(root).map_err(|error| error.to_string())?;
    let commit = CanonicalCommitProof::bind_receipt(&manifest, root, &args[4])
        .map_err(|error| error.to_string())?;
    let fence = CanonicalFenceProof::bind_receipt(&manifest, &commit, root, &args[5])
        .map_err(|error| error.to_string())?;
    write_new(
        &rooted(root, &args[6]),
        &commit.canonical_bytes().map_err(|error| error.to_string())?,
    )?;
    write_new(
        &rooted(root, &args[7]),
        &fence.canonical_bytes().map_err(|error| error.to_string())?,
    )?;
    println!(
        "{} {}",
        hex(commit.digest().map_err(|error| error.to_string())?.0),
        hex(fence.digest().map_err(|error| error.to_string())?.0)
    );
    Ok(())
}

fn verify_proofs(args: &[String]) -> Result<(), String> {
    if args.len() != 6 {
        usage();
    }
    let root = Path::new(&args[2]);
    let manifest = read_manifest(&rooted(root, &args[3]))?;
    manifest.verify_at(root).map_err(|error| error.to_string())?;
    let commit = read_canonical_commit(&rooted(root, &args[4]))?;
    let fence = read_canonical_fence(&rooted(root, &args[5]))?;
    commit.verify_binding(&manifest, root).map_err(|error| error.to_string())?;
    fence.verify_binding(&manifest, &commit, root).map_err(|error| error.to_string())?;
    println!(
        "{} {}",
        hex(commit.digest().map_err(|error| error.to_string())?.0),
        hex(fence.digest().map_err(|error| error.to_string())?.0)
    );
    Ok(())
}

fn hex(bytes: [u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn run() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("seal") => seal(&args),
        Some("verify") => verify(&args),
        Some("bind-proofs") => bind_proofs(&args),
        Some("verify-proofs") => verify_proofs(&args),
        _ => usage(),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("visa-wasi-migration-bind: {error}");
        std::process::exit(1);
    }
}
