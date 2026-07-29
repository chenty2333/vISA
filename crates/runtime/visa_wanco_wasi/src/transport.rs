use std::{
    env,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use visa_wasi_protocol::{
    ClientId, GuestCapability, GuestRequest, GuestResponse, MAX_FRAME_BYTES, Operation, OwnerId,
    PROTOCOL_VERSION, SessionId, WireRequest, WireResponse, decode_response, encode_request, errno,
};

const EXCHANGE_ATTEMPTS: usize = 3;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct Config {
    socket: PathBuf,
    session: SessionId,
    owner: OwnerId,
    client: ClientId,
    capability: GuestCapability,
    authority_epoch: u64,
}

#[derive(Clone, Copy, Debug)]
enum ConfigError {
    Missing,
    Invalid,
}

static CONFIG: OnceLock<Result<Config, ConfigError>> = OnceLock::new();
static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(crate) fn invoke(operation: Operation) -> Result<visa_wasi_protocol::OperationResult, u16> {
    let response = exchange(operation)?;
    if response.errno == errno::SUCCESS { Ok(response.result) } else { Err(response.errno) }
}

fn exchange(operation: Operation) -> Result<GuestResponse, u16> {
    let config = CONFIG.get_or_init(load_config).as_ref().map_err(|error| match error {
        ConfigError::Missing => errno::IO,
        ConfigError::Invalid => errno::INVAL,
    })?;
    let sequence = NEXT_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            (current < i64::MAX as u64).then_some(current + 1)
        })
        .map_err(|_| errno::OVERFLOW)?;
    let request = WireRequest::Guest(GuestRequest {
        version: PROTOCOL_VERSION,
        session: config.session,
        owner: config.owner,
        client: config.client,
        capability: config.capability,
        sequence,
        authority_epoch: config.authority_epoch,
        operation,
    });
    let request = encode_request(&request).map_err(|_| errno::INVAL)?;
    if request.is_empty() || request.len() > MAX_FRAME_BYTES {
        return Err(errno::FBIG);
    }

    let mut last_error = errno::IO;
    for _ in 0..EXCHANGE_ATTEMPTS {
        match exchange_once(config, &request, sequence) {
            Ok(response) => return Ok(response),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn exchange_once(config: &Config, request: &[u8], sequence: u64) -> Result<GuestResponse, u16> {
    let mut stream = UnixStream::connect(&config.socket).map_err(|_| errno::IO)?;
    stream.set_read_timeout(Some(SOCKET_TIMEOUT)).map_err(|_| errno::IO)?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT)).map_err(|_| errno::IO)?;
    let request_len = u32::try_from(request.len()).map_err(|_| errno::FBIG)?;
    stream.write_all(&request_len.to_be_bytes()).map_err(|_| errno::IO)?;
    stream.write_all(request).map_err(|_| errno::IO)?;
    stream.flush().map_err(|_| errno::IO)?;

    let mut encoded_len = [0_u8; 4];
    stream.read_exact(&mut encoded_len).map_err(|_| errno::IO)?;
    let encoded_len = u32::from_be_bytes(encoded_len) as usize;
    if encoded_len == 0 || encoded_len > MAX_FRAME_BYTES {
        return Err(errno::IO);
    }
    let mut encoded = vec![0_u8; encoded_len];
    stream.read_exact(&mut encoded).map_err(|_| errno::IO)?;
    let response = decode_response(&encoded).map_err(|_| errno::IO)?;
    let WireResponse::Guest(response) = response else {
        return Err(errno::IO);
    };
    if !response.version.is_supported() || response.sequence != sequence {
        return Err(errno::IO);
    }
    Ok(response)
}

fn load_config() -> Result<Config, ConfigError> {
    let socket = env::var_os("VISA_WASI_SOCKET")
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::Missing)?;
    let session = SessionId(parse_identity("VISA_WASI_SESSION_ID")?);
    let owner = OwnerId(parse_identity("VISA_WASI_OWNER_ID")?);
    let client = ClientId(parse_identity("VISA_WASI_CLIENT_ID")?);
    let capability = GuestCapability(parse_capability("VISA_WASI_GUEST_CAPABILITY")?);
    let authority_epoch = env::var("VISA_WASI_AUTHORITY_EPOCH")
        .map_err(|_| ConfigError::Missing)?
        .parse::<u64>()
        .map_err(|_| ConfigError::Invalid)?;
    if session.is_zero()
        || owner.is_zero()
        || client.is_zero()
        || capability.is_zero()
        || authority_epoch == 0
        || authority_epoch > i64::MAX as u64
    {
        return Err(ConfigError::Invalid);
    }
    Ok(Config { socket: socket.into(), session, owner, client, capability, authority_epoch })
}

fn parse_identity(name: &str) -> Result<[u8; 16], ConfigError> {
    let encoded = env::var(name).map_err(|_| ConfigError::Missing)?;
    parse_identity_value(&encoded).ok_or(ConfigError::Invalid)
}

fn parse_identity_value(encoded: &str) -> Option<[u8; 16]> {
    let compact = match encoded.as_bytes() {
        bytes if bytes.len() == 32 && !bytes.contains(&b'-') => bytes.to_vec(),
        bytes
            if bytes.len() == 36
                && [8, 13, 18, 23].into_iter().all(|index| bytes[index] == b'-') =>
        {
            bytes.iter().copied().filter(|byte| *byte != b'-').collect()
        }
        _ => return None,
    };
    let mut output = [0_u8; 16];
    for (index, pair) in compact.chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn parse_capability(name: &str) -> Result<[u8; 32], ConfigError> {
    let encoded = env::var(name).map_err(|_| ConfigError::Missing)?;
    parse_capability_value(&encoded).ok_or(ConfigError::Invalid)
}

fn parse_capability_value(encoded: &str) -> Option<[u8; 32]> {
    (encoded.len() == 64).then_some(())?;
    let mut output = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_parser_accepts_hex_and_uuid_spelling() {
        let expected = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(parse_identity_value("00112233445566778899aabbccddeeff"), Some(expected));
        assert_eq!(parse_identity_value("00112233-4455-6677-8899-AABBCCDDEEFF"), Some(expected));
    }

    #[test]
    fn identity_parser_rejects_ambiguous_input() {
        assert_eq!(parse_identity_value("0011"), None);
        assert_eq!(parse_identity_value("00112233445566778899aabbccddeefg"), None);
        assert_eq!(parse_identity_value("00112233_4455_6677_8899_aabbccddeeff"), None);
        assert_eq!(parse_identity_value("00112233445566778899aabbccddeeff-"), None);
        assert_eq!(parse_identity_value("0011223-34455-6677-8899-aabbccddeeff"), None);
    }

    #[test]
    fn capability_parser_requires_exact_non_ambiguous_hex() {
        assert_eq!(parse_capability_value(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(parse_capability_value(&"ab".repeat(31)), None);
        assert_eq!(parse_capability_value(&format!("{}gg", "ab".repeat(31))), None);
    }
}
