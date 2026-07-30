use std::{
    cell::RefCell,
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

use sha2::{Digest as _, Sha256};
use visa_wasi_protocol::{
    BarrierDirective, BarrierPollRequest, BarrierToken, ClientId, EffectId, GuestCapability,
    GuestCompletion, GuestCompletionResponse, GuestRequest, GuestResponse, MAX_FRAME_BYTES,
    Operation, OwnerId, PROTOCOL_VERSION, SessionId, WireRequest, WireResponse, decode_response,
    encode_request, errno,
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

#[derive(Clone, Copy)]
struct PendingCompletion {
    sequence: u64,
    effect: EffectId,
}

#[derive(Clone, Copy)]
struct PendingBarrier {
    request: PendingCompletion,
    token: BarrierToken,
}

thread_local! {
    static PENDING_COMPLETION: RefCell<Option<PendingCompletion>> = const { RefCell::new(None) };
    static PENDING_BARRIER: RefCell<Option<PendingBarrier>> = const { RefCell::new(None) };
    static PENDING_DIRECTIVE: RefCell<Option<BarrierDirective>> = const { RefCell::new(None) };
}

pub(crate) fn invoke(operation: Operation) -> Result<visa_wasi_protocol::OperationResult, u16> {
    let directive = complete_pending()?;
    if directive != BarrierDirective::Continue {
        PENDING_DIRECTIVE.with(|pending| *pending.borrow_mut() = Some(directive));
        return Err(errno::AGAIN);
    }
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
    let effect = deterministic_effect_id(config, sequence, &operation)?;
    let request = WireRequest::Guest(GuestRequest {
        version: PROTOCOL_VERSION,
        session: config.session,
        owner: config.owner,
        client: config.client,
        capability: config.capability,
        sequence,
        effect,
        authority_epoch: config.authority_epoch,
        operation,
    });
    let request = encode_request(&request).map_err(|_| errno::INVAL)?;
    if request.is_empty() || request.len() > MAX_FRAME_BYTES {
        return Err(errno::FBIG);
    }

    let mut last_error = errno::IO;
    for _ in 0..EXCHANGE_ATTEMPTS {
        match exchange_once(config, &request, sequence, effect) {
            Ok(response) => {
                if response.completion_required {
                    PENDING_COMPLETION.with(|pending| {
                        *pending.borrow_mut() = Some(PendingCompletion { sequence, effect });
                    });
                }
                return Ok(response);
            }
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn exchange_once(
    config: &Config,
    request: &[u8],
    sequence: u64,
    effect: EffectId,
) -> Result<GuestResponse, u16> {
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
    if !response.version.is_supported()
        || response.sequence != sequence
        || response.effect != effect
    {
        return Err(errno::IO);
    }
    Ok(response)
}

pub(crate) fn hostcall_completed() -> Result<BarrierDirective, u16> {
    if let Some(directive) = PENDING_DIRECTIVE.with(|pending| pending.borrow_mut().take()) {
        return Ok(directive);
    }
    complete_pending()
}

fn complete_pending() -> Result<BarrierDirective, u16> {
    if let Some(waiting) = PENDING_BARRIER.with(|pending| *pending.borrow()) {
        return poll_barrier(waiting);
    }
    let pending = PENDING_COMPLETION.with(|pending| pending.borrow_mut().take());
    let Some(pending) = pending else { return Ok(BarrierDirective::Continue) };
    let config = CONFIG.get_or_init(load_config).as_ref().map_err(|error| match error {
        ConfigError::Missing => errno::IO,
        ConfigError::Invalid => errno::INVAL,
    })?;
    let completion = WireRequest::Completion(GuestCompletion {
        version: PROTOCOL_VERSION,
        session: config.session,
        owner: config.owner,
        client: config.client,
        capability: config.capability,
        sequence: pending.sequence,
        effect: pending.effect,
        authority_epoch: config.authority_epoch,
    });
    let encoded = encode_request(&completion).map_err(|_| errno::INVAL)?;
    let mut last_error = errno::IO;
    for _ in 0..EXCHANGE_ATTEMPTS {
        match completion_once(config, &encoded, pending) {
            Ok(response) => {
                return match response.directive {
                    BarrierDirective::Continue | BarrierDirective::Checkpoint => {
                        Ok(response.directive)
                    }
                    BarrierDirective::Wait => {
                        let token = response.barrier.ok_or(errno::IO)?;
                        let waiting = PendingBarrier { request: pending, token };
                        PENDING_BARRIER.with(|slot| *slot.borrow_mut() = Some(waiting));
                        poll_barrier(waiting)
                    }
                };
            }
            Err(error) => last_error = error,
        }
    }
    PENDING_COMPLETION.with(|slot| *slot.borrow_mut() = Some(pending));
    Err(last_error)
}

fn completion_once(
    config: &Config,
    encoded: &[u8],
    pending: PendingCompletion,
) -> Result<GuestCompletionResponse, u16> {
    let mut stream = UnixStream::connect(&config.socket).map_err(|_| errno::IO)?;
    stream.set_read_timeout(Some(SOCKET_TIMEOUT)).map_err(|_| errno::IO)?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT)).map_err(|_| errno::IO)?;
    let request_len = u32::try_from(encoded.len()).map_err(|_| errno::FBIG)?;
    stream.write_all(&request_len.to_be_bytes()).map_err(|_| errno::IO)?;
    stream.write_all(encoded).map_err(|_| errno::IO)?;
    stream.flush().map_err(|_| errno::IO)?;
    let mut encoded_len = [0_u8; 4];
    stream.read_exact(&mut encoded_len).map_err(|_| errno::IO)?;
    let encoded_len = u32::from_be_bytes(encoded_len) as usize;
    if encoded_len == 0 || encoded_len > MAX_FRAME_BYTES {
        return Err(errno::IO);
    }
    let mut response = vec![0_u8; encoded_len];
    stream.read_exact(&mut response).map_err(|_| errno::IO)?;
    let WireResponse::Completion(response) = decode_response(&response).map_err(|_| errno::IO)?
    else {
        return Err(errno::IO);
    };
    if !response.version.is_supported()
        || response.sequence != pending.sequence
        || response.effect != pending.effect
        || response.errno != errno::SUCCESS
    {
        return Err(if response.errno == errno::SUCCESS { errno::IO } else { response.errno });
    }
    Ok(response)
}

fn poll_barrier(waiting: PendingBarrier) -> Result<BarrierDirective, u16> {
    let config = CONFIG.get_or_init(load_config).as_ref().map_err(|error| match error {
        ConfigError::Missing => errno::IO,
        ConfigError::Invalid => errno::INVAL,
    })?;
    let request = WireRequest::BarrierPoll(BarrierPollRequest {
        version: PROTOCOL_VERSION,
        session: config.session,
        owner: config.owner,
        client: config.client,
        capability: config.capability,
        authority_epoch: config.authority_epoch,
        token: waiting.token,
        sequence: waiting.request.sequence,
        effect: waiting.request.effect,
    });
    let encoded = encode_request(&request).map_err(|_| errno::INVAL)?;
    loop {
        match poll_once(config, &encoded, waiting.token) {
            Ok(BarrierDirective::Wait) => std::thread::sleep(Duration::from_millis(5)),
            Ok(directive) => {
                PENDING_BARRIER.with(|slot| *slot.borrow_mut() = None);
                return Ok(directive);
            }
            Err(error) => return Err(error),
        }
    }
}

fn poll_once(
    config: &Config,
    encoded: &[u8],
    token: BarrierToken,
) -> Result<BarrierDirective, u16> {
    let mut stream = UnixStream::connect(&config.socket).map_err(|_| errno::IO)?;
    stream.set_read_timeout(Some(SOCKET_TIMEOUT)).map_err(|_| errno::IO)?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT)).map_err(|_| errno::IO)?;
    let request_len = u32::try_from(encoded.len()).map_err(|_| errno::FBIG)?;
    stream.write_all(&request_len.to_be_bytes()).map_err(|_| errno::IO)?;
    stream.write_all(encoded).map_err(|_| errno::IO)?;
    stream.flush().map_err(|_| errno::IO)?;
    let mut encoded_len = [0_u8; 4];
    stream.read_exact(&mut encoded_len).map_err(|_| errno::IO)?;
    let encoded_len = u32::from_be_bytes(encoded_len) as usize;
    if encoded_len == 0 || encoded_len > MAX_FRAME_BYTES {
        return Err(errno::IO);
    }
    let mut response = vec![0_u8; encoded_len];
    stream.read_exact(&mut response).map_err(|_| errno::IO)?;
    let WireResponse::BarrierPoll(response) = decode_response(&response).map_err(|_| errno::IO)?
    else {
        return Err(errno::IO);
    };
    if !response.version.is_supported()
        || response.token != token
        || response.errno != errno::SUCCESS
    {
        return Err(if response.errno == errno::SUCCESS { errno::IO } else { response.errno });
    }
    Ok(response.directive)
}

fn deterministic_effect_id(
    config: &Config,
    sequence: u64,
    operation: &Operation,
) -> Result<EffectId, u16> {
    let request = WireRequest::Guest(GuestRequest {
        version: PROTOCOL_VERSION,
        session: config.session,
        owner: config.owner,
        client: config.client,
        capability: config.capability,
        sequence,
        effect: EffectId([0; 16]),
        authority_epoch: config.authority_epoch,
        operation: operation.clone(),
    });
    let canonical_request = encode_request(&request).map_err(|_| errno::INVAL)?;
    let digest = Sha256::new()
        .chain_update(b"visa-wanco-effect-id-v1\0")
        .chain_update(canonical_request)
        .finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    if bytes == [0; 16] {
        bytes.copy_from_slice(&digest[16..]);
        if bytes == [0; 16] {
            bytes[15] = 1;
        }
    }
    Ok(EffectId(bytes))
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

    fn test_config() -> Config {
        Config {
            socket: "/tmp/unused.sock".into(),
            session: SessionId([1; 16]),
            owner: OwnerId([2; 16]),
            client: ClientId([3; 16]),
            capability: GuestCapability([4; 32]),
            authority_epoch: 7,
        }
    }

    #[test]
    fn effect_id_is_stable_for_native_process_replay() {
        let config = test_config();
        let operation = Operation::FdSync { fd: 5 };
        let first = deterministic_effect_id(&config, 41, &operation).expect("effect");
        let replay = deterministic_effect_id(&config, 41, &operation).expect("effect");
        assert_eq!(first, replay);
        assert!(!first.is_zero());
    }

    #[test]
    fn effect_id_binds_delivery_and_operation() {
        let config = test_config();
        let baseline =
            deterministic_effect_id(&config, 41, &Operation::FdSync { fd: 5 }).expect("effect");
        assert_ne!(
            baseline,
            deterministic_effect_id(&config, 42, &Operation::FdSync { fd: 5 }).expect("sequence")
        );
        assert_ne!(
            baseline,
            deterministic_effect_id(&config, 41, &Operation::FdSync { fd: 6 }).expect("operation")
        );
        let mut other = config;
        other.client = ClientId([9; 16]);
        assert_ne!(
            baseline,
            deterministic_effect_id(&other, 41, &Operation::FdSync { fd: 5 }).expect("client")
        );
    }

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
