use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use rustix::fs::{CWD, RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use visa_durable_sqlite::{
    DatabaseGuard, StoreLock, checkpoint_truncate, cleanup_owned_initialization_files,
    ensure_private_parent, ensure_sqlite_sidecars_absent, initialization_path, publish_noreplace,
    sync_file, sync_parent_directory,
};
use visa_wasi_protocol::{
    AdminCapability, AdminOperation, AdminRequest, AdminResponse, BarrierDirective, BarrierPhase,
    BarrierPollRequest, BarrierPollResponse, BarrierReleaseAction, BarrierToken, DirectoryEntry,
    EffectId, FdStat, FileStat, GuestCapability, GuestCompletion, GuestCompletionResponse,
    GuestRequest, GuestResponse, HostcallKind, HostcallPredicate, LockLevel,
    NAMESPACE_SNAPSHOT_VERSION, NamespaceDescriptor, NamespaceLock, NamespaceObject, NamespacePath,
    NamespaceSnapshot, NamespaceSnapshotReceipt, ObjectId, Operation, OperationResult,
    OutcomePredicate, OwnerId, PROTOCOL_VERSION, ProviderMode, ProviderStatus, ROOT_PREOPEN_FD,
    ResourceSelector, SeekWhence, SessionId, encode_namespace_snapshot, errno, rights,
};

const APPLICATION_ID: i64 = 0x5657_4153;
const SCHEMA_VERSION: i64 = 5;
const SQLITE_PAGE_SIZE: i64 = 4096;
const FILE_TYPE_DIRECTORY: u8 = 3;
const FILE_TYPE_REGULAR: u8 = 4;
const FILE_TYPE_SYMLINK: u8 = 7;
const FD_FLAG_APPEND: u16 = 1;
const OPEN_CREATE: u16 = 1;
const OPEN_DIRECTORY: u16 = 2;
const OPEN_EXCLUSIVE: u16 = 4;
const OPEN_TRUNCATE: u16 = 8;
const LOOKUP_SYMLINK_FOLLOW: u32 = 1;
const MAX_PATH_BYTES: usize = 4096;
const MAX_IO_BYTES: usize = 1024 * 1024;
const CHUNK_SIZE: usize = 64 * 1024;
const MAX_SYMLINK_DEPTH: usize = 16;
const BUNDLE_SCHEMA: &str = "visa-wasi-filesystem-capsule-v2";

const SCHEMA_SQL: &str = r#"
CREATE TABLE meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 5),
    session BLOB NOT NULL CHECK(length(session) = 16),
    capability_digest BLOB NOT NULL CHECK(length(capability_digest) = 32),
    guest_capability_digest BLOB NOT NULL CHECK(length(guest_capability_digest) = 32),
    mode INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 3),
    authority_epoch INTEGER NOT NULL CHECK(authority_epoch > 0),
    handoff BLOB CHECK(handoff IS NULL OR length(handoff) = 16),
    destination_epoch INTEGER,
    completed_handoff BLOB CHECK(completed_handoff IS NULL OR length(completed_handoff) = 16),
    barrier_phase INTEGER NOT NULL DEFAULT 0 CHECK(barrier_phase BETWEEN 0 AND 4),
    barrier_token BLOB CHECK(barrier_token IS NULL OR length(barrier_token) = 16),
    barrier_predicate BLOB,
    barrier_remaining INTEGER CHECK(barrier_remaining IS NULL OR barrier_remaining > 0),
    barrier_effect BLOB CHECK(barrier_effect IS NULL OR length(barrier_effect) = 16),
    completed_barrier BLOB CHECK(completed_barrier IS NULL OR length(completed_barrier) = 16),
    completed_barrier_effect BLOB CHECK(
        completed_barrier_effect IS NULL OR length(completed_barrier_effect) = 16
    ),
    next_object INTEGER NOT NULL CHECK(next_object > 0),
    next_fd INTEGER NOT NULL CHECK(next_fd >= 4),
    completed_requests INTEGER NOT NULL DEFAULT 0 CHECK(completed_requests >= 0),
    bytes_read INTEGER NOT NULL DEFAULT 0 CHECK(bytes_read >= 0),
    bytes_written INTEGER NOT NULL DEFAULT 0 CHECK(bytes_written >= 0)
) STRICT;
CREATE TABLE objects (
    object_id BLOB PRIMARY KEY CHECK(length(object_id) = 16),
    kind INTEGER NOT NULL CHECK(kind IN (3, 4, 7)),
    size INTEGER NOT NULL CHECK(size >= 0),
    symlink_target BLOB,
    mode INTEGER NOT NULL DEFAULT 438 CHECK(mode BETWEEN 0 AND 4095),
    uid INTEGER NOT NULL DEFAULT 0 CHECK(uid BETWEEN 0 AND 4294967295),
    gid INTEGER NOT NULL DEFAULT 0 CHECK(gid BETWEEN 0 AND 4294967295),
    accessed_ns INTEGER NOT NULL CHECK(accessed_ns >= 0),
    modified_ns INTEGER NOT NULL CHECK(modified_ns >= 0),
    changed_ns INTEGER NOT NULL CHECK(changed_ns >= 0),
    CHECK((kind = 7) = (symlink_target IS NOT NULL)),
    CHECK(kind = 4 OR size = 0)
) STRICT;
CREATE TABLE object_chunks (
    object_id BLOB NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0),
    bytes BLOB NOT NULL CHECK(length(bytes) <= 65536),
    PRIMARY KEY(object_id, chunk_index)
) STRICT;
CREATE TABLE paths (
    path BLOB PRIMARY KEY,
    object_id BLOB NOT NULL REFERENCES objects(object_id),
    CHECK(length(path) <= 4096)
) STRICT;
CREATE TABLE descriptors (
    fd INTEGER PRIMARY KEY CHECK(fd >= 3),
    object_id BLOB NOT NULL REFERENCES objects(object_id),
    directory_path BLOB NOT NULL,
    offset INTEGER NOT NULL CHECK(offset >= 0),
    flags INTEGER NOT NULL CHECK(flags BETWEEN 0 AND 65535),
    rights_base INTEGER NOT NULL,
    rights_inheriting INTEGER NOT NULL,
    preopen INTEGER NOT NULL CHECK(preopen IN (0, 1))
) STRICT;
CREATE TABLE locks (
    object_id BLOB NOT NULL REFERENCES objects(object_id),
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 4),
    PRIMARY KEY(object_id, owner)
) STRICT;
CREATE TABLE requests (
    client BLOB NOT NULL CHECK(length(client) = 16),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    effect_id BLOB NOT NULL REFERENCES effects(effect_id),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    response BLOB NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
    PRIMARY KEY(client, sequence)
) STRICT;
CREATE TABLE effects (
    effect_id BLOB PRIMARY KEY CHECK(length(effect_id) = 16),
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    operation_digest BLOB NOT NULL CHECK(length(operation_digest) = 32),
    response BLOB NOT NULL,
    first_authority_epoch INTEGER NOT NULL CHECK(first_authority_epoch > 0)
) STRICT;
"#;

#[derive(Debug)]
pub enum ProviderError {
    Invalid(&'static str),
    Busy,
    AlreadyExists,
    Missing,
    Integrity(&'static str),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Codec,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid provider input: {message}"),
            Self::Busy => formatter.write_str("provider is busy"),
            Self::AlreadyExists => formatter.write_str("provider target already exists"),
            Self::Missing => formatter.write_str("provider input is missing"),
            Self::Integrity(message) => write!(formatter, "provider integrity failure: {message}"),
            Self::Io(error) => write!(formatter, "provider filesystem failure: {error}"),
            Self::Sqlite(error) => write!(formatter, "provider SQLite failure: {error}"),
            Self::Codec => formatter.write_str("provider wire codec failure"),
        }
    }
}

impl std::error::Error for ProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ProviderError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for ProviderError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

#[derive(Clone, Debug)]
pub struct ImportFile {
    pub host_path: PathBuf,
    pub guest_path: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CreateConfig {
    pub database: PathBuf,
    pub session: SessionId,
    pub capability: AdminCapability,
    pub guest_capability: GuestCapability,
    pub authority_epoch: u64,
    pub imports: Vec<ImportFile>,
}

#[derive(Clone, Debug)]
pub struct RestoreConfig {
    pub bundle: PathBuf,
    pub database: PathBuf,
    pub capability: AdminCapability,
    pub guest_capability: GuestCapability,
}

pub struct Provider {
    connection: Connection,
    database_guard: DatabaseGuard,
    _lock: StoreLock,
    shutdown_requested: bool,
}

#[derive(Clone)]
struct Meta {
    session: SessionId,
    mode: ProviderMode,
    authority_epoch: u64,
    handoff: Option<[u8; 16]>,
    destination_epoch: Option<u64>,
    completed_handoff: Option<[u8; 16]>,
    barrier: BarrierPhase,
    barrier_token: Option<BarrierToken>,
    barrier_predicate: Option<Vec<u8>>,
    barrier_remaining: Option<u64>,
    barrier_effect: Option<EffectId>,
    completed_barrier: Option<BarrierToken>,
    completed_barrier_effect: Option<EffectId>,
}

type RawMeta = (
    Vec<u8>,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

#[derive(Clone)]
struct Descriptor {
    object: ObjectId,
    directory_path: Vec<u8>,
    offset: u64,
    flags: u16,
    rights_base: u64,
    rights_inheriting: u64,
    preopen: bool,
}

#[derive(Clone)]
struct Object {
    id: ObjectId,
    kind: u8,
    size: u64,
    symlink_target: Option<Vec<u8>>,
    accessed_ns: u64,
    modified_ns: u64,
    changed_ns: u64,
}

struct ApplyResult {
    errno: u16,
    result: OperationResult,
    bytes_read: u64,
    bytes_written: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEffectResponse {
    errno: u16,
    result: OperationResult,
}

impl ApplyResult {
    fn ok(result: OperationResult) -> Self {
        Self { errno: errno::SUCCESS, result, bytes_read: 0, bytes_written: 0 }
    }

    fn error(errno: u16) -> Self {
        Self { errno, result: OperationResult::None, bytes_read: 0, bytes_written: 0 }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleManifest {
    schema: String,
    session_hex: String,
    source_epoch: u64,
    destination_epoch: u64,
    handoff_hex: String,
    state_file: String,
    state_size: u64,
    state_sha256: String,
}

impl Provider {
    pub fn handle_guest(&mut self, request: GuestRequest) -> GuestResponse {
        let response = |errno, result, completion_required| GuestResponse {
            version: PROTOCOL_VERSION,
            sequence: request.sequence,
            effect: request.effect,
            completion_required,
            errno,
            result,
        };
        let invalid = || response(errno::INVAL, OperationResult::None, false);
        let unavailable = || response(errno::IO, OperationResult::None, false);
        if !request.is_well_formed()
            || request.sequence > i64::MAX as u64
            || request.authority_epoch > i64::MAX as u64
        {
            return invalid();
        }
        if !self.guest_capability_matches(request.capability).unwrap_or(false) {
            return response(errno::ACCES, OperationResult::None, false);
        }
        let operation_bytes = match postcard::to_allocvec(&request.operation) {
            Ok(bytes) if bytes.len() <= visa_wasi_protocol::MAX_FRAME_BYTES => bytes,
            _ => return invalid(),
        };
        let mut operation_hasher = Sha256::new();
        operation_hasher.update(b"vISA/WASI/effect/v1\0");
        operation_hasher.update(request.session.0);
        operation_hasher.update(request.owner.0);
        operation_hasher.update(&operation_bytes);
        let operation_digest = operation_hasher.finalize();
        let mut request_hasher = Sha256::new();
        request_hasher.update(b"vISA/WASI/request/v2\0");
        request_hasher.update(request.session.0);
        request_hasher.update(request.owner.0);
        request_hasher.update(request.client.0);
        request_hasher.update(request.capability.0);
        request_hasher.update(request.sequence.to_le_bytes());
        request_hasher.update(request.effect.0);
        request_hasher.update(request.authority_epoch.to_le_bytes());
        request_hasher.update(&operation_bytes);
        let request_digest = request_hasher.finalize();
        let transaction =
            match self.connection.transaction_with_behavior(TransactionBehavior::Immediate) {
                Ok(transaction) => transaction,
                Err(_) => return response(errno::AGAIN, OperationResult::None, false),
            };
        let meta = match load_meta(&transaction) {
            Ok(meta) => meta,
            Err(_) => return invalid(),
        };
        let authority_errno = if meta.session != request.session {
            Some(errno::ACCES)
        } else {
            match meta.mode {
                ProviderMode::Prepared => Some(errno::AGAIN),
                ProviderMode::Frozen | ProviderMode::Fenced => Some(errno::PERM),
                ProviderMode::Active if meta.authority_epoch != request.authority_epoch => {
                    Some(errno::PERM)
                }
                ProviderMode::Active => None,
            }
        };
        if let Some(errno) = authority_errno {
            return response(errno, OperationResult::None, false);
        }
        let replay = transaction
            .query_row(
                "SELECT effect_id, request_digest, response
                 FROM requests WHERE client = ?1 AND sequence = ?2",
                params![request.client.0.as_slice(), request.sequence as i64],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional();
        if let Ok(Some((stored_effect, stored_digest, response_bytes))) = replay {
            if stored_effect.as_slice() != request.effect.0.as_slice()
                || stored_digest.as_slice() != request_digest.as_slice()
            {
                return invalid();
            }
            return postcard::from_bytes(&response_bytes).unwrap_or_else(|_| invalid());
        }
        if replay.is_err() {
            return unavailable();
        }
        if matches!(
            meta.barrier,
            BarrierPhase::Triggered | BarrierPhase::Held | BarrierPhase::CheckpointReleased
        ) {
            return response(errno::AGAIN, OperationResult::None, false);
        }
        let previous_sequence: Result<Option<i64>, _> = transaction.query_row(
            "SELECT max(sequence) FROM requests WHERE client = ?1",
            params![request.client.0.as_slice()],
            |row| row.get(0),
        );
        let sequence_is_fresh = match (previous_sequence, i64::try_from(request.sequence)) {
            (Ok(Some(previous)), Ok(current)) => current > previous,
            (Ok(None), Ok(_)) => true,
            _ => false,
        };
        if !sequence_is_fresh {
            return invalid();
        }

        let effect = transaction
            .query_row(
                "SELECT owner, operation_digest, response FROM effects WHERE effect_id = ?1",
                params![request.effect.0.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional();
        if let Ok(Some((stored_owner, stored_digest, stored_response))) = effect {
            if stored_owner.as_slice() != request.owner.0
                || stored_digest.as_slice() != operation_digest.as_slice()
            {
                return invalid();
            }
            let stored: StoredEffectResponse = match postcard::from_bytes(&stored_response) {
                Ok(stored) => stored,
                Err(_) => return unavailable(),
            };
            let replayed = response(stored.errno, stored.result, true);
            let response_bytes = match postcard::to_allocvec(&replayed) {
                Ok(bytes) => bytes,
                Err(_) => return unavailable(),
            };
            if record_request(&transaction, &request, request_digest.as_slice(), &response_bytes)
                .and_then(|()| transaction.commit())
                .is_err()
            {
                return unavailable();
            }
            return replayed;
        }
        if effect.is_err() {
            return unavailable();
        }
        if transaction.execute_batch("SAVEPOINT guest_operation").is_err() {
            return unavailable();
        }
        let barrier_outcome =
            match barrier_outcome_for_operation(&transaction, &meta, &request.operation) {
                Ok(matches) => matches,
                Err(_) => return unavailable(),
            };
        let applied = match apply_operation(&transaction, &request.owner, &request.operation) {
            Ok(applied) => applied,
            Err(error) => ApplyResult::error(operation_errno(&error)),
        };
        let operation_finalized = if applied.errno == errno::SUCCESS {
            transaction.execute_batch("RELEASE guest_operation")
        } else {
            // Keep the deterministic error response in the replay ledger, but
            // never commit mutations performed before an operation discovered
            // its semantic failure.
            transaction.execute_batch(
                "ROLLBACK TO guest_operation;
                 RELEASE guest_operation;",
            )
        };
        if operation_finalized.is_err() {
            return unavailable();
        }
        let stored = StoredEffectResponse { errno: applied.errno, result: applied.result.clone() };
        let response = response(applied.errno, applied.result, true);
        let stored_bytes = match postcard::to_allocvec(&stored) {
            Ok(bytes) => bytes,
            Err(_) => return unavailable(),
        };
        let response_bytes = match postcard::to_allocvec(&response) {
            Ok(bytes) => bytes,
            Err(_) => return unavailable(),
        };
        if transaction
            .execute(
                "INSERT INTO effects(effect_id, owner, operation_digest, response,
                 first_authority_epoch) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    request.effect.0.as_slice(),
                    request.owner.0.as_slice(),
                    operation_digest.as_slice(),
                    stored_bytes,
                    request.authority_epoch as i64,
                ],
            )
            .map(|_| ())
            .and_then(|()| {
                record_request(&transaction, &request, request_digest.as_slice(), &response_bytes)
            })
            .and_then(|_| {
                transaction.execute(
                    "UPDATE meta SET completed_requests = completed_requests + 1,
                     bytes_read = bytes_read + ?1, bytes_written = bytes_written + ?2
                     WHERE singleton = 1",
                    params![
                        sql_i64(applied.bytes_read).unwrap_or(i64::MAX),
                        sql_i64(applied.bytes_written).unwrap_or(i64::MAX)
                    ],
                )
            })
            .and_then(|_| {
                advance_barrier_after_response(
                    &transaction,
                    &meta,
                    barrier_outcome,
                    applied.errno,
                    request.effect,
                )
            })
            .and_then(|_| transaction.commit())
            .is_err()
        {
            return unavailable();
        }
        response
    }

    pub fn handle_completion(&mut self, completion: GuestCompletion) -> GuestCompletionResponse {
        let response = |errno, directive, barrier| GuestCompletionResponse {
            version: PROTOCOL_VERSION,
            sequence: completion.sequence,
            effect: completion.effect,
            errno,
            directive,
            barrier,
        };
        if !completion.is_well_formed()
            || completion.sequence > i64::MAX as u64
            || completion.authority_epoch > i64::MAX as u64
        {
            return response(errno::INVAL, BarrierDirective::Continue, None);
        }
        if !self.guest_capability_matches(completion.capability).unwrap_or(false) {
            return response(errno::ACCES, BarrierDirective::Continue, None);
        }
        let transaction =
            match self.connection.transaction_with_behavior(TransactionBehavior::Immediate) {
                Ok(transaction) => transaction,
                Err(_) => return response(errno::AGAIN, BarrierDirective::Continue, None),
            };
        let meta = match load_meta(&transaction) {
            Ok(meta) => meta,
            Err(_) => return response(errno::IO, BarrierDirective::Continue, None),
        };
        if meta.session != completion.session {
            return response(errno::ACCES, BarrierDirective::Continue, None);
        }
        if meta.mode != ProviderMode::Active || meta.authority_epoch != completion.authority_epoch {
            return response(errno::PERM, BarrierDirective::Continue, None);
        }
        let binding = transaction
            .query_row(
                "SELECT e.owner, r.completed FROM requests r
                 JOIN effects e ON e.effect_id = r.effect_id
                 WHERE r.client = ?1 AND r.sequence = ?2 AND r.effect_id = ?3",
                params![
                    completion.client.0.as_slice(),
                    completion.sequence as i64,
                    completion.effect.0.as_slice(),
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional();
        let Ok(Some((owner, completed))) = binding else {
            return response(
                if binding.is_err() { errno::IO } else { errno::INVAL },
                BarrierDirective::Continue,
                None,
            );
        };
        if owner.as_slice() != completion.owner.0.as_slice() || !matches!(completed, 0 | 1) {
            return response(errno::INVAL, BarrierDirective::Continue, None);
        }
        if completed == 0
            && transaction
                .execute(
                    "UPDATE requests SET completed = 1
                     WHERE client = ?1 AND sequence = ?2 AND effect_id = ?3",
                    params![
                        completion.client.0.as_slice(),
                        completion.sequence as i64,
                        completion.effect.0.as_slice(),
                    ],
                )
                .ok()
                != Some(1)
        {
            return response(errno::IO, BarrierDirective::Continue, None);
        }
        let target = meta.barrier_effect == Some(completion.effect);
        if target
            && meta.barrier == BarrierPhase::Triggered
            && transaction
                .execute(
                    "UPDATE meta SET barrier_phase = 3 WHERE singleton = 1
                     AND barrier_phase = 2 AND barrier_effect = ?1",
                    params![completion.effect.0.as_slice()],
                )
                .ok()
                != Some(1)
        {
            return response(errno::IO, BarrierDirective::Continue, None);
        }
        if transaction.commit().is_err() {
            return response(errno::IO, BarrierDirective::Continue, None);
        }
        let (directive, barrier) = match (target, meta.barrier) {
            (true, BarrierPhase::Triggered | BarrierPhase::Held) => {
                (BarrierDirective::Wait, meta.barrier_token)
            }
            (true, BarrierPhase::CheckpointReleased) => {
                (BarrierDirective::Checkpoint, meta.barrier_token)
            }
            _ => (BarrierDirective::Continue, None),
        };
        response(errno::SUCCESS, directive, barrier)
    }

    pub fn handle_barrier_poll(&mut self, poll: BarrierPollRequest) -> BarrierPollResponse {
        let response = |errno, directive| BarrierPollResponse {
            version: PROTOCOL_VERSION,
            token: poll.token,
            errno,
            directive,
        };
        if !poll.is_well_formed() || poll.authority_epoch > i64::MAX as u64 {
            return response(errno::INVAL, BarrierDirective::Continue);
        }
        if !self.guest_capability_matches(poll.capability).unwrap_or(false) {
            return response(errno::ACCES, BarrierDirective::Continue);
        }
        let Ok(meta) = load_meta(&self.connection) else {
            return response(errno::IO, BarrierDirective::Continue);
        };
        if meta.session != poll.session {
            return response(errno::ACCES, BarrierDirective::Continue);
        }
        if meta.mode != ProviderMode::Active || meta.authority_epoch != poll.authority_epoch {
            return response(errno::PERM, BarrierDirective::Continue);
        }
        let binding = self
            .connection
            .query_row(
                "SELECT e.owner, r.completed FROM requests r
                 JOIN effects e ON e.effect_id = r.effect_id
                 WHERE r.client = ?1 AND r.sequence = ?2 AND r.effect_id = ?3",
                params![poll.client.0.as_slice(), poll.sequence as i64, poll.effect.0.as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional();
        let (owner, completed) = match binding {
            Ok(Some(binding)) => binding,
            Ok(None) => return response(errno::INVAL, BarrierDirective::Continue),
            Err(_) => return response(errno::IO, BarrierDirective::Continue),
        };
        if completed != 1 {
            return response(errno::INVAL, BarrierDirective::Continue);
        }
        if owner.as_slice() != poll.owner.0.as_slice() {
            return response(errno::INVAL, BarrierDirective::Continue);
        }
        if meta.barrier == BarrierPhase::Open
            && meta.completed_barrier == Some(poll.token)
            && meta.completed_barrier_effect == Some(poll.effect)
        {
            return response(errno::SUCCESS, BarrierDirective::Continue);
        }
        if meta.barrier_token != Some(poll.token) || meta.barrier_effect != Some(poll.effect) {
            return response(errno::INVAL, BarrierDirective::Continue);
        }
        match meta.barrier {
            BarrierPhase::Triggered | BarrierPhase::Held => {
                response(errno::SUCCESS, BarrierDirective::Wait)
            }
            BarrierPhase::CheckpointReleased => {
                response(errno::SUCCESS, BarrierDirective::Checkpoint)
            }
            BarrierPhase::Open | BarrierPhase::Armed => {
                response(errno::INVAL, BarrierDirective::Continue)
            }
        }
    }

    pub fn handle_admin(&mut self, request: AdminRequest) -> AdminResponse {
        let reject = |message: &str| AdminResponse {
            version: PROTOCOL_VERSION,
            ok: false,
            message: message.to_owned(),
            status: None,
            snapshot: None,
        };
        if !request.version.is_supported() {
            return reject("unsupported protocol version");
        }
        if !self.capability_matches(request.capability).unwrap_or(false) {
            return reject("admin capability rejected");
        }
        let result = match request.operation {
            AdminOperation::Status => {
                self.status().map(|status| ("status".to_owned(), Some(status), None))
            }
            AdminOperation::BarrierArm { token, predicate } => self
                .barrier_arm(token, &predicate)
                .and_then(|()| self.status())
                .map(|status| ("barrier armed".to_owned(), Some(status), None)),
            AdminOperation::BarrierRelease { token, action } => self
                .barrier_release(token, action)
                .and_then(|()| self.status())
                .map(|status| ("barrier released".to_owned(), Some(status), None)),
            AdminOperation::Freeze { barrier, handoff, destination_epoch } => self
                .freeze(barrier, handoff, destination_epoch)
                .and_then(|()| self.status())
                .map(|status| ("source frozen".to_owned(), Some(status), None)),
            AdminOperation::Export { bundle } => self
                .export_bundle(Path::new(&bundle))
                .and_then(|()| self.status())
                .map(|status| ("capsule exported".to_owned(), Some(status), None)),
            AdminOperation::Resume { handoff, authority_epoch } => self
                .resume(handoff, authority_epoch)
                .and_then(|()| self.status())
                .map(|status| ("source resumed".to_owned(), Some(status), None)),
            AdminOperation::Fence { handoff, committed_epoch } => self
                .fence(handoff, committed_epoch)
                .and_then(|()| self.status())
                .map(|status| ("source fenced".to_owned(), Some(status), None)),
            AdminOperation::Activate { handoff, authority_epoch } => self
                .activate(handoff, authority_epoch)
                .and_then(|()| self.status())
                .map(|status| ("destination activated".to_owned(), Some(status), None)),
            AdminOperation::Materialize { guest_path, host_path } => self
                .materialize(&guest_path, Path::new(&host_path))
                .and_then(|()| self.status())
                .map(|status| ("file materialized".to_owned(), Some(status), None)),
            AdminOperation::SnapshotNamespace { output } => {
                self.snapshot_namespace(Path::new(&output)).and_then(|receipt| {
                    self.status().map(|status| {
                        ("namespace snapshot published".to_owned(), Some(status), Some(receipt))
                    })
                })
            }
            AdminOperation::Shutdown => {
                self.shutdown_requested = true;
                self.status().map(|status| ("shutdown requested".to_owned(), Some(status), None))
            }
        };
        match result {
            Ok((message, status, snapshot)) => {
                AdminResponse { version: PROTOCOL_VERSION, ok: true, message, status, snapshot }
            }
            Err(error) => reject(&error.to_string()),
        }
    }

    pub const fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    pub fn status(&self) -> Result<ProviderStatus, ProviderError> {
        let meta = load_meta(&self.connection)?;
        let raw: (i64, i64, i64, i64, i64, i64, i64, i64) = self.connection.query_row(
            "SELECT
                   (SELECT count(*) FROM descriptors),
                   (SELECT count(*) FROM objects),
                   (SELECT count(*) FROM paths),
                   (SELECT count(*) FROM locks),
                   (SELECT count(*) FROM effects),
                   completed_requests, bytes_read, bytes_written
                 FROM meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )?;
        let (
            open_descriptors,
            objects,
            paths,
            locks,
            effects,
            completed_requests,
            bytes_read,
            bytes_written,
        ) = (
            nonnegative(raw.0)?,
            nonnegative(raw.1)?,
            nonnegative(raw.2)?,
            nonnegative(raw.3)?,
            nonnegative(raw.4)?,
            nonnegative(raw.5)?,
            nonnegative(raw.6)?,
            nonnegative(raw.7)?,
        );
        Ok(ProviderStatus {
            session: meta.session,
            mode: meta.mode,
            authority_epoch: meta.authority_epoch,
            barrier: meta.barrier,
            barrier_remaining: meta.barrier_remaining,
            barrier_effect: meta.barrier_effect,
            completed_barrier: meta.completed_barrier,
            completed_barrier_effect: meta.completed_barrier_effect,
            open_descriptors,
            objects,
            paths,
            locks,
            effects,
            completed_requests,
            bytes_read,
            bytes_written,
        })
    }

    fn capability_matches(&self, capability: AdminCapability) -> Result<bool, ProviderError> {
        let expected: Vec<u8> = self.connection.query_row(
            "SELECT capability_digest FROM meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let actual = Sha256::digest(capability.0);
        Ok(constant_time_eq(&expected, actual.as_slice()))
    }

    fn guest_capability_matches(&self, capability: GuestCapability) -> Result<bool, ProviderError> {
        let expected: Vec<u8> = self.connection.query_row(
            "SELECT guest_capability_digest FROM meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let actual = Sha256::digest(capability.0);
        Ok(constant_time_eq(&expected, actual.as_slice()))
    }

    fn barrier_arm(
        &mut self,
        token: BarrierToken,
        predicate: &HostcallPredicate,
    ) -> Result<(), ProviderError> {
        validate_barrier_predicate(token, predicate)?;
        let predicate_bytes = postcard::to_allocvec(predicate).map_err(|_| ProviderError::Codec)?;
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let meta = load_meta(&transaction)?;
        if meta.mode == ProviderMode::Active
            && meta.barrier == BarrierPhase::Armed
            && meta.barrier_token == Some(token)
            && meta.barrier_predicate.as_deref() == Some(predicate_bytes.as_slice())
        {
            return transaction.commit().map_err(Into::into);
        }
        if meta.mode != ProviderMode::Active || meta.barrier != BarrierPhase::Open {
            return Err(ProviderError::Invalid("barrier arm rejected"));
        }
        let incomplete: i64 = transaction.query_row(
            "SELECT count(*) FROM requests WHERE completed = 0",
            [],
            |row| row.get(0),
        )?;
        if incomplete != 0 {
            return Err(ProviderError::Busy);
        }
        transaction.execute(
            "UPDATE meta SET barrier_phase = 1, barrier_token = ?1,
             barrier_predicate = ?2, barrier_remaining = ?3, barrier_effect = NULL,
             completed_barrier = NULL, completed_barrier_effect = NULL WHERE singleton = 1",
            params![token.0.as_slice(), predicate_bytes, sql_i64(predicate.occurrence)?],
        )?;
        transaction.commit()?;
        self.sync()
    }

    fn barrier_release(
        &mut self,
        token: BarrierToken,
        action: BarrierReleaseAction,
    ) -> Result<(), ProviderError> {
        if token.is_zero() {
            return Err(ProviderError::Invalid("zero barrier token"));
        }
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let meta = load_meta(&transaction)?;
        match action {
            BarrierReleaseAction::Continue
                if meta.mode == ProviderMode::Active
                    && meta.barrier == BarrierPhase::Open
                    && meta.completed_barrier == Some(token) =>
            {
                return transaction.commit().map_err(Into::into);
            }
            BarrierReleaseAction::Checkpoint
                if meta.mode == ProviderMode::Active
                    && meta.barrier == BarrierPhase::CheckpointReleased
                    && meta.barrier_token == Some(token) =>
            {
                return transaction.commit().map_err(Into::into);
            }
            _ => {}
        }
        if meta.mode != ProviderMode::Active
            || meta.barrier != BarrierPhase::Held
            || meta.barrier_token != Some(token)
        {
            return Err(ProviderError::Invalid("barrier release rejected"));
        }
        let incomplete: i64 = transaction.query_row(
            "SELECT count(*) FROM requests WHERE completed = 0",
            [],
            |row| row.get(0),
        )?;
        if incomplete != 0 {
            return Err(ProviderError::Busy);
        }
        match action {
            BarrierReleaseAction::Continue => {
                transaction.execute(
                    "UPDATE meta SET barrier_phase = 0, barrier_token = NULL,
                     barrier_predicate = NULL, barrier_remaining = NULL,
                     completed_barrier = ?1, completed_barrier_effect = barrier_effect,
                     barrier_effect = NULL WHERE singleton = 1",
                    params![token.0.as_slice()],
                )?;
            }
            BarrierReleaseAction::Checkpoint => {
                transaction.execute(
                    "UPDATE meta SET barrier_phase = 4, barrier_predicate = NULL,
                     barrier_remaining = NULL WHERE singleton = 1",
                    [],
                )?;
            }
        }
        transaction.commit()?;
        self.sync()
    }

    fn freeze(
        &mut self,
        barrier: BarrierToken,
        handoff: [u8; 16],
        destination_epoch: u64,
    ) -> Result<(), ProviderError> {
        if handoff == [0; 16] || barrier.is_zero() {
            return Err(ProviderError::Invalid("zero handoff or barrier identity"));
        }
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let meta = load_meta(&transaction)?;
        if meta.mode == ProviderMode::Frozen
            && meta.handoff == Some(handoff)
            && meta.destination_epoch == Some(destination_epoch)
            && meta.barrier == BarrierPhase::CheckpointReleased
            && meta.barrier_token == Some(barrier)
        {
            return transaction.commit().map_err(Into::into);
        }
        if meta.mode != ProviderMode::Active
            || meta.barrier != BarrierPhase::CheckpointReleased
            || meta.barrier_token != Some(barrier)
            || destination_epoch
                != meta
                    .authority_epoch
                    .checked_add(1)
                    .ok_or(ProviderError::Invalid("authority epoch overflow"))?
        {
            return Err(ProviderError::Invalid("freeze transition rejected"));
        }
        transaction.execute(
            "UPDATE meta SET mode = 1, handoff = ?1, destination_epoch = ?2,
             completed_handoff = NULL
             WHERE singleton = 1",
            params![handoff.as_slice(), sql_i64(destination_epoch)?],
        )?;
        transaction.commit()?;
        self.sync()
    }

    fn resume(&mut self, handoff: [u8; 16], authority_epoch: u64) -> Result<(), ProviderError> {
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let meta = load_meta(&transaction)?;
        if meta.mode == ProviderMode::Active
            && meta.authority_epoch == authority_epoch
            && meta.handoff.is_none()
            && meta.completed_handoff == Some(handoff)
            && meta.barrier == BarrierPhase::Open
        {
            return transaction.commit().map_err(Into::into);
        }
        if meta.mode != ProviderMode::Frozen
            || meta.handoff != Some(handoff)
            || meta.authority_epoch != authority_epoch
        {
            return Err(ProviderError::Invalid("resume transition rejected"));
        }
        transaction.execute(
            "UPDATE meta SET mode = 0, handoff = NULL, destination_epoch = NULL,
             completed_handoff = ?1, completed_barrier = barrier_token,
             completed_barrier_effect = barrier_effect,
             barrier_phase = 0, barrier_token = NULL, barrier_predicate = NULL,
             barrier_remaining = NULL, barrier_effect = NULL
             WHERE singleton = 1",
            params![handoff.as_slice()],
        )?;
        transaction.commit()?;
        self.sync()
    }

    fn fence(&mut self, handoff: [u8; 16], committed_epoch: u64) -> Result<(), ProviderError> {
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let meta = load_meta(&transaction)?;
        if meta.mode == ProviderMode::Fenced
            && meta.handoff == Some(handoff)
            && meta.destination_epoch == Some(committed_epoch)
        {
            return transaction.commit().map_err(Into::into);
        }
        if meta.mode != ProviderMode::Frozen
            || meta.handoff != Some(handoff)
            || meta.destination_epoch != Some(committed_epoch)
        {
            return Err(ProviderError::Invalid("fence transition rejected"));
        }
        transaction.execute("UPDATE meta SET mode = 3 WHERE singleton = 1", [])?;
        transaction.commit()?;
        self.sync()
    }

    fn activate(&mut self, handoff: [u8; 16], authority_epoch: u64) -> Result<(), ProviderError> {
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let meta = load_meta(&transaction)?;
        if meta.mode == ProviderMode::Active
            && meta.authority_epoch == authority_epoch
            && meta.handoff.is_none()
            && meta.completed_handoff == Some(handoff)
            && meta.barrier == BarrierPhase::Open
        {
            return transaction.commit().map_err(Into::into);
        }
        if meta.mode != ProviderMode::Prepared
            || meta.handoff != Some(handoff)
            || meta.destination_epoch != Some(authority_epoch)
        {
            return Err(ProviderError::Invalid("activation transition rejected"));
        }
        transaction.execute(
            "UPDATE meta SET mode = 0, authority_epoch = ?1, handoff = NULL,
             destination_epoch = NULL, completed_handoff = ?2,
             completed_barrier = barrier_token, completed_barrier_effect = barrier_effect,
             barrier_phase = 0, barrier_token = NULL,
             barrier_predicate = NULL, barrier_remaining = NULL, barrier_effect = NULL
             WHERE singleton = 1",
            params![sql_i64(authority_epoch)?, handoff.as_slice()],
        )?;
        transaction.commit()?;
        self.sync()
    }

    fn export_bundle(&mut self, bundle: &Path) -> Result<(), ProviderError> {
        let meta = load_meta(&self.connection)?;
        if meta.mode != ProviderMode::Frozen {
            return Err(ProviderError::Invalid("only a frozen source can export"));
        }
        let handoff = meta.handoff.ok_or(ProviderError::Integrity("frozen handoff missing"))?;
        let destination_epoch =
            meta.destination_epoch.ok_or(ProviderError::Integrity("destination epoch missing"))?;
        if bundle.exists() {
            return self.verify_existing_bundle(bundle, meta.session, handoff, destination_epoch);
        }
        ensure_private_parent(bundle)
            .map_err(|_| ProviderError::Invalid("private capsule parent required"))?;
        checkpoint_truncate(&self.connection)
            .map_err(|_| ProviderError::Integrity("checkpoint failed"))?;
        self.sync()?;
        let parent = bundle
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .ok_or(ProviderError::Invalid("capsule path has no parent"))?;
        let temporary = parent.join(format!(
            ".visa-capsule-{}-{}-{}.tmp",
            &hex(handoff)[..16],
            std::process::id(),
            now_ns()?
        ));
        let result = (|| {
            fs::create_dir(&temporary)?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))?;
            let state_path = temporary.join("state.sqlite");
            copy_new(self.database_guard.path(), &state_path)?;
            let state_bytes = fs::read(&state_path)?;
            let manifest = BundleManifest {
                schema: BUNDLE_SCHEMA.to_owned(),
                session_hex: hex(meta.session.0),
                source_epoch: meta.authority_epoch,
                destination_epoch,
                handoff_hex: hex(handoff),
                state_file: "state.sqlite".to_owned(),
                state_size: u64::try_from(state_bytes.len())
                    .map_err(|_| ProviderError::Integrity("state size overflow"))?,
                state_sha256: hex(Sha256::digest(&state_bytes)),
            };
            let manifest_bytes =
                serde_json::to_vec_pretty(&manifest).map_err(|_| ProviderError::Codec)?;
            write_new_synced(&temporary.join("manifest.json"), &manifest_bytes)?;
            sync_directory(&temporary)?;
            renameat_with(CWD, &temporary, CWD, bundle, RenameFlags::NOREPLACE).map_err(
                |error| {
                    if error == rustix::io::Errno::EXIST {
                        ProviderError::AlreadyExists
                    } else {
                        ProviderError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()))
                    }
                },
            )?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temporary);
        }
        result
    }

    fn verify_existing_bundle(
        &self,
        bundle: &Path,
        session: SessionId,
        handoff: [u8; 16],
        destination_epoch: u64,
    ) -> Result<(), ProviderError> {
        let manifest = read_manifest(bundle)?;
        verify_manifest_bytes(bundle, &manifest)?;
        if manifest.session_hex != hex(session.0)
            || manifest.handoff_hex != hex(handoff)
            || manifest.destination_epoch != destination_epoch
        {
            return Err(ProviderError::Integrity("existing capsule binding differs"));
        }
        Ok(())
    }

    fn materialize(&self, guest_path: &[u8], host_path: &Path) -> Result<(), ProviderError> {
        let path = normalize_path(&[], guest_path).map_err(|_| {
            ProviderError::Invalid("materialize path is not a canonical guest path")
        })?;
        let object =
            object_for_path(&self.connection, &path, true)?.ok_or(ProviderError::Missing)?;
        if object.kind != FILE_TYPE_REGULAR {
            return Err(ProviderError::Invalid("materialize target is not a regular file"));
        }
        let bytes = read_object_range(
            &self.connection,
            object.id,
            0,
            usize::try_from(object.size)
                .map_err(|_| ProviderError::Invalid("materialized file is too large"))?,
        )?;
        write_new_synced(host_path, &bytes)
    }

    pub fn snapshot_namespace(
        &mut self,
        output: &Path,
    ) -> Result<NamespaceSnapshotReceipt, ProviderError> {
        if output.exists() {
            return Err(ProviderError::AlreadyExists);
        }
        ensure_private_parent(output)
            .map_err(|_| ProviderError::Invalid("private snapshot parent required"))?;
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let meta = load_meta(&transaction)?;
        if meta.barrier != BarrierPhase::CheckpointReleased
            || !matches!(meta.mode, ProviderMode::Active | ProviderMode::Frozen)
        {
            return Err(ProviderError::Invalid(
                "namespace snapshot requires a checkpoint-released barrier",
            ));
        }
        let (effect_frontier, effects) = effect_frontier(&transaction)?;

        let raw_objects = {
            let mut statement = transaction.prepare(
                "SELECT object_id, kind, size, symlink_target, mode, uid, gid,
                 accessed_ns, modified_ns, changed_ns FROM objects ORDER BY object_id",
            )?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut objects = Vec::with_capacity(raw_objects.len());
        for (id, kind, size, symlink_target, mode, uid, gid, atime, mtime, ctime) in raw_objects {
            let object = ObjectId(
                id.try_into().map_err(|_| ProviderError::Integrity("snapshot object identity"))?,
            );
            let kind =
                u8::try_from(kind).map_err(|_| ProviderError::Integrity("snapshot object kind"))?;
            let size = nonnegative(size)?;
            let bytes = if kind == FILE_TYPE_REGULAR {
                read_object_range(
                    &transaction,
                    object,
                    0,
                    usize::try_from(size)
                        .map_err(|_| ProviderError::Invalid("snapshot object is too large"))?,
                )?
            } else {
                Vec::new()
            };
            objects.push(NamespaceObject {
                object,
                kind,
                size,
                symlink_target,
                mode: u32::try_from(mode).map_err(|_| ProviderError::Integrity("snapshot mode"))?,
                uid: u32::try_from(uid).map_err(|_| ProviderError::Integrity("snapshot uid"))?,
                gid: u32::try_from(gid).map_err(|_| ProviderError::Integrity("snapshot gid"))?,
                accessed_ns: nonnegative(atime)?,
                modified_ns: nonnegative(mtime)?,
                changed_ns: nonnegative(ctime)?,
                bytes,
            });
        }

        let paths = {
            let mut statement = transaction
                .prepare("SELECT path, object_id FROM paths ORDER BY path, object_id")?;
            let raw = statement
                .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            raw.into_iter()
                .map(|(path, object)| {
                    Ok(NamespacePath {
                        path,
                        object: ObjectId(object.try_into().map_err(|_| {
                            ProviderError::Integrity("snapshot path object identity")
                        })?),
                    })
                })
                .collect::<Result<Vec<_>, ProviderError>>()?
        };

        let descriptors = {
            let mut statement = transaction.prepare(
                "SELECT fd, object_id, directory_path, offset, flags, rights_base,
                 rights_inheriting, preopen FROM descriptors ORDER BY fd",
            )?;
            let raw = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            raw.into_iter()
                .map(|(fd, object, directory_path, offset, flags, base, inheriting, preopen)| {
                    Ok(NamespaceDescriptor {
                        fd: u32::try_from(fd)
                            .map_err(|_| ProviderError::Integrity("snapshot fd"))?,
                        object: ObjectId(object.try_into().map_err(|_| {
                            ProviderError::Integrity("snapshot descriptor object identity")
                        })?),
                        directory_path,
                        offset: nonnegative(offset)?,
                        flags: u16::try_from(flags)
                            .map_err(|_| ProviderError::Integrity("snapshot fd flags"))?,
                        rights_base: sql_to_u64(base),
                        rights_inheriting: sql_to_u64(inheriting),
                        preopen: match preopen {
                            0 => false,
                            1 => true,
                            _ => return Err(ProviderError::Integrity("snapshot preopen flag")),
                        },
                    })
                })
                .collect::<Result<Vec<_>, ProviderError>>()?
        };

        let locks = {
            let mut statement = transaction
                .prepare("SELECT object_id, owner, level FROM locks ORDER BY object_id, owner")?;
            let raw = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            raw.into_iter()
                .map(|(object, owner, level)| {
                    Ok(NamespaceLock {
                        object: ObjectId(object.try_into().map_err(|_| {
                            ProviderError::Integrity("snapshot lock object identity")
                        })?),
                        owner: OwnerId(owner.try_into().map_err(|_| {
                            ProviderError::Integrity("snapshot lock owner identity")
                        })?),
                        level: sql_to_lock(level)?,
                    })
                })
                .collect::<Result<Vec<_>, ProviderError>>()?
        };

        let unlinked_objects = objects
            .iter()
            .filter(|object| !paths.iter().any(|path| path.object == object.object))
            .count();
        let snapshot = NamespaceSnapshot {
            version: NAMESPACE_SNAPSHOT_VERSION,
            session: meta.session,
            authority_epoch: meta.authority_epoch,
            mode: meta.mode,
            barrier: meta.barrier,
            effect_frontier,
            effects,
            objects,
            paths,
            descriptors,
            locks,
        };
        transaction.commit()?;
        let encoded = encode_namespace_snapshot(&snapshot).map_err(|_| ProviderError::Codec)?;
        let receipt = NamespaceSnapshotReceipt {
            version: NAMESPACE_SNAPSHOT_VERSION,
            sha256: Sha256::digest(&encoded).into(),
            effect_frontier: snapshot.effect_frontier,
            effects: snapshot.effects,
            encoded_bytes: u64::try_from(encoded.len())
                .map_err(|_| ProviderError::Integrity("snapshot size overflow"))?,
            objects: u64::try_from(snapshot.objects.len())
                .map_err(|_| ProviderError::Integrity("snapshot object count overflow"))?,
            paths: u64::try_from(snapshot.paths.len())
                .map_err(|_| ProviderError::Integrity("snapshot path count overflow"))?,
            descriptors: u64::try_from(snapshot.descriptors.len())
                .map_err(|_| ProviderError::Integrity("snapshot descriptor count overflow"))?,
            locks: u64::try_from(snapshot.locks.len())
                .map_err(|_| ProviderError::Integrity("snapshot lock count overflow"))?,
            unlinked_objects: u64::try_from(unlinked_objects)
                .map_err(|_| ProviderError::Integrity("snapshot unlinked count overflow"))?,
        };
        write_atomic_snapshot(output, &encoded)?;
        Ok(receipt)
    }

    fn sync(&self) -> Result<(), ProviderError> {
        sync_file(self.database_guard.file())
            .map_err(|_| ProviderError::Integrity("database sync failed"))?;
        sync_parent_directory(self.database_guard.path())
            .map_err(|_| ProviderError::Integrity("database parent sync failed"))
    }
}

fn record_request(
    transaction: &Transaction<'_>,
    request: &GuestRequest,
    request_digest: &[u8],
    response: &[u8],
) -> Result<(), rusqlite::Error> {
    transaction.execute(
        "INSERT INTO requests(client, sequence, effect_id, request_digest, response)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            request.client.0.as_slice(),
            request.sequence as i64,
            request.effect.0.as_slice(),
            request_digest,
            response,
        ],
    )?;
    // The synchronous client has acknowledged every older sequence. Durable
    // effect outcomes remain in `effects`; only the transport replay window is
    // compacted here.
    transaction.execute(
        "DELETE FROM requests WHERE client = ?1 AND sequence < ?2 AND completed = 1",
        params![request.client.0.as_slice(), request.sequence as i64],
    )?;
    Ok(())
}

fn validate_barrier_predicate(
    token: BarrierToken,
    predicate: &HostcallPredicate,
) -> Result<(), ProviderError> {
    if token.is_zero() || !predicate.is_well_formed() || predicate.occurrence > i64::MAX as u64 {
        return Err(ProviderError::Invalid("barrier identity or occurrence"));
    }
    if let ResourceSelector::ExactPath(path) = &predicate.resource
        && (path.is_empty() || normalize_path(&[], path).ok().as_deref() != Some(path.as_slice()))
    {
        return Err(ProviderError::Invalid("barrier path is not canonical"));
    }
    Ok(())
}

fn barrier_outcome_for_operation(
    connection: &Connection,
    meta: &Meta,
    operation: &Operation,
) -> Result<Option<OutcomePredicate>, ProviderError> {
    if meta.barrier != BarrierPhase::Armed {
        return Ok(None);
    }
    let encoded = meta
        .barrier_predicate
        .as_deref()
        .ok_or(ProviderError::Integrity("armed barrier lacks predicate"))?;
    let predicate: HostcallPredicate = postcard::from_bytes(encoded)
        .map_err(|_| ProviderError::Integrity("barrier predicate encoding"))?;
    validate_barrier_predicate(
        meta.barrier_token.ok_or(ProviderError::Integrity("armed barrier lacks token"))?,
        &predicate,
    )?;
    if predicate.kind != HostcallKind::Any && operation_kind(operation) != Some(predicate.kind) {
        return Ok(None);
    }
    let resource_matches = match &predicate.resource {
        ResourceSelector::Any => true,
        ResourceSelector::Fd(expected) => operation_fds(operation).contains(expected),
        ResourceSelector::ExactPath(expected) => {
            operation_paths(connection, operation)?.iter().any(|path| path == expected)
        }
    };
    Ok(resource_matches.then_some(predicate.outcome))
}

fn advance_barrier_after_response(
    transaction: &Transaction<'_>,
    meta: &Meta,
    outcome: Option<OutcomePredicate>,
    errno_value: u16,
    effect: EffectId,
) -> rusqlite::Result<usize> {
    let Some(outcome) = outcome else {
        return Ok(0);
    };
    let outcome_matches = match outcome {
        OutcomePredicate::Any => true,
        OutcomePredicate::Success => errno_value == errno::SUCCESS,
        OutcomePredicate::Errno(expected) => errno_value == expected,
    };
    if !outcome_matches {
        return Ok(0);
    }
    let remaining = meta.barrier_remaining.ok_or(rusqlite::Error::InvalidQuery)?;
    if remaining > 1 {
        transaction.execute(
            "UPDATE meta SET barrier_remaining = barrier_remaining - 1
             WHERE singleton = 1 AND barrier_phase = 1 AND barrier_remaining = ?1",
            params![remaining as i64],
        )
    } else {
        transaction.execute(
            "UPDATE meta SET barrier_phase = 2, barrier_remaining = NULL, barrier_effect = ?1
             WHERE singleton = 1 AND barrier_phase = 1 AND barrier_remaining = 1",
            params![effect.0.as_slice()],
        )
    }
}

fn operation_kind(operation: &Operation) -> Option<HostcallKind> {
    match operation {
        Operation::FdClose { .. } => Some(HostcallKind::FdClose),
        Operation::FdDataSync { .. } => Some(HostcallKind::FdDataSync),
        Operation::FdPread { .. } => Some(HostcallKind::FdPread),
        Operation::FdPwrite { .. } => Some(HostcallKind::FdPwrite),
        Operation::FdRead { .. } => Some(HostcallKind::FdRead),
        Operation::FdSync { .. } => Some(HostcallKind::FdSync),
        Operation::FdWrite { .. } => Some(HostcallKind::FdWrite),
        Operation::PathCreateDirectory { .. } => Some(HostcallKind::PathCreateDirectory),
        Operation::PathOpen { .. } => Some(HostcallKind::PathOpen),
        Operation::PathRemoveDirectory { .. } => Some(HostcallKind::PathRemoveDirectory),
        Operation::PathRename { .. } => Some(HostcallKind::PathRename),
        Operation::PathUnlinkFile { .. } => Some(HostcallKind::PathUnlinkFile),
        Operation::VfsLock { .. } => Some(HostcallKind::VfsLock),
        Operation::VfsUnlock { .. } => Some(HostcallKind::VfsUnlock),
        _ => None,
    }
}

fn operation_fds(operation: &Operation) -> Vec<u32> {
    match operation {
        Operation::FdAdvise { fd, .. }
        | Operation::FdAllocate { fd, .. }
        | Operation::FdClose { fd }
        | Operation::FdDataSync { fd }
        | Operation::FdStatGet { fd }
        | Operation::FdStatSetFlags { fd, .. }
        | Operation::FdStatSetRights { fd, .. }
        | Operation::FdFileStatGet { fd }
        | Operation::FdFileStatSetSize { fd, .. }
        | Operation::FdFileStatSetTimes { fd, .. }
        | Operation::FdPread { fd, .. }
        | Operation::FdPwrite { fd, .. }
        | Operation::FdPrestatGet { fd }
        | Operation::FdPrestatDirName { fd }
        | Operation::FdRead { fd, .. }
        | Operation::FdReadDir { fd, .. }
        | Operation::FdSeek { fd, .. }
        | Operation::FdSync { fd }
        | Operation::FdTell { fd }
        | Operation::FdWrite { fd, .. }
        | Operation::VfsLock { fd, .. }
        | Operation::VfsUnlock { fd, .. }
        | Operation::VfsCheckReserved { fd } => vec![*fd],
        Operation::FdRenumber { from, to } => vec![*from, *to],
        Operation::PathCreateDirectory { dir_fd, .. }
        | Operation::PathFileStatGet { dir_fd, .. }
        | Operation::PathFileStatSetTimes { dir_fd, .. }
        | Operation::PathOpen { dir_fd, .. }
        | Operation::PathReadLink { dir_fd, .. }
        | Operation::PathRemoveDirectory { dir_fd, .. }
        | Operation::PathSymlink { dir_fd, .. }
        | Operation::PathUnlinkFile { dir_fd, .. }
        | Operation::PathChmod { dir_fd, .. }
        | Operation::PathChown { dir_fd, .. } => vec![*dir_fd],
        Operation::PathLink { old_dir_fd, new_dir_fd, .. }
        | Operation::PathRename { old_dir_fd, new_dir_fd, .. } => {
            vec![*old_dir_fd, *new_dir_fd]
        }
    }
}

fn operation_paths(
    connection: &Connection,
    operation: &Operation,
) -> Result<Vec<Vec<u8>>, ProviderError> {
    let requested = |dir_fd, path: &[u8]| -> Result<Vec<u8>, ProviderError> {
        let descriptor = descriptor(connection, dir_fd)?
            .ok_or(ProviderError::Invalid("barrier path directory fd is missing"))?;
        normalize_path(&descriptor.directory_path, path)
            .map_err(|_| ProviderError::Invalid("barrier operation path escaped root"))
    };
    let fd_paths = |fd| -> Result<Vec<Vec<u8>>, ProviderError> {
        let Some(descriptor) = descriptor(connection, fd)? else {
            return Ok(Vec::new());
        };
        let mut statement =
            connection.prepare("SELECT path FROM paths WHERE object_id = ?1 ORDER BY path")?;
        Ok(statement
            .query_map(params![descriptor.object.0.as_slice()], |row| row.get(0))?
            .collect::<Result<Vec<Vec<u8>>, _>>()?)
    };
    match operation {
        Operation::PathCreateDirectory { dir_fd, path }
        | Operation::PathFileStatGet { dir_fd, path, .. }
        | Operation::PathFileStatSetTimes { dir_fd, path, .. }
        | Operation::PathOpen { dir_fd, path, .. }
        | Operation::PathReadLink { dir_fd, path, .. }
        | Operation::PathRemoveDirectory { dir_fd, path }
        | Operation::PathUnlinkFile { dir_fd, path }
        | Operation::PathChmod { dir_fd, path, .. }
        | Operation::PathChown { dir_fd, path, .. } => Ok(vec![requested(*dir_fd, path)?]),
        Operation::PathSymlink { dir_fd, new_path, .. } => Ok(vec![requested(*dir_fd, new_path)?]),
        Operation::PathLink { old_dir_fd, old_path, new_dir_fd, new_path, .. }
        | Operation::PathRename { old_dir_fd, old_path, new_dir_fd, new_path } => {
            Ok(vec![requested(*old_dir_fd, old_path)?, requested(*new_dir_fd, new_path)?])
        }
        _ => {
            let mut paths = Vec::new();
            for fd in operation_fds(operation) {
                paths.extend(fd_paths(fd)?);
            }
            paths.sort();
            paths.dedup();
            Ok(paths)
        }
    }
}

fn effect_frontier(connection: &Connection) -> Result<([u8; 32], u64), ProviderError> {
    let mut statement = connection.prepare(
        "SELECT effect_id, owner, operation_digest, response, first_authority_epoch
         FROM effects ORDER BY effect_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"vISA/WASI/effect-frontier/v1\0");
    let mut count = 0_u64;
    for row in rows {
        let (effect, owner, operation, response, epoch) = row?;
        for field in [&effect, &owner, &operation, &response] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        hasher.update(nonnegative(epoch)?.to_be_bytes());
        count = count
            .checked_add(1)
            .ok_or(ProviderError::Integrity("effect frontier count overflow"))?;
    }
    Ok((hasher.finalize().into(), count))
}

fn operation_errno(error: &ProviderError) -> u16 {
    match error {
        ProviderError::Invalid(message)
            if matches!(
                *message,
                "path escaped the preopen"
                    | "path escaped the directory capability"
                    | "symlink target escaped root"
                    | "symlink target escaped the directory capability"
            ) =>
        {
            errno::NOTCAPABLE
        }
        ProviderError::Invalid(_) => errno::INVAL,
        ProviderError::Busy => errno::AGAIN,
        ProviderError::AlreadyExists => errno::EXIST,
        ProviderError::Missing => errno::NOENT,
        ProviderError::Integrity(_)
        | ProviderError::Io(_)
        | ProviderError::Sqlite(_)
        | ProviderError::Codec => errno::IO,
    }
}

pub fn create_provider(config: &CreateConfig) -> Result<(), ProviderError> {
    if config.session.is_zero()
        || config.capability.is_zero()
        || config.guest_capability.is_zero()
        || config.authority_epoch == 0
        || config.authority_epoch > i64::MAX as u64
        || config.database.exists()
    {
        return Err(ProviderError::Invalid("create binding or target"));
    }
    ensure_private_parent(&config.database)
        .map_err(|_| ProviderError::Invalid("private database parent required"))?;
    let lock = StoreLock::acquire(lock_path(&config.database)).map_err(|_| ProviderError::Busy)?;
    ensure_sqlite_sidecars_absent(&config.database).map_err(|_| ProviderError::AlreadyExists)?;
    let nonce = first_16(Sha256::digest(
        [
            config.session.0.as_slice(),
            config.capability.0.as_slice(),
            config.guest_capability.0.as_slice(),
        ]
        .concat(),
    ));
    let temporary_path = initialization_path(&config.database, nonce);
    let guard =
        DatabaseGuard::create_new(&temporary_path).map_err(|_| ProviderError::AlreadyExists)?;
    let result = (|| {
        let mut connection = open_connection(&temporary_path, true)?;
        configure_connection(&connection)?;
        connection.execute_batch(SCHEMA_SQL)?;
        let now = now_ns()?;
        let root = derived_object(config.session, 0);
        connection.execute(
            "INSERT INTO meta(singleton, schema_version, session, capability_digest,
             guest_capability_digest, mode, authority_epoch, handoff, destination_epoch,
             next_object, next_fd)
             VALUES (1, 5, ?1, ?2, ?3, 0, ?4, NULL, NULL, 1, 4)",
            params![
                config.session.0.as_slice(),
                Sha256::digest(config.capability.0).as_slice(),
                Sha256::digest(config.guest_capability.0).as_slice(),
                config.authority_epoch as i64,
            ],
        )?;
        connection.execute(
            "INSERT INTO objects(object_id, kind, size, symlink_target, mode,
             accessed_ns, modified_ns, changed_ns)
             VALUES (?1, 3, 0, NULL, ?2, ?3, ?3, ?3)",
            params![root.0.as_slice(), 0o755_u32, sql_i64(now)?],
        )?;
        connection.execute(
            "INSERT INTO paths(path, object_id) VALUES (x'', ?1)",
            params![root.0.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO descriptors(fd, object_id, directory_path, offset, flags,
             rights_base, rights_inheriting, preopen)
             VALUES (?1, ?2, x'', 0, 0, ?3, ?3, 1)",
            params![ROOT_PREOPEN_FD, root.0.as_slice(), u64_to_sql(u64::MAX)],
        )?;
        for import in &config.imports {
            import_file(&mut connection, config.session, import)?;
        }
        audit_connection(&connection)?;
        checkpoint_truncate(&connection)
            .map_err(|_| ProviderError::Integrity("initial checkpoint failed"))?;
        connection.close().map_err(|_| ProviderError::Integrity("initial close failed"))?;
        ensure_sqlite_sidecars_absent(&temporary_path)
            .map_err(|_| ProviderError::Integrity("initial sidecar remained"))?;
        publish_noreplace(&temporary_path, &config.database, guard.file())
            .map_err(|_| ProviderError::AlreadyExists)
    })();
    if result.is_err() {
        cleanup_owned_initialization_files(&temporary_path, guard.file());
    }
    drop(lock);
    result
}

pub fn restore_provider(config: &RestoreConfig) -> Result<(), ProviderError> {
    if config.capability.is_zero() || config.guest_capability.is_zero() || config.database.exists()
    {
        return Err(ProviderError::Invalid("restore binding or target"));
    }
    let manifest = read_manifest(&config.bundle)?;
    verify_manifest_bytes(&config.bundle, &manifest)?;
    ensure_private_parent(&config.database)
        .map_err(|_| ProviderError::Invalid("private database parent required"))?;
    let lock = StoreLock::acquire(lock_path(&config.database)).map_err(|_| ProviderError::Busy)?;
    let source = config.bundle.join(&manifest.state_file);
    let nonce = first_16(Sha256::digest(
        [
            manifest.state_sha256.as_bytes(),
            config.capability.0.as_slice(),
            config.guest_capability.0.as_slice(),
        ]
        .concat(),
    ));
    let temporary_path = initialization_path(&config.database, nonce);
    copy_new(&source, &temporary_path)?;
    fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600))?;
    let result = (|| {
        let guard = DatabaseGuard::open_existing(&temporary_path)
            .map_err(|_| ProviderError::Integrity("capsule state is not SQLite"))?;
        let connection = open_connection(&temporary_path, false)?;
        configure_connection(&connection)?;
        audit_connection(&connection)?;
        let meta = load_meta(&connection)?;
        if meta.mode != ProviderMode::Frozen
            || hex(meta.session.0) != manifest.session_hex
            || meta.handoff.map(hex) != Some(manifest.handoff_hex.clone())
            || meta.destination_epoch != Some(manifest.destination_epoch)
            || meta.authority_epoch != manifest.source_epoch
        {
            return Err(ProviderError::Integrity("capsule state binding differs"));
        }
        connection.execute(
            "UPDATE meta SET capability_digest = ?1, guest_capability_digest = ?2,
             mode = 2 WHERE singleton = 1",
            params![
                Sha256::digest(config.capability.0).as_slice(),
                Sha256::digest(config.guest_capability.0).as_slice(),
            ],
        )?;
        checkpoint_truncate(&connection)
            .map_err(|_| ProviderError::Integrity("restore checkpoint failed"))?;
        connection.close().map_err(|_| ProviderError::Integrity("restore close failed"))?;
        publish_noreplace(&temporary_path, &config.database, guard.file())
            .map_err(|_| ProviderError::AlreadyExists)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    drop(lock);
    result
}

pub fn open_provider(database: impl AsRef<Path>) -> Result<Provider, ProviderError> {
    let database = database.as_ref();
    let lock = StoreLock::acquire(lock_path(database)).map_err(|_| ProviderError::Busy)?;
    let database_guard = DatabaseGuard::open_existing(database)
        .map_err(|_| ProviderError::Integrity("provider database rejected"))?;
    let connection = open_connection(database, false)?;
    configure_connection(&connection)?;
    audit_connection(&connection)?;
    Ok(Provider { connection, database_guard, _lock: lock, shutdown_requested: false })
}

fn apply_operation(
    transaction: &Transaction<'_>,
    owner: &OwnerId,
    operation: &Operation,
) -> Result<ApplyResult, ProviderError> {
    macro_rules! require_fd {
        ($fd:expr, $right:expr) => {
            match descriptor_with_right(transaction, $fd, $right)? {
                Ok(descriptor) => descriptor,
                Err(error) => return Ok(ApplyResult::error(error)),
            }
        };
    }
    match operation {
        Operation::FdAdvise { fd, advice, .. } => {
            let _ = require_fd!(*fd, rights::FD_ADVISE);
            if *advice > 5 {
                return Ok(ApplyResult::error(errno::INVAL));
            }
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::FdAllocate { fd, offset, length } => {
            let descriptor = require_fd!(*fd, rights::FD_ALLOCATE);
            if object_kind(transaction, descriptor.object)? != FILE_TYPE_REGULAR {
                return Ok(ApplyResult::error(errno::BADF));
            }
            let end = match offset.checked_add(*length) {
                Some(end) if end <= i64::MAX as u64 => end,
                _ => return Ok(ApplyResult::error(errno::FBIG)),
            };
            let current = object_size(transaction, descriptor.object)?;
            if end > current {
                resize_object(transaction, descriptor.object, end)?;
            }
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::FdClose { fd } => {
            if *fd == ROOT_PREOPEN_FD {
                return Ok(ApplyResult::error(errno::BADF));
            }
            let Some(closing) = descriptor(transaction, *fd)? else {
                return Ok(ApplyResult::error(errno::BADF));
            };
            let changed =
                transaction.execute("DELETE FROM descriptors WHERE fd = ?1", params![fd])?;
            transaction.execute(
                "DELETE FROM locks WHERE object_id = ?1 AND owner = ?2",
                params![closing.object.0.as_slice(), owner.0.as_slice()],
            )?;
            collect_object_if_unreferenced(transaction, closing.object)?;
            Ok(if changed == 1 {
                ApplyResult::ok(OperationResult::None)
            } else {
                ApplyResult::error(errno::BADF)
            })
        }
        Operation::FdDataSync { fd } => {
            let _ = require_fd!(*fd, rights::FD_DATASYNC);
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::FdSync { fd } => {
            let _ = require_fd!(*fd, rights::FD_SYNC);
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::FdStatGet { fd } => {
            let Some(descriptor) = descriptor(transaction, *fd)? else {
                return Ok(ApplyResult::error(errno::BADF));
            };
            let kind = object_kind(transaction, descriptor.object)?;
            Ok(ApplyResult::ok(OperationResult::FdStat(FdStat {
                file_type: kind,
                flags: descriptor.flags,
                rights_base: descriptor.rights_base,
                rights_inheriting: descriptor.rights_inheriting,
            })))
        }
        Operation::FdStatSetFlags { fd, flags } => {
            let _ = require_fd!(*fd, rights::FD_FDSTAT_SET_FLAGS);
            if flags & !0x1f != 0 {
                return Ok(ApplyResult::error(errno::INVAL));
            }
            let changed = transaction
                .execute("UPDATE descriptors SET flags = ?1 WHERE fd = ?2", params![flags, fd])?;
            Ok(if changed == 1 {
                ApplyResult::ok(OperationResult::None)
            } else {
                ApplyResult::error(errno::BADF)
            })
        }
        Operation::FdStatSetRights { fd, rights_base, rights_inheriting } => {
            let Some(existing) = descriptor(transaction, *fd)? else {
                return Ok(ApplyResult::error(errno::BADF));
            };
            if rights_base & !existing.rights_base != 0
                || rights_inheriting & !existing.rights_inheriting != 0
            {
                return Ok(ApplyResult::error(errno::NOTCAPABLE));
            }
            transaction.execute(
                "UPDATE descriptors SET rights_base = ?1, rights_inheriting = ?2 WHERE fd = ?3",
                params![u64_to_sql(*rights_base), u64_to_sql(*rights_inheriting), fd],
            )?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::FdFileStatGet { fd } => {
            let descriptor = require_fd!(*fd, rights::FD_FILESTAT_GET);
            let stat = file_stat(transaction, descriptor.object)?;
            Ok(ApplyResult::ok(OperationResult::FileStat(stat)))
        }
        Operation::FdFileStatSetSize { fd, size } => {
            let descriptor = require_fd!(*fd, rights::FD_FILESTAT_SET_SIZE);
            if object_kind(transaction, descriptor.object)? != FILE_TYPE_REGULAR {
                return Ok(ApplyResult::error(errno::BADF));
            }
            resize_object(transaction, descriptor.object, *size)?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::FdFileStatSetTimes { fd, atim, mtim, fst_flags } => {
            let descriptor = require_fd!(*fd, rights::FD_FILESTAT_SET_TIMES);
            set_times(transaction, descriptor.object, *atim, *mtim, *fst_flags)?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::FdPread { fd, length, offset } => {
            let _ = require_fd!(*fd, rights::FD_READ | rights::FD_SEEK);
            read_at(transaction, *fd, *offset, *length, false)
        }
        Operation::FdPwrite { fd, bytes, offset } => {
            let _ = require_fd!(*fd, rights::FD_WRITE | rights::FD_SEEK);
            write_at(transaction, *fd, *offset, bytes, false)
        }
        Operation::FdPrestatGet { fd } | Operation::FdPrestatDirName { fd } => {
            let Some(descriptor) = descriptor(transaction, *fd)? else {
                return Ok(ApplyResult::error(errno::BADF));
            };
            if !descriptor.preopen {
                return Ok(ApplyResult::error(errno::BADF));
            }
            Ok(ApplyResult::ok(OperationResult::Prestat { name: b"/".to_vec() }))
        }
        Operation::FdRead { fd, length } => {
            let descriptor = require_fd!(*fd, rights::FD_READ);
            read_at(transaction, *fd, descriptor.offset, *length, true)
        }
        Operation::FdReadDir { fd, cookie, buffer_len } => {
            let _ = require_fd!(*fd, rights::FD_READDIR);
            read_directory(transaction, *fd, *cookie, *buffer_len)
        }
        Operation::FdRenumber { from, to } => {
            if *from == ROOT_PREOPEN_FD || *to == ROOT_PREOPEN_FD {
                return Ok(ApplyResult::error(errno::BADF));
            }
            let Some(_) = descriptor(transaction, *from)? else {
                return Ok(ApplyResult::error(errno::BADF));
            };
            if from == to {
                return Ok(ApplyResult::ok(OperationResult::None));
            }
            let replaced = descriptor(transaction, *to)?;
            transaction.execute("DELETE FROM descriptors WHERE fd = ?1", params![to])?;
            if let Some(replaced) = replaced {
                transaction.execute(
                    "DELETE FROM locks WHERE object_id = ?1 AND owner = ?2",
                    params![replaced.object.0.as_slice(), owner.0.as_slice()],
                )?;
                collect_object_if_unreferenced(transaction, replaced.object)?;
            }
            transaction
                .execute("UPDATE descriptors SET fd = ?1 WHERE fd = ?2", params![to, from])?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::FdSeek { fd, delta, whence } => {
            let Some(descriptor) = descriptor(transaction, *fd)? else {
                return Ok(ApplyResult::error(errno::BADF));
            };
            let tell_only = *delta == 0 && *whence == SeekWhence::Current;
            let allowed = if tell_only {
                descriptor.rights_base & (rights::FD_SEEK | rights::FD_TELL) != 0
            } else {
                descriptor.rights_base & rights::FD_SEEK != 0
            };
            if !allowed {
                return Ok(ApplyResult::error(errno::NOTCAPABLE));
            }
            if object_kind(transaction, descriptor.object)? != FILE_TYPE_REGULAR {
                return Ok(ApplyResult::error(errno::SPIPE));
            }
            let basis = match whence {
                SeekWhence::Set => 0_i128,
                SeekWhence::Current => i128::from(descriptor.offset),
                SeekWhence::End => i128::from(object_size(transaction, descriptor.object)?),
            };
            let next = basis + i128::from(*delta);
            if next < 0 || next > i128::from(i64::MAX) {
                return Ok(ApplyResult::error(errno::INVAL));
            }
            let next = next as u64;
            transaction.execute(
                "UPDATE descriptors SET offset = ?1 WHERE fd = ?2",
                params![sql_i64(next)?, fd],
            )?;
            Ok(ApplyResult::ok(OperationResult::Offset(next)))
        }
        Operation::FdTell { fd } => {
            let Some(descriptor) = descriptor(transaction, *fd)? else {
                return Ok(ApplyResult::error(errno::BADF));
            };
            if descriptor.rights_base & (rights::FD_SEEK | rights::FD_TELL) == 0 {
                return Ok(ApplyResult::error(errno::NOTCAPABLE));
            }
            Ok(ApplyResult::ok(OperationResult::Offset(descriptor.offset)))
        }
        Operation::FdWrite { fd, bytes } => {
            let descriptor = require_fd!(*fd, rights::FD_WRITE);
            let offset = if descriptor.flags & FD_FLAG_APPEND != 0 {
                object_size(transaction, descriptor.object)?
            } else {
                descriptor.offset
            };
            write_at(transaction, *fd, offset, bytes, true)
        }
        Operation::PathCreateDirectory { dir_fd, path } => {
            let _ = require_fd!(*dir_fd, rights::PATH_CREATE_DIRECTORY);
            let full = resolve_new_path(transaction, *dir_fd, path)?;
            create_path_object(transaction, &full, FILE_TYPE_DIRECTORY, &[], None)?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::PathFileStatGet { dir_fd, lookup_flags, path } => {
            let directory = require_fd!(*dir_fd, rights::PATH_FILESTAT_GET);
            if lookup_flags & !LOOKUP_SYMLINK_FOLLOW != 0 {
                return Ok(ApplyResult::error(errno::INVAL));
            }
            let full = resolve_path(transaction, *dir_fd, path)?;
            let Some(object) = object_for_path_beneath(
                transaction,
                &full,
                lookup_flags & LOOKUP_SYMLINK_FOLLOW != 0,
                &directory.directory_path,
            )?
            else {
                return Ok(ApplyResult::error(errno::NOENT));
            };
            Ok(ApplyResult::ok(OperationResult::FileStat(file_stat(transaction, object.id)?)))
        }
        Operation::PathFileStatSetTimes { dir_fd, lookup_flags, path, atim, mtim, fst_flags } => {
            let directory = require_fd!(*dir_fd, rights::PATH_FILESTAT_SET_TIMES);
            if lookup_flags & !LOOKUP_SYMLINK_FOLLOW != 0 {
                return Ok(ApplyResult::error(errno::INVAL));
            }
            let full = resolve_path(transaction, *dir_fd, path)?;
            let Some(object) = object_for_path_beneath(
                transaction,
                &full,
                lookup_flags & LOOKUP_SYMLINK_FOLLOW != 0,
                &directory.directory_path,
            )?
            else {
                return Ok(ApplyResult::error(errno::NOENT));
            };
            set_times(transaction, object.id, *atim, *mtim, *fst_flags)?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::PathLink { old_dir_fd, old_lookup_flags, old_path, new_dir_fd, new_path } => {
            let old_directory = require_fd!(*old_dir_fd, rights::PATH_LINK_SOURCE);
            let _ = require_fd!(*new_dir_fd, rights::PATH_LINK_TARGET);
            if old_lookup_flags & !LOOKUP_SYMLINK_FOLLOW != 0 {
                return Ok(ApplyResult::error(errno::INVAL));
            }
            let old = resolve_path(transaction, *old_dir_fd, old_path)?;
            let new = resolve_new_path(transaction, *new_dir_fd, new_path)?;
            let Some(object) = object_for_path_beneath(
                transaction,
                &old,
                old_lookup_flags & LOOKUP_SYMLINK_FOLLOW != 0,
                &old_directory.directory_path,
            )?
            else {
                return Ok(ApplyResult::error(errno::NOENT));
            };
            if object.kind == FILE_TYPE_DIRECTORY {
                return Ok(ApplyResult::error(errno::PERM));
            }
            if path_object_id(transaction, &new)?.is_some() {
                return Ok(ApplyResult::error(errno::EXIST));
            }
            transaction.execute(
                "INSERT INTO paths(path, object_id) VALUES (?1, ?2)",
                params![new, object.id.0.as_slice()],
            )?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::PathOpen {
            dir_fd,
            lookup_flags,
            path,
            open_flags,
            rights_base,
            rights_inheriting,
            fd_flags,
        } => path_open(
            transaction,
            OpenRequest {
                dir_fd: *dir_fd,
                path,
                lookup_flags: *lookup_flags,
                open_flags: *open_flags,
                rights_base: *rights_base,
                rights_inheriting: *rights_inheriting,
                fd_flags: *fd_flags,
            },
        ),
        Operation::PathReadLink { dir_fd, path, buffer_len } => {
            let _ = require_fd!(*dir_fd, rights::PATH_READLINK);
            let full = resolve_path(transaction, *dir_fd, path)?;
            let Some(object) = object_for_path(transaction, &full, false)? else {
                return Ok(ApplyResult::error(errno::NOENT));
            };
            if object.kind != FILE_TYPE_SYMLINK {
                return Ok(ApplyResult::error(errno::INVAL));
            }
            let mut target = object.symlink_target.unwrap_or_default();
            target.truncate(*buffer_len as usize);
            Ok(ApplyResult::ok(OperationResult::Bytes(target)))
        }
        Operation::PathRemoveDirectory { dir_fd, path } => {
            let _ = require_fd!(*dir_fd, rights::PATH_REMOVE_DIRECTORY);
            let full = resolve_path(transaction, *dir_fd, path)?;
            if full.is_empty() {
                return Ok(ApplyResult::error(errno::PERM));
            }
            let Some(object) = object_for_path(transaction, &full, false)? else {
                return Ok(ApplyResult::error(errno::NOENT));
            };
            if object.kind != FILE_TYPE_DIRECTORY {
                return Ok(ApplyResult::error(errno::NOTDIR));
            }
            if directory_has_children(transaction, &full)? {
                return Ok(ApplyResult::error(errno::NOTEMPTY));
            }
            if object_has_descriptors(transaction, object.id)? {
                return Ok(ApplyResult::error(errno::BUSY));
            }
            remove_path(transaction, &full, object.id)?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::PathRename { old_dir_fd, old_path, new_dir_fd, new_path } => {
            let _ = require_fd!(*old_dir_fd, rights::PATH_RENAME_SOURCE);
            let _ = require_fd!(*new_dir_fd, rights::PATH_RENAME_TARGET);
            let old = resolve_path(transaction, *old_dir_fd, old_path)?;
            let new = resolve_new_path(transaction, *new_dir_fd, new_path)?;
            rename_path(transaction, &old, &new)
        }
        Operation::PathSymlink { old_path, dir_fd, new_path } => {
            let _ = require_fd!(*dir_fd, rights::PATH_SYMLINK);
            if old_path.is_empty() || old_path.len() > MAX_PATH_BYTES {
                return Ok(ApplyResult::error(errno::INVAL));
            }
            let full = resolve_new_path(transaction, *dir_fd, new_path)?;
            create_path_object(transaction, &full, FILE_TYPE_SYMLINK, &[], Some(old_path))?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::PathUnlinkFile { dir_fd, path } => {
            let _ = require_fd!(*dir_fd, rights::PATH_UNLINK_FILE);
            let full = resolve_path(transaction, *dir_fd, path)?;
            let Some(object) = object_for_path(transaction, &full, false)? else {
                return Ok(ApplyResult::error(errno::NOENT));
            };
            if object.kind == FILE_TYPE_DIRECTORY {
                return Ok(ApplyResult::error(errno::ISDIR));
            }
            remove_path(transaction, &full, object.id)?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::PathChmod { dir_fd, path, mode } => {
            let directory = require_fd!(*dir_fd, rights::VFS_METADATA);
            let full = resolve_path(transaction, *dir_fd, path)?;
            let Some(object) =
                object_for_path_beneath(transaction, &full, true, &directory.directory_path)?
            else {
                return Ok(ApplyResult::error(errno::NOENT));
            };
            let now = now_ns()?;
            transaction.execute(
                "UPDATE objects SET mode = ?1, changed_ns = ?2 WHERE object_id = ?3",
                params![mode & 0o7777, sql_i64(now)?, object.id.0.as_slice()],
            )?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::PathChown { dir_fd, path, uid, gid } => {
            let directory = require_fd!(*dir_fd, rights::VFS_METADATA);
            let full = resolve_path(transaction, *dir_fd, path)?;
            let Some(object) =
                object_for_path_beneath(transaction, &full, true, &directory.directory_path)?
            else {
                return Ok(ApplyResult::error(errno::NOENT));
            };
            let now = now_ns()?;
            transaction.execute(
                "UPDATE objects SET
                 uid = CASE WHEN ?1 = 4294967295 THEN uid ELSE ?1 END,
                 gid = CASE WHEN ?2 = 4294967295 THEN gid ELSE ?2 END,
                 changed_ns = ?3 WHERE object_id = ?4",
                params![i64::from(*uid), i64::from(*gid), sql_i64(now)?, object.id.0.as_slice()],
            )?;
            Ok(ApplyResult::ok(OperationResult::None))
        }
        Operation::VfsLock { fd, level } => {
            let _ = require_fd!(*fd, rights::VFS_LOCK);
            lock(transaction, *fd, owner, *level)
        }
        Operation::VfsUnlock { fd, level } => {
            let _ = require_fd!(*fd, rights::VFS_LOCK);
            unlock(transaction, *fd, owner, *level)
        }
        Operation::VfsCheckReserved { fd } => {
            let _ = require_fd!(*fd, rights::VFS_LOCK);
            check_reserved(transaction, *fd)
        }
    }
}

struct OpenRequest<'a> {
    dir_fd: u32,
    path: &'a [u8],
    lookup_flags: u32,
    open_flags: u16,
    rights_base: u64,
    rights_inheriting: u64,
    fd_flags: u16,
}

fn path_open(
    transaction: &Transaction<'_>,
    request: OpenRequest<'_>,
) -> Result<ApplyResult, ProviderError> {
    let OpenRequest {
        dir_fd,
        path,
        lookup_flags,
        open_flags,
        rights_base,
        rights_inheriting,
        fd_flags,
    } = request;
    let Some(directory) = descriptor(transaction, dir_fd)? else {
        return Ok(ApplyResult::error(errno::BADF));
    };
    if object_kind(transaction, directory.object)? != FILE_TYPE_DIRECTORY {
        return Ok(ApplyResult::error(errno::NOTDIR));
    }
    let mut required = rights::PATH_OPEN;
    if open_flags & OPEN_CREATE != 0 {
        required |= rights::PATH_CREATE_FILE;
    }
    if open_flags & OPEN_TRUNCATE != 0 {
        required |= rights::PATH_FILESTAT_SET_SIZE;
    }
    if directory.rights_base & required != required
        || rights_base & !directory.rights_inheriting != 0
        || rights_inheriting & !directory.rights_inheriting != 0
    {
        return Ok(ApplyResult::error(errno::NOTCAPABLE));
    }
    if lookup_flags & !LOOKUP_SYMLINK_FOLLOW != 0
        || open_flags & !(OPEN_CREATE | OPEN_DIRECTORY | OPEN_EXCLUSIVE | OPEN_TRUNCATE) != 0
        || fd_flags & !0x1f != 0
    {
        return Ok(ApplyResult::error(errno::INVAL));
    }
    let full = resolve_path(transaction, dir_fd, path)?;
    let raw_object = load_object_for_path(transaction, &full)?;
    if raw_object.is_some() && open_flags & OPEN_CREATE != 0 && open_flags & OPEN_EXCLUSIVE != 0 {
        return Ok(ApplyResult::error(errno::EXIST));
    }
    if raw_object.as_ref().is_some_and(|object| object.kind == FILE_TYPE_SYMLINK)
        && lookup_flags & LOOKUP_SYMLINK_FOLLOW == 0
    {
        return Ok(ApplyResult::error(errno::LOOP));
    }
    let mut resolved = resolved_object_for_path_beneath(
        transaction,
        &full,
        lookup_flags & LOOKUP_SYMLINK_FOLLOW != 0,
        &directory.directory_path,
    )?;
    if resolved.is_none() {
        if raw_object.is_some() {
            return Ok(ApplyResult::error(errno::NOENT));
        }
        if open_flags & OPEN_CREATE == 0 {
            return Ok(ApplyResult::error(errno::NOENT));
        }
        create_path_object(transaction, &full, FILE_TYPE_REGULAR, &[], None)?;
        resolved =
            resolved_object_for_path_beneath(transaction, &full, true, &directory.directory_path)?;
    }
    let (resolved_path, object) =
        resolved.ok_or(ProviderError::Integrity("created path disappeared"))?;
    if open_flags & OPEN_DIRECTORY != 0 && object.kind != FILE_TYPE_DIRECTORY {
        return Ok(ApplyResult::error(errno::NOTDIR));
    }
    if open_flags & OPEN_TRUNCATE != 0 {
        if object.kind != FILE_TYPE_REGULAR {
            return Ok(ApplyResult::error(errno::ISDIR));
        }
        resize_object(transaction, object.id, 0)?;
    }
    let fd = allocate_fd(transaction)?;
    let directory_path =
        if object.kind == FILE_TYPE_DIRECTORY { resolved_path } else { Vec::new() };
    transaction.execute(
        "INSERT INTO descriptors(fd, object_id, directory_path, offset, flags,
         rights_base, rights_inheriting, preopen) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, 0)",
        params![
            fd,
            object.id.0.as_slice(),
            directory_path,
            fd_flags,
            u64_to_sql(rights_base),
            u64_to_sql(rights_inheriting)
        ],
    )?;
    Ok(ApplyResult::ok(OperationResult::FileDescriptor(fd)))
}

fn read_at(
    transaction: &Transaction<'_>,
    fd: u32,
    offset: u64,
    length: u32,
    advance: bool,
) -> Result<ApplyResult, ProviderError> {
    let Some(descriptor) = descriptor(transaction, fd)? else {
        return Ok(ApplyResult::error(errno::BADF));
    };
    if object_kind(transaction, descriptor.object)? != FILE_TYPE_REGULAR {
        return Ok(ApplyResult::error(errno::ISDIR));
    }
    let length = usize::try_from(length).unwrap_or(usize::MAX).min(MAX_IO_BYTES);
    let bytes = read_object_range(transaction, descriptor.object, offset, length)?;
    if advance {
        let next = offset
            .checked_add(bytes.len() as u64)
            .ok_or(ProviderError::Invalid("read cursor overflow"))?;
        transaction.execute(
            "UPDATE descriptors SET offset = ?1 WHERE fd = ?2",
            params![sql_i64(next)?, fd],
        )?;
    }
    let now = now_ns()?;
    transaction.execute(
        "UPDATE objects SET accessed_ns = ?1 WHERE object_id = ?2",
        params![sql_i64(now)?, descriptor.object.0.as_slice()],
    )?;
    Ok(ApplyResult {
        errno: errno::SUCCESS,
        bytes_read: bytes.len() as u64,
        bytes_written: 0,
        result: OperationResult::Bytes(bytes),
    })
}

fn write_at(
    transaction: &Transaction<'_>,
    fd: u32,
    offset: u64,
    bytes: &[u8],
    advance: bool,
) -> Result<ApplyResult, ProviderError> {
    if bytes.len() > MAX_IO_BYTES {
        return Ok(ApplyResult::error(errno::FBIG));
    }
    let Some(descriptor) = descriptor(transaction, fd)? else {
        return Ok(ApplyResult::error(errno::BADF));
    };
    if object_kind(transaction, descriptor.object)? != FILE_TYPE_REGULAR {
        return Ok(ApplyResult::error(errno::ISDIR));
    }
    let end = offset
        .checked_add(bytes.len() as u64)
        .ok_or(ProviderError::Invalid("write offset overflow"))?;
    if end > i64::MAX as u64 {
        return Ok(ApplyResult::error(errno::FBIG));
    }
    let now = now_ns()?;
    write_object_range(transaction, descriptor.object, offset, bytes)?;
    transaction.execute(
        "UPDATE objects SET size = max(size, ?1), modified_ns = ?2, changed_ns = ?2
         WHERE object_id = ?3",
        params![sql_i64(end)?, sql_i64(now)?, descriptor.object.0.as_slice()],
    )?;
    if advance {
        transaction.execute(
            "UPDATE descriptors SET offset = ?1 WHERE fd = ?2",
            params![sql_i64(end)?, fd],
        )?;
    }
    Ok(ApplyResult {
        errno: errno::SUCCESS,
        result: OperationResult::Count(bytes.len() as u32),
        bytes_read: 0,
        bytes_written: bytes.len() as u64,
    })
}

fn read_object_range(
    connection: &Connection,
    object: ObjectId,
    offset: u64,
    requested: usize,
) -> Result<Vec<u8>, ProviderError> {
    let size = object_size(connection, object)?;
    if requested == 0 || offset >= size {
        return Ok(Vec::new());
    }
    let available = size - offset;
    let length = requested.min(
        usize::try_from(available)
            .map_err(|_| ProviderError::Invalid("read range exceeds host address space"))?,
    );
    let mut output = vec![0_u8; length];
    let first_chunk = offset / CHUNK_SIZE as u64;
    let last_offset = offset
        .checked_add(length as u64)
        .and_then(|value| value.checked_sub(1))
        .ok_or(ProviderError::Invalid("read range overflow"))?;
    let last_chunk = last_offset / CHUNK_SIZE as u64;
    let mut statement = connection.prepare(
        "SELECT chunk_index, bytes FROM object_chunks
         WHERE object_id = ?1 AND chunk_index BETWEEN ?2 AND ?3 ORDER BY chunk_index",
    )?;
    let rows = statement.query_map(
        params![object.0.as_slice(), sql_i64(first_chunk)?, sql_i64(last_chunk)?],
        |row| Ok((row_u64(row, 0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    for row in rows {
        let (chunk_index, bytes) = row?;
        if bytes.len() > CHUNK_SIZE {
            return Err(ProviderError::Integrity("oversized object chunk"));
        }
        let chunk_start = chunk_index
            .checked_mul(CHUNK_SIZE as u64)
            .ok_or(ProviderError::Integrity("chunk offset overflow"))?;
        let copy_start = chunk_start.max(offset);
        let copy_end = chunk_start
            .checked_add(bytes.len() as u64)
            .ok_or(ProviderError::Integrity("chunk end overflow"))?
            .min(offset + length as u64);
        if copy_end > copy_start {
            let source_start = usize::try_from(copy_start - chunk_start)
                .map_err(|_| ProviderError::Integrity("chunk source offset"))?;
            let destination_start = usize::try_from(copy_start - offset)
                .map_err(|_| ProviderError::Integrity("chunk destination offset"))?;
            let count = usize::try_from(copy_end - copy_start)
                .map_err(|_| ProviderError::Integrity("chunk copy length"))?;
            output[destination_start..destination_start + count]
                .copy_from_slice(&bytes[source_start..source_start + count]);
        }
    }
    Ok(output)
}

fn write_object_range(
    transaction: &Transaction<'_>,
    object: ObjectId,
    offset: u64,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let end = offset
        .checked_add(bytes.len() as u64)
        .ok_or(ProviderError::Invalid("write range overflow"))?;
    let first_chunk = offset / CHUNK_SIZE as u64;
    let last_chunk = (end - 1) / CHUNK_SIZE as u64;
    for chunk_index in first_chunk..=last_chunk {
        let chunk_start = chunk_index
            .checked_mul(CHUNK_SIZE as u64)
            .ok_or(ProviderError::Invalid("chunk offset overflow"))?;
        let mut chunk = transaction
            .query_row(
                "SELECT bytes FROM object_chunks WHERE object_id = ?1 AND chunk_index = ?2",
                params![object.0.as_slice(), sql_i64(chunk_index)?],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .unwrap_or_default();
        if chunk.len() > CHUNK_SIZE {
            return Err(ProviderError::Integrity("oversized object chunk"));
        }
        let copy_start = chunk_start.max(offset);
        let copy_end = (chunk_start + CHUNK_SIZE as u64).min(end);
        let target_end = usize::try_from(copy_end - chunk_start)
            .map_err(|_| ProviderError::Invalid("chunk target offset"))?;
        if chunk.len() < target_end {
            chunk.resize(target_end, 0);
        }
        let source_start = usize::try_from(copy_start - offset)
            .map_err(|_| ProviderError::Invalid("chunk source offset"))?;
        let target_start = usize::try_from(copy_start - chunk_start)
            .map_err(|_| ProviderError::Invalid("chunk target offset"))?;
        let count = usize::try_from(copy_end - copy_start)
            .map_err(|_| ProviderError::Invalid("chunk copy length"))?;
        chunk[target_start..target_start + count]
            .copy_from_slice(&bytes[source_start..source_start + count]);
        transaction.execute(
            "INSERT INTO object_chunks(object_id, chunk_index, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(object_id, chunk_index) DO UPDATE SET bytes = excluded.bytes",
            params![object.0.as_slice(), sql_i64(chunk_index)?, chunk],
        )?;
    }
    Ok(())
}

fn read_directory(
    transaction: &Transaction<'_>,
    fd: u32,
    cookie: u64,
    buffer_len: u32,
) -> Result<ApplyResult, ProviderError> {
    let Some(descriptor) = descriptor(transaction, fd)? else {
        return Ok(ApplyResult::error(errno::BADF));
    };
    if object_kind(transaction, descriptor.object)? != FILE_TYPE_DIRECTORY {
        return Ok(ApplyResult::error(errno::NOTDIR));
    }
    let entries = direct_children(transaction, &descriptor.directory_path)?;
    let start = usize::try_from(cookie).unwrap_or(usize::MAX).min(entries.len());
    let mut used = 0_usize;
    let mut output = Vec::new();
    for (index, (name, object)) in entries.into_iter().enumerate().skip(start) {
        let encoded = 24_usize.saturating_add(name.len());
        if !output.is_empty() && used.saturating_add(encoded) > buffer_len as usize {
            break;
        }
        used = used.saturating_add(encoded);
        output.push(DirectoryEntry {
            next_cookie: (index + 1) as u64,
            inode: virtual_inode(object.id),
            file_type: object.kind,
            name,
        });
    }
    Ok(ApplyResult::ok(OperationResult::Directory(output)))
}

fn rename_path(
    transaction: &Transaction<'_>,
    old: &[u8],
    new: &[u8],
) -> Result<ApplyResult, ProviderError> {
    if old.is_empty() || new.is_empty() || old == new {
        return Ok(if old == new && path_object_id(transaction, old)?.is_some() {
            ApplyResult::ok(OperationResult::None)
        } else {
            ApplyResult::error(errno::INVAL)
        });
    }
    let Some(old_object) = object_for_path(transaction, old, false)? else {
        return Ok(ApplyResult::error(errno::NOENT));
    };
    if old_object.kind == FILE_TYPE_DIRECTORY && is_descendant(new, old) {
        return Ok(ApplyResult::error(errno::INVAL));
    }
    if let Some(new_object) = object_for_path(transaction, new, false)? {
        // POSIX rename is a no-op when both names already resolve to the same
        // inode. In particular, do not collapse two hard links into one name.
        if new_object.id == old_object.id {
            return Ok(ApplyResult::ok(OperationResult::None));
        }
        if old_object.kind == FILE_TYPE_DIRECTORY && new_object.kind != FILE_TYPE_DIRECTORY {
            return Ok(ApplyResult::error(errno::NOTDIR));
        }
        if old_object.kind != FILE_TYPE_DIRECTORY && new_object.kind == FILE_TYPE_DIRECTORY {
            return Ok(ApplyResult::error(errno::ISDIR));
        }
        if new_object.kind == FILE_TYPE_DIRECTORY && directory_has_children(transaction, new)? {
            return Ok(ApplyResult::error(errno::NOTEMPTY));
        }
        if new_object.kind == FILE_TYPE_DIRECTORY
            && object_has_descriptors(transaction, new_object.id)?
        {
            return Ok(ApplyResult::error(errno::BUSY));
        }
        remove_path(transaction, new, new_object.id)?;
    }
    let mut affected = all_paths(transaction)?
        .into_iter()
        .filter(|path| path == old || is_descendant(path, old))
        .collect::<Vec<_>>();
    affected.sort_by_key(Vec::len);
    for path in affected {
        let suffix = &path[old.len()..];
        let mut replacement = new.to_vec();
        replacement.extend_from_slice(suffix);
        transaction
            .execute("UPDATE paths SET path = ?1 WHERE path = ?2", params![replacement, path])?;
        transaction.execute(
            "UPDATE descriptors SET directory_path = ?1 WHERE directory_path = ?2",
            params![replacement, path],
        )?;
    }
    Ok(ApplyResult::ok(OperationResult::None))
}

fn lock(
    transaction: &Transaction<'_>,
    fd: u32,
    owner: &OwnerId,
    requested: LockLevel,
) -> Result<ApplyResult, ProviderError> {
    if requested == LockLevel::None {
        return unlock(transaction, fd, owner, requested);
    }
    let Some(descriptor) = descriptor(transaction, fd)? else {
        return Ok(ApplyResult::error(errno::BADF));
    };
    if object_kind(transaction, descriptor.object)? != FILE_TYPE_REGULAR {
        return Ok(ApplyResult::error(errno::BADF));
    }
    let current = current_lock(transaction, descriptor.object, owner)?.unwrap_or(LockLevel::None);
    if requested == current {
        return Ok(ApplyResult::ok(OperationResult::None));
    }
    if requested < current {
        return Ok(ApplyResult::error(errno::INVAL));
    }
    let other = other_locks(transaction, descriptor.object, owner)?;
    let compatible = match requested {
        LockLevel::None => true,
        LockLevel::Shared => other.iter().all(|level| *level < LockLevel::Pending),
        LockLevel::Reserved | LockLevel::Pending => {
            other.iter().all(|level| *level == LockLevel::Shared)
        }
        LockLevel::Exclusive => other.is_empty(),
    };
    if !compatible {
        return Ok(ApplyResult::error(errno::AGAIN));
    }
    transaction.execute(
        "INSERT INTO locks(object_id, owner, level) VALUES (?1, ?2, ?3)
         ON CONFLICT(object_id, owner) DO UPDATE SET level = excluded.level",
        params![descriptor.object.0.as_slice(), owner.0.as_slice(), lock_to_sql(requested)],
    )?;
    Ok(ApplyResult::ok(OperationResult::None))
}

fn unlock(
    transaction: &Transaction<'_>,
    fd: u32,
    owner: &OwnerId,
    requested: LockLevel,
) -> Result<ApplyResult, ProviderError> {
    let Some(descriptor) = descriptor(transaction, fd)? else {
        return Ok(ApplyResult::error(errno::BADF));
    };
    if object_kind(transaction, descriptor.object)? != FILE_TYPE_REGULAR {
        return Ok(ApplyResult::error(errno::BADF));
    }
    let current = current_lock(transaction, descriptor.object, owner)?.unwrap_or(LockLevel::None);
    if requested > current {
        return Ok(ApplyResult::error(errno::INVAL));
    }
    if requested == LockLevel::None {
        transaction.execute(
            "DELETE FROM locks WHERE object_id = ?1 AND owner = ?2",
            params![descriptor.object.0.as_slice(), owner.0.as_slice()],
        )?;
    } else {
        transaction.execute(
            "UPDATE locks SET level = ?1 WHERE object_id = ?2 AND owner = ?3",
            params![lock_to_sql(requested), descriptor.object.0.as_slice(), owner.0.as_slice()],
        )?;
    }
    Ok(ApplyResult::ok(OperationResult::None))
}

fn check_reserved(transaction: &Transaction<'_>, fd: u32) -> Result<ApplyResult, ProviderError> {
    let Some(descriptor) = descriptor(transaction, fd)? else {
        return Ok(ApplyResult::error(errno::BADF));
    };
    if object_kind(transaction, descriptor.object)? != FILE_TYPE_REGULAR {
        return Ok(ApplyResult::error(errno::BADF));
    }
    let reserved: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM locks WHERE object_id = ?1 AND level >= 2)",
        params![descriptor.object.0.as_slice()],
        |row| row.get(0),
    )?;
    Ok(ApplyResult::ok(OperationResult::Reserved(reserved)))
}

fn import_file(
    connection: &mut Connection,
    session: SessionId,
    import: &ImportFile,
) -> Result<(), ProviderError> {
    let metadata = fs::symlink_metadata(&import.host_path)?;
    if !metadata.file_type().is_file() {
        return Err(ProviderError::Invalid("import is not a regular file"));
    }
    let mut file = File::open(&import.host_path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    let path = normalize_path(&[], &import.guest_path)
        .map_err(|_| ProviderError::Invalid("import guest path"))?;
    if path.is_empty() {
        return Err(ProviderError::Invalid("cannot import over root"));
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_parent_directories(&transaction, session, &path)?;
    let object = create_path_object(&transaction, &path, FILE_TYPE_REGULAR, &content, None)?;
    transaction.execute(
        "UPDATE objects SET mode = ?1, uid = ?2, gid = ?3 WHERE object_id = ?4",
        params![
            metadata.mode() & 0o7777,
            i64::from(metadata.uid()),
            i64::from(metadata.gid()),
            object.0.as_slice()
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn create_parent_directories(
    transaction: &Transaction<'_>,
    _session: SessionId,
    path: &[u8],
) -> Result<(), ProviderError> {
    let components = path.split(|byte| *byte == b'/').collect::<Vec<_>>();
    let mut current = Vec::new();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        if !current.is_empty() {
            current.push(b'/');
        }
        current.extend_from_slice(component);
        if path_object_id(transaction, &current)?.is_none() {
            create_path_object(transaction, &current, FILE_TYPE_DIRECTORY, &[], None)?;
        }
    }
    Ok(())
}

fn create_path_object(
    transaction: &Transaction<'_>,
    path: &[u8],
    kind: u8,
    content: &[u8],
    symlink_target: Option<&Vec<u8>>,
) -> Result<ObjectId, ProviderError> {
    if path.is_empty() {
        return Err(ProviderError::Invalid("path names root"));
    }
    if path_object_id(transaction, path)?.is_some() {
        return Err(ProviderError::AlreadyExists);
    }
    require_parent_directory(transaction, path)?;
    let (session, counter): (Vec<u8>, i64) = transaction.query_row(
        "SELECT session, next_object FROM meta WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let session =
        SessionId(session.try_into().map_err(|_| ProviderError::Integrity("session length"))?);
    let object = derived_object(session, nonnegative(counter)?);
    let now = now_ns()?;
    transaction.execute(
        "INSERT INTO objects(object_id, kind, size, symlink_target, mode,
         accessed_ns, modified_ns, changed_ns)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?6)",
        params![
            object.0.as_slice(),
            kind,
            if kind == FILE_TYPE_REGULAR { sql_i64(content.len() as u64)? } else { 0 },
            symlink_target.map(Vec::as_slice),
            default_mode(kind),
            sql_i64(now)?
        ],
    )?;
    if kind == FILE_TYPE_REGULAR {
        write_object_range(transaction, object, 0, content)?;
    }
    transaction.execute(
        "INSERT INTO paths(path, object_id) VALUES (?1, ?2)",
        params![path, object.0.as_slice()],
    )?;
    transaction.execute("UPDATE meta SET next_object = next_object + 1 WHERE singleton = 1", [])?;
    Ok(object)
}

const fn default_mode(kind: u8) -> u32 {
    match kind {
        FILE_TYPE_DIRECTORY => 0o755,
        FILE_TYPE_SYMLINK => 0o777,
        _ => 0o666,
    }
}

fn remove_path(
    transaction: &Transaction<'_>,
    path: &[u8],
    object: ObjectId,
) -> Result<(), ProviderError> {
    transaction.execute("DELETE FROM paths WHERE path = ?1", params![path])?;
    collect_object_if_unreferenced(transaction, object)
}

fn collect_object_if_unreferenced(
    transaction: &Transaction<'_>,
    object: ObjectId,
) -> Result<(), ProviderError> {
    let references: i64 = transaction.query_row(
        "SELECT (SELECT count(*) FROM paths WHERE object_id = ?1) +
                (SELECT count(*) FROM descriptors WHERE object_id = ?1)",
        params![object.0.as_slice()],
        |row| row.get(0),
    )?;
    if references == 0 {
        transaction
            .execute("DELETE FROM locks WHERE object_id = ?1", params![object.0.as_slice()])?;
        transaction
            .execute("DELETE FROM objects WHERE object_id = ?1", params![object.0.as_slice()])?;
    }
    Ok(())
}

fn descriptor(connection: &Connection, fd: u32) -> Result<Option<Descriptor>, ProviderError> {
    connection
        .query_row(
            "SELECT fd, object_id, directory_path, offset, flags, rights_base,
             rights_inheriting, preopen FROM descriptors WHERE fd = ?1",
            params![fd],
            |row| {
                let object: Vec<u8> = row.get(1)?;
                Ok(Descriptor {
                    object: ObjectId(
                        object
                            .try_into()
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, 16))?,
                    ),
                    directory_path: row.get(2)?,
                    offset: row_u64(row, 3)?,
                    flags: row.get(4)?,
                    rights_base: sql_to_u64(row.get(5)?),
                    rights_inheriting: sql_to_u64(row.get(6)?),
                    preopen: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn descriptor_with_right(
    connection: &Connection,
    fd: u32,
    required: u64,
) -> Result<Result<Descriptor, u16>, ProviderError> {
    let Some(descriptor) = descriptor(connection, fd)? else {
        return Ok(Err(errno::BADF));
    };
    if descriptor.rights_base & required != required {
        return Ok(Err(errno::NOTCAPABLE));
    }
    Ok(Ok(descriptor))
}

fn object_for_path(
    connection: &Connection,
    path: &[u8],
    follow: bool,
) -> Result<Option<Object>, ProviderError> {
    object_for_path_beneath(connection, path, follow, &[])
}

fn object_for_path_beneath(
    connection: &Connection,
    path: &[u8],
    follow: bool,
    boundary: &[u8],
) -> Result<Option<Object>, ProviderError> {
    Ok(resolved_object_for_path_beneath(connection, path, follow, boundary)?
        .map(|(_, object)| object))
}

fn resolved_object_for_path_beneath(
    connection: &Connection,
    path: &[u8],
    follow: bool,
    boundary: &[u8],
) -> Result<Option<(Vec<u8>, Object)>, ProviderError> {
    let mut current = path.to_vec();
    for _ in 0..=MAX_SYMLINK_DEPTH {
        current = resolve_intermediate_symlinks_beneath(connection, &current, boundary)?;
        let object = load_object_for_path(connection, &current)?;
        let Some(object) = object else {
            return Ok(None);
        };
        if !follow || object.kind != FILE_TYPE_SYMLINK {
            return Ok(Some((current, object)));
        }
        let target = object.symlink_target.as_deref().unwrap_or_default();
        let base = parent_path(&current);
        current = normalize_path(base, target)
            .map_err(|_| ProviderError::Invalid("symlink target escaped root"))?;
        if !is_within_boundary(&current, boundary) {
            return Err(ProviderError::Invalid("symlink target escaped the directory capability"));
        }
    }
    Err(ProviderError::Invalid("symlink depth exceeded"))
}

fn load_object_for_path(
    connection: &Connection,
    path: &[u8],
) -> Result<Option<Object>, ProviderError> {
    connection
        .query_row(
            "SELECT o.object_id, o.kind, o.size, o.symlink_target,
             o.accessed_ns, o.modified_ns, o.changed_ns
             FROM paths p JOIN objects o ON o.object_id = p.object_id WHERE p.path = ?1",
            params![path],
            |row| {
                let id: Vec<u8> = row.get(0)?;
                Ok(Object {
                    id: ObjectId(
                        id.try_into()
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, 16))?,
                    ),
                    kind: row.get(1)?,
                    size: row_u64(row, 2)?,
                    symlink_target: row.get(3)?,
                    accessed_ns: row_u64(row, 4)?,
                    modified_ns: row_u64(row, 5)?,
                    changed_ns: row_u64(row, 6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn path_object_id(connection: &Connection, path: &[u8]) -> Result<Option<ObjectId>, ProviderError> {
    let bytes: Option<Vec<u8>> = connection
        .query_row("SELECT object_id FROM paths WHERE path = ?1", params![path], |row| row.get(0))
        .optional()?;
    bytes
        .map(|bytes| {
            bytes
                .try_into()
                .map(ObjectId)
                .map_err(|_| ProviderError::Integrity("object identity length"))
        })
        .transpose()
}

fn object_kind(connection: &Connection, object: ObjectId) -> Result<u8, ProviderError> {
    connection
        .query_row(
            "SELECT kind FROM objects WHERE object_id = ?1",
            params![object.0.as_slice()],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn object_size(connection: &Connection, object: ObjectId) -> Result<u64, ProviderError> {
    connection
        .query_row(
            "SELECT size FROM objects WHERE object_id = ?1",
            params![object.0.as_slice()],
            |row| row_u64(row, 0),
        )
        .map_err(Into::into)
}

fn object_has_descriptors(
    connection: &Connection,
    object: ObjectId,
) -> Result<bool, ProviderError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM descriptors WHERE object_id = ?1)",
            params![object.0.as_slice()],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn resize_object(
    transaction: &Transaction<'_>,
    object: ObjectId,
    size: u64,
) -> Result<(), ProviderError> {
    if size > i64::MAX as u64 {
        return Err(ProviderError::Invalid("file size exceeds SQLite limit"));
    }
    let now = now_ns()?;
    transaction.execute(
        "UPDATE objects SET size = ?1, modified_ns = ?2, changed_ns = ?2
         WHERE object_id = ?3 AND kind = 4",
        params![sql_i64(size)?, sql_i64(now)?, object.0.as_slice()],
    )?;
    let first_removed = size
        .checked_add(CHUNK_SIZE as u64 - 1)
        .ok_or(ProviderError::Invalid("file size overflow"))?
        / CHUNK_SIZE as u64;
    transaction.execute(
        "DELETE FROM object_chunks WHERE object_id = ?1 AND chunk_index >= ?2",
        params![object.0.as_slice(), sql_i64(first_removed)?],
    )?;
    if size != 0 && !size.is_multiple_of(CHUNK_SIZE as u64) {
        let last = size / CHUNK_SIZE as u64;
        let keep = usize::try_from(size % CHUNK_SIZE as u64)
            .map_err(|_| ProviderError::Invalid("chunk tail overflow"))?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT bytes FROM object_chunks WHERE object_id = ?1 AND chunk_index = ?2",
                params![object.0.as_slice(), sql_i64(last)?],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(mut bytes) = existing {
            bytes.truncate(keep);
            transaction.execute(
                "UPDATE object_chunks SET bytes = ?1 WHERE object_id = ?2 AND chunk_index = ?3",
                params![bytes, object.0.as_slice(), sql_i64(last)?],
            )?;
        }
    }
    Ok(())
}

fn file_stat(connection: &Connection, object: ObjectId) -> Result<FileStat, ProviderError> {
    let value: Object = connection.query_row(
        "SELECT object_id, kind, size, symlink_target, accessed_ns,
             modified_ns, changed_ns FROM objects WHERE object_id = ?1",
        params![object.0.as_slice()],
        |row| {
            let id: Vec<u8> = row.get(0)?;
            Ok(Object {
                id: ObjectId(
                    id.try_into().map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, 16))?,
                ),
                kind: row.get(1)?,
                size: row_u64(row, 2)?,
                symlink_target: row.get(3)?,
                accessed_ns: row_u64(row, 4)?,
                modified_ns: row_u64(row, 5)?,
                changed_ns: row_u64(row, 6)?,
            })
        },
    )?;
    let links: i64 = connection.query_row(
        "SELECT count(*) FROM paths WHERE object_id = ?1",
        params![object.0.as_slice()],
        |row| row.get(0),
    )?;
    Ok(FileStat {
        device: 0x5649_5341,
        inode: virtual_inode(value.id),
        file_type: value.kind,
        link_count: nonnegative(links)?,
        size: if value.kind == FILE_TYPE_REGULAR {
            value.size
        } else if value.kind == FILE_TYPE_SYMLINK {
            value.symlink_target.as_ref().map_or(0, |value| value.len() as u64)
        } else {
            0
        },
        accessed_ns: value.accessed_ns,
        modified_ns: value.modified_ns,
        changed_ns: value.changed_ns,
    })
}

fn set_times(
    transaction: &Transaction<'_>,
    object: ObjectId,
    atim: u64,
    mtim: u64,
    flags: u16,
) -> Result<(), ProviderError> {
    if flags & !0x0f != 0 {
        return Err(ProviderError::Invalid("unknown timestamp flag"));
    }
    let now = now_ns()?;
    let set_atim = flags & 1 != 0;
    let set_atim_now = flags & 2 != 0;
    let set_mtim = flags & 4 != 0;
    let set_mtim_now = flags & 8 != 0;
    if (set_atim && set_atim_now) || (set_mtim && set_mtim_now) {
        return Err(ProviderError::Invalid("conflicting timestamp flags"));
    }
    transaction.execute(
        "UPDATE objects SET
         accessed_ns = CASE WHEN ?1 THEN ?2 WHEN ?3 THEN ?4 ELSE accessed_ns END,
         modified_ns = CASE WHEN ?5 THEN ?6 WHEN ?7 THEN ?4 ELSE modified_ns END,
         changed_ns = ?4 WHERE object_id = ?8",
        params![
            set_atim,
            sql_i64(atim)?,
            set_atim_now,
            sql_i64(now)?,
            set_mtim,
            sql_i64(mtim)?,
            set_mtim_now,
            object.0.as_slice()
        ],
    )?;
    Ok(())
}

fn resolve_path(
    connection: &Connection,
    dir_fd: u32,
    path: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    let Some(descriptor) = descriptor(connection, dir_fd)? else {
        return Err(ProviderError::Invalid("directory fd is missing"));
    };
    if object_kind(connection, descriptor.object)? != FILE_TYPE_DIRECTORY {
        return Err(ProviderError::Invalid("base fd is not a directory"));
    }
    let normalized = normalize_path(&descriptor.directory_path, path)
        .map_err(|_| ProviderError::Invalid("path escaped the preopen"))?;
    if !is_within_boundary(&normalized, &descriptor.directory_path) {
        return Err(ProviderError::Invalid("path escaped the directory capability"));
    }
    resolve_intermediate_symlinks_beneath(connection, &normalized, &descriptor.directory_path)
}

fn resolve_new_path(
    connection: &Connection,
    dir_fd: u32,
    path: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    let full = resolve_path(connection, dir_fd, path)?;
    if full.is_empty() {
        return Err(ProviderError::Invalid("operation cannot replace root"));
    }
    require_parent_directory(connection, &full)?;
    Ok(full)
}

fn require_parent_directory(connection: &Connection, path: &[u8]) -> Result<(), ProviderError> {
    let parent = parent_path(path);
    match object_for_path(connection, parent, true)? {
        Some(object) if object.kind == FILE_TYPE_DIRECTORY => Ok(()),
        Some(_) => Err(ProviderError::Invalid("parent is not a directory")),
        None => Err(ProviderError::Missing),
    }
}

fn parent_path(path: &[u8]) -> &[u8] {
    path.iter().rposition(|byte| *byte == b'/').map_or(&[], |index| &path[..index])
}

fn normalize_path(base: &[u8], path: &[u8]) -> Result<Vec<u8>, ()> {
    if path.len() > MAX_PATH_BYTES || path.contains(&0) || path.first() == Some(&b'/') {
        return Err(());
    }
    let mut components = Vec::<Vec<u8>>::new();
    for component in base.split(|byte| *byte == b'/').chain(path.split(|byte| *byte == b'/')) {
        match component {
            b"" | b"." => {}
            b".." => {
                if components.pop().is_none() {
                    return Err(());
                }
            }
            value => components.push(value.to_vec()),
        }
    }
    let mut normalized = Vec::new();
    for component in components {
        if !normalized.is_empty() {
            normalized.push(b'/');
        }
        normalized.extend_from_slice(&component);
    }
    if normalized.len() > MAX_PATH_BYTES { Err(()) } else { Ok(normalized) }
}

fn resolve_intermediate_symlinks_beneath(
    connection: &Connection,
    path: &[u8],
    boundary: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    let mut current = path.to_vec();
    if !is_within_boundary(&current, boundary) {
        return Err(ProviderError::Invalid("path escaped the directory capability"));
    }
    for _ in 0..=MAX_SYMLINK_DEPTH {
        let components = current
            .split(|byte| *byte == b'/')
            .filter(|component| !component.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let mut prefix = Vec::new();
        let mut replaced = false;
        for (index, component) in components.iter().enumerate() {
            if !prefix.is_empty() {
                prefix.push(b'/');
            }
            prefix.extend_from_slice(component);
            if index + 1 == components.len() {
                break;
            }
            let Some(object) = load_object_for_path(connection, &prefix)? else {
                return Err(ProviderError::Missing);
            };
            match object.kind {
                FILE_TYPE_DIRECTORY => {}
                FILE_TYPE_SYMLINK => {
                    let target = object.symlink_target.as_deref().unwrap_or_default();
                    let mut replacement = normalize_path(parent_path(&prefix), target)
                        .map_err(|_| ProviderError::Invalid("symlink target escaped root"))?;
                    for remaining in &components[index + 1..] {
                        if !replacement.is_empty() {
                            replacement.push(b'/');
                        }
                        replacement.extend_from_slice(remaining);
                    }
                    current = normalize_path(&[], &replacement)
                        .map_err(|_| ProviderError::Invalid("symlink target escaped root"))?;
                    if !is_within_boundary(&current, boundary) {
                        return Err(ProviderError::Invalid(
                            "symlink target escaped the directory capability",
                        ));
                    }
                    replaced = true;
                    break;
                }
                _ => return Err(ProviderError::Invalid("path component is not a directory")),
            }
        }
        if !replaced {
            return Ok(current);
        }
    }
    Err(ProviderError::Invalid("symlink depth exceeded"))
}

fn directory_has_children(connection: &Connection, path: &[u8]) -> Result<bool, ProviderError> {
    Ok(all_paths(connection)?.into_iter().any(|candidate| is_descendant(&candidate, path)))
}

fn direct_children(
    connection: &Connection,
    path: &[u8],
) -> Result<Vec<(Vec<u8>, Object)>, ProviderError> {
    let mut entries = Vec::new();
    for candidate in all_paths(connection)? {
        let parent = parent_path(&candidate);
        if parent == path && candidate != path {
            let name = candidate[parent.len() + usize::from(!parent.is_empty())..].to_vec();
            let object = object_for_path(connection, &candidate, false)?
                .ok_or(ProviderError::Integrity("directory entry disappeared"))?;
            entries.push((name, object));
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn all_paths(connection: &Connection) -> Result<Vec<Vec<u8>>, ProviderError> {
    let mut statement = connection.prepare("SELECT path FROM paths ORDER BY path")?;
    let values = statement.query_map([], |row| row.get(0))?.collect::<Result<Vec<Vec<u8>>, _>>()?;
    Ok(values)
}

fn is_descendant(candidate: &[u8], parent: &[u8]) -> bool {
    if parent.is_empty() {
        !candidate.is_empty()
    } else {
        candidate.len() > parent.len()
            && candidate.starts_with(parent)
            && candidate[parent.len()] == b'/'
    }
}

fn is_within_boundary(candidate: &[u8], boundary: &[u8]) -> bool {
    boundary.is_empty() || candidate == boundary || is_descendant(candidate, boundary)
}

fn allocate_fd(transaction: &Transaction<'_>) -> Result<u32, ProviderError> {
    let fd: i64 =
        transaction
            .query_row("SELECT next_fd FROM meta WHERE singleton = 1", [], |row| row.get(0))?;
    let fd = nonnegative(fd)?;
    if fd > u32::MAX as u64 {
        return Err(ProviderError::Invalid("fd space exhausted"));
    }
    transaction.execute("UPDATE meta SET next_fd = next_fd + 1 WHERE singleton = 1", [])?;
    Ok(fd as u32)
}

fn load_meta(connection: &Connection) -> Result<Meta, ProviderError> {
    let (
        session,
        mode,
        authority_epoch,
        handoff,
        destination_epoch,
        completed_handoff,
        barrier,
        barrier_token,
        barrier_predicate,
        barrier_remaining,
        barrier_effect,
        completed_barrier,
        completed_barrier_effect,
    ): RawMeta = connection.query_row(
        "SELECT session, mode, authority_epoch, handoff, destination_epoch, completed_handoff,
             barrier_phase, barrier_token, barrier_predicate, barrier_remaining, barrier_effect,
             completed_barrier, completed_barrier_effect
         FROM meta WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
            ))
        },
    )?;
    Ok(Meta {
        session: SessionId(
            session.try_into().map_err(|_| ProviderError::Integrity("session length"))?,
        ),
        mode: sql_to_mode(mode)?,
        authority_epoch: nonnegative(authority_epoch)?,
        handoff: handoff
            .map(|value| value.try_into().map_err(|_| ProviderError::Integrity("handoff length")))
            .transpose()?,
        destination_epoch: destination_epoch.map(nonnegative).transpose()?,
        completed_handoff: completed_handoff
            .map(|value| {
                value.try_into().map_err(|_| ProviderError::Integrity("completed handoff length"))
            })
            .transpose()?,
        barrier: sql_to_barrier(barrier)?,
        barrier_token: barrier_token
            .map(|value| {
                value
                    .try_into()
                    .map(BarrierToken)
                    .map_err(|_| ProviderError::Integrity("barrier token length"))
            })
            .transpose()?,
        barrier_predicate,
        barrier_remaining: barrier_remaining.map(nonnegative).transpose()?,
        barrier_effect: barrier_effect
            .map(|value| {
                value
                    .try_into()
                    .map(EffectId)
                    .map_err(|_| ProviderError::Integrity("barrier effect length"))
            })
            .transpose()?,
        completed_barrier: completed_barrier
            .map(|value| {
                value
                    .try_into()
                    .map(BarrierToken)
                    .map_err(|_| ProviderError::Integrity("completed barrier length"))
            })
            .transpose()?,
        completed_barrier_effect: completed_barrier_effect
            .map(|value| {
                value
                    .try_into()
                    .map(EffectId)
                    .map_err(|_| ProviderError::Integrity("completed barrier effect length"))
            })
            .transpose()?,
    })
}

fn current_lock(
    connection: &Connection,
    object: ObjectId,
    owner: &OwnerId,
) -> Result<Option<LockLevel>, ProviderError> {
    connection
        .query_row(
            "SELECT level FROM locks WHERE object_id = ?1 AND owner = ?2",
            params![object.0.as_slice(), owner.0.as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(sql_to_lock)
        .transpose()
}

fn other_locks(
    connection: &Connection,
    object: ObjectId,
    owner: &OwnerId,
) -> Result<Vec<LockLevel>, ProviderError> {
    let mut statement =
        connection.prepare("SELECT level FROM locks WHERE object_id = ?1 AND owner != ?2")?;
    statement
        .query_map(params![object.0.as_slice(), owner.0.as_slice()], |row| row.get::<_, i64>(0))?
        .map(|value| value.map_err(ProviderError::from).and_then(sql_to_lock))
        .collect()
}

fn open_connection(path: &Path, create: bool) -> Result<Connection, ProviderError> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    Connection::open_with_flags(path, flags).map_err(Into::into)
}

fn configure_connection(connection: &Connection) -> Result<(), ProviderError> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys=ON;
         PRAGMA trusted_schema=OFF;
         PRAGMA defensive=ON;
         PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA wal_autocheckpoint=1;
         PRAGMA temp_store=MEMORY;",
    )?;
    Ok(())
}

fn audit_connection(connection: &Connection) -> Result<(), ProviderError> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id == 0 {
        connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        connection.pragma_update(None, "page_size", SQLITE_PAGE_SIZE)?;
    } else if application_id != APPLICATION_ID {
        return Err(ProviderError::Integrity("application id mismatch"));
    }
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(ProviderError::Integrity("schema version mismatch"));
    }
    let integrity: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(ProviderError::Integrity("SQLite quick_check failed"));
    }
    let foreign_key_errors: i64 =
        connection
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| row.get(0))?;
    if foreign_key_errors != 0 {
        return Err(ProviderError::Integrity("foreign key violation"));
    }
    let meta_count: i64 =
        connection.query_row("SELECT count(*) FROM meta", [], |row| row.get(0))?;
    if meta_count != 1 {
        return Err(ProviderError::Integrity("meta singleton missing"));
    }
    let root_count: i64 = connection.query_row(
        "SELECT count(*) FROM paths p JOIN objects o ON o.object_id = p.object_id
         WHERE p.path = x'' AND o.kind = 3",
        [],
        |row| row.get(0),
    )?;
    let preopen_count: i64 = connection.query_row(
        "SELECT count(*) FROM descriptors WHERE fd = 3 AND preopen = 1",
        [],
        |row| row.get(0),
    )?;
    if root_count != 1 || preopen_count != 1 {
        return Err(ProviderError::Integrity("root preopen binding mismatch"));
    }
    let meta = load_meta(connection)?;
    let transition_consistent = match meta.mode {
        ProviderMode::Active => meta.handoff.is_none() && meta.destination_epoch.is_none(),
        ProviderMode::Frozen | ProviderMode::Prepared | ProviderMode::Fenced => {
            meta.handoff.is_some()
                && meta.destination_epoch == meta.authority_epoch.checked_add(1)
                && meta.completed_handoff.is_none()
                && meta.barrier == BarrierPhase::CheckpointReleased
        }
    };
    if !transition_consistent {
        return Err(ProviderError::Integrity("mode and handoff binding mismatch"));
    }
    let barrier_consistent = match meta.barrier {
        BarrierPhase::Open => {
            meta.barrier_token.is_none()
                && meta.barrier_predicate.is_none()
                && meta.barrier_remaining.is_none()
                && meta.barrier_effect.is_none()
        }
        BarrierPhase::Armed => {
            meta.barrier_token.is_some_and(|token| !token.is_zero())
                && meta.barrier_predicate.is_some()
                && meta.barrier_remaining.is_some()
                && meta.barrier_effect.is_none()
        }
        BarrierPhase::Triggered | BarrierPhase::Held => {
            meta.barrier_token.is_some_and(|token| !token.is_zero())
                && meta.barrier_predicate.is_some()
                && meta.barrier_remaining.is_none()
                && meta.barrier_effect.is_some_and(|effect| !effect.is_zero())
        }
        BarrierPhase::CheckpointReleased => {
            meta.barrier_token.is_some_and(|token| !token.is_zero())
                && meta.barrier_predicate.is_none()
                && meta.barrier_remaining.is_none()
                && meta.barrier_effect.is_some_and(|effect| !effect.is_zero())
        }
    } && match (meta.completed_barrier, meta.completed_barrier_effect) {
        (None, None) => true,
        (Some(token), Some(effect)) => !token.is_zero() && !effect.is_zero(),
        _ => false,
    };
    if !barrier_consistent {
        return Err(ProviderError::Integrity("barrier binding mismatch"));
    }
    if let (Some(token), Some(encoded)) = (meta.barrier_token, meta.barrier_predicate.as_deref()) {
        let predicate: HostcallPredicate = postcard::from_bytes(encoded)
            .map_err(|_| ProviderError::Integrity("barrier predicate encoding"))?;
        validate_barrier_predicate(token, &predicate)
            .map_err(|_| ProviderError::Integrity("barrier predicate fields"))?;
    }
    if let Some(effect) = meta.barrier_effect {
        let effect_rows: i64 = connection.query_row(
            "SELECT count(*) FROM effects WHERE effect_id = ?1",
            params![effect.0.as_slice()],
            |row| row.get(0),
        )?;
        if effect_rows != 1 {
            return Err(ProviderError::Integrity("barrier target effect is missing"));
        }
        let completed_deliveries: i64 = connection.query_row(
            "SELECT count(*) FROM requests WHERE effect_id = ?1 AND completed = 1",
            params![effect.0.as_slice()],
            |row| row.get(0),
        )?;
        match meta.barrier {
            BarrierPhase::Triggered if completed_deliveries != 0 => {
                return Err(ProviderError::Integrity(
                    "triggered barrier already has a completed target delivery",
                ));
            }
            BarrierPhase::Held | BarrierPhase::CheckpointReleased if completed_deliveries == 0 => {
                return Err(ProviderError::Integrity(
                    "held barrier lacks a completed target delivery",
                ));
            }
            _ => {}
        }
    }
    if let Some(effect) = meta.completed_barrier_effect {
        let completed_deliveries: i64 = connection.query_row(
            "SELECT count(*) FROM requests WHERE effect_id = ?1 AND completed = 1",
            params![effect.0.as_slice()],
            |row| row.get(0),
        )?;
        if completed_deliveries == 0 {
            return Err(ProviderError::Integrity(
                "completed barrier lacks a completed target delivery",
            ));
        }
    }
    if meta.barrier == BarrierPhase::CheckpointReleased {
        audit_zero(
            connection,
            "SELECT count(*) FROM requests WHERE completed = 0",
            "held barrier has incomplete response deliveries",
        )?;
    }
    audit_zero(
        connection,
        "SELECT count(*) FROM object_chunks c JOIN objects o USING(object_id)
         WHERE o.kind != 4 OR length(c.bytes) = 0
            OR c.chunk_index > 140737488355327
            OR c.chunk_index * 65536 >= o.size
            OR length(c.bytes) > min(65536, o.size - c.chunk_index * 65536)",
        "chunk extent lies outside object",
    )?;
    audit_zero(
        connection,
        "SELECT count(*) FROM objects o
         WHERE NOT EXISTS (SELECT 1 FROM paths p WHERE p.object_id = o.object_id)
           AND NOT EXISTS (SELECT 1 FROM descriptors d WHERE d.object_id = o.object_id)",
        "unreachable object",
    )?;
    audit_zero(
        connection,
        "SELECT count(*) FROM descriptors d JOIN objects o USING(object_id)
         WHERE (o.kind = 3 AND d.directory_path != x'' AND
                  NOT EXISTS (
                    SELECT 1 FROM paths p
                    WHERE p.path = d.directory_path AND p.object_id = d.object_id
                  ))
            OR (o.kind != 3 AND length(d.directory_path) != 0)
            OR (d.preopen = 1 AND (d.fd != 3 OR o.kind != 3 OR d.directory_path != x''))",
        "descriptor binding mismatch",
    )?;
    audit_zero(
        connection,
        "SELECT count(*) FROM locks
         WHERE owner = zeroblob(16)",
        "zero lock owner",
    )?;
    audit_zero(
        connection,
        "SELECT count(*) FROM locks l JOIN objects o USING(object_id)
         WHERE o.kind != 4
            OR NOT EXISTS (
                 SELECT 1 FROM descriptors d WHERE d.object_id = l.object_id
               )",
        "lock is not backed by an open regular file",
    )?;
    audit_zero(
        connection,
        "SELECT count(*) FROM (
           SELECT object_id,
             sum(CASE WHEN level >= 2 THEN 1 ELSE 0 END) AS writers,
             sum(CASE WHEN level = 4 THEN 1 ELSE 0 END) AS exclusive,
             count(*) AS total
           FROM locks GROUP BY object_id
         ) WHERE writers > 1 OR (exclusive = 1 AND total != 1)",
        "incompatible lock registry",
    )?;
    let next_fd: i64 =
        connection
            .query_row("SELECT next_fd FROM meta WHERE singleton = 1", [], |row| row.get(0))?;
    let maximum_fd: i64 =
        connection
            .query_row("SELECT coalesce(max(fd), 3) FROM descriptors", [], |row| row.get(0))?;
    if next_fd <= maximum_fd {
        return Err(ProviderError::Integrity("fd allocator regressed"));
    }
    for path in all_paths(connection)? {
        if normalize_path(&[], &path).ok().as_deref() != Some(path.as_slice()) {
            return Err(ProviderError::Integrity("noncanonical namespace path"));
        }
        if !path.is_empty() {
            let parent = parent_path(&path);
            match object_for_path(connection, parent, true) {
                Ok(Some(object)) if object.kind == FILE_TYPE_DIRECTORY => {}
                _ => return Err(ProviderError::Integrity("path parent is not a directory")),
            }
        }
    }
    Ok(())
}

fn audit_zero(
    connection: &Connection,
    query: &str,
    message: &'static str,
) -> Result<(), ProviderError> {
    let count: i64 = connection.query_row(query, [], |row| row.get(0))?;
    if count == 0 { Ok(()) } else { Err(ProviderError::Integrity(message)) }
}

fn read_manifest(bundle: &Path) -> Result<BundleManifest, ProviderError> {
    let bytes = fs::read(bundle.join("manifest.json")).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ProviderError::Missing
        } else {
            ProviderError::Io(error)
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|_| ProviderError::Codec)
}

fn verify_manifest_bytes(bundle: &Path, manifest: &BundleManifest) -> Result<(), ProviderError> {
    if manifest.schema != BUNDLE_SCHEMA
        || manifest.state_file != "state.sqlite"
        || manifest.source_epoch == 0
        || manifest.destination_epoch != manifest.source_epoch.saturating_add(1)
        || manifest.session_hex.len() != 32
        || manifest.handoff_hex.len() != 32
    {
        return Err(ProviderError::Integrity("capsule manifest fields"));
    }
    let bytes = fs::read(bundle.join(&manifest.state_file))?;
    if bytes.len() as u64 != manifest.state_size
        || hex(Sha256::digest(&bytes)) != manifest.state_sha256
    {
        return Err(ProviderError::Integrity("capsule state digest"));
    }
    Ok(())
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), ProviderError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn write_atomic_snapshot(path: &Path, bytes: &[u8]) -> Result<(), ProviderError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or(ProviderError::Invalid("snapshot path has no parent"))?;
    let digest = Sha256::digest(bytes);
    let temporary = parent.join(format!(
        ".visa-namespace-{}-{}-{}.tmp",
        &hex(digest)[..16],
        std::process::id(),
        now_ns()?
    ));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(ProviderError::AlreadyExists);
            }
            Err(error) => return Err(ProviderError::Io(error)),
        }
        sync_directory(parent)?;
        fs::remove_file(&temporary)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn copy_new(source: &Path, destination: &Path) -> Result<(), ProviderError> {
    let bytes = fs::read(source)?;
    write_new_synced(destination, &bytes)
}

fn sync_directory(path: &Path) -> Result<(), ProviderError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn lock_path(database: &Path) -> PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn now_ns() -> Result<u64, ProviderError> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProviderError::Integrity("host clock before epoch"))?
        .as_nanos();
    u64::try_from(value).map_err(|_| ProviderError::Integrity("host timestamp overflow"))
}

fn derived_object(session: SessionId, counter: u64) -> ObjectId {
    let mut digest = Sha256::new();
    digest.update(b"vISA/WASI/object/v1\0");
    digest.update(session.0);
    digest.update(counter.to_be_bytes());
    ObjectId(first_16(digest.finalize()))
}

fn virtual_inode(object: ObjectId) -> u64 {
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&object.0[..8]);
    u64::from_be_bytes(bytes).max(1)
}

fn first_16(value: impl AsRef<[u8]>) -> [u8; 16] {
    let mut output = [0_u8; 16];
    output.copy_from_slice(&value.as_ref()[..16]);
    output
}

fn hex(value: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(value.as_ref().len() * 2);
    for byte in value.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0_u8, |difference, (left, right)| difference | (left ^ right)) == 0
}

fn sql_to_mode(value: i64) -> Result<ProviderMode, ProviderError> {
    match value {
        0 => Ok(ProviderMode::Active),
        1 => Ok(ProviderMode::Frozen),
        2 => Ok(ProviderMode::Prepared),
        3 => Ok(ProviderMode::Fenced),
        _ => Err(ProviderError::Integrity("provider mode")),
    }
}

fn sql_to_barrier(value: i64) -> Result<BarrierPhase, ProviderError> {
    match value {
        0 => Ok(BarrierPhase::Open),
        1 => Ok(BarrierPhase::Armed),
        2 => Ok(BarrierPhase::Triggered),
        3 => Ok(BarrierPhase::Held),
        4 => Ok(BarrierPhase::CheckpointReleased),
        _ => Err(ProviderError::Integrity("barrier phase")),
    }
}

fn lock_to_sql(value: LockLevel) -> i64 {
    match value {
        LockLevel::None => 0,
        LockLevel::Shared => 1,
        LockLevel::Reserved => 2,
        LockLevel::Pending => 3,
        LockLevel::Exclusive => 4,
    }
}

fn sql_to_lock(value: i64) -> Result<LockLevel, ProviderError> {
    match value {
        1 => Ok(LockLevel::Shared),
        2 => Ok(LockLevel::Reserved),
        3 => Ok(LockLevel::Pending),
        4 => Ok(LockLevel::Exclusive),
        _ => Err(ProviderError::Integrity("lock level")),
    }
}

fn sql_i64(value: u64) -> Result<i64, ProviderError> {
    i64::try_from(value).map_err(|_| ProviderError::Invalid("integer exceeds SQLite range"))
}

fn nonnegative(value: i64) -> Result<u64, ProviderError> {
    u64::try_from(value).map_err(|_| ProviderError::Integrity("negative durable counter"))
}

fn row_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn u64_to_sql(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

fn sql_to_u64(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}
