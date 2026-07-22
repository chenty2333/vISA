//! Transport-independent core for the vISA native-v1 Nexus adapter.
//!
//! The core owns one private SQLite store, exact local-RPC replay, and the
//! one-way dispatch-grant ledger.  A [`NativePeer`] supplies the Nexus-owned
//! native-v1 operation; the peer is deliberately an interface here so the
//! D-Bus/process boundary can be added without moving durability semantics
//! into a transport implementation.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use visa_durable_sqlite::{
    DatabaseGuard, DurableStoreError, StoreLock, checkpoint_truncate,
    cleanup_owned_initialization_files, ensure_private_parent, ensure_sqlite_sidecars_absent,
    initialization_path, publish_noreplace, sync_file, sync_parent_directory,
};
use visa_local_rpc::{
    WireValidation,
    common::{
        AgentBinding, AgentRole, AuthorityRole, AuthorityServiceBinding, BootId, CanonicalPayload,
        CohortId, GrantId, LogicalIncarnation, OperationId, PRODUCT_VERSION, ProcessNonce,
        RegistryInstanceId, RequestId, RuntimeSessionId, ServiceIncarnation, Sha256Digest,
    },
    nexus_adapter as wire,
};

const SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x5641_4e58;
const MAX_NATIVE_REQUEST_BYTES: usize = 65_536;
const MAX_NATIVE_RECEIPT_SEQUENCE: u64 = i64::MAX as u64;
const MAX_STORED_PROVIDER_REVISION: u64 = i64::MAX as u64;
const RESERVED_TERMINAL_RESPONSE_BYTES: u64 = visa_local_rpc::MAX_INNER_RESPONSE_BYTES as u64;

const STORE_META_SQL: &str = "CREATE TABLE store_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    product_major INTEGER NOT NULL CHECK(product_major = 0),
    product_minor INTEGER NOT NULL CHECK(product_minor = 1),
    product_patch INTEGER NOT NULL CHECK(product_patch = 0),
    cohort BLOB NOT NULL CHECK(length(cohort) = 16),
    boot BLOB NOT NULL CHECK(length(boot) = 16),
    runtime_session BLOB NOT NULL CHECK(length(runtime_session) = 16),
    service_incarnation BLOB NOT NULL CHECK(length(service_incarnation) = 16),
    registry_instance BLOB NOT NULL CHECK(length(registry_instance) = 16),
    provider_identity_digest BLOB NOT NULL CHECK(length(provider_identity_digest) = 32),
    process_generation INTEGER NOT NULL CHECK(process_generation >= 0),
    last_process_nonce BLOB NOT NULL CHECK(length(last_process_nonce) = 16),
    max_exchanges INTEGER NOT NULL CHECK(max_exchanges > 0),
    max_exchange_bytes INTEGER NOT NULL CHECK(max_exchange_bytes > 0)
) STRICT";

const PROCESS_INSTANCE_SQL: &str = "CREATE TABLE process_instance (
    process_generation INTEGER PRIMARY KEY CHECK(process_generation > 0),
    process_nonce BLOB NOT NULL UNIQUE CHECK(length(process_nonce) = 16),
    start_completion_order INTEGER NOT NULL CHECK(start_completion_order > 0)
) STRICT";

const RPC_EXCHANGE_SQL: &str = "CREATE TABLE rpc_exchange (
    exchange_no INTEGER PRIMARY KEY,
    family_id BLOB NOT NULL CHECK(length(family_id) = 16),
    request_id BLOB NOT NULL CHECK(length(request_id) = 16),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    request_bytes BLOB NOT NULL CHECK(length(request_bytes) BETWEEN 1 AND 1048576),
    rpc_phase INTEGER NOT NULL CHECK(rpc_phase IN (0, 1)),
    native_attempted INTEGER NOT NULL CHECK(native_attempted IN (0, 1)),
    response_digest BLOB,
    response_bytes BLOB,
    completion_order INTEGER UNIQUE,
    UNIQUE(family_id, request_id),
    CHECK((rpc_phase = 0 AND response_digest IS NULL AND response_bytes IS NULL AND completion_order IS NULL)
          OR (rpc_phase = 1 AND length(response_digest) = 32 AND length(response_bytes) BETWEEN 1 AND 1048576
              AND completion_order > 0))
) STRICT";

const NATIVE_EXCHANGE_SQL: &str = "CREATE TABLE native_exchange (
    request_id BLOB PRIMARY KEY CHECK(length(request_id) = 16),
    native_request_id INTEGER NOT NULL UNIQUE CHECK(native_request_id > 0),
    native_request_bytes BLOB NOT NULL CHECK(length(native_request_bytes) BETWEEN 1 AND 65536),
    native_input_digest BLOB NOT NULL CHECK(length(native_input_digest) = 32),
    native_request_digest BLOB NOT NULL CHECK(length(native_request_digest) = 32),
    effect_operation BLOB NOT NULL CHECK(length(effect_operation) = 16),
    effect_idempotency BLOB NOT NULL CHECK(length(effect_idempotency) = 16),
    role INTEGER NOT NULL CHECK(role IN (0, 1)),
    logical_incarnation BLOB NOT NULL CHECK(length(logical_incarnation) = 16),
    cohort BLOB NOT NULL CHECK(length(cohort) = 16),
    boot BLOB NOT NULL CHECK(length(boot) = 16),
    runtime_session BLOB NOT NULL CHECK(length(runtime_session) = 16),
    process_nonce BLOB NOT NULL CHECK(length(process_nonce) = 16),
    process_generation INTEGER NOT NULL CHECK(process_generation > 0),
    projection_digest BLOB NOT NULL CHECK(length(projection_digest) = 32),
    expected_provider_revision INTEGER NOT NULL CHECK(expected_provider_revision > 0),
    phase INTEGER NOT NULL CHECK(phase IN (0, 1, 2)),
    native_receipt_digest BLOB,
    native_receipt_sequence INTEGER UNIQUE,
    provider_revision INTEGER,
    grant_sequence INTEGER,
    grant_bytes BLOB,
    CHECK(((phase = 0 OR phase = 2) AND native_receipt_digest IS NULL
           AND native_receipt_sequence IS NULL AND provider_revision IS NULL
           AND grant_sequence IS NULL AND grant_bytes IS NULL)
          OR (phase = 1 AND length(native_receipt_digest) = 32 AND native_receipt_sequence > 0
              AND provider_revision > 0 AND grant_sequence > 0 AND length(grant_bytes) > 0))
) STRICT";

const GRANT_SQL: &str = "CREATE TABLE dispatch_grant (
    grant_sequence INTEGER PRIMARY KEY CHECK(grant_sequence > 0),
    grant_id BLOB NOT NULL UNIQUE CHECK(length(grant_id) = 16),
    effect_operation BLOB NOT NULL CHECK(length(effect_operation) = 16),
    effect_idempotency BLOB NOT NULL CHECK(length(effect_idempotency) = 16),
    role INTEGER NOT NULL CHECK(role IN (0, 1)),
    logical_incarnation BLOB NOT NULL CHECK(length(logical_incarnation) = 16),
    cohort BLOB NOT NULL CHECK(length(cohort) = 16),
    boot BLOB NOT NULL CHECK(length(boot) = 16),
    projection_digest BLOB NOT NULL CHECK(length(projection_digest) = 32),
    native_request_digest BLOB NOT NULL CHECK(length(native_request_digest) = 32),
    native_receipt_digest BLOB NOT NULL CHECK(length(native_receipt_digest) = 32),
    provider_revision INTEGER NOT NULL CHECK(provider_revision > 0),
    grant_bytes BLOB NOT NULL CHECK(length(grant_bytes) > 0),
    UNIQUE(effect_operation, effect_idempotency)
) STRICT";

const SCHEMA_TABLES: [(&str, &str); 5] = [
    ("store_meta", STORE_META_SQL),
    ("process_instance", PROCESS_INSTANCE_SQL),
    ("rpc_exchange", RPC_EXCHANGE_SQL),
    ("native_exchange", NATIVE_EXCHANGE_SQL),
    ("dispatch_grant", GRANT_SQL),
];

/// Binding shared by every local service store in one same-boot cohort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterBinding {
    pub cohort: CohortId,
    pub boot: BootId,
    pub runtime_session: RuntimeSessionId,
}

impl AdapterBinding {
    fn validate(self) -> Result<(), NexusServiceError> {
        self.cohort.validate().map_err(|_| NexusServiceError::InvalidRequest)?;
        self.boot.validate().map_err(|_| NexusServiceError::InvalidRequest)?;
        self.runtime_session.validate().map_err(|_| NexusServiceError::InvalidRequest)
    }
}

/// Durable identity of one adapter/Registry attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterIdentity {
    pub service_incarnation: ServiceIncarnation,
    pub registry_instance: RegistryInstanceId,
    pub provider_identity_digest: Sha256Digest,
}

impl AdapterIdentity {
    fn validate(self) -> Result<(), NexusServiceError> {
        self.service_incarnation.validate().map_err(|_| NexusServiceError::InvalidRequest)?;
        self.registry_instance.validate().map_err(|_| NexusServiceError::InvalidRequest)?;
        self.provider_identity_digest.validate().map_err(|_| NexusServiceError::InvalidRequest)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreLimits {
    pub max_exchanges: u64,
    pub max_exchange_bytes: u64,
}

impl StoreLimits {
    pub const fn development_default() -> Self {
        Self { max_exchanges: 65_536, max_exchange_bytes: 256 * 1024 * 1024 }
    }

    fn validate(self) -> Result<(), NexusServiceError> {
        if self.max_exchanges == 0
            || self.max_exchange_bytes < 2 * visa_local_rpc::MAX_INNER_REQUEST_BYTES as u64
            || self.max_exchanges > i64::MAX as u64
            || self.max_exchange_bytes > i64::MAX as u64
        {
            Err(NexusServiceError::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreBootstrap {
    pub binding: AdapterBinding,
    pub identity: AdapterIdentity,
    pub process_nonce: ProcessNonce,
    pub create_new: bool,
    pub limits: StoreLimits,
}

/// The exact local request material handed to a native peer encoder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCommitInput {
    pub native_request_id: u64,
    pub effect: wire::EffectIdentity,
    pub caller: AgentBinding,
    pub expected_provider_revision: u64,
    pub expected_projection_digest: Sha256Digest,
    pub invocation: CanonicalPayload,
}

/// Canonical native request bytes prepared before the Registry call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedNativeCommit {
    pub native_request_id: u64,
    pub input_digest: Sha256Digest,
    pub request_bytes: Vec<u8>,
    pub request_digest: Sha256Digest,
}

impl PreparedNativeCommit {
    fn validate_for(&self, input: &NativeCommitInput) -> Result<(), NexusServiceError> {
        let input_bytes = postcard::to_allocvec(input).map_err(|_| NexusServiceError::Integrity)?;
        let expected_input_digest = Sha256Digest::of(&input_bytes);
        if self.native_request_id == 0
            || self.input_digest != expected_input_digest
            || self.request_bytes.is_empty()
            || self.request_bytes.len() > MAX_NATIVE_REQUEST_BYTES
            || self.request_digest != Sha256Digest::of(&self.request_bytes)
        {
            return Err(NexusServiceError::Integrity);
        }
        Ok(())
    }
}

/// Verified native-v1 result. The peer implementation owns JSON/schema/chain
/// verification; this core rechecks the cross-boundaries that it owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeCommitReceipt {
    pub native_request_id: u64,
    pub registry_instance: RegistryInstanceId,
    pub provider_revision: u64,
    pub request_digest: Sha256Digest,
    pub receipt_digest: Sha256Digest,
    pub receipt_sequence: u64,
}

impl NativeCommitReceipt {
    fn validate_for(
        &self,
        identity: AdapterIdentity,
        prepared: &PreparedNativeCommit,
        expected_provider_revision: u64,
    ) -> Result<(), NexusServiceError> {
        self.registry_instance.validate().map_err(|_| NexusServiceError::Integrity)?;
        self.request_digest.validate().map_err(|_| NexusServiceError::Integrity)?;
        self.receipt_digest.validate().map_err(|_| NexusServiceError::Integrity)?;
        if self.registry_instance != identity.registry_instance
            || self.native_request_id != prepared.native_request_id
            || self.request_digest != prepared.request_digest
            || self.receipt_sequence == 0
            || self.receipt_sequence > MAX_NATIVE_RECEIPT_SEQUENCE
            || self.provider_revision > MAX_STORED_PROVIDER_REVISION
            || Some(self.provider_revision) != expected_provider_revision.checked_add(1)
        {
            return Err(NexusServiceError::Integrity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeCommitRejection {
    pub native_request_id: u64,
    pub request_digest: Sha256Digest,
    pub rejection: wire::Rejection,
}

impl NativeCommitRejection {
    fn validate_for(&self, prepared: &PreparedNativeCommit) -> Result<(), NexusServiceError> {
        self.request_digest.validate().map_err(|_| NexusServiceError::Integrity)?;
        if self.native_request_id != prepared.native_request_id
            || self.request_digest != prepared.request_digest
        {
            return Err(NexusServiceError::Integrity);
        }
        self.rejection.validate().map_err(|_| NexusServiceError::Integrity)
    }
}

/// Native peer operation result. A rejection is a known terminal semantic
/// response; transport/peer loss is represented by [`NativePeerError::Unavailable`]
/// and leaves the durable pending row for exact retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeCommitResult {
    Committed(NativeCommitReceipt),
    Rejected(NativeCommitRejection),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativePeerError {
    Unavailable,
    Integrity,
}

/// Narrow seam consumed by the future Nexus JSONL/process adapter.
///
/// `prepare_commit` is an encoder-only operation. It must be deterministic and
/// side-effect free: it may not talk to the child, Registry, filesystem, or
/// advance any native state. All external native effects begin only in
/// `commit`, after the returned bytes have been durably stored by this core.
pub trait NativePeer {
    fn prepare_commit(
        &self,
        input: &NativeCommitInput,
    ) -> Result<PreparedNativeCommit, NativePeerError>;

    fn commit(
        &mut self,
        prepared: &PreparedNativeCommit,
    ) -> Result<NativeCommitResult, NativePeerError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NexusServiceError {
    InvalidRequest,
    RequestIdConflict,
    CallerBindingConflict,
    NativeUnavailable,
    StoreBusy,
    StoreMismatch,
    Integrity,
    Storage,
    Capacity,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AgentCallerCursors {
    source: Option<AgentBinding>,
    destination: Option<AgentBinding>,
}

impl AgentCallerCursors {
    fn transition(mut self, caller: AgentBinding) -> Option<Self> {
        let slot = match caller.role {
            AgentRole::Source => &mut self.source,
            AgentRole::Destination => &mut self.destination,
        };
        if let Some(previous) = slot
            && (!same_stable_agent(*previous, caller)
                || caller.process_generation < previous.process_generation
                || (caller.process_generation == previous.process_generation
                    && caller.process_nonce != previous.process_nonce)
                || (caller.process_generation > previous.process_generation
                    && caller.process_nonce == previous.process_nonce))
        {
            return None;
        }
        *slot = Some(caller);
        Some(self)
    }
}

fn same_stable_agent(left: AgentBinding, right: AgentBinding) -> bool {
    left.product_version == right.product_version
        && left.cohort == right.cohort
        && left.boot == right.boot
        && left.runtime_session == right.runtime_session
        && left.role == right.role
        && left.logical_incarnation == right.logical_incarnation
}

impl std::fmt::Display for NexusServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "invalid nexus adapter request",
            Self::RequestIdConflict => "request id was reused with different bytes",
            Self::CallerBindingConflict => "caller binding regressed or conflicted",
            Self::NativeUnavailable => "native Nexus peer is unavailable",
            Self::StoreBusy => "nexus adapter store is busy",
            Self::StoreMismatch => "nexus adapter store identity mismatch",
            Self::Integrity => "nexus adapter integrity failure",
            Self::Storage => "nexus adapter storage failure",
            Self::Capacity => "nexus adapter store capacity exhausted",
        })
    }
}

impl std::error::Error for NexusServiceError {}

impl From<DurableStoreError> for NexusServiceError {
    fn from(error: DurableStoreError) -> Self {
        match error {
            DurableStoreError::Busy => Self::StoreBusy,
            DurableStoreError::AlreadyExists
            | DurableStoreError::Missing
            | DurableStoreError::Insecure
            | DurableStoreError::NotSqlite
            | DurableStoreError::SidecarExists => Self::StoreMismatch,
            DurableStoreError::InvalidPath | DurableStoreError::Integrity => Self::Integrity,
            DurableStoreError::Io(_) | DurableStoreError::Sqlite(_) => Self::Storage,
        }
    }
}

/// One opened adapter store. The lock and descriptor guards remain held for
/// the lifetime of the service, enforcing one writer per registry attempt.
pub struct NexusAdapterStore {
    connection: Connection,
    _database_guard: DatabaseGuard,
    _lock: StoreLock,
    binding: AdapterBinding,
    identity: AdapterIdentity,
    server_binding: AuthorityServiceBinding,
    caller_cursors: AgentCallerCursors,
    limits: StoreLimits,
}

impl NexusAdapterStore {
    pub fn open(
        database_path: impl AsRef<Path>,
        bootstrap: StoreBootstrap,
    ) -> Result<Self, NexusServiceError> {
        bootstrap.binding.validate()?;
        bootstrap.identity.validate()?;
        bootstrap.process_nonce.validate().map_err(|_| NexusServiceError::InvalidRequest)?;
        bootstrap.limits.validate()?;
        let database_path = database_path.as_ref();
        ensure_private_parent(database_path)?;
        let lock = StoreLock::acquire(lock_path(database_path))?;
        if bootstrap.create_new {
            initialize_and_publish(database_path, bootstrap)?;
        }
        let database_guard = DatabaseGuard::open_existing(database_path)?;
        let connection = Connection::open_with_flags(
            database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| NexusServiceError::Storage)?;
        configure_session(&connection)?;
        audit_schema(&connection)?;
        let meta = load_meta(&connection)?;
        if meta.binding != bootstrap.binding
            || meta.identity != bootstrap.identity
            || meta.limits != bootstrap.limits
        {
            return Err(NexusServiceError::StoreMismatch);
        }
        verify_storage_mode(&connection)?;
        let process_instances =
            audit_process_instances(&connection, meta.process_generation, meta.last_process_nonce)?;
        let caller_cursors = audit_rpc_exchanges(
            &connection,
            meta.binding,
            meta.identity,
            &process_instances,
            meta.limits,
        )?;
        audit_native_exchanges(&connection, meta.identity)?;
        audit_dispatch_grants(&connection, meta.identity)?;
        let process_generation = advance_process_generation(&connection, bootstrap.process_nonce)?;
        let server_binding = AuthorityServiceBinding {
            product_version: PRODUCT_VERSION,
            cohort: meta.binding.cohort,
            boot: meta.binding.boot,
            runtime_session: meta.binding.runtime_session,
            role: AuthorityRole::NexusAdapter,
            service_incarnation: meta.identity.service_incarnation,
            process_nonce: bootstrap.process_nonce,
            process_generation,
        };
        server_binding.validate().map_err(|_| NexusServiceError::Integrity)?;
        database_guard.verify_sqlite_header()?;
        sync_file(database_guard.file())?;
        sync_parent_directory(database_path)?;
        Ok(Self {
            connection,
            _database_guard: database_guard,
            _lock: lock,
            binding: meta.binding,
            identity: meta.identity,
            server_binding,
            caller_cursors,
            limits: meta.limits,
        })
    }

    pub const fn binding(&self) -> AdapterBinding {
        self.binding
    }
    pub const fn identity(&self) -> AdapterIdentity {
        self.identity
    }
    pub const fn server_binding(&self) -> AuthorityServiceBinding {
        self.server_binding
    }

    /// Reconcile every durably admitted native commit without requiring the
    /// original agent process identity. This is the adapter-owned recovery path
    /// for a response lost after the local pending record was committed. It
    /// never invents a new request: each row is sent through the exact prepared
    /// bytes and native request ID already stored in `native_exchange`.
    pub fn reconcile_pending<P: NativePeer>(
        &mut self,
        peer: &mut P,
    ) -> Result<u64, NexusServiceError> {
        let mut statement = self
            .connection
            .prepare("SELECT request_id FROM native_exchange WHERE phase = 0 ORDER BY rowid")
            .map_err(map_sqlite_error)?;
        let rows =
            statement.query_map([], |row| row.get::<_, Vec<u8>>(0)).map_err(map_sqlite_error)?;
        let request_ids = rows
            .map(|row| {
                let bytes = row.map_err(map_sqlite_error)?;
                Ok(RequestId::from_bytes(id16(bytes).map_err(map_sqlite_error)?))
            })
            .collect::<Result<Vec<_>, NexusServiceError>>()?;
        drop(statement);
        let mut reconciled = 0_u64;
        for request_id in request_ids {
            let request_bytes: Vec<u8> = self
                .connection
                .query_row(
                    "SELECT request_bytes FROM rpc_exchange
                     WHERE family_id = ?1 AND request_id = ?2",
                    params![wire::FAMILY_ID.as_slice(), request_id.0.as_slice()],
                    |row| row.get(0),
                )
                .map_err(map_sqlite_error)?;
            let request =
                wire::decode_request(&request_bytes).map_err(|_| NexusServiceError::Integrity)?;
            let pending = load_pending(&self.connection, request_id)?;
            self.finish_pending(request, pending, peer)?;
            reconciled = reconciled.checked_add(1).ok_or(NexusServiceError::Integrity)?;
        }
        Ok(reconciled)
    }

    /// Execute one exact local-RPC request. A native commit is first recorded
    /// as pending, then sent through `peer`; finalizing the grant and response
    /// is one SQLite transaction. If the peer call loses its reply, the
    /// pending row remains and the same prepared bytes are retried.
    pub fn execute_exact<P: NativePeer>(
        &mut self,
        admitted_caller: AgentBinding,
        exact_request_bytes: &[u8],
        peer: &mut P,
    ) -> Result<Vec<u8>, NexusServiceError> {
        admitted_caller.validate().map_err(|_| NexusServiceError::InvalidRequest)?;
        let request = wire::decode_request(exact_request_bytes)
            .map_err(|_| NexusServiceError::InvalidRequest)?;
        if request.caller != admitted_caller
            || request.caller.cohort != self.binding.cohort
            || request.caller.boot != self.binding.boot
            || request.caller.runtime_session != self.binding.runtime_session
            || !fits_positive_sqlite_integer(request.caller.process_generation)
        {
            return Err(NexusServiceError::InvalidRequest);
        }

        if let wire::Operation::CommitAndAuthorizeDispatch(commit) = &request.operation
            && (commit.expected_provider_revision >= MAX_STORED_PROVIDER_REVISION
                || !fits_positive_sqlite_integer(commit.expected_provider_revision))
        {
            return Err(NexusServiceError::InvalidRequest);
        }

        let next_cursors = self
            .caller_cursors
            .transition(request.caller)
            .ok_or(NexusServiceError::CallerBindingConflict)?;

        if let Some(existing) = self.find_exchange(request.request_id)? {
            if existing.request_bytes != exact_request_bytes {
                return Err(NexusServiceError::RequestIdConflict);
            }
            if existing.phase == 1 {
                let response_bytes = existing.response_bytes.ok_or(NexusServiceError::Integrity)?;
                let response = wire::decode_response_for(&request, &response_bytes)
                    .map_err(|_| NexusServiceError::Integrity)?;
                let _ = response;
                self.caller_cursors = next_cursors;
                return Ok(response_bytes);
            }
            let response = self.resume_pending(request, existing, peer);
            if response.is_ok() {
                self.caller_cursors = next_cursors;
            }
            return response;
        }

        match request.operation.clone() {
            wire::Operation::CommitAndAuthorizeDispatch(commit) => {
                if self.effect_has_active_exchange(commit.effect)? {
                    let response = self.execute_rejection(
                        request,
                        exact_request_bytes,
                        wire::Rejection::Conflict,
                    );
                    if response.is_ok() {
                        self.caller_cursors = next_cursors;
                    }
                    response
                } else {
                    self.start_pending(request, exact_request_bytes, &commit, next_cursors, peer)
                }
            }
            wire::Operation::Descriptor | wire::Operation::Query(_) => {
                let response = self.execute_read_only(request, exact_request_bytes);
                if response.is_ok() {
                    self.caller_cursors = next_cursors;
                }
                response
            }
            _ => {
                let response = self.execute_rejection(
                    request,
                    exact_request_bytes,
                    wire::Rejection::Unsupported,
                );
                if response.is_ok() {
                    self.caller_cursors = next_cursors;
                }
                response
            }
        }
    }

    fn start_pending<P: NativePeer>(
        &mut self,
        request: wire::Request,
        exact_request_bytes: &[u8],
        commit: &wire::DispatchCommitRequest,
        next_cursors: AgentCallerCursors,
        peer: &mut P,
    ) -> Result<Vec<u8>, NexusServiceError> {
        let request_digest = request.digest().map_err(|_| NexusServiceError::Integrity)?;
        let native_request_id = derive_native_request_id(request_digest);
        let input = NativeCommitInput {
            native_request_id,
            effect: commit.effect,
            caller: request.caller,
            expected_provider_revision: commit.expected_provider_revision,
            expected_projection_digest: commit.expected_projection_digest,
            invocation: commit.invocation.clone(),
        };
        let prepared = peer.prepare_commit(&input).map_err(map_native_peer_error)?;
        prepared.validate_for(&input)?;
        if prepared.native_request_id != native_request_id {
            return Err(NexusServiceError::Integrity);
        }
        self.insert_pending(&request, exact_request_bytes, &prepared)?;
        self.caller_cursors = next_cursors;
        let pending = pending_from(&request, &prepared, commit);
        self.finish_pending(request, pending, peer)
    }

    fn resume_pending<P: NativePeer>(
        &mut self,
        request: wire::Request,
        _exchange: ExistingExchange,
        peer: &mut P,
    ) -> Result<Vec<u8>, NexusServiceError> {
        let pending = load_pending(&self.connection, request.request_id)?;
        if pending.request_id != request.request_id
            || pending.effect != operation_effect(&request.operation)?
            || pending.caller != request.caller
        {
            return Err(NexusServiceError::Integrity);
        }
        self.finish_pending(request, pending, peer)
    }

    fn finish_pending<P: NativePeer>(
        &mut self,
        request: wire::Request,
        pending: PendingNative,
        peer: &mut P,
    ) -> Result<Vec<u8>, NexusServiceError> {
        let result = peer.commit(&pending.prepared).map_err(map_native_peer_error)?;
        let (receipt, rejection) = match result {
            NativeCommitResult::Committed(receipt) => (Some(receipt), None),
            NativeCommitResult::Rejected(rejection) => {
                rejection.validate_for(&pending.prepared)?;
                (None, Some(rejection.rejection))
            }
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let current = load_pending_tx(&transaction, request.request_id)?;
        if current.prepared != pending.prepared || current.caller != pending.caller {
            return Err(NexusServiceError::Integrity);
        }
        if matches!(current.phase, 1 | 2) {
            let response = load_terminal_response_tx(&transaction, request.request_id, &request)?;
            transaction.commit().map_err(map_sqlite_error)?;
            return Ok(response);
        }
        if current.phase != 0 {
            return Err(NexusServiceError::Integrity);
        }

        let outcome = if let Some(receipt) = receipt {
            receipt.validate_for(
                self.identity,
                &pending.prepared,
                pending.expected_provider_revision,
            )?;
            let grant =
                Self::persist_grant_tx(&transaction, self.identity, &request, &pending, receipt)?;
            wire::Outcome::Success(wire::Success::DispatchAuthorized(grant))
        } else {
            wire::Outcome::Rejected(rejection.unwrap_or(wire::Rejection::Integrity))
        };
        let response = wire::Response::new(&request, self.server_binding, outcome)
            .map_err(|_| NexusServiceError::Integrity)?;
        let response_bytes = wire::encode_response_for(&request, &response)
            .map_err(|_| NexusServiceError::Integrity)?;
        let response_digest = response.digest().map_err(|_| NexusServiceError::Integrity)?;
        let completion_order = next_completion_order(&transaction)?;
        if response_bytes.len() > visa_local_rpc::MAX_INNER_RESPONSE_BYTES {
            return Err(NexusServiceError::Capacity);
        }
        ensure_response_capacity_tx(&transaction, response_bytes.len(), self.limits, true)?;
        let changed = transaction
            .execute(
                "UPDATE rpc_exchange SET rpc_phase = 1, response_digest = ?2,
                 response_bytes = ?3, completion_order = ?4
                 WHERE family_id = ?5 AND request_id = ?1 AND rpc_phase = 0",
                params![
                    request.request_id.0.as_slice(),
                    response_digest.0.as_slice(),
                    response_bytes,
                    completion_order,
                    wire::FAMILY_ID.as_slice(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(NexusServiceError::Integrity);
        }
        if matches!(outcome_kind(&response), OutcomeKind::Rejected) {
            let changed = transaction
                .execute(
                    "UPDATE native_exchange SET phase = 2
                     WHERE request_id = ?1 AND phase = 0",
                    params![request.request_id.0.as_slice()],
                )
                .map_err(map_sqlite_error)?;
            if changed != 1 {
                return Err(NexusServiceError::Integrity);
            }
        }
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(response_bytes)
    }

    fn persist_grant_tx(
        transaction: &Transaction<'_>,
        identity: AdapterIdentity,
        request: &wire::Request,
        pending: &PendingNative,
        receipt: NativeCommitReceipt,
    ) -> Result<wire::DispatchGrant, NexusServiceError> {
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT grant_bytes FROM dispatch_grant WHERE effect_operation = ?1 AND effect_idempotency = ?2",
                params![pending.effect.operation.0.as_slice(), pending.effect.idempotency.0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sqlite_error)?;
        if let Some(bytes) = existing {
            let grant = decode_grant(&bytes)?;
            if grant.projection_digest != pending.projection_digest
                || grant.native_request_digest != pending.prepared.request_digest
                || grant.native_receipt_digest != receipt.receipt_digest
            {
                return Err(NexusServiceError::CallerBindingConflict);
            }
            let grant_bytes = encode_grant(&grant)?;
            let changed = transaction
                .execute(
                    "UPDATE native_exchange SET phase = 1, native_receipt_digest = ?2,
                     native_receipt_sequence = ?3, provider_revision = ?4,
                     grant_sequence = ?5, grant_bytes = ?6
                     WHERE request_id = ?1 AND phase = 0",
                    params![
                        request.request_id.0.as_slice(),
                        receipt.receipt_digest.0.as_slice(),
                        sqlite_positive_integer(receipt.receipt_sequence)?,
                        sqlite_positive_integer(receipt.provider_revision)?,
                        sqlite_positive_integer(grant.grant_sequence)?,
                        grant_bytes,
                    ],
                )
                .map_err(map_sqlite_error)?;
            if changed != 1 {
                return Err(NexusServiceError::Integrity);
            }
            return Ok(grant);
        }
        let sequence = next_grant_sequence(transaction)?;
        let grant = wire::DispatchGrant {
            grant: GrantId::from_u128(sequence as u128),
            registry_instance: identity.registry_instance,
            effect: pending.effect,
            role: request.caller.role,
            logical_incarnation: request.caller.logical_incarnation,
            cohort: request.caller.cohort,
            boot: request.caller.boot,
            projection_digest: pending.projection_digest,
            native_request_digest: pending.prepared.request_digest,
            native_receipt_digest: receipt.receipt_digest,
            grant_sequence: sequence,
        };
        grant.validate().map_err(|_| NexusServiceError::Integrity)?;
        let grant_bytes = encode_grant(&grant)?;
        transaction
            .execute(
                "INSERT INTO dispatch_grant(
                 grant_sequence, grant_id, effect_operation, effect_idempotency, role,
                 logical_incarnation, cohort, boot, projection_digest,
                 native_request_digest, native_receipt_digest, provider_revision, grant_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    sqlite_positive_integer(sequence)?,
                    grant.grant.0.as_slice(),
                    grant.effect.operation.0.as_slice(),
                    grant.effect.idempotency.0.as_slice(),
                    role_i64(grant.role),
                    grant.logical_incarnation.0.as_slice(),
                    grant.cohort.0.as_slice(),
                    grant.boot.0.as_slice(),
                    grant.projection_digest.0.as_slice(),
                    grant.native_request_digest.0.as_slice(),
                    grant.native_receipt_digest.0.as_slice(),
                    sqlite_positive_integer(receipt.provider_revision)?,
                    grant_bytes,
                ],
            )
            .map_err(map_sqlite_error)?;
        let changed = transaction
            .execute(
                "UPDATE native_exchange SET phase = 1, native_receipt_digest = ?2,
                 native_receipt_sequence = ?3, provider_revision = ?4,
                 grant_sequence = ?5, grant_bytes = ?6 WHERE request_id = ?1 AND phase = 0",
                params![
                    request.request_id.0.as_slice(),
                    receipt.receipt_digest.0.as_slice(),
                    sqlite_positive_integer(receipt.receipt_sequence)?,
                    sqlite_positive_integer(receipt.provider_revision)?,
                    sqlite_positive_integer(sequence)?,
                    grant_bytes,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(NexusServiceError::Integrity);
        }
        Ok(grant)
    }

    fn execute_read_only(
        &mut self,
        request: wire::Request,
        exact_request_bytes: &[u8],
    ) -> Result<Vec<u8>, NexusServiceError> {
        let outcome = match request.operation {
            wire::Operation::Descriptor => {
                wire::Outcome::Success(wire::Success::Descriptor(wire::ProviderDescriptor {
                    provider_protocol_major: 2,
                    provider_protocol_minor: 1,
                    native_wire_major: 1,
                    registry_instance: self.identity.registry_instance,
                    provider_identity_digest: self.identity.provider_identity_digest,
                    maximum_native_request_bytes: MAX_NATIVE_REQUEST_BYTES as u32,
                }))
            }
            wire::Operation::Query(query) => self.query_outcome(request.caller, query)?,
            _ => return Err(NexusServiceError::InvalidRequest),
        };
        self.persist_terminal(&request, exact_request_bytes, outcome)
    }

    fn execute_rejection(
        &mut self,
        request: wire::Request,
        exact_request_bytes: &[u8],
        rejection: wire::Rejection,
    ) -> Result<Vec<u8>, NexusServiceError> {
        self.persist_terminal(&request, exact_request_bytes, wire::Outcome::Rejected(rejection))
    }

    fn persist_terminal(
        &mut self,
        request: &wire::Request,
        exact_request_bytes: &[u8],
        outcome: wire::Outcome,
    ) -> Result<Vec<u8>, NexusServiceError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        insert_exchange_tx(&transaction, request, exact_request_bytes, self.limits, false)?;
        let response = wire::Response::new(request, self.server_binding, outcome)
            .map_err(|_| NexusServiceError::Integrity)?;
        let response_bytes = wire::encode_response_for(request, &response)
            .map_err(|_| NexusServiceError::Integrity)?;
        if response_bytes.len() > visa_local_rpc::MAX_INNER_RESPONSE_BYTES {
            return Err(NexusServiceError::Capacity);
        }
        ensure_response_capacity_tx(&transaction, response_bytes.len(), self.limits, false)?;
        let response_digest = response.digest().map_err(|_| NexusServiceError::Integrity)?;
        let completion_order = next_completion_order(&transaction)?;
        let changed = transaction
            .execute(
                "UPDATE rpc_exchange SET rpc_phase = 1, response_digest = ?2,
                 response_bytes = ?3, completion_order = ?4
                 WHERE family_id = ?5 AND request_id = ?1 AND rpc_phase = 0",
                params![
                    request.request_id.0.as_slice(),
                    response_digest.0.as_slice(),
                    response_bytes,
                    completion_order,
                    wire::FAMILY_ID.as_slice(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(NexusServiceError::Integrity);
        }
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(response_bytes)
    }

    fn insert_pending(
        &mut self,
        request: &wire::Request,
        exact_request_bytes: &[u8],
        prepared: &PreparedNativeCommit,
    ) -> Result<(), NexusServiceError> {
        let commit = match &request.operation {
            wire::Operation::CommitAndAuthorizeDispatch(value) => value,
            _ => return Err(NexusServiceError::InvalidRequest),
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        insert_exchange_tx(&transaction, request, exact_request_bytes, self.limits, true)?;
        let effect = commit.effect;
        transaction
            .execute(
                "INSERT INTO native_exchange(
                 request_id, native_request_id, native_request_bytes, native_input_digest,
                 native_request_digest,
                 effect_operation, effect_idempotency, role, logical_incarnation, cohort, boot,
                 runtime_session, process_nonce, process_generation, projection_digest,
                 expected_provider_revision, phase)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, 0)",
                params![
                    request.request_id.0.as_slice(),
                    sqlite_positive_integer(prepared.native_request_id)?,
                    prepared.request_bytes,
                    prepared.input_digest.0.as_slice(),
                    prepared.request_digest.0.as_slice(),
                    effect.operation.0.as_slice(),
                    effect.idempotency.0.as_slice(),
                    role_i64(request.caller.role),
                    request.caller.logical_incarnation.0.as_slice(),
                    request.caller.cohort.0.as_slice(),
                    request.caller.boot.0.as_slice(),
                    request.caller.runtime_session.0.as_slice(),
                    request.caller.process_nonce.0.as_slice(),
                    sqlite_positive_integer(request.caller.process_generation)?,
                    commit.expected_projection_digest.0.as_slice(),
                    sqlite_positive_integer(commit.expected_provider_revision)?,
                ],
            )
            .map_err(map_native_insert_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(())
    }

    fn query_outcome(
        &self,
        caller: AgentBinding,
        query: wire::QueryRequest,
    ) -> Result<wire::Outcome, NexusServiceError> {
        let result = match query {
            wire::QueryRequest::Grant(grant_id) => {
                let bytes: Option<Vec<u8>> = self
                    .connection
                    .query_row(
                        "SELECT grant_bytes FROM dispatch_grant WHERE grant_id = ?1",
                        params![grant_id.0.as_slice()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(map_sqlite_error)?;
                match bytes {
                    Some(value) => {
                        let grant = decode_grant(&value)?;
                        validate_grant_caller(caller, &grant)?;
                        wire::QueryResult::Grant(grant)
                    }
                    None => wire::QueryResult::Missing,
                }
            }
            wire::QueryRequest::Effect(effect) => {
                let mut statement = self
                    .connection
                    .prepare(
                        "SELECT request_id FROM native_exchange
                         WHERE effect_operation = ?1 AND effect_idempotency = ?2 AND phase = 0",
                    )
                    .map_err(map_sqlite_error)?;
                let pending_ids = statement
                    .query_map(
                        params![effect.operation.0.as_slice(), effect.idempotency.0.as_slice()],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .map_err(map_sqlite_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(map_sqlite_error)?;
                drop(statement);
                match pending_ids.as_slice() {
                    [] => {}
                    [request_id] => {
                        let request_id = RequestId::from_bytes(
                            id16(request_id.clone()).map_err(map_sqlite_error)?,
                        );
                        let pending = load_pending(&self.connection, request_id)?;
                        if !same_stable_agent(pending.caller, caller) {
                            return Err(NexusServiceError::InvalidRequest);
                        }
                        return Ok(wire::Outcome::Unknown(wire::Unknown {
                            query: wire::QueryRequest::Effect(effect),
                            last_known_provider_revision: pending.expected_provider_revision,
                        }));
                    }
                    _ => return Err(NexusServiceError::Integrity),
                }
                let row: Option<(Vec<u8>, i64)> = self
                    .connection
                    .query_row(
                        "SELECT grant_bytes, provider_revision FROM dispatch_grant
                         WHERE effect_operation = ?1 AND effect_idempotency = ?2",
                        params![effect.operation.0.as_slice(), effect.idempotency.0.as_slice()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(map_sqlite_error)?;
                match row {
                    None => wire::QueryResult::Missing,
                    Some((bytes, revision)) => {
                        let grant = decode_grant(&bytes)?;
                        validate_grant_caller(caller, &grant)?;
                        let state = wire::EffectState {
                            effect,
                            phase: wire::EffectPhase::Committed,
                            provider_revision: positive_i64(revision)?,
                            native_request_digest: grant.native_request_digest,
                            native_receipt_digest: grant.native_receipt_digest,
                        };
                        wire::QueryResult::Effect(state)
                    }
                }
            }
            wire::QueryRequest::Joint(_) => wire::QueryResult::Missing,
        };
        Ok(wire::Outcome::Success(wire::Success::Query(result)))
    }

    fn effect_has_active_exchange(
        &self,
        effect: wire::EffectIdentity,
    ) -> Result<bool, NexusServiceError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT count(*) FROM native_exchange
                 WHERE effect_operation = ?1 AND effect_idempotency = ?2 AND phase IN (0, 1)",
                params![effect.operation.0.as_slice(), effect.idempotency.0.as_slice()],
                |row| row.get(0),
            )
            .map_err(map_sqlite_error)?;
        match count {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(NexusServiceError::Integrity),
        }
    }

    fn find_exchange(
        &self,
        request_id: RequestId,
    ) -> Result<Option<ExistingExchange>, NexusServiceError> {
        self.connection
            .query_row(
                "SELECT request_bytes, rpc_phase, response_bytes FROM rpc_exchange
                 WHERE family_id = ?1 AND request_id = ?2",
                params![wire::FAMILY_ID.as_slice(), request_id.0.as_slice()],
                |row| {
                    Ok(ExistingExchange {
                        request_bytes: row.get(0)?,
                        phase: row.get(1)?,
                        response_bytes: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutcomeKind {
    Rejected,
    Other,
}

fn outcome_kind(response: &wire::Response) -> OutcomeKind {
    match &response.outcome {
        wire::Outcome::Rejected(_) => OutcomeKind::Rejected,
        _ => OutcomeKind::Other,
    }
}

#[derive(Clone, Debug)]
struct ExistingExchange {
    request_bytes: Vec<u8>,
    phase: i64,
    response_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingNative {
    request_id: RequestId,
    native_request_id: u64,
    prepared: PreparedNativeCommit,
    effect: wire::EffectIdentity,
    caller: AgentBinding,
    projection_digest: Sha256Digest,
    expected_provider_revision: u64,
    phase: i64,
}

impl PendingNative {
    fn from_request(
        request: &wire::Request,
        prepared: &PreparedNativeCommit,
        commit: &wire::DispatchCommitRequest,
    ) -> Self {
        Self {
            request_id: request.request_id,
            native_request_id: prepared.native_request_id,
            prepared: prepared.clone(),
            effect: commit.effect,
            caller: request.caller,
            projection_digest: commit.expected_projection_digest,
            expected_provider_revision: commit.expected_provider_revision,
            phase: 0,
        }
    }
}

fn pending_from(
    request: &wire::Request,
    prepared: &PreparedNativeCommit,
    commit: &wire::DispatchCommitRequest,
) -> PendingNative {
    PendingNative::from_request(request, prepared, commit)
}

fn operation_effect(
    operation: &wire::Operation,
) -> Result<wire::EffectIdentity, NexusServiceError> {
    match operation {
        wire::Operation::CommitAndAuthorizeDispatch(value) => Ok(value.effect),
        _ => Err(NexusServiceError::Integrity),
    }
}

fn validate_grant_caller(
    caller: AgentBinding,
    grant: &wire::DispatchGrant,
) -> Result<(), NexusServiceError> {
    if grant.cohort != caller.cohort
        || grant.boot != caller.boot
        || grant.role != caller.role
        || grant.logical_incarnation != caller.logical_incarnation
    {
        return Err(NexusServiceError::InvalidRequest);
    }
    Ok(())
}

fn derive_native_request_id(request_digest: Sha256Digest) -> u64 {
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&request_digest.0[..8]);
    let value = u64::from_be_bytes(bytes) & i64::MAX as u64;
    if value == 0 { 1 } else { value }
}

fn encode_grant(grant: &wire::DispatchGrant) -> Result<Vec<u8>, NexusServiceError> {
    postcard::to_allocvec(grant).map_err(|_| NexusServiceError::Integrity)
}

fn decode_grant(bytes: &[u8]) -> Result<wire::DispatchGrant, NexusServiceError> {
    let (grant, remaining) = postcard::take_from_bytes::<wire::DispatchGrant>(bytes)
        .map_err(|_| NexusServiceError::Integrity)?;
    if !remaining.is_empty() {
        return Err(NexusServiceError::Integrity);
    }
    grant.validate().map_err(|_| NexusServiceError::Integrity)?;
    Ok(grant)
}

fn role_i64(role: AgentRole) -> i64 {
    match role {
        AgentRole::Source => 0,
        AgentRole::Destination => 1,
    }
}

fn role_from_i64(value: i64) -> Result<AgentRole, NexusServiceError> {
    match value {
        0 => Ok(AgentRole::Source),
        1 => Ok(AgentRole::Destination),
        _ => Err(NexusServiceError::Integrity),
    }
}

fn positive_i64(value: i64) -> Result<u64, NexusServiceError> {
    u64::try_from(value).ok().filter(|value| *value > 0).ok_or(NexusServiceError::Integrity)
}

fn nonnegative_i64(value: i64) -> Result<u64, NexusServiceError> {
    u64::try_from(value).map_err(|_| NexusServiceError::Integrity)
}

fn fits_positive_sqlite_integer(value: u64) -> bool {
    value > 0 && value <= i64::MAX as u64
}

fn sqlite_positive_integer(value: u64) -> Result<i64, NexusServiceError> {
    i64::try_from(value).ok().filter(|value| *value > 0).ok_or(NexusServiceError::Integrity)
}

fn map_sqlite_error(error: rusqlite::Error) -> NexusServiceError {
    match classify_sqlite_error(&error) {
        SqliteFailureClass::Busy => NexusServiceError::StoreBusy,
        SqliteFailureClass::Unique | SqliteFailureClass::Integrity => NexusServiceError::Integrity,
        SqliteFailureClass::Other => NexusServiceError::Storage,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SqliteFailureClass {
    Busy,
    Unique,
    Integrity,
    Other,
}

fn classify_sqlite_error(error: &rusqlite::Error) -> SqliteFailureClass {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            SqliteFailureClass::Busy
        }
        Some(rusqlite::ErrorCode::ConstraintViolation) => {
            let extended_code = match error {
                rusqlite::Error::SqliteFailure(failure, _) => failure.extended_code,
                _ => return SqliteFailureClass::Integrity,
            };
            if matches!(
                extended_code,
                rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                    | rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                    | rusqlite::ffi::SQLITE_CONSTRAINT_ROWID
            ) {
                SqliteFailureClass::Unique
            } else {
                SqliteFailureClass::Integrity
            }
        }
        _ => SqliteFailureClass::Other,
    }
}

fn map_exchange_insert_error(error: rusqlite::Error) -> NexusServiceError {
    match classify_sqlite_error(&error) {
        SqliteFailureClass::Busy => NexusServiceError::StoreBusy,
        SqliteFailureClass::Unique => NexusServiceError::RequestIdConflict,
        SqliteFailureClass::Integrity => NexusServiceError::Integrity,
        SqliteFailureClass::Other => NexusServiceError::Storage,
    }
}

fn map_native_insert_error(error: rusqlite::Error) -> NexusServiceError {
    match classify_sqlite_error(&error) {
        SqliteFailureClass::Busy => NexusServiceError::StoreBusy,
        SqliteFailureClass::Unique | SqliteFailureClass::Integrity => NexusServiceError::Integrity,
        SqliteFailureClass::Other => NexusServiceError::Storage,
    }
}

fn map_process_insert_error(error: rusqlite::Error) -> NexusServiceError {
    match classify_sqlite_error(&error) {
        SqliteFailureClass::Busy => NexusServiceError::StoreBusy,
        SqliteFailureClass::Unique => NexusServiceError::StoreMismatch,
        SqliteFailureClass::Integrity => NexusServiceError::Integrity,
        SqliteFailureClass::Other => NexusServiceError::Storage,
    }
}

fn map_native_peer_error(error: NativePeerError) -> NexusServiceError {
    match error {
        NativePeerError::Unavailable => NexusServiceError::NativeUnavailable,
        NativePeerError::Integrity => NexusServiceError::Integrity,
    }
}

fn lock_path(database_path: &Path) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn configure_session(connection: &Connection) -> Result<(), NexusServiceError> {
    connection.busy_timeout(Duration::from_secs(5)).map_err(map_sqlite_error)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA wal_autocheckpoint = 1000;",
        )
        .map_err(map_sqlite_error)?;
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    if !journal.eq_ignore_ascii_case("wal") || synchronous != 2 {
        return Err(NexusServiceError::Integrity);
    }
    Ok(())
}

fn verify_storage_mode(connection: &Connection) -> Result<(), NexusServiceError> {
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
    {
        return Err(NexusServiceError::Integrity);
    }
    Ok(())
}

fn initialize_and_publish(
    database_path: &Path,
    bootstrap: StoreBootstrap,
) -> Result<(), NexusServiceError> {
    ensure_sqlite_sidecars_absent(database_path)?;
    let temporary_path = initialization_path(database_path, bootstrap.process_nonce.0);
    ensure_sqlite_sidecars_absent(&temporary_path)?;
    let database_guard = DatabaseGuard::create_new(&temporary_path)?;
    let result = (|| {
        let connection = Connection::open_with_flags(
            &temporary_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| NexusServiceError::Storage)?;
        configure_session(&connection)?;
        initialize_schema(&connection, bootstrap)?;
        checkpoint_truncate(&connection)?;
        connection.close().map_err(|_| NexusServiceError::Storage)?;
        ensure_sqlite_sidecars_absent(&temporary_path)?;
        ensure_sqlite_sidecars_absent(database_path)?;
        publish_noreplace(&temporary_path, database_path, database_guard.file())?;
        Ok(())
    })();
    if result.is_err() {
        cleanup_owned_initialization_files(&temporary_path, database_guard.file());
    }
    result
}

fn initialize_schema(
    connection: &Connection,
    bootstrap: StoreBootstrap,
) -> Result<(), NexusServiceError> {
    connection
        .execute_batch(&format!(
            "PRAGMA application_id = {APPLICATION_ID};
             PRAGMA user_version = {SCHEMA_VERSION};
             {STORE_META_SQL};
             {PROCESS_INSTANCE_SQL};
             {RPC_EXCHANGE_SQL};
             {NATIVE_EXCHANGE_SQL};
             {GRANT_SQL};"
        ))
        .map_err(map_sqlite_error)?;
    connection
        .execute(
            "INSERT INTO store_meta(singleton, product_major, product_minor, product_patch,
             cohort, boot, runtime_session, service_incarnation, registry_instance,
             provider_identity_digest, process_generation, last_process_nonce,
             max_exchanges, max_exchange_bytes)
             VALUES (1, 0, 1, 0, ?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9)",
            params![
                bootstrap.binding.cohort.0.as_slice(),
                bootstrap.binding.boot.0.as_slice(),
                bootstrap.binding.runtime_session.0.as_slice(),
                bootstrap.identity.service_incarnation.0.as_slice(),
                bootstrap.identity.registry_instance.0.as_slice(),
                bootstrap.identity.provider_identity_digest.0.as_slice(),
                ProcessNonce::ZERO.0.as_slice(),
                sqlite_positive_integer(bootstrap.limits.max_exchanges)?,
                sqlite_positive_integer(bootstrap.limits.max_exchange_bytes)?,
            ],
        )
        .map_err(map_sqlite_error)?;
    audit_schema(connection)
}

#[derive(Clone, Copy)]
struct Meta {
    binding: AdapterBinding,
    identity: AdapterIdentity,
    process_generation: u64,
    last_process_nonce: ProcessNonce,
    limits: StoreLimits,
}

fn audit_schema(connection: &Connection) -> Result<(), NexusServiceError> {
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    if user_version != SCHEMA_VERSION || application_id != APPLICATION_ID {
        return Err(NexusServiceError::StoreMismatch);
    }
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(map_sqlite_error)?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(map_sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sqlite_error)?;
    if objects.len() != SCHEMA_TABLES.len()
        || objects.iter().any(|(object_type, name, table_name, sql)| {
            object_type != "table"
                || name != table_name
                || SCHEMA_TABLES
                    .iter()
                    .find(|(expected_name, _)| name == expected_name)
                    .is_none_or(|(_, expected_sql)| sql != expected_sql)
        })
    {
        return Err(NexusServiceError::Integrity);
    }
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    if quick_check != "ok" {
        return Err(NexusServiceError::Integrity);
    }
    let mut foreign_key_check =
        connection.prepare("PRAGMA foreign_key_check").map_err(map_sqlite_error)?;
    if foreign_key_check
        .query([])
        .map_err(map_sqlite_error)?
        .next()
        .map_err(map_sqlite_error)?
        .is_some()
    {
        return Err(NexusServiceError::Integrity);
    }
    Ok(())
}

fn load_meta(connection: &Connection) -> Result<Meta, NexusServiceError> {
    connection
        .query_row(
            "SELECT cohort, boot, runtime_session, service_incarnation, registry_instance,
                    provider_identity_digest, process_generation, last_process_nonce,
                    max_exchanges, max_exchange_bytes
             FROM store_meta WHERE singleton = 1",
            [],
            |row| {
                let cohort = id16(row.get(0)?)?;
                let boot = id16(row.get(1)?)?;
                let runtime_session = id16(row.get(2)?)?;
                let service_incarnation = id16(row.get(3)?)?;
                let registry_instance = id16(row.get(4)?)?;
                let provider_identity_digest = id32(row.get(5)?)?;
                let process_generation: i64 = row.get(6)?;
                let last_process_nonce = id16(row.get(7)?)?;
                let max_exchanges: i64 = row.get(8)?;
                let max_exchange_bytes: i64 = row.get(9)?;
                Ok(Meta {
                    binding: AdapterBinding {
                        cohort: CohortId::from_bytes(cohort),
                        boot: BootId::from_bytes(boot),
                        runtime_session: RuntimeSessionId::from_bytes(runtime_session),
                    },
                    identity: AdapterIdentity {
                        service_incarnation: ServiceIncarnation::from_bytes(service_incarnation),
                        registry_instance: RegistryInstanceId::from_bytes(registry_instance),
                        provider_identity_digest: Sha256Digest(provider_identity_digest),
                    },
                    process_generation: u64::try_from(process_generation)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    last_process_nonce: ProcessNonce::from_bytes(last_process_nonce),
                    limits: StoreLimits {
                        max_exchanges: positive_i64(max_exchanges)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        max_exchange_bytes: positive_i64(max_exchange_bytes)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    },
                })
            },
        )
        .map_err(map_sqlite_error)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessInstance {
    generation: u64,
    nonce: ProcessNonce,
    start_completion_order: i64,
}

fn audit_process_instances(
    connection: &Connection,
    process_generation: u64,
    last_process_nonce: ProcessNonce,
) -> Result<Vec<ProcessInstance>, NexusServiceError> {
    let mut statement = connection
        .prepare(
            "SELECT process_generation, process_nonce, start_completion_order
             FROM process_instance ORDER BY process_generation",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?))
        })
        .map_err(map_sqlite_error)?;
    let mut instances = Vec::new();
    let mut expected_generation = 1_u64;
    let mut previous_start = 0_i64;
    for row in rows {
        let (generation, nonce, start_completion_order) = row.map_err(map_sqlite_error)?;
        let generation = u64::try_from(generation).map_err(|_| NexusServiceError::Integrity)?;
        let nonce = ProcessNonce::from_bytes(id16(nonce).map_err(map_sqlite_error)?);
        nonce.validate().map_err(|_| NexusServiceError::Integrity)?;
        if generation != expected_generation
            || start_completion_order <= 0
            || start_completion_order < previous_start
            || (generation == 1 && start_completion_order != 1)
        {
            return Err(NexusServiceError::Integrity);
        }
        instances.push(ProcessInstance { generation, nonce, start_completion_order });
        expected_generation =
            expected_generation.checked_add(1).ok_or(NexusServiceError::Integrity)?;
        previous_start = start_completion_order;
    }
    if instances.len() as u64 != process_generation {
        return Err(NexusServiceError::Integrity);
    }
    match instances.last() {
        Some(instance) if instance.nonce == last_process_nonce => {}
        None if last_process_nonce == ProcessNonce::ZERO => {}
        _ => return Err(NexusServiceError::Integrity),
    }
    let next_completion = next_completion_order_connection(connection)?;
    if instances.last().is_some_and(|instance| instance.start_completion_order > next_completion) {
        return Err(NexusServiceError::Integrity);
    }
    Ok(instances)
}

fn audit_rpc_exchanges(
    connection: &Connection,
    binding: AdapterBinding,
    identity: AdapterIdentity,
    process_instances: &[ProcessInstance],
    limits: StoreLimits,
) -> Result<AgentCallerCursors, NexusServiceError> {
    let mut statement = connection
        .prepare(
            "SELECT exchange_no, family_id, request_id, request_digest, request_bytes,
                    rpc_phase, native_attempted, response_digest, response_bytes,
                    completion_order
             FROM rpc_exchange ORDER BY exchange_no",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, Option<Vec<u8>>>(8)?,
                row.get::<_, Option<i64>>(9)?,
            ))
        })
        .map_err(map_sqlite_error)?;
    let mut expected_exchange = 1_i64;
    let mut caller_cursors = AgentCallerCursors::default();
    let mut completion_orders = BTreeSet::new();
    let mut count = 0_u64;
    let mut retained = 0_u64;
    let mut pending_native = 0_u64;
    for row in rows {
        let row = row.map_err(map_sqlite_error)?;
        let request = wire::decode_request(&row.4).map_err(|_| NexusServiceError::Integrity)?;
        if row.0 != expected_exchange
            || row.1.as_slice() != wire::FAMILY_ID
            || row.2.as_slice() != request.request_id.0
            || row.3.as_slice() != request.digest().map_err(|_| NexusServiceError::Integrity)?.0
            || request.caller.cohort != binding.cohort
            || request.caller.boot != binding.boot
            || request.caller.runtime_session != binding.runtime_session
        {
            return Err(NexusServiceError::Integrity);
        }
        caller_cursors =
            caller_cursors.transition(request.caller).ok_or(NexusServiceError::Integrity)?;
        match row.5 {
            0 => {
                if row.6 != 1 || row.7.is_some() || row.8.is_some() || row.9.is_some() {
                    return Err(NexusServiceError::Integrity);
                }
                if !matches!(request.operation, wire::Operation::CommitAndAuthorizeDispatch(_)) {
                    return Err(NexusServiceError::Integrity);
                }
                if native_phase_count(connection, request.request_id, 0)? != 1 {
                    return Err(NexusServiceError::Integrity);
                }
                pending_native =
                    pending_native.checked_add(1).ok_or(NexusServiceError::Integrity)?;
            }
            1 => {
                let response_digest = row.7.ok_or(NexusServiceError::Integrity)?;
                let response_bytes = row.8.ok_or(NexusServiceError::Integrity)?;
                let completion_order = row.9.ok_or(NexusServiceError::Integrity)?;
                let response = wire::decode_response_for(&request, &response_bytes)
                    .map_err(|_| NexusServiceError::Integrity)?;
                match (&request.operation, &response.outcome, row.6) {
                    (
                        wire::Operation::CommitAndAuthorizeDispatch(_),
                        wire::Outcome::Success(wire::Success::DispatchAuthorized(_)),
                        1,
                    ) if native_phase_count(connection, request.request_id, 1)? == 1 => {}
                    (
                        wire::Operation::CommitAndAuthorizeDispatch(_),
                        wire::Outcome::Rejected(_),
                        1,
                    ) if native_phase_count(connection, request.request_id, 2)? == 1 => {}
                    (
                        wire::Operation::CommitAndAuthorizeDispatch(_),
                        wire::Outcome::Rejected(_),
                        0,
                    ) if native_phase_count(connection, request.request_id, 0)? == 0
                        && native_phase_count(connection, request.request_id, 1)? == 0
                        && native_phase_count(connection, request.request_id, 2)? == 0 => {}
                    (wire::Operation::CommitAndAuthorizeDispatch(_), _, _) => {
                        return Err(NexusServiceError::Integrity);
                    }
                    (_, _, 0)
                        if native_phase_count(connection, request.request_id, 0)? == 0
                            && native_phase_count(connection, request.request_id, 1)? == 0
                            && native_phase_count(connection, request.request_id, 2)? == 0 => {}
                    _ => return Err(NexusServiceError::Integrity),
                }
                let process = process_instances
                    .iter()
                    .rev()
                    .find(|process| process.start_completion_order <= completion_order)
                    .ok_or(NexusServiceError::Integrity)?;
                let expected_server = AuthorityServiceBinding {
                    product_version: PRODUCT_VERSION,
                    cohort: binding.cohort,
                    boot: binding.boot,
                    runtime_session: binding.runtime_session,
                    role: AuthorityRole::NexusAdapter,
                    service_incarnation: identity.service_incarnation,
                    process_nonce: process.nonce,
                    process_generation: process.generation,
                };
                if completion_order <= 0
                    || !completion_orders.insert(completion_order)
                    || response.server != expected_server
                    || response_digest.as_slice()
                        != response.digest().map_err(|_| NexusServiceError::Integrity)?.0
                {
                    return Err(NexusServiceError::Integrity);
                }
                retained = retained
                    .checked_add(response_bytes.len() as u64)
                    .ok_or(NexusServiceError::Integrity)?;
            }
            _ => return Err(NexusServiceError::Integrity),
        }
        count = count.checked_add(1).ok_or(NexusServiceError::Integrity)?;
        retained = retained.checked_add(row.4.len() as u64).ok_or(NexusServiceError::Integrity)?;
        expected_exchange = expected_exchange.checked_add(1).ok_or(NexusServiceError::Integrity)?;
    }
    let effective_retained = retained
        .checked_add(
            pending_native
                .checked_mul(RESERVED_TERMINAL_RESPONSE_BYTES)
                .ok_or(NexusServiceError::Integrity)?,
        )
        .ok_or(NexusServiceError::Integrity)?;
    if count > limits.max_exchanges || effective_retained > limits.max_exchange_bytes {
        return Err(NexusServiceError::Integrity);
    }
    for expected in 1..=completion_orders.len() {
        let expected = i64::try_from(expected).map_err(|_| NexusServiceError::Integrity)?;
        if !completion_orders.contains(&expected) {
            return Err(NexusServiceError::Integrity);
        }
    }
    Ok(caller_cursors)
}

fn native_input_for(
    request: &wire::Request,
    commit: &wire::DispatchCommitRequest,
    native_request_id: u64,
) -> NativeCommitInput {
    NativeCommitInput {
        native_request_id,
        effect: commit.effect,
        caller: request.caller,
        expected_provider_revision: commit.expected_provider_revision,
        expected_projection_digest: commit.expected_projection_digest,
        invocation: commit.invocation.clone(),
    }
}

fn native_phase_count(
    connection: &Connection,
    request_id: RequestId,
    phase: i64,
) -> Result<i64, NexusServiceError> {
    connection
        .query_row(
            "SELECT count(*) FROM native_exchange WHERE request_id = ?1 AND phase = ?2",
            params![request_id.0.as_slice(), phase],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)
}

struct NativeTerminal {
    receipt_digest: Option<Vec<u8>>,
    receipt_sequence: Option<i64>,
    provider_revision: Option<i64>,
    grant_sequence: Option<i64>,
    grant_bytes: Option<Vec<u8>>,
}

fn audit_native_exchanges(
    connection: &Connection,
    identity: AdapterIdentity,
) -> Result<(), NexusServiceError> {
    let mut statement = connection
        .prepare("SELECT request_id FROM native_exchange ORDER BY native_request_id")
        .map_err(map_sqlite_error)?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0)).map_err(map_sqlite_error)?;
    let mut receipt_sequences = BTreeSet::new();
    for row in rows {
        let request_id =
            RequestId::from_bytes(id16(row.map_err(map_sqlite_error)?).map_err(map_sqlite_error)?);
        request_id.validate().map_err(|_| NexusServiceError::Integrity)?;
        let native = load_pending(connection, request_id)?;
        let (request_bytes, rpc_phase, response_bytes): (Vec<u8>, i64, Option<Vec<u8>>) =
            connection
                .query_row(
                    "SELECT request_bytes, rpc_phase, response_bytes FROM rpc_exchange
                     WHERE family_id = ?1 AND request_id = ?2",
                    params![wire::FAMILY_ID.as_slice(), request_id.0.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(map_sqlite_error)?;
        let request =
            wire::decode_request(&request_bytes).map_err(|_| NexusServiceError::Integrity)?;
        let wire::Operation::CommitAndAuthorizeDispatch(commit) = &request.operation else {
            return Err(NexusServiceError::Integrity);
        };
        let request_digest = request.digest().map_err(|_| NexusServiceError::Integrity)?;
        let expected_native_request_id = derive_native_request_id(request_digest);
        let input = native_input_for(&request, commit, expected_native_request_id);
        native.prepared.validate_for(&input)?;
        if native.request_id != request.request_id
            || native.native_request_id != expected_native_request_id
            || native.effect != commit.effect
            || native.caller != request.caller
            || native.projection_digest != commit.expected_projection_digest
            || native.expected_provider_revision != commit.expected_provider_revision
        {
            return Err(NexusServiceError::Integrity);
        }
        let terminal = connection
            .query_row(
                "SELECT native_receipt_digest, native_receipt_sequence,
                        provider_revision, grant_sequence, grant_bytes
                 FROM native_exchange WHERE request_id = ?1",
                params![request_id.0.as_slice()],
                |row| {
                    Ok(NativeTerminal {
                        receipt_digest: row.get(0)?,
                        receipt_sequence: row.get(1)?,
                        provider_revision: row.get(2)?,
                        grant_sequence: row.get(3)?,
                        grant_bytes: row.get(4)?,
                    })
                },
            )
            .map_err(map_sqlite_error)?;
        match native.phase {
            0 => {
                if rpc_phase != 0
                    || response_bytes.is_some()
                    || terminal.receipt_digest.is_some()
                    || terminal.receipt_sequence.is_some()
                    || terminal.provider_revision.is_some()
                    || terminal.grant_sequence.is_some()
                    || terminal.grant_bytes.is_some()
                {
                    return Err(NexusServiceError::Integrity);
                }
            }
            1 => {
                let response_bytes = response_bytes.ok_or(NexusServiceError::Integrity)?;
                let response = wire::decode_response_for(&request, &response_bytes)
                    .map_err(|_| NexusServiceError::Integrity)?;
                let wire::Outcome::Success(wire::Success::DispatchAuthorized(grant)) =
                    response.outcome
                else {
                    return Err(NexusServiceError::Integrity);
                };
                let receipt_digest = Sha256Digest(
                    id32(terminal.receipt_digest.ok_or(NexusServiceError::Integrity)?)
                        .map_err(map_sqlite_error)?,
                );
                let receipt_sequence =
                    positive_i64(terminal.receipt_sequence.ok_or(NexusServiceError::Integrity)?)?;
                let provider_revision =
                    positive_i64(terminal.provider_revision.ok_or(NexusServiceError::Integrity)?)?;
                let grant_sequence =
                    positive_i64(terminal.grant_sequence.ok_or(NexusServiceError::Integrity)?)?;
                let grant_bytes = terminal.grant_bytes.ok_or(NexusServiceError::Integrity)?;
                if rpc_phase != 1
                    || !receipt_sequences.insert(receipt_sequence)
                    || Some(provider_revision) != native.expected_provider_revision.checked_add(1)
                    || grant_sequence != grant.grant_sequence
                    || receipt_digest != grant.native_receipt_digest
                    || grant.native_request_digest != native.prepared.request_digest
                    || grant.registry_instance != identity.registry_instance
                    || grant_bytes != encode_grant(&grant)?
                {
                    return Err(NexusServiceError::Integrity);
                }
                let stored_grant: Vec<u8> = connection
                    .query_row(
                        "SELECT grant_bytes FROM dispatch_grant WHERE grant_sequence = ?1",
                        params![sqlite_positive_integer(grant_sequence)?],
                        |row| row.get(0),
                    )
                    .map_err(map_sqlite_error)?;
                if stored_grant != grant_bytes {
                    return Err(NexusServiceError::Integrity);
                }
            }
            2 => {
                let response_bytes = response_bytes.ok_or(NexusServiceError::Integrity)?;
                let response = wire::decode_response_for(&request, &response_bytes)
                    .map_err(|_| NexusServiceError::Integrity)?;
                if rpc_phase != 1
                    || !matches!(response.outcome, wire::Outcome::Rejected(_))
                    || terminal.receipt_digest.is_some()
                    || terminal.receipt_sequence.is_some()
                    || terminal.provider_revision.is_some()
                    || terminal.grant_sequence.is_some()
                    || terminal.grant_bytes.is_some()
                {
                    return Err(NexusServiceError::Integrity);
                }
            }
            _ => return Err(NexusServiceError::Integrity),
        }
    }
    let duplicate_active_effects: i64 = connection
        .query_row(
            "SELECT count(*) FROM (
                 SELECT 1 FROM native_exchange WHERE phase IN (0, 1)
                 GROUP BY effect_operation, effect_idempotency HAVING count(*) > 1
             )",
            [],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)?;
    if duplicate_active_effects != 0 {
        return Err(NexusServiceError::Integrity);
    }
    Ok(())
}

fn audit_dispatch_grants(
    connection: &Connection,
    identity: AdapterIdentity,
) -> Result<(), NexusServiceError> {
    let mut statement = connection
        .prepare(
            "SELECT grant_sequence, grant_id, effect_operation, effect_idempotency, role,
                    logical_incarnation, cohort, boot, projection_digest,
                    native_request_digest, native_receipt_digest, provider_revision, grant_bytes
             FROM dispatch_grant ORDER BY grant_sequence",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, Vec<u8>>(12)?,
            ))
        })
        .map_err(map_sqlite_error)?;
    let mut expected_sequence = 1_u64;
    for row in rows {
        let row = row.map_err(map_sqlite_error)?;
        let sequence = positive_i64(row.0)?;
        let grant = decode_grant(&row.12)?;
        if sequence != expected_sequence
            || grant.grant != GrantId::from_u128(sequence as u128)
            || grant.registry_instance != identity.registry_instance
            || row.1.as_slice() != grant.grant.0
            || row.2.as_slice() != grant.effect.operation.0
            || row.3.as_slice() != grant.effect.idempotency.0
            || role_from_i64(row.4)? != grant.role
            || row.5.as_slice() != grant.logical_incarnation.0
            || row.6.as_slice() != grant.cohort.0
            || row.7.as_slice() != grant.boot.0
            || row.8.as_slice() != grant.projection_digest.0
            || row.9.as_slice() != grant.native_request_digest.0
            || row.10.as_slice() != grant.native_receipt_digest.0
            || positive_i64(row.11).is_err()
            || encode_grant(&grant)? != row.12
        {
            return Err(NexusServiceError::Integrity);
        }
        let provider_revision = positive_i64(row.11)?;
        let native_count: i64 = connection
            .query_row(
                "SELECT count(*) FROM native_exchange
                 WHERE phase = 1 AND grant_sequence = ?1 AND grant_bytes = ?2
                       AND provider_revision = ?3",
                params![
                    sqlite_positive_integer(sequence)?,
                    row.12,
                    sqlite_positive_integer(provider_revision)?,
                ],
                |row| row.get(0),
            )
            .map_err(map_sqlite_error)?;
        if native_count != 1 {
            return Err(NexusServiceError::Integrity);
        }
        expected_sequence = expected_sequence.checked_add(1).ok_or(NexusServiceError::Integrity)?;
    }
    Ok(())
}

fn advance_process_generation(
    connection: &Connection,
    nonce: ProcessNonce,
) -> Result<u64, NexusServiceError> {
    let transaction = connection.unchecked_transaction().map_err(map_sqlite_error)?;
    let current: i64 = transaction
        .query_row("SELECT process_generation FROM store_meta WHERE singleton = 1", [], |row| {
            row.get(0)
        })
        .map_err(map_sqlite_error)?;
    let next = current.checked_add(1).ok_or(NexusServiceError::Integrity)?;
    let start_completion_order = next_completion_order(&transaction)?;
    transaction
        .execute(
            "INSERT INTO process_instance(
                 process_generation, process_nonce, start_completion_order
             ) VALUES (?1, ?2, ?3)",
            params![next, nonce.0.as_slice(), start_completion_order],
        )
        .map_err(map_process_insert_error)?;
    let changed = transaction
        .execute(
            "UPDATE store_meta SET process_generation = ?1, last_process_nonce = ?2
             WHERE singleton = 1 AND process_generation = ?3",
            params![next, nonce.0.as_slice(), current],
        )
        .map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(NexusServiceError::Integrity);
    }
    transaction.commit().map_err(map_sqlite_error)?;
    positive_i64(next)
}

fn id16(value: Vec<u8>) -> rusqlite::Result<[u8; 16]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn id32(value: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExchangeUsage {
    count: u64,
    retained_bytes: u64,
    pending_native: u64,
}

fn exchange_usage_tx(transaction: &Transaction<'_>) -> Result<ExchangeUsage, NexusServiceError> {
    let (count, retained_bytes, pending_native): (i64, i64, i64) = transaction
        .query_row(
            "SELECT count(*),
                    coalesce(sum(length(request_bytes) + coalesce(length(response_bytes), 0)), 0),
                    coalesce(sum(CASE WHEN rpc_phase = 0 AND native_attempted = 1
                                      THEN 1 ELSE 0 END), 0)
             FROM rpc_exchange",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(map_sqlite_error)?;
    Ok(ExchangeUsage {
        count: nonnegative_i64(count)?,
        retained_bytes: nonnegative_i64(retained_bytes)?,
        pending_native: nonnegative_i64(pending_native)?,
    })
}

fn effective_retained_bytes(usage: ExchangeUsage) -> Result<u64, NexusServiceError> {
    usage
        .pending_native
        .checked_mul(RESERVED_TERMINAL_RESPONSE_BYTES)
        .and_then(|reserved| usage.retained_bytes.checked_add(reserved))
        .ok_or(NexusServiceError::Integrity)
}

fn insert_exchange_tx(
    transaction: &Transaction<'_>,
    request: &wire::Request,
    exact_request_bytes: &[u8],
    limits: StoreLimits,
    native_attempted: bool,
) -> Result<(), NexusServiceError> {
    if exact_request_bytes.len() > visa_local_rpc::MAX_INNER_REQUEST_BYTES {
        return Err(NexusServiceError::Capacity);
    }
    let request_digest = request.digest().map_err(|_| NexusServiceError::Integrity)?;
    let usage = exchange_usage_tx(transaction)?;
    let request_len =
        u64::try_from(exact_request_bytes.len()).map_err(|_| NexusServiceError::Capacity)?;
    let reservation = if native_attempted { RESERVED_TERMINAL_RESPONSE_BYTES } else { 0 };
    let admitted_bytes = effective_retained_bytes(usage)?
        .checked_add(request_len)
        .and_then(|bytes| bytes.checked_add(reservation))
        .ok_or(NexusServiceError::Capacity)?;
    if usage.count >= limits.max_exchanges || admitted_bytes > limits.max_exchange_bytes {
        return Err(NexusServiceError::Capacity);
    }
    transaction
        .execute(
            "INSERT INTO rpc_exchange(
                 family_id, request_id, request_digest, request_bytes, rpc_phase, native_attempted
             ) VALUES (?1, ?2, ?3, ?4, 0, ?5)",
            params![
                wire::FAMILY_ID.as_slice(),
                request.request_id.0.as_slice(),
                request_digest.0.as_slice(),
                exact_request_bytes,
                i64::from(native_attempted),
            ],
        )
        .map_err(map_exchange_insert_error)?;
    Ok(())
}

fn ensure_response_capacity_tx(
    transaction: &Transaction<'_>,
    response_len: usize,
    limits: StoreLimits,
    consume_native_reservation: bool,
) -> Result<(), NexusServiceError> {
    if response_len > visa_local_rpc::MAX_INNER_RESPONSE_BYTES {
        return Err(NexusServiceError::Capacity);
    }
    let usage = exchange_usage_tx(transaction)?;
    let pending_native = if consume_native_reservation {
        usage.pending_native.checked_sub(1).ok_or(NexusServiceError::Integrity)?
    } else {
        usage.pending_native
    };
    let future = usage
        .retained_bytes
        .checked_add(
            pending_native
                .checked_mul(RESERVED_TERMINAL_RESPONSE_BYTES)
                .ok_or(NexusServiceError::Capacity)?,
        )
        .and_then(|bytes| bytes.checked_add(u64::try_from(response_len).ok()?))
        .ok_or(NexusServiceError::Capacity)?;
    if future > limits.max_exchange_bytes {
        return Err(NexusServiceError::Capacity);
    }
    Ok(())
}

fn load_pending(
    connection: &Connection,
    request_id: RequestId,
) -> Result<PendingNative, NexusServiceError> {
    connection
        .query_row(
            "SELECT native_request_id, native_request_bytes, native_input_digest,
                    native_request_digest, effect_operation,
                    effect_idempotency, role, logical_incarnation, cohort, boot,
                    runtime_session, process_nonce, process_generation,
                    projection_digest, expected_provider_revision, phase
             FROM native_exchange WHERE request_id = ?1",
            params![request_id.0.as_slice()],
            |row| pending_from_row(request_id, row),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => NexusServiceError::Integrity,
            other => map_sqlite_error(other),
        })
}

fn load_pending_tx(
    transaction: &Transaction<'_>,
    request_id: RequestId,
) -> Result<PendingNative, NexusServiceError> {
    transaction
        .query_row(
            "SELECT native_request_id, native_request_bytes, native_input_digest,
                    native_request_digest, effect_operation,
                    effect_idempotency, role, logical_incarnation, cohort, boot,
                    runtime_session, process_nonce, process_generation,
                    projection_digest, expected_provider_revision, phase
             FROM native_exchange WHERE request_id = ?1",
            params![request_id.0.as_slice()],
            |row| pending_from_row(request_id, row),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => NexusServiceError::Integrity,
            other => map_sqlite_error(other),
        })
}

fn pending_from_row(
    request_id: RequestId,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PendingNative> {
    let native_request_id: i64 = row.get(0)?;
    let native_request_bytes: Vec<u8> = row.get(1)?;
    let native_input_digest = id32(row.get(2)?)?;
    let native_request_digest = id32(row.get(3)?)?;
    let operation = id16(row.get(4)?)?;
    let idempotency = id16(row.get(5)?)?;
    let role = role_from_i64(row.get(6)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let logical_incarnation = id16(row.get(7)?)?;
    let cohort = id16(row.get(8)?)?;
    let boot = id16(row.get(9)?)?;
    let runtime_session = id16(row.get(10)?)?;
    let process_nonce = id16(row.get(11)?)?;
    let process_generation: i64 = row.get(12)?;
    let projection_digest = id32(row.get(13)?)?;
    let expected_provider_revision: i64 = row.get(14)?;
    let phase: i64 = row.get(15)?;
    let native_request_id =
        positive_i64(native_request_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    if native_request_bytes.is_empty()
        || native_request_bytes.len() > MAX_NATIVE_REQUEST_BYTES
        || Sha256Digest::of(&native_request_bytes).0 != native_request_digest
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let prepared = PreparedNativeCommit {
        native_request_id,
        input_digest: Sha256Digest(native_input_digest),
        request_bytes: native_request_bytes,
        request_digest: Sha256Digest(native_request_digest),
    };
    Ok(PendingNative {
        request_id,
        native_request_id,
        prepared,
        effect: wire::EffectIdentity {
            operation: OperationId::from_bytes(operation),
            idempotency: visa_local_rpc::common::IdempotencyId::from_bytes(idempotency),
        },
        caller: AgentBinding {
            product_version: PRODUCT_VERSION,
            cohort: CohortId::from_bytes(cohort),
            boot: BootId::from_bytes(boot),
            runtime_session: RuntimeSessionId::from_bytes(runtime_session),
            role,
            logical_incarnation: LogicalIncarnation::from_bytes(logical_incarnation),
            process_nonce: ProcessNonce::from_bytes(process_nonce),
            process_generation: positive_i64(process_generation)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        },
        projection_digest: Sha256Digest(projection_digest),
        expected_provider_revision: positive_i64(expected_provider_revision)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        phase,
    })
}

fn load_terminal_response_tx(
    transaction: &Transaction<'_>,
    request_id: RequestId,
    request: &wire::Request,
) -> Result<Vec<u8>, NexusServiceError> {
    let bytes: Vec<u8> = transaction
        .query_row(
            "SELECT response_bytes FROM rpc_exchange WHERE family_id = ?1 AND request_id = ?2 AND rpc_phase = 1",
            params![wire::FAMILY_ID.as_slice(), request_id.0.as_slice()],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)?;
    wire::decode_response_for(request, &bytes).map_err(|_| NexusServiceError::Integrity)?;
    Ok(bytes)
}

fn next_completion_order_connection(connection: &Connection) -> Result<i64, NexusServiceError> {
    let value: i64 = connection
        .query_row("SELECT coalesce(max(completion_order), 0) + 1 FROM rpc_exchange", [], |row| {
            row.get(0)
        })
        .map_err(map_sqlite_error)?;
    if value <= 0 { Err(NexusServiceError::Integrity) } else { Ok(value) }
}

fn next_completion_order(transaction: &Transaction<'_>) -> Result<i64, NexusServiceError> {
    let value: i64 = transaction
        .query_row("SELECT coalesce(max(completion_order), 0) + 1 FROM rpc_exchange", [], |row| {
            row.get(0)
        })
        .map_err(map_sqlite_error)?;
    if value <= 0 { Err(NexusServiceError::Integrity) } else { Ok(value) }
}

fn next_grant_sequence(transaction: &Transaction<'_>) -> Result<u64, NexusServiceError> {
    let value: i64 = transaction
        .query_row("SELECT coalesce(max(grant_sequence), 0) + 1 FROM dispatch_grant", [], |row| {
            row.get(0)
        })
        .map_err(map_sqlite_error)?;
    positive_i64(value)
}

#[cfg(test)]
mod tests;
