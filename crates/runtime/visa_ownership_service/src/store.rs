use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use joint_handoff_core::{Digest, Identity, ReceiptIssuerIdentity};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use visa_durable_sqlite::{
    DatabaseGuard, DurableStoreError, StoreLock, checkpoint_truncate,
    cleanup_owned_initialization_files, ensure_private_parent as ensure_durable_private_parent,
    ensure_sqlite_sidecars_absent as ensure_durable_sidecars_absent,
    initialization_path as durable_initialization_path,
    publish_noreplace as publish_durable_noreplace, sync_file as sync_durable_file,
    sync_parent_directory as sync_durable_parent,
};
use visa_local_rpc::{
    WireValidation,
    common::{
        AgentBinding, AgentRole, AuthorityRole, AuthorityServiceBinding, BootId, CohortId,
        IssuerId, IssuerKeyId, IssuerLogId, PRODUCT_VERSION, ProcessNonce, RuntimeSessionId,
        ServiceIncarnation,
    },
    ownership as wire,
};

use crate::{
    OwnershipServiceError, PinnedLocalReceiptAuthenticator, SqliteFailureClass,
    classify_sqlite_error, state,
};

const SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x5649_5341;
const SQLITE_PAGE_SIZE: u64 = 4096;

const STORE_META_TABLE_SQL: &str = "CREATE TABLE store_meta (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 product_major INTEGER NOT NULL CHECK(product_major = 0),
                 product_minor INTEGER NOT NULL CHECK(product_minor = 1),
                 product_patch INTEGER NOT NULL CHECK(product_patch = 0),
                 cohort BLOB NOT NULL CHECK(length(cohort) = 16),
                 boot BLOB NOT NULL CHECK(length(boot) = 16),
                 runtime_session BLOB NOT NULL CHECK(length(runtime_session) = 16),
                 service_incarnation BLOB NOT NULL CHECK(length(service_incarnation) = 16),
                 issuer BLOB NOT NULL CHECK(length(issuer) = 16),
                 issuer_key_id BLOB NOT NULL CHECK(length(issuer_key_id) = 16),
                 issuer_log_namespace BLOB NOT NULL CHECK(length(issuer_log_namespace) = 16),
                 receipt_policy_digest BLOB NOT NULL CHECK(length(receipt_policy_digest) = 32),
                 process_generation INTEGER NOT NULL CHECK(process_generation >= 0),
                 last_process_nonce BLOB NOT NULL CHECK(length(last_process_nonce) = 16),
                 max_exchanges INTEGER NOT NULL CHECK(max_exchanges > 0),
                 max_exchange_bytes INTEGER NOT NULL CHECK(max_exchange_bytes > 0),
                 max_database_bytes INTEGER NOT NULL CHECK(max_database_bytes > 0)
             ) STRICT";

const OWNERSHIP_UNIT_TABLE_SQL: &str = "CREATE TABLE ownership_unit (
                 continuity_unit BLOB NOT NULL CHECK(length(continuity_unit) = 16),
                 continuity_generation BLOB NOT NULL CHECK(length(continuity_generation) = 8),
                 record BLOB NOT NULL CHECK(length(record) > 0),
                 PRIMARY KEY(continuity_unit, continuity_generation)
             ) WITHOUT ROWID, STRICT";

const PROCESS_INSTANCE_TABLE_SQL: &str = "CREATE TABLE process_instance (
                 process_generation INTEGER PRIMARY KEY CHECK(process_generation > 0),
                 process_nonce BLOB NOT NULL UNIQUE CHECK(length(process_nonce) = 16),
                 start_completion_order INTEGER NOT NULL CHECK(start_completion_order > 0)
             ) STRICT";

const OWNERSHIP_HANDOFF_TABLE_SQL: &str = "CREATE TABLE ownership_handoff (
                 handoff_id BLOB PRIMARY KEY CHECK(length(handoff_id) = 16),
                 continuity_unit BLOB NOT NULL CHECK(length(continuity_unit) = 16),
                 continuity_generation BLOB NOT NULL CHECK(length(continuity_generation) = 8),
                 expected_epoch BLOB NOT NULL CHECK(length(expected_epoch) = 8),
                 record BLOB NOT NULL CHECK(length(record) > 0),
                 FOREIGN KEY(continuity_unit, continuity_generation)
                   REFERENCES ownership_unit(continuity_unit, continuity_generation)
                   ON DELETE RESTRICT
             ) WITHOUT ROWID, STRICT";

const RPC_EXCHANGE_TABLE_SQL: &str = "CREATE TABLE rpc_exchange (
                 exchange_no INTEGER PRIMARY KEY,
                 family_id BLOB NOT NULL CHECK(length(family_id) = 16),
                 request_id BLOB NOT NULL CHECK(length(request_id) = 16),
                 request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                 request_bytes BLOB NOT NULL
                   CHECK(length(request_bytes) BETWEEN 1 AND 1048576),
                 rpc_phase INTEGER NOT NULL CHECK(rpc_phase IN (0, 1)),
                 response_digest BLOB,
                 response_bytes BLOB,
                 completion_order INTEGER UNIQUE,
                 UNIQUE(family_id, request_id),
                 CHECK(
                   (rpc_phase = 0 AND response_digest IS NULL AND response_bytes IS NULL
                    AND completion_order IS NULL)
                   OR
                   (rpc_phase = 1 AND length(response_digest) = 32
                    AND length(response_bytes) BETWEEN 1 AND 1048576
                    AND completion_order > 0)
                 )
             ) STRICT";

const SCHEMA_TABLES: [(&str, &str); 5] = [
    ("store_meta", STORE_META_TABLE_SQL),
    ("process_instance", PROCESS_INSTANCE_TABLE_SQL),
    ("ownership_unit", OWNERSHIP_UNIT_TABLE_SQL),
    ("ownership_handoff", OWNERSHIP_HANDOFF_TABLE_SQL),
    ("rpc_exchange", RPC_EXCHANGE_TABLE_SQL),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreBinding {
    pub cohort: CohortId,
    pub boot: BootId,
    pub runtime_session: RuntimeSessionId,
}

impl StoreBinding {
    fn validate(self) -> Result<(), OwnershipServiceError> {
        self.cohort.validate().map_err(|_| OwnershipServiceError::InvalidRequest)?;
        self.boot.validate().map_err(|_| OwnershipServiceError::InvalidRequest)?;
        self.runtime_session.validate().map_err(|_| OwnershipServiceError::InvalidRequest)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnershipServiceIdentity {
    pub service_incarnation: ServiceIncarnation,
    pub issuer: IssuerId,
    pub key_id: IssuerKeyId,
    pub log_namespace: IssuerLogId,
}

impl OwnershipServiceIdentity {
    fn validate(self) -> Result<(), OwnershipServiceError> {
        self.service_incarnation.validate().map_err(|_| OwnershipServiceError::InvalidRequest)?;
        self.issuer.validate().map_err(|_| OwnershipServiceError::InvalidRequest)?;
        self.key_id.validate().map_err(|_| OwnershipServiceError::InvalidRequest)?;
        self.log_namespace.validate().map_err(|_| OwnershipServiceError::InvalidRequest)
    }

    fn issuer_namespace(self) -> ReceiptIssuerIdentity {
        ReceiptIssuerIdentity {
            issuer: Identity::from_bytes(self.issuer.0),
            issuer_incarnation: Identity::from_bytes(self.service_incarnation.0),
            key_id: Identity::from_bytes(self.key_id.0),
            log_id: Identity::from_bytes(self.log_namespace.0),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreLimits {
    pub max_exchanges: u64,
    pub max_exchange_bytes: u64,
    pub max_database_bytes: u64,
}

impl StoreLimits {
    pub const fn development_default() -> Self {
        Self {
            max_exchanges: 65_536,
            max_exchange_bytes: 256 * 1024 * 1024,
            max_database_bytes: 512 * 1024 * 1024,
        }
    }

    fn validate(self) -> Result<(), OwnershipServiceError> {
        if self.max_exchanges == 0
            || self.max_exchange_bytes < 2 * visa_local_rpc::MAX_INNER_REQUEST_BYTES as u64
            || self.max_database_bytes < 1024 * 1024
            || !self.max_database_bytes.is_multiple_of(SQLITE_PAGE_SIZE)
            || self.max_exchanges > i64::MAX as u64
            || self.max_exchange_bytes > i64::MAX as u64
            || self.max_database_bytes > i64::MAX as u64
        {
            Err(OwnershipServiceError::InvalidRequest)
        } else {
            Ok(())
        }
    }

    fn max_page_count(self) -> i64 {
        (self.max_database_bytes / SQLITE_PAGE_SIZE) as i64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreBootstrap {
    pub binding: StoreBinding,
    pub create_identity: Option<OwnershipServiceIdentity>,
    pub process_nonce: ProcessNonce,
    pub limits: StoreLimits,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurabilityReport {
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: i64,
    pub trusted_schema: i64,
    pub page_size: i64,
    pub max_page_count: i64,
    pub sqlite_version: String,
    pub sqlite_source_id: String,
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

pub struct AuthorityStore {
    connection: Connection,
    _database_guard: DatabaseGuard,
    _lock: StoreLock,
    authenticator: PinnedLocalReceiptAuthenticator,
    binding: StoreBinding,
    identity: OwnershipServiceIdentity,
    server_binding: AuthorityServiceBinding,
    caller_cursors: AgentCallerCursors,
    limits: StoreLimits,
}

impl AuthorityStore {
    pub fn open(
        database_path: impl AsRef<Path>,
        bootstrap: StoreBootstrap,
        authenticator: PinnedLocalReceiptAuthenticator,
    ) -> Result<Self, OwnershipServiceError> {
        bootstrap.binding.validate()?;
        bootstrap.limits.validate()?;
        bootstrap.process_nonce.validate().map_err(|_| OwnershipServiceError::InvalidRequest)?;
        if let Some(identity) = bootstrap.create_identity {
            identity.validate()?;
            if authenticator.ownership_namespace() != identity.issuer_namespace() {
                return Err(OwnershipServiceError::StoreMismatch);
            }
        }

        let database_path = database_path.as_ref();
        ensure_private_parent(database_path)?;
        let lock = acquire_process_lock(&lock_path(database_path))?;
        let create_new = bootstrap.create_identity.is_some();
        if create_new {
            initialize_and_publish_database(database_path, bootstrap, &authenticator)?;
        }
        let database_guard = open_database_guard(database_path, false)?;
        let connection = Connection::open_with_flags(
            database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
        configure_session(&connection)?;
        audit_schema(&connection)?;
        let meta = load_meta(&connection)?;
        if meta.binding != bootstrap.binding
            || meta.limits != bootstrap.limits
            || meta.receipt_policy_digest != authenticator.policy_digest()
            || authenticator.ownership_namespace() != meta.identity.issuer_namespace()
            || bootstrap.create_identity.is_some_and(|identity| identity != meta.identity)
        {
            return Err(OwnershipServiceError::StoreMismatch);
        }
        verify_storage_mode(&connection)?;
        state::audit_authority_state(&connection, meta.identity.issuer_namespace())?;
        let process_instances =
            audit_process_instances(&connection, meta.process_generation, meta.last_process_nonce)?;
        let caller_cursors = audit_rpc_exchanges(
            &connection,
            meta.binding,
            meta.identity,
            &process_instances,
            meta.limits,
        )?;
        state::audit_replay_projection(
            &connection,
            meta.identity.issuer_namespace(),
            &authenticator,
        )?;
        set_max_page_count(&connection, meta.limits)?;
        let process_generation = advance_process_generation(&connection, bootstrap.process_nonce)?;
        let server_binding = AuthorityServiceBinding {
            product_version: PRODUCT_VERSION,
            cohort: meta.binding.cohort,
            boot: meta.binding.boot,
            runtime_session: meta.binding.runtime_session,
            role: AuthorityRole::Ownership,
            service_incarnation: meta.identity.service_incarnation,
            process_nonce: bootstrap.process_nonce,
            process_generation,
        };
        server_binding.validate().map_err(|_| OwnershipServiceError::Integrity)?;
        database_guard.verify_sqlite_header().map_err(map_durable_error)?;
        sync_durable_file(database_guard.file()).map_err(map_durable_error)?;
        sync_parent_directory(database_path)?;
        Ok(Self {
            connection,
            _database_guard: database_guard,
            _lock: lock,
            authenticator,
            binding: meta.binding,
            identity: meta.identity,
            server_binding,
            caller_cursors,
            limits: meta.limits,
        })
    }

    pub const fn binding(&self) -> StoreBinding {
        self.binding
    }

    pub const fn identity(&self) -> OwnershipServiceIdentity {
        self.identity
    }

    pub const fn server_binding(&self) -> AuthorityServiceBinding {
        self.server_binding
    }

    pub fn execute_exact(
        &mut self,
        admitted_caller: AgentBinding,
        exact_request_bytes: &[u8],
    ) -> Result<Vec<u8>, OwnershipServiceError> {
        admitted_caller.validate().map_err(|_| OwnershipServiceError::InvalidRequest)?;
        let request = wire::decode_request(exact_request_bytes)
            .map_err(|_| OwnershipServiceError::InvalidRequest)?;
        if request.caller != admitted_caller
            || request.caller.cohort != self.binding.cohort
            || request.caller.boot != self.binding.boot
            || request.caller.runtime_session != self.binding.runtime_session
        {
            return Err(OwnershipServiceError::InvalidRequest);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_transaction_error)?;
        let next_cursors = self
            .caller_cursors
            .transition(request.caller)
            .ok_or(OwnershipServiceError::CallerBindingConflict)?;
        match begin_or_replay(&transaction, &request, exact_request_bytes, self.limits)? {
            ExchangeAdmission::ExactReplay(response_bytes) => {
                transaction.commit().map_err(map_sqlite_error)?;
                Ok(response_bytes)
            }
            ExchangeAdmission::RequestIdConflict => Err(OwnershipServiceError::RequestIdConflict),
            ExchangeAdmission::New(exchange) => {
                let outcome = state::apply_operation(
                    &transaction,
                    &request,
                    self.identity.issuer_namespace(),
                    &self.authenticator,
                )?;
                let response = wire::Response::new(&request, self.server_binding, outcome)
                    .map_err(|_| OwnershipServiceError::Integrity)?;
                let response_bytes = wire::encode_response_for(&request, &response)
                    .map_err(|_| OwnershipServiceError::Integrity)?;
                let replay = wire::ReplayRecord::from_exchange(&request, &response)
                    .map_err(|_| OwnershipServiceError::Integrity)?;
                replay.validate().map_err(|_| OwnershipServiceError::Integrity)?;
                record_terminal(&transaction, exchange, &response, &response_bytes, self.limits)?;
                transaction.commit().map_err(map_sqlite_error)?;
                self.caller_cursors = next_cursors;
                Ok(response_bytes)
            }
        }
    }

    pub fn durability_report(&self) -> Result<DurabilityReport, OwnershipServiceError> {
        Ok(DurabilityReport {
            journal_mode: pragma_string(&self.connection, "journal_mode")?,
            synchronous: pragma_i64(&self.connection, "synchronous")?,
            foreign_keys: pragma_i64(&self.connection, "foreign_keys")?,
            trusted_schema: pragma_i64(&self.connection, "trusted_schema")?,
            page_size: pragma_i64(&self.connection, "page_size")?,
            max_page_count: pragma_i64(&self.connection, "max_page_count")?,
            sqlite_version: self
                .connection
                .query_row("SELECT sqlite_version()", [], |row| row.get(0))
                .map_err(|_| OwnershipServiceError::Storage)?,
            sqlite_source_id: self
                .connection
                .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
                .map_err(|_| OwnershipServiceError::Storage)?,
        })
    }
}

struct NewExchange {
    exchange_no: i64,
}

enum ExchangeAdmission {
    New(NewExchange),
    ExactReplay(Vec<u8>),
    RequestIdConflict,
}

fn begin_or_replay(
    transaction: &Transaction<'_>,
    request: &wire::Request,
    request_bytes: &[u8],
    limits: StoreLimits,
) -> Result<ExchangeAdmission, OwnershipServiceError> {
    let existing = transaction
        .query_row(
            "SELECT exchange_no, request_digest, request_bytes, rpc_phase,
                    response_digest, response_bytes, completion_order
             FROM rpc_exchange WHERE family_id = ?1 AND request_id = ?2",
            params![wire::FAMILY_ID.as_slice(), request.request_id.0.as_slice()],
            |row| {
                Ok(ExistingExchange {
                    exchange_no: row.get(0)?,
                    request_digest: row.get(1)?,
                    request_bytes: row.get(2)?,
                    phase: row.get(3)?,
                    response_digest: row.get(4)?,
                    response_bytes: row.get(5)?,
                    completion_order: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?;
    if let Some(existing) = existing {
        validate_existing_exchange(request.request_id, &existing)?;
        if existing.request_bytes != request_bytes {
            return Ok(ExchangeAdmission::RequestIdConflict);
        }
        let response_bytes = existing.response_bytes.ok_or(OwnershipServiceError::Integrity)?;
        wire::decode_response_for(request, &response_bytes)
            .map_err(|_| OwnershipServiceError::Integrity)?;
        return Ok(ExchangeAdmission::ExactReplay(response_bytes));
    }

    let (count, retained_bytes): (i64, i64) = transaction
        .query_row(
            "SELECT count(*), coalesce(sum(length(request_bytes) +
                    coalesce(length(response_bytes), 0)), 0) FROM rpc_exchange",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(map_sqlite_error)?;
    if count < 0
        || retained_bytes < 0
        || count as u64 >= limits.max_exchanges
        || (retained_bytes as u64)
            .checked_add(request_bytes.len() as u64)
            .is_none_or(|bytes| bytes > limits.max_exchange_bytes)
    {
        return Err(OwnershipServiceError::Capacity);
    }
    let request_digest = request.digest().map_err(|_| OwnershipServiceError::Integrity)?;
    transaction
        .execute(
            "INSERT INTO rpc_exchange(
                 family_id, request_id, request_digest, request_bytes, rpc_phase
             ) VALUES (?1, ?2, ?3, ?4, 0)",
            params![
                wire::FAMILY_ID.as_slice(),
                request.request_id.0.as_slice(),
                request_digest.0.as_slice(),
                request_bytes,
            ],
        )
        .map_err(map_exchange_insert_error)?;
    Ok(ExchangeAdmission::New(NewExchange { exchange_no: transaction.last_insert_rowid() }))
}

fn record_terminal(
    transaction: &Transaction<'_>,
    exchange: NewExchange,
    response: &wire::Response,
    response_bytes: &[u8],
    limits: StoreLimits,
) -> Result<(), OwnershipServiceError> {
    let retained_bytes: i64 = transaction
        .query_row(
            "SELECT coalesce(sum(length(request_bytes) +
                    coalesce(length(response_bytes), 0)), 0) FROM rpc_exchange",
            [],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)?;
    if retained_bytes < 0
        || (retained_bytes as u64)
            .checked_add(response_bytes.len() as u64)
            .is_none_or(|bytes| bytes > limits.max_exchange_bytes)
    {
        return Err(OwnershipServiceError::Capacity);
    }
    let response_digest = response.digest().map_err(|_| OwnershipServiceError::Integrity)?;
    let completion_order: i64 = transaction
        .query_row("SELECT coalesce(max(completion_order), 0) + 1 FROM rpc_exchange", [], |row| {
            row.get(0)
        })
        .map_err(map_sqlite_error)?;
    if completion_order <= 0 {
        return Err(OwnershipServiceError::Integrity);
    }
    let changed = transaction
        .execute(
            "UPDATE rpc_exchange
             SET rpc_phase = 1, response_digest = ?2, response_bytes = ?3,
                 completion_order = ?4
             WHERE exchange_no = ?1 AND rpc_phase = 0",
            params![
                exchange.exchange_no,
                response_digest.0.as_slice(),
                response_bytes,
                completion_order,
            ],
        )
        .map_err(map_sqlite_error)?;
    if changed == 1 { Ok(()) } else { Err(OwnershipServiceError::Integrity) }
}

struct ExistingExchange {
    exchange_no: i64,
    request_digest: Vec<u8>,
    request_bytes: Vec<u8>,
    phase: i64,
    response_digest: Option<Vec<u8>>,
    response_bytes: Option<Vec<u8>>,
    completion_order: Option<i64>,
}

fn validate_existing_exchange(
    request_id: visa_local_rpc::common::RequestId,
    exchange: &ExistingExchange,
) -> Result<(), OwnershipServiceError> {
    let stored_request = wire::decode_request(&exchange.request_bytes)
        .map_err(|_| OwnershipServiceError::Integrity)?;
    if exchange.exchange_no <= 0
        || exchange.phase != 1
        || stored_request.request_id != request_id
        || exchange.request_digest.as_slice()
            != stored_request.digest().map_err(|_| OwnershipServiceError::Integrity)?.0
        || exchange.completion_order.is_none_or(|order| order <= 0)
    {
        return Err(OwnershipServiceError::Integrity);
    }
    let response_bytes =
        exchange.response_bytes.as_ref().ok_or(OwnershipServiceError::Integrity)?;
    let response = wire::decode_response_for(&stored_request, response_bytes)
        .map_err(|_| OwnershipServiceError::Integrity)?;
    let digest = response.digest().map_err(|_| OwnershipServiceError::Integrity)?;
    if exchange.response_digest.as_deref() != Some(digest.0.as_slice()) {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(())
}

fn configure_session(connection: &Connection) -> Result<(), OwnershipServiceError> {
    connection.busy_timeout(Duration::from_secs(5)).map_err(|_| OwnershipServiceError::Storage)?;
    connection
        .execute_batch(
            "PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA wal_autocheckpoint = 1000;",
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    if pragma_i64(connection, "synchronous")? != 2
        || pragma_i64(connection, "foreign_keys")? != 1
        || pragma_i64(connection, "trusted_schema")? != 0
    {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(())
}

// Publication deliberately leaves a valid generation-zero store. The caller
// reopens the final path and durably advances generation before it may serve;
// a crash between those steps is therefore recoverable rather than ambiguous.
pub(crate) fn initialize_and_publish_database(
    database_path: &Path,
    bootstrap: StoreBootstrap,
    authenticator: &PinnedLocalReceiptAuthenticator,
) -> Result<(), OwnershipServiceError> {
    ensure_sqlite_sidecars_absent(database_path, OwnershipServiceError::StoreMismatch)?;
    let temporary_path = initialization_path(database_path, bootstrap.process_nonce);
    ensure_sqlite_sidecars_absent(&temporary_path, OwnershipServiceError::StoreMismatch)?;
    let database_guard = open_database_guard(&temporary_path, true)?;
    let result = (|| {
        let mut connection = Connection::open_with_flags(
            &temporary_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
        configure_session(&connection)?;
        initialize_storage_mode(&connection)?;
        initialize_schema(&mut connection, bootstrap, authenticator.policy_digest())?;
        audit_schema(&connection)?;

        let meta = load_meta(&connection)?;
        if meta.binding != bootstrap.binding
            || meta.identity
                != bootstrap.create_identity.ok_or(OwnershipServiceError::StoreMismatch)?
            || meta.limits != bootstrap.limits
            || meta.receipt_policy_digest != authenticator.policy_digest()
        {
            return Err(OwnershipServiceError::Integrity);
        }
        verify_storage_mode(&connection)?;
        state::audit_authority_state(&connection, meta.identity.issuer_namespace())?;
        let process_instances =
            audit_process_instances(&connection, meta.process_generation, meta.last_process_nonce)?;
        audit_rpc_exchanges(
            &connection,
            meta.binding,
            meta.identity,
            &process_instances,
            meta.limits,
        )?;
        state::audit_replay_projection(
            &connection,
            meta.identity.issuer_namespace(),
            authenticator,
        )?;
        set_max_page_count(&connection, meta.limits)?;
        checkpoint_for_publish(&connection)?;
        connection.close().map_err(|_| OwnershipServiceError::Storage)?;

        ensure_sqlite_sidecars_absent(&temporary_path, OwnershipServiceError::Storage)?;
        ensure_sqlite_sidecars_absent(database_path, OwnershipServiceError::StoreMismatch)?;
        database_guard.verify_sqlite_header().map_err(map_durable_error)?;
        publish_durable_noreplace(&temporary_path, database_path, database_guard.file())
            .map_err(map_durable_error)?;
        Ok(())
    })();
    if result.is_err() {
        remove_owned_initialization_files(&temporary_path, &database_guard);
    }
    result
}

fn checkpoint_for_publish(connection: &Connection) -> Result<(), OwnershipServiceError> {
    checkpoint_truncate(connection).map_err(|error| match error {
        DurableStoreError::Busy | DurableStoreError::Integrity => OwnershipServiceError::Storage,
        other => map_durable_error(other),
    })
}

fn ensure_sqlite_sidecars_absent(
    database_path: &Path,
    existing_error: OwnershipServiceError,
) -> Result<(), OwnershipServiceError> {
    match ensure_durable_sidecars_absent(database_path) {
        Ok(()) => Ok(()),
        Err(DurableStoreError::SidecarExists) => Err(existing_error),
        Err(error) => Err(map_durable_error(error)),
    }
}

fn initialize_storage_mode(connection: &Connection) -> Result<(), OwnershipServiceError> {
    connection
        .pragma_update(None, "page_size", SQLITE_PAGE_SIZE as i64)
        .map_err(|_| OwnershipServiceError::Storage)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|_| OwnershipServiceError::Storage)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(OwnershipServiceError::Integrity);
    }
    verify_storage_mode(connection)
}

fn verify_storage_mode(connection: &Connection) -> Result<(), OwnershipServiceError> {
    if !pragma_string(connection, "journal_mode")?.eq_ignore_ascii_case("wal")
        || pragma_i64(connection, "page_size")? != SQLITE_PAGE_SIZE as i64
    {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(())
}

fn initialize_schema(
    connection: &mut Connection,
    bootstrap: StoreBootstrap,
    receipt_policy_digest: Digest,
) -> Result<(), OwnershipServiceError> {
    let identity = bootstrap.create_identity.ok_or(OwnershipServiceError::StoreMismatch)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_transaction_error)?;
    for (_, sql) in SCHEMA_TABLES {
        transaction.execute_batch(sql).map_err(|_| OwnershipServiceError::Storage)?;
    }
    transaction
        .execute(
            "INSERT INTO store_meta(
                 singleton, product_major, product_minor, product_patch,
                 cohort, boot, runtime_session, service_incarnation, issuer,
                 issuer_key_id, issuer_log_namespace, receipt_policy_digest,
                 process_generation, last_process_nonce, max_exchanges,
                 max_exchange_bytes, max_database_bytes
             ) VALUES (1, 0, 1, 0, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11, ?12)",
            params![
                bootstrap.binding.cohort.0.as_slice(),
                bootstrap.binding.boot.0.as_slice(),
                bootstrap.binding.runtime_session.0.as_slice(),
                identity.service_incarnation.0.as_slice(),
                identity.issuer.0.as_slice(),
                identity.key_id.0.as_slice(),
                identity.log_namespace.0.as_slice(),
                receipt_policy_digest.0.as_slice(),
                [0_u8; 16].as_slice(),
                bootstrap.limits.max_exchanges as i64,
                bootstrap.limits.max_exchange_bytes as i64,
                bootstrap.limits.max_database_bytes as i64,
            ],
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|_| OwnershipServiceError::Storage)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| OwnershipServiceError::Storage)?;
    transaction.commit().map_err(|_| OwnershipServiceError::Storage)
}

fn audit_schema(connection: &Connection) -> Result<(), OwnershipServiceError> {
    if pragma_i64(connection, "application_id")? != APPLICATION_ID
        || pragma_i64(connection, "user_version")? != SCHEMA_VERSION
    {
        return Err(OwnershipServiceError::StoreMismatch);
    }
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| OwnershipServiceError::Storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OwnershipServiceError::Storage)?;
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
        return Err(OwnershipServiceError::Integrity);
    }
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| OwnershipServiceError::Storage)?;
    if quick_check != "ok" {
        return Err(OwnershipServiceError::Integrity);
    }
    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| OwnershipServiceError::Storage)?;
    if foreign_key_check
        .query([])
        .map_err(|_| OwnershipServiceError::Storage)?
        .next()
        .map_err(|_| OwnershipServiceError::Storage)?
        .is_some()
    {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct StoreMeta {
    binding: StoreBinding,
    identity: OwnershipServiceIdentity,
    receipt_policy_digest: Digest,
    process_generation: u64,
    last_process_nonce: ProcessNonce,
    limits: StoreLimits,
}

fn load_meta(connection: &Connection) -> Result<StoreMeta, OwnershipServiceError> {
    let row = connection
        .query_row(
            "SELECT product_major, product_minor, product_patch, cohort, boot,
                    runtime_session, service_incarnation, issuer, issuer_key_id,
                    issuer_log_namespace, receipt_policy_digest, process_generation,
                    last_process_nonce, max_exchanges, max_exchange_bytes,
                    max_database_bytes
             FROM store_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                ))
            },
        )
        .map_err(|_| OwnershipServiceError::Integrity)?;
    if (row.0, row.1, row.2) != (0, 1, 0) || row.11 < 0 || [row.13, row.14, row.15].contains(&0) {
        return Err(OwnershipServiceError::Integrity);
    }
    let meta = StoreMeta {
        binding: StoreBinding {
            cohort: CohortId(array16(&row.3)?),
            boot: BootId(array16(&row.4)?),
            runtime_session: RuntimeSessionId(array16(&row.5)?),
        },
        identity: OwnershipServiceIdentity {
            service_incarnation: ServiceIncarnation(array16(&row.6)?),
            issuer: IssuerId(array16(&row.7)?),
            key_id: IssuerKeyId(array16(&row.8)?),
            log_namespace: IssuerLogId(array16(&row.9)?),
        },
        receipt_policy_digest: Digest(array32(&row.10)?),
        process_generation: u64::try_from(row.11).map_err(|_| OwnershipServiceError::Integrity)?,
        last_process_nonce: ProcessNonce(array16(&row.12)?),
        limits: StoreLimits {
            max_exchanges: u64::try_from(row.13).map_err(|_| OwnershipServiceError::Integrity)?,
            max_exchange_bytes: u64::try_from(row.14)
                .map_err(|_| OwnershipServiceError::Integrity)?,
            max_database_bytes: u64::try_from(row.15)
                .map_err(|_| OwnershipServiceError::Integrity)?,
        },
    };
    meta.binding.validate().map_err(|_| OwnershipServiceError::Integrity)?;
    meta.identity.validate().map_err(|_| OwnershipServiceError::Integrity)?;
    if meta.receipt_policy_digest == Digest::ZERO {
        return Err(OwnershipServiceError::Integrity);
    }
    meta.limits.validate().map_err(|_| OwnershipServiceError::Integrity)?;
    Ok(meta)
}

fn advance_process_generation(
    connection: &Connection,
    nonce: ProcessNonce,
) -> Result<u64, OwnershipServiceError> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .map_err(map_transaction_error)?;
    let (generation, previous_nonce): (i64, Vec<u8>) = transaction
        .query_row(
            "SELECT process_generation, last_process_nonce FROM store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    if generation < 0 || previous_nonce.as_slice() == nonce.0 {
        return Err(OwnershipServiceError::StoreMismatch);
    }
    let next = generation.checked_add(1).ok_or(OwnershipServiceError::Integrity)?;
    let last_completion: Option<i64> = transaction
        .query_row("SELECT max(completion_order) FROM rpc_exchange", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    let start_completion_order =
        last_completion.unwrap_or(0).checked_add(1).ok_or(OwnershipServiceError::Integrity)?;
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
            params![next, nonce.0.as_slice(), generation],
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    if changed != 1 {
        return Err(OwnershipServiceError::Integrity);
    }
    transaction.commit().map_err(|_| OwnershipServiceError::Storage)?;
    u64::try_from(next).map_err(|_| OwnershipServiceError::Integrity)
}

#[derive(Clone, Copy)]
struct ProcessInstance {
    generation: u64,
    nonce: ProcessNonce,
    start_completion_order: i64,
}

fn audit_process_instances(
    connection: &Connection,
    process_generation: u64,
    last_process_nonce: ProcessNonce,
) -> Result<Vec<ProcessInstance>, OwnershipServiceError> {
    let mut statement = connection
        .prepare(
            "SELECT process_generation, process_nonce, start_completion_order
             FROM process_instance ORDER BY process_generation",
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?))
        })
        .map_err(|_| OwnershipServiceError::Storage)?;
    let mut instances = Vec::new();
    let mut expected_generation = 1_u64;
    let mut previous_start = 0_i64;
    for row in rows {
        let (generation, nonce, start_completion_order) =
            row.map_err(|_| OwnershipServiceError::Storage)?;
        let generation = u64::try_from(generation).map_err(|_| OwnershipServiceError::Integrity)?;
        let nonce = ProcessNonce(array16(&nonce)?);
        nonce.validate().map_err(|_| OwnershipServiceError::Integrity)?;
        if generation != expected_generation
            || start_completion_order <= 0
            || start_completion_order < previous_start
            || (generation == 1 && start_completion_order != 1)
        {
            return Err(OwnershipServiceError::Integrity);
        }
        instances.push(ProcessInstance { generation, nonce, start_completion_order });
        expected_generation =
            expected_generation.checked_add(1).ok_or(OwnershipServiceError::Integrity)?;
        previous_start = start_completion_order;
    }
    if instances.len() as u64 != process_generation {
        return Err(OwnershipServiceError::Integrity);
    }
    match instances.last() {
        Some(instance) if instance.nonce == last_process_nonce => {}
        None if last_process_nonce == ProcessNonce([0; 16]) => {}
        _ => return Err(OwnershipServiceError::Integrity),
    }
    let max_completion: Option<i64> = connection
        .query_row("SELECT max(completion_order) FROM rpc_exchange", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    let next_completion =
        max_completion.unwrap_or(0).checked_add(1).ok_or(OwnershipServiceError::Integrity)?;
    if instances.last().is_some_and(|instance| instance.start_completion_order > next_completion) {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(instances)
}

fn audit_rpc_exchanges(
    connection: &Connection,
    binding: StoreBinding,
    identity: OwnershipServiceIdentity,
    process_instances: &[ProcessInstance],
    limits: StoreLimits,
) -> Result<AgentCallerCursors, OwnershipServiceError> {
    let mut statement = connection
        .prepare(
            "SELECT exchange_no, family_id, request_id, request_digest, request_bytes,
                    rpc_phase, response_digest, response_bytes, completion_order
             FROM rpc_exchange ORDER BY exchange_no",
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, Option<i64>>(8)?,
            ))
        })
        .map_err(|_| OwnershipServiceError::Storage)?;
    let mut count = 0_u64;
    let mut retained = 0_u64;
    let mut previous_completion = 0_i64;
    let mut previous_process_generation = 0_u64;
    let mut process_index = 0_usize;
    let mut caller_cursors = AgentCallerCursors::default();
    for row in rows {
        let row = row.map_err(|_| OwnershipServiceError::Storage)?;
        let request = wire::decode_request(&row.4).map_err(|_| OwnershipServiceError::Integrity)?;
        if row.0 <= 0
            || row.1.as_slice() != wire::FAMILY_ID
            || row.2.as_slice() != request.request_id.0
            || row.3.as_slice() != request.digest().map_err(|_| OwnershipServiceError::Integrity)?.0
            || row.5 != 1
            || request.caller.cohort != binding.cohort
            || request.caller.boot != binding.boot
            || request.caller.runtime_session != binding.runtime_session
        {
            return Err(OwnershipServiceError::Integrity);
        }
        caller_cursors =
            caller_cursors.transition(request.caller).ok_or(OwnershipServiceError::Integrity)?;
        let response_bytes = row.7.ok_or(OwnershipServiceError::Integrity)?;
        let response = wire::decode_response_for(&request, &response_bytes)
            .map_err(|_| OwnershipServiceError::Integrity)?;
        let completion = row.8.ok_or(OwnershipServiceError::Integrity)?;
        while process_index + 1 < process_instances.len()
            && process_instances[process_index + 1].start_completion_order <= completion
        {
            process_index += 1;
        }
        let process = process_instances
            .get(process_index)
            .filter(|process| process.start_completion_order <= completion)
            .ok_or(OwnershipServiceError::Integrity)?;
        let expected_server = AuthorityServiceBinding {
            product_version: PRODUCT_VERSION,
            cohort: binding.cohort,
            boot: binding.boot,
            runtime_session: binding.runtime_session,
            role: AuthorityRole::Ownership,
            service_incarnation: identity.service_incarnation,
            process_nonce: process.nonce,
            process_generation: process.generation,
        };
        if response.server != expected_server
            || response.server.process_generation < previous_process_generation
            || row.6.as_deref()
                != Some(
                    response.digest().map_err(|_| OwnershipServiceError::Integrity)?.0.as_slice(),
                )
        {
            return Err(OwnershipServiceError::Integrity);
        }
        previous_process_generation = response.server.process_generation;
        if previous_completion.checked_add(1) != Some(completion) {
            return Err(OwnershipServiceError::Integrity);
        }
        previous_completion = completion;
        count = count.checked_add(1).ok_or(OwnershipServiceError::Integrity)?;
        retained = retained
            .checked_add(row.4.len() as u64)
            .and_then(|bytes| bytes.checked_add(response_bytes.len() as u64))
            .ok_or(OwnershipServiceError::Integrity)?;
    }
    if count > limits.max_exchanges || retained > limits.max_exchange_bytes {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(caller_cursors)
}

fn set_max_page_count(
    connection: &Connection,
    limits: StoreLimits,
) -> Result<(), OwnershipServiceError> {
    connection
        .pragma_update(None, "max_page_count", limits.max_page_count())
        .map_err(|_| OwnershipServiceError::Storage)?;
    if pragma_i64(connection, "max_page_count")? != limits.max_page_count() {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(())
}

fn ensure_private_parent(database_path: &Path) -> Result<(), OwnershipServiceError> {
    ensure_durable_private_parent(database_path).map_err(map_durable_error)
}

fn acquire_process_lock(path: &Path) -> Result<StoreLock, OwnershipServiceError> {
    StoreLock::acquire(path).map_err(map_durable_error)
}

fn open_database_guard(
    path: &Path,
    create_new: bool,
) -> Result<DatabaseGuard, OwnershipServiceError> {
    if create_new { DatabaseGuard::create_new(path) } else { DatabaseGuard::open_existing(path) }
        .map_err(map_durable_error)
}

fn sync_parent_directory(database_path: &Path) -> Result<(), OwnershipServiceError> {
    sync_durable_parent(database_path).map_err(map_durable_error)
}

pub(crate) fn initialization_path(database_path: &Path, process_nonce: ProcessNonce) -> PathBuf {
    durable_initialization_path(database_path, process_nonce.0)
}

#[cfg(test)]
pub(crate) fn sqlite_sidecar_path(database_path: &Path, suffix: &str) -> PathBuf {
    visa_durable_sqlite::sqlite_sidecar_path(database_path, suffix)
}

fn remove_owned_initialization_files(temporary_path: &Path, database_guard: &DatabaseGuard) {
    cleanup_owned_initialization_files(temporary_path, database_guard.file())
}

fn lock_path(database_path: &Path) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn map_durable_error(error: DurableStoreError) -> OwnershipServiceError {
    match error {
        DurableStoreError::InvalidPath => OwnershipServiceError::InvalidRequest,
        DurableStoreError::Busy => OwnershipServiceError::StoreBusy,
        DurableStoreError::AlreadyExists
        | DurableStoreError::Missing
        | DurableStoreError::Insecure
        | DurableStoreError::NotSqlite
        | DurableStoreError::SidecarExists => OwnershipServiceError::StoreMismatch,
        DurableStoreError::Io(_) | DurableStoreError::Sqlite(_) => OwnershipServiceError::Storage,
        DurableStoreError::Integrity => OwnershipServiceError::Integrity,
    }
}

fn map_transaction_error(error: rusqlite::Error) -> OwnershipServiceError {
    map_sqlite_error(error)
}

fn map_sqlite_error(error: rusqlite::Error) -> OwnershipServiceError {
    match classify_sqlite_error(&error) {
        SqliteFailureClass::Busy => OwnershipServiceError::StoreBusy,
        SqliteFailureClass::Unique | SqliteFailureClass::Integrity => {
            OwnershipServiceError::Integrity
        }
        SqliteFailureClass::Other => OwnershipServiceError::Storage,
    }
}

fn map_exchange_insert_error(error: rusqlite::Error) -> OwnershipServiceError {
    match classify_sqlite_error(&error) {
        SqliteFailureClass::Busy => OwnershipServiceError::StoreBusy,
        SqliteFailureClass::Unique => OwnershipServiceError::RequestIdConflict,
        SqliteFailureClass::Integrity => OwnershipServiceError::Integrity,
        SqliteFailureClass::Other => OwnershipServiceError::Storage,
    }
}

fn map_process_insert_error(error: rusqlite::Error) -> OwnershipServiceError {
    match classify_sqlite_error(&error) {
        SqliteFailureClass::Busy => OwnershipServiceError::StoreBusy,
        SqliteFailureClass::Unique => OwnershipServiceError::StoreMismatch,
        SqliteFailureClass::Integrity => OwnershipServiceError::Integrity,
        SqliteFailureClass::Other => OwnershipServiceError::Storage,
    }
}

fn pragma_i64(connection: &Connection, name: &str) -> Result<i64, OwnershipServiceError> {
    connection.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0)).map_err(map_sqlite_error)
}

fn pragma_string(connection: &Connection, name: &str) -> Result<String, OwnershipServiceError> {
    connection.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0)).map_err(map_sqlite_error)
}

fn array16(bytes: &[u8]) -> Result<[u8; 16], OwnershipServiceError> {
    bytes.try_into().map_err(|_| OwnershipServiceError::Integrity)
}

fn array32(bytes: &[u8]) -> Result<[u8; 32], OwnershipServiceError> {
    bytes.try_into().map_err(|_| OwnershipServiceError::Integrity)
}
