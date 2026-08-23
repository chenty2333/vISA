//! The one reference resource provider: a durable key/value value.

use std::fmt;

use rusqlite::{OptionalExtension, params};
use visa_core::Rights;

use crate::authority::{Authority, BindingId, BindingRole, BindingView, SourceBinding};
use crate::db::{
    ReferenceDatabase, ReferenceDatabaseError, sqlite_bool, sqlite_to_u64, u64_to_sqlite,
};

const KV_READ: Rights = Rights(1 << 0);
const KV_WRITE: Rights = Rights(1 << 1);

#[derive(Debug)]
pub enum ProviderError {
    Database(ReferenceDatabaseError),
    BindingNotFound(BindingId),
    Inactive(BindingId),
    Fenced(BindingId),
    DispatchClosed(BindingId),
    StaleGeneration { expected: u64, actual: u64 },
    StaleEpoch { expected: u64, actual: u64 },
    RightsDenied,
    CompareAndSwapMismatch { expected: Option<u64>, actual: Option<u64> },
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "provider database error: {error}"),
            Self::BindingNotFound(id) => write!(formatter, "binding not found: {id}"),
            Self::Inactive(id) => write!(formatter, "inactive binding: {id}"),
            Self::Fenced(id) => write!(formatter, "fenced binding: {id}"),
            Self::DispatchClosed(id) => write!(formatter, "provider dispatch is closed: {id}"),
            Self::StaleGeneration { expected, actual } => {
                write!(
                    formatter,
                    "stale provider generation {expected}, durable generation is {actual}"
                )
            }
            Self::StaleEpoch { expected, actual } => {
                write!(formatter, "stale execution epoch {expected}, durable epoch is {actual}")
            }
            Self::RightsDenied => formatter.write_str("binding lacks required provider rights"),
            Self::CompareAndSwapMismatch { expected, actual } => {
                write!(formatter, "CAS expected revision {expected:?}, actual {actual:?}")
            }
        }
    }
}

impl std::error::Error for ProviderError {}

impl From<ReferenceDatabaseError> for ProviderError {
    fn from(value: ReferenceDatabaseError) -> Self {
        Self::Database(value)
    }
}

impl From<rusqlite::Error> for ProviderError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value.into())
    }
}

#[derive(Clone, Debug)]
pub struct DurableKvProvider {
    database: ReferenceDatabase,
}

impl DurableKvProvider {
    pub fn new(database: ReferenceDatabase) -> Self {
        Self { database }
    }

    pub fn database(&self) -> ReferenceDatabase {
        self.database.clone()
    }

    pub fn bind_bootstrap_source(
        &self,
        authority: &Authority,
        source: &SourceBinding,
    ) -> Result<BindingHandle, ProviderError> {
        let view = authority
            .binding(&source.binding_id)
            .map_err(|error| {
                ProviderError::Database(match error {
                    crate::authority::AuthorityError::Database(error) => error,
                    other => ReferenceDatabaseError::Invalid(other.to_string()),
                })
            })?
            .ok_or_else(|| ProviderError::BindingNotFound(source.binding_id.clone()))?;
        if view.role != BindingRole::Source {
            return Err(ProviderError::Inactive(source.binding_id.clone()));
        }
        Self::handle(self.database.clone(), view)
    }

    pub(crate) fn bind_destination(
        &self,
        authority: &Authority,
        operation: &[u8; 16],
    ) -> Result<BindingHandle, ProviderError> {
        let view = authority.destination_binding(operation).map_err(|error| {
            ProviderError::Database(match error {
                crate::authority::AuthorityError::Database(error) => error,
                other => ReferenceDatabaseError::Invalid(other.to_string()),
            })
        })?;
        Self::handle(self.database.clone(), view)
    }

    fn handle(
        database: ReferenceDatabase,
        view: BindingView,
    ) -> Result<BindingHandle, ProviderError> {
        if !view.active {
            return Err(ProviderError::Inactive(view.binding_id));
        }
        if view.fenced {
            return Err(ProviderError::Fenced(view.binding_id));
        }
        Ok(BindingHandle {
            database,
            binding_id: view.binding_id,
            generation: view.generation,
            epoch: view.execution_epoch,
            rights: view.rights,
        })
    }

    pub fn get_for_handle(
        &self,
        handle: &BindingHandle,
        key: &[u8],
    ) -> Result<Option<KvEntry>, ProviderError> {
        handle.get(key)
    }

    pub fn cas_for_handle(
        &self,
        handle: &BindingHandle,
        key: &[u8],
        expected_revision: Option<u64>,
        value: &[u8],
    ) -> Result<KvEntry, ProviderError> {
        handle.cas(key, expected_revision, value)
    }

    pub(crate) fn ensure_live(&self, handle: &BindingHandle) -> Result<(), ProviderError> {
        handle.validate(Rights(0))
    }

    pub(crate) fn capture_and_close(
        &self,
        handle: &BindingHandle,
        key: &[u8],
    ) -> Result<Option<KvEntry>, ProviderError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        validate(&transaction, handle, KV_READ)?;
        let entry = entry(&transaction, key)?;
        let changed = transaction.execute(
            "UPDATE visa_authority_bindings SET dispatch_open = 0
             WHERE binding_id = ?1 AND generation = ?2 AND epoch = ?3
               AND active = 1 AND fenced = 0 AND dispatch_open = 1",
            params![
                handle.binding_id,
                u64_to_sqlite(handle.generation, "binding generation")?,
                u64_to_sqlite(handle.epoch, "execution epoch")?,
            ],
        )?;
        if changed != 1 {
            return Err(ProviderError::DispatchClosed(handle.binding_id.clone()));
        }
        transaction.commit()?;
        Ok(entry)
    }
}

/// Opaque host-local binding. It deliberately carries no serializable or
/// authority-bearing token and is revalidated on every provider call.
pub struct BindingHandle {
    database: ReferenceDatabase,
    binding_id: BindingId,
    generation: u64,
    epoch: u64,
    rights: Rights,
}

impl fmt::Debug for BindingHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindingHandle")
            .field("binding_id", &self.binding_id)
            .field("generation", &self.generation)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl BindingHandle {
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    pub fn execution_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<KvEntry>, ProviderError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        validate(&transaction, self, KV_READ)?;
        let entry = entry(&transaction, key)?;
        transaction.commit()?;
        Ok(entry)
    }

    pub fn cas(
        &self,
        key: &[u8],
        expected_revision: Option<u64>,
        value: &[u8],
    ) -> Result<KvEntry, ProviderError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        validate(&transaction, self, KV_WRITE)?;
        let current = entry(&transaction, key)?;
        let actual = current.as_ref().map(|entry| entry.revision);
        if actual != expected_revision {
            return Err(ProviderError::CompareAndSwapMismatch {
                expected: expected_revision,
                actual,
            });
        }
        let revision = actual.unwrap_or(0).checked_add(1).ok_or_else(|| {
            ProviderError::Database(ReferenceDatabaseError::Invalid(
                "provider revision overflow".into(),
            ))
        })?;
        transaction.execute(
            "INSERT INTO visa_provider_kv (key, value, revision) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, revision = excluded.revision",
            params![key, value, u64_to_sqlite(revision, "provider revision")?],
        )?;
        transaction.commit()?;
        Ok(KvEntry { value: value.to_vec(), revision })
    }

    fn validate(&self, rights: Rights) -> Result<(), ProviderError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        validate(&transaction, self, rights)?;
        transaction.commit()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvEntry {
    pub value: Vec<u8>,
    pub revision: u64,
}

fn validate(
    transaction: &rusqlite::Transaction<'_>,
    handle: &BindingHandle,
    required: Rights,
) -> Result<(), ProviderError> {
    let row = transaction
        .query_row(
            "SELECT generation, epoch, rights, active, fenced, dispatch_open
             FROM visa_authority_bindings WHERE binding_id = ?1",
            params![handle.binding_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((generation, epoch, rights, active, fenced, dispatch_open)) = row else {
        return Err(ProviderError::BindingNotFound(handle.binding_id.clone()));
    };
    let generation = sqlite_to_u64(generation, "binding generation")?;
    let epoch = sqlite_to_u64(epoch, "execution epoch")?;
    let rights = Rights(sqlite_to_u64(rights, "binding rights")?);
    if generation != handle.generation {
        return Err(ProviderError::StaleGeneration {
            expected: handle.generation,
            actual: generation,
        });
    }
    if epoch != handle.epoch {
        return Err(ProviderError::StaleEpoch { expected: handle.epoch, actual: epoch });
    }
    if sqlite_bool(fenced, "binding fenced")? {
        return Err(ProviderError::Fenced(handle.binding_id.clone()));
    }
    if !sqlite_bool(active, "binding active")? {
        return Err(ProviderError::Inactive(handle.binding_id.clone()));
    }
    if !sqlite_bool(dispatch_open, "binding dispatch")? {
        return Err(ProviderError::DispatchClosed(handle.binding_id.clone()));
    }
    if !rights.contains(required) {
        return Err(ProviderError::RightsDenied);
    }
    Ok(())
}

fn entry(
    transaction: &rusqlite::Transaction<'_>,
    key: &[u8],
) -> Result<Option<KvEntry>, ProviderError> {
    transaction
        .query_row(
            "SELECT value, revision FROM visa_provider_kv WHERE key = ?1",
            params![key],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .map(|(value, revision)| {
            Ok(KvEntry { value, revision: sqlite_to_u64(revision, "provider revision")? })
        })
        .transpose()
}
