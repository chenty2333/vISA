//! Durable provider state bound to authority-issued, host-local handles.

use std::fmt;

use rusqlite::{OptionalExtension, params};

use crate::authority::{Authority, AuthorityError, BindingId, Rights};
use crate::db::{
    ReferenceDatabase, ReferenceDatabaseError, sqlite_bool, sqlite_to_u64, u64_to_sqlite,
};

#[derive(Debug)]
pub enum ProviderError {
    Database(ReferenceDatabaseError),
    Authority(AuthorityError),
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
            Self::Authority(error) => write!(formatter, "provider authority error: {error}"),
            Self::BindingNotFound(id) => write!(formatter, "binding {id} not found"),
            Self::Inactive(id) => write!(formatter, "binding {id} is not active"),
            Self::Fenced(id) => write!(formatter, "binding {id} is fenced"),
            Self::DispatchClosed(id) => write!(formatter, "binding {id} dispatch is closed"),
            Self::StaleGeneration { expected, actual } => {
                write!(formatter, "provider generation {expected} is stale (actual {actual})")
            }
            Self::StaleEpoch { expected, actual } => {
                write!(formatter, "execution epoch {expected} is stale (actual {actual})")
            }
            Self::RightsDenied => formatter.write_str("provider binding lacks the requested right"),
            Self::CompareAndSwapMismatch { expected, actual } => {
                write!(formatter, "CAS expected {expected:?}, actual {actual:?}")
            }
        }
    }
}

impl std::error::Error for ProviderError {}
impl From<ReferenceDatabaseError> for ProviderError {
    fn from(error: ReferenceDatabaseError) -> Self {
        Self::Database(error)
    }
}
impl From<AuthorityError> for ProviderError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}
impl From<rusqlite::Error> for ProviderError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(ReferenceDatabaseError::Sqlite(error))
    }
}

/// A durable key/value provider. Values are independent of binding identity;
/// a fresh destination handle therefore observes the same values after commit.
#[derive(Clone)]
pub struct DurableKvProvider {
    database: ReferenceDatabase,
}

impl fmt::Debug for DurableKvProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("DurableKvProvider").finish_non_exhaustive()
    }
}

impl DurableKvProvider {
    pub fn new(database: ReferenceDatabase) -> Self {
        Self { database }
    }

    pub fn database(&self) -> ReferenceDatabase {
        self.database.clone()
    }

    /// Open the initial host-owned source. Destination handles remain an
    /// internal runtime concern and cannot be minted by crate consumers.
    pub fn bind_bootstrap_source(
        &self,
        authority: &Authority,
        binding_id: &str,
    ) -> Result<BindingHandle, ProviderError> {
        let view = authority
            .binding(binding_id)?
            .ok_or_else(|| ProviderError::BindingNotFound(binding_id.to_owned()))?;
        if view.role != crate::authority::BindingRole::Source {
            return Err(ProviderError::Inactive(binding_id.to_owned()));
        }
        self.bind(authority, binding_id)
    }

    /// Mint a host-local handle for the reference runtime adapter.
    pub(crate) fn bind(
        &self,
        authority: &Authority,
        binding_id: &str,
    ) -> Result<BindingHandle, ProviderError> {
        let view = authority
            .binding(binding_id)?
            .ok_or_else(|| ProviderError::BindingNotFound(binding_id.to_owned()))?;
        if view.fenced {
            return Err(ProviderError::Fenced(binding_id.to_owned()));
        }
        if !view.active {
            return Err(ProviderError::Inactive(binding_id.to_owned()));
        }
        Ok(BindingHandle {
            database: self.database.clone(),
            binding_id: view.binding_id,
            owner: view.owner,
            provider_generation: view.provider_generation,
            execution_epoch: view.execution_epoch,
            rights: view.rights,
        })
    }

    /// The binding check is intentionally performed by every operation. A
    /// commit can fence a previously returned handle without touching it.
    fn validate<'a>(
        transaction: &'a rusqlite::Transaction<'a>,
        handle: &BindingHandle,
        required: Rights,
    ) -> Result<(), ProviderError> {
        let row = transaction
            .query_row(
                "SELECT b.provider_generation, b.execution_epoch, b.rights, b.active, b.fenced,
                        b.dispatch_open, b.role,
                        (SELECT p.status FROM visa_authority_activation_permits p
                         WHERE p.destination_binding_id = b.binding_id
                           AND p.execution_epoch = b.execution_epoch)
                 FROM visa_authority_bindings b WHERE b.binding_id = ?1",
                params![handle.binding_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((generation, epoch, rights, active, fenced, dispatch_open, role, activation)) =
            row
        else {
            return Err(ProviderError::BindingNotFound(handle.binding_id.clone()));
        };
        let generation = sqlite_to_u64(generation, "provider_generation")?;
        let epoch = sqlite_to_u64(epoch, "execution_epoch")?;
        let rights = sqlite_to_u64(rights, "rights")?;
        let active = sqlite_bool(active, "active")?;
        let fenced = sqlite_bool(fenced, "fenced")?;
        let dispatch_open = sqlite_bool(dispatch_open, "dispatch_open")?;
        if role != "source" && role != "destination" {
            return Err(ProviderError::Database(ReferenceDatabaseError::Invalid(
                "binding has an unknown role".into(),
            )));
        }
        if generation != handle.provider_generation {
            return Err(ProviderError::StaleGeneration {
                expected: handle.provider_generation,
                actual: generation,
            });
        }
        if epoch != handle.execution_epoch {
            return Err(ProviderError::StaleEpoch {
                expected: handle.execution_epoch,
                actual: epoch,
            });
        }
        if fenced {
            return Err(ProviderError::Fenced(handle.binding_id.clone()));
        }
        if !active {
            return Err(ProviderError::Inactive(handle.binding_id.clone()));
        }
        if !dispatch_open {
            return Err(ProviderError::DispatchClosed(handle.binding_id.clone()));
        }
        if role == "destination" && activation.as_deref() != Some("activated") {
            return Err(ProviderError::DispatchClosed(handle.binding_id.clone()));
        }
        if !Rights::from_bits(rights).contains(required) {
            return Err(ProviderError::RightsDenied);
        }
        Ok(())
    }

    /// Check the live authority fence for runtime-local business calls. The
    /// handle's cached coordinates are never trusted after a continuation
    /// boundary or an authority commit.
    pub(crate) fn ensure_live(&self, handle: &BindingHandle) -> Result<(), ProviderError> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        Self::validate(&tx, handle, Rights::default())?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_for_handle(
        &self,
        handle: &BindingHandle,
        key: &[u8],
    ) -> Result<Option<KvEntry>, ProviderError> {
        handle.get_with(self, key)
    }

    pub fn cas_for_handle(
        &self,
        handle: &BindingHandle,
        key: &[u8],
        expected_revision: Option<u64>,
        value: &[u8],
    ) -> Result<KvEntry, ProviderError> {
        handle.cas_with(self, key, expected_revision, value)
    }

    /// Capture the logical provider revision and atomically close dispatch for
    /// every host-local clone of this binding. The returned data is portable;
    /// the handle itself remains native and is never serialized.
    pub fn capture_and_close(
        &self,
        handle: &BindingHandle,
        key: &[u8],
    ) -> Result<Option<KvEntry>, ProviderError> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        Self::validate(&tx, handle, Rights::READ)?;
        let value = tx
            .query_row(
                "SELECT value, revision FROM visa_provider_kv WHERE key = ?1",
                params![key],
                |row| {
                    let revision = row.get::<_, i64>(1)?;
                    Ok((row.get(0)?, revision))
                },
            )
            .optional()?;
        let value = value
            .map(|(value, revision)| {
                Ok::<KvEntry, ReferenceDatabaseError>(KvEntry {
                    value,
                    revision: sqlite_to_u64(revision, "revision")?,
                })
            })
            .transpose()?;
        let generation = u64_to_sqlite(handle.provider_generation, "provider_generation")?;
        let epoch = u64_to_sqlite(handle.execution_epoch, "execution_epoch")?;
        let changed = tx.execute(
            "UPDATE visa_authority_bindings SET dispatch_open = 0
             WHERE binding_id = ?1 AND provider_generation = ?2
               AND execution_epoch = ?3 AND active = 1 AND fenced = 0
               AND dispatch_open = 1",
            params![handle.binding_id, generation, epoch,],
        )?;
        if changed != 1 {
            return Err(ProviderError::DispatchClosed(handle.binding_id.clone()));
        }
        tx.commit()?;
        Ok(value)
    }
}

/// Opaque, host-local, non-serializable provider binding. It intentionally has
/// no serde derives and no public constructor from a string.
pub struct BindingHandle {
    database: ReferenceDatabase,
    binding_id: BindingId,
    owner: String,
    provider_generation: u64,
    execution_epoch: u64,
    rights: Rights,
}

impl Clone for BindingHandle {
    fn clone(&self) -> Self {
        Self {
            database: self.database.clone(),
            binding_id: self.binding_id.clone(),
            owner: self.owner.clone(),
            provider_generation: self.provider_generation,
            execution_epoch: self.execution_epoch,
            rights: self.rights,
        }
    }
}

impl fmt::Debug for BindingHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindingHandle")
            .field("binding_id", &self.binding_id)
            .field("provider_generation", &self.provider_generation)
            .field("execution_epoch", &self.execution_epoch)
            .finish_non_exhaustive()
    }
}

impl BindingHandle {
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn provider_generation(&self) -> u64 {
        self.provider_generation
    }
    pub fn execution_epoch(&self) -> u64 {
        self.execution_epoch
    }
    pub fn rights(&self) -> Rights {
        self.rights
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<KvEntry>, ProviderError> {
        self.get_with(&DurableKvProvider::new(self.database.clone()), key)
    }

    fn get_with(
        &self,
        _provider: &DurableKvProvider,
        key: &[u8],
    ) -> Result<Option<KvEntry>, ProviderError> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        DurableKvProvider::validate(&tx, self, Rights::READ)?;
        let value = tx
            .query_row(
                "SELECT value, revision FROM visa_provider_kv WHERE key = ?1",
                params![key],
                |row| {
                    let revision = row.get::<_, i64>(1)?;
                    Ok((row.get(0)?, revision))
                },
            )
            .optional()?;
        let value = value
            .map(|(value, revision)| {
                Ok::<KvEntry, ReferenceDatabaseError>(KvEntry {
                    value,
                    revision: sqlite_to_u64(revision, "revision")?,
                })
            })
            .transpose()?;
        tx.commit()?;
        Ok(value)
    }

    /// Compare-and-swap is one SQLite transaction including the binding check.
    pub fn compare_and_swap(
        &self,
        key: &[u8],
        expected_revision: Option<u64>,
        value: &[u8],
    ) -> Result<KvEntry, ProviderError> {
        self.cas_with(&DurableKvProvider::new(self.database.clone()), key, expected_revision, value)
    }

    fn cas_with(
        &self,
        _provider: &DurableKvProvider,
        key: &[u8],
        expected_revision: Option<u64>,
        value: &[u8],
    ) -> Result<KvEntry, ProviderError> {
        if !self.rights.contains(Rights::WRITE) {
            return Err(ProviderError::RightsDenied);
        }
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        DurableKvProvider::validate(&tx, self, Rights::WRITE)?;
        let current = tx
            .query_row(
                "SELECT revision FROM visa_provider_kv WHERE key = ?1",
                params![key],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|revision| sqlite_to_u64(revision, "revision"))
            .transpose()?;
        if current != expected_revision {
            return Err(ProviderError::CompareAndSwapMismatch {
                expected: expected_revision,
                actual: current,
            });
        }
        let revision = current.map_or(Ok(0), |revision| {
            revision
                .checked_add(1)
                .ok_or_else(|| ReferenceDatabaseError::Invalid("revision overflow".into()))
        })?;
        let revision_sql = u64_to_sqlite(revision, "revision")?;
        if current.is_some() {
            tx.execute(
                "UPDATE visa_provider_kv SET value = ?2, revision = ?3 WHERE key = ?1",
                params![key, value, revision_sql],
            )?;
        } else {
            tx.execute(
                "INSERT INTO visa_provider_kv(key, value, revision) VALUES (?1, ?2, ?3)",
                params![key, value, revision_sql],
            )?;
        }
        tx.commit()?;
        Ok(KvEntry { value: value.to_vec(), revision })
    }

    pub fn cas(
        &self,
        key: &[u8],
        expected_revision: Option<u64>,
        value: &[u8],
    ) -> Result<KvEntry, ProviderError> {
        self.compare_and_swap(key, expected_revision, value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvEntry {
    pub value: Vec<u8>,
    pub revision: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{CommitRequest, PrepareRequest};
    use visa_core::{
        AuthorityId, ContinuationId, Digest, ExternalCoordinate, OperationId, RebindDisposition,
        RequirementId, ResourceRequirement, Rights as CoreRights, SnapshotId,
    };

    fn coordinate(value: &str) -> ExternalCoordinate {
        ExternalCoordinate {
            authority: AuthorityId::from_u128(1),
            value: value.as_bytes().to_vec(),
        }
    }

    #[test]
    fn values_survive_fresh_destination_and_old_handle_is_fenced() {
        let database = ReferenceDatabase::in_memory().unwrap();
        let authority = Authority::new(database.clone()).unwrap();
        let source = authority.bootstrap("owner", 1, Rights::READ | Rights::WRITE).unwrap();
        let provider = DurableKvProvider::new(database);
        let old = provider.bind(&authority, &source.binding_id).unwrap();
        assert_eq!(old.cas(b"counter", None, b"one").unwrap().revision, 0);
        assert_eq!(provider.capture_and_close(&old, b"counter").unwrap().unwrap().value, b"one");
        assert!(matches!(old.get(b"counter"), Err(ProviderError::DispatchClosed(_))));
        let requirement = ResourceRequirement {
            id: RequirementId::from_u128(1),
            kind: b"kv".to_vec(),
            logical_name: b"counter".to_vec(),
            required_rights: CoreRights(Rights::READ.bits() | Rights::WRITE.bits()),
            disposition: RebindDisposition::Reconnect,
            profile_data: Vec::new(),
        };
        let prepare = PrepareRequest {
            operation: OperationId::from_u128(1),
            continuation: ContinuationId::from_u128(2),
            snapshot: SnapshotId::from_u128(3),
            source: coordinate(&source.binding_id),
            destination: coordinate("next-world"),
            requirements: vec![requirement],
            capture_receipt: None,
            preparation_digest: Digest::of_bytes(b"snapshot"),
        };
        let prepared = authority.prepare(prepare.clone()).unwrap();
        let receipt = authority
            .commit(CommitRequest {
                operation: OperationId::from_u128(4),
                continuation: prepare.continuation,
                snapshot: prepare.snapshot,
                source: prepare.source,
                destination: prepare.destination,
                requirements: prepare.requirements,
                capture_receipt: prepare.capture_receipt,
                preparation_digest: prepare.preparation_digest,
                preparation: prepared.core_receipt,
            })
            .unwrap();
        assert!(matches!(old.get(b"counter"), Err(ProviderError::Fenced(_))));
        let fresh = provider.bind(&authority, &receipt.destination_binding_id).unwrap();
        assert_eq!(fresh.provider_generation(), 2);
        assert!(matches!(fresh.get(b"counter"), Err(ProviderError::DispatchClosed(_))));
        let admission = crate::authority::ActivationAdmissionRequest {
            operation: OperationId::from_u128(5),
            continuation: receipt.core_receipt.continuation,
            snapshot: receipt.core_receipt.snapshot,
            destination: receipt.core_receipt.destination.clone(),
            destination_binding_id: receipt.destination_binding_id.clone(),
            commit: receipt.core_receipt.clone(),
        };
        authority.open_destination(&admission).unwrap();
        assert!(matches!(fresh.get(b"counter"), Err(ProviderError::DispatchClosed(_))));
        authority.confirm_destination_activation(&admission).unwrap();
        assert_eq!(fresh.get(b"counter").unwrap().unwrap().value, b"one");
    }
}
