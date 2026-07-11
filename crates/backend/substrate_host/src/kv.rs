use contract_core::{
    EffectKind, EffectOutcome, EffectRequest, EffectResult, Identity, Rights, VersionedValue,
};
use rusqlite::{OptionalExtension, params};
use substrate_api::{KvPort, ProviderError, ProviderErrorKind};

use crate::{
    FaultPoint, SqliteProvider, authority::authorize_effect_on, database_error, effect_evidence,
    ensure_intent, error, generation, lease::check_lease_on, load_operation_by_idempotency,
    load_operation_by_identity, write_outcome,
};

impl KvPort for SqliteProvider {
    fn read(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        let EffectKind::KeyValueRead { key } = &request.kind else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };

        let transaction = self.immediate_transaction()?;
        let intent = ensure_intent(&transaction, request)?;
        if let Some(outcome) = intent.record.outcome {
            transaction.commit().map_err(database_error)?;
            return Ok(outcome);
        }
        authorize_effect_on(&transaction, request, Rights::KV_READ)?;
        check_lease_on(&transaction, request.resource, request.node, request.lease_epoch)?;
        ensure_kv_resource(&transaction, request.resource, request.node)?;
        let value = transaction
            .query_row(
                "SELECT value, version FROM kv_entry
                 WHERE resource_id = ?1 AND resource_generation = ?2 AND key = ?3",
                params![
                    request.resource.identity.0.as_slice(),
                    generation(request.resource.generation),
                    key
                ],
                |row| {
                    let version: i64 = row.get(1)?;
                    Ok(VersionedValue {
                        value: row.get(0)?,
                        version: u64::try_from(version)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)?;
        let result = EffectResult::KeyValueRead { value };
        let outcome = EffectOutcome::Succeeded {
            evidence: effect_evidence(&transaction, request, &result)?,
            result,
        };
        write_outcome(&transaction, request.operation, &outcome)?;
        transaction.commit().map_err(database_error)?;
        Ok(outcome)
    }

    fn compare_and_set(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        let EffectKind::KeyValueCompareAndSet { key, expected_version, value } = &request.kind
        else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };

        let transaction = self.immediate_transaction()?;
        let intent = match load_operation_by_identity(&transaction, request.operation)? {
            Some(_) => ensure_intent(&transaction, request)?,
            None => {
                // Admission is safe to evaluate without an intent and lets a fenced
                // client receive the authoritative lease error. The provider still
                // requires a durable Coordinator-written intent before any KV read
                // or mutation can occur.
                authorize_effect_on(&transaction, request, Rights::KV_WRITE)?;
                check_lease_on(&transaction, request.resource, request.node, request.lease_epoch)?;
                ensure_kv_resource(&transaction, request.resource, request.node)?;
                transaction.commit().map_err(database_error)?;
                return Err(error(ProviderErrorKind::NotFound, false));
            }
        };
        if let Some(outcome) = intent.record.outcome {
            transaction.commit().map_err(database_error)?;
            return Ok(outcome);
        }
        authorize_effect_on(&transaction, request, Rights::KV_WRITE)?;
        check_lease_on(&transaction, request.resource, request.node, request.lease_epoch)?;
        ensure_kv_resource(&transaction, request.resource, request.node)?;

        let current = transaction
            .query_row(
                "SELECT version FROM kv_entry
                 WHERE resource_id = ?1 AND resource_generation = ?2 AND key = ?3",
                params![
                    request.resource.identity.0.as_slice(),
                    generation(request.resource.generation),
                    key
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(database_error)?
            .map(|value| {
                u64::try_from(value).map_err(|_| error(ProviderErrorKind::Integrity, false))
            })
            .transpose()?;

        let applies = match (*expected_version, current) {
            (None, None) => true,
            (Some(expected), Some(actual)) => expected == actual,
            _ => false,
        };
        let version = if applies {
            let version = current
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| error(ProviderErrorKind::Storage, false))?;
            let stored_version =
                i64::try_from(version).map_err(|_| error(ProviderErrorKind::Storage, false))?;
            transaction
                .execute(
                    "INSERT INTO kv_entry(
                         resource_id, resource_generation, key, value, version
                     ) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(resource_id, resource_generation, key)
                     DO UPDATE SET value = excluded.value, version = excluded.version",
                    params![
                        request.resource.identity.0.as_slice(),
                        generation(request.resource.generation),
                        key,
                        value,
                        stored_version
                    ],
                )
                .map_err(database_error)?;
            version
        } else {
            current.unwrap_or(0)
        };
        let result = EffectResult::KeyValue { version, applied: applies };
        let outcome = EffectOutcome::Succeeded {
            evidence: effect_evidence(&transaction, request, &result)?,
            result,
        };
        write_outcome(&transaction, request.operation, &outcome)?;
        transaction.commit().map_err(database_error)?;

        if self.take_fault(FaultPoint::AfterKvCommit) {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        Ok(outcome)
    }

    fn query_operation(
        &self,
        operation: Identity,
        idempotency_key: contract_core::IdempotencyKey,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        let by_operation = load_operation_by_identity(&self.connection, operation)?;
        let by_key = load_operation_by_idempotency(&self.connection, idempotency_key)?;
        match (by_operation, by_key) {
            (None, None) => Ok(None),
            (Some(observation), Some(key))
                if observation.record.request == key.record.request
                    && observation.record.request.operation == operation
                    && observation.record.request.idempotency_key == idempotency_key =>
            {
                Ok(observation.record.outcome)
            }
            _ => Err(error(ProviderErrorKind::Conflict, false)),
        }
    }
}

#[cfg(any(test, feature = "test-control"))]
impl SqliteProvider {
    pub fn inspect_key_value(
        &self,
        resource: contract_core::EntityRef,
        key: &[u8],
    ) -> Result<Option<VersionedValue>, ProviderError> {
        self.connection
            .query_row(
                "SELECT value, version FROM kv_entry
                 WHERE resource_id = ?1 AND resource_generation = ?2 AND key = ?3",
                params![resource.identity.0.as_slice(), generation(resource.generation), key],
                |row| {
                    let version: i64 = row.get(1)?;
                    Ok(VersionedValue {
                        value: row.get(0)?,
                        version: u64::try_from(version)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }
}

fn ensure_kv_resource(
    connection: &rusqlite::Connection,
    resource: contract_core::EntityRef,
    node: contract_core::NodeIdentity,
) -> Result<(), ProviderError> {
    let namespace = connection
        .query_row(
            "SELECT namespace_id FROM kv_resource
             WHERE resource_id = ?1 AND resource_generation = ?2",
            params![resource.identity.0.as_slice(), generation(resource.generation)],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(database_error)?;
    if let Some(namespace) = namespace {
        let available: bool = connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM kv_namespace_availability
                     WHERE node_id = ?1 AND namespace_id = ?2
                 )",
                params![node.0.0.as_slice(), namespace],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        return if available { Ok(()) } else { Err(error(ProviderErrorKind::NotFound, false)) };
    }
    let identity_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM kv_resource WHERE resource_id = ?1)",
            params![resource.identity.0.as_slice()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    Err(error(
        if identity_exists {
            ProviderErrorKind::StaleGeneration
        } else {
            ProviderErrorKind::NotFound
        },
        false,
    ))
}
