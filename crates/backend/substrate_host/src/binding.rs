use contract_core::{BindingReceipt, Digest, EntityRef, EvidenceKind, EvidenceRef, Identity};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest as _, Sha256};
use substrate_api::{BindingKind, BindingPort, BindingRequest, ProviderError, ProviderErrorKind};

use crate::{
    SqliteProvider, authority::require_prepared_chain, database_error, deserialize, error,
    generation, lease::check_lease_on, next_identity, number, serialize,
};

impl SqliteProvider {
    /// Provision the durable namespace backing a source KV claim.
    ///
    /// This is deployment configuration, not component authority. Repeating
    /// the same mapping is idempotent; substituting a namespace is a visible
    /// conflict.
    pub fn provision_key_value_namespace(
        &mut self,
        resource: EntityRef,
        namespace: Identity,
    ) -> Result<(), ProviderError> {
        let node = self.scope.node;
        let transaction = self.immediate_transaction()?;
        install_kv_resource(&transaction, resource, namespace)?;
        install_kv_availability(&transaction, node, namespace)?;
        transaction.commit().map_err(database_error)
    }

    /// Declare that one deployment node can bind an existing durable
    /// namespace. This never creates or changes a logical claim mapping.
    pub fn provision_key_value_namespace_availability(
        &mut self,
        node: contract_core::NodeIdentity,
        namespace: Identity,
    ) -> Result<(), ProviderError> {
        if node.is_zero() || namespace.is_zero() {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        install_kv_availability(&self.connection, node, namespace)
    }
}

impl BindingPort for SqliteProvider {
    fn prepare_binding(
        &mut self,
        request: BindingRequest,
    ) -> Result<BindingReceipt, ProviderError> {
        let transaction = self.immediate_transaction()?;
        if let Some((receipt, cleaned, kind, namespace)) =
            load_binding_record(&transaction, request.snapshot, request.claim)?
        {
            let expected = binding_storage_kind(request.kind);
            if cleaned
                || receipt.handoff != request.handoff
                || receipt.snapshot != request.snapshot
                || receipt.claim != request.claim
                || receipt.authority != request.authority
                || receipt.exposed_rights != request.exposed_rights
                || receipt.node != request.candidate_owner
                || receipt.lease_epoch != request.candidate_epoch
                || kind != expected.0
                || namespace != expected.1
            {
                return Err(error(ProviderErrorKind::Conflict, false));
            }
            transaction.commit().map_err(database_error)?;
            return Ok(receipt);
        }

        let authority = require_prepared_chain(
            &transaction,
            request.authority,
            request.handoff,
            request.snapshot,
        )?;
        if authority.resource != request.claim
            || !request.exposed_rights.is_subset_of(authority.rights)
        {
            return Err(error(ProviderErrorKind::Denied, false));
        }
        if request.expected_epoch.next() != Some(request.candidate_epoch) {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        check_lease_on(
            &transaction,
            request.claim,
            request.expected_owner,
            request.expected_epoch,
        )?;

        let binding = EntityRef::initial(next_identity(&transaction)?);
        let evidence_identity = next_identity(&transaction)?;
        let mut digest = Sha256::new();
        digest.update(request.handoff.0);
        digest.update(request.snapshot.0);
        digest.update(request.claim.identity.0);
        digest.update(number(request.claim.generation.0));
        digest.update(binding.identity.0);
        digest.update(request.authority.identity.0);
        digest.update(number(request.authority.generation.0));
        digest.update(request.exposed_rights.bits().to_be_bytes());
        digest.update(request.candidate_owner.0.0);
        digest.update(number(request.candidate_epoch.0));
        let digest: [u8; 32] = digest.finalize().into();
        let receipt = BindingReceipt {
            handoff: request.handoff,
            snapshot: request.snapshot,
            claim: request.claim,
            binding,
            authority: request.authority,
            exposed_rights: request.exposed_rights,
            node: request.candidate_owner,
            lease_epoch: request.candidate_epoch,
            evidence: EvidenceRef {
                identity: evidence_identity,
                kind: EvidenceKind::Binding,
                digest: Digest::from_bytes(digest),
            },
        };
        let (kind, namespace) = binding_storage_kind(request.kind);
        transaction
            .execute(
                "INSERT INTO binding(
                     snapshot_id, claim_id, claim_generation, kind,
                     namespace_id, receipt
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    request.snapshot.0.as_slice(),
                    request.claim.identity.0.as_slice(),
                    generation(request.claim.generation),
                    kind,
                    namespace.map(|identity| identity.0.to_vec()),
                    serialize(&receipt)?
                ],
            )
            .map_err(database_error)?;
        if let BindingKind::KeyValueNamespace { namespace } = request.kind {
            validate_kv_binding(&transaction, request.claim, namespace, request.candidate_owner)?;
        }
        transaction.commit().map_err(database_error)?;
        Ok(receipt)
    }

    fn binding(
        &self,
        snapshot: Identity,
        claim: EntityRef,
    ) -> Result<Option<BindingReceipt>, ProviderError> {
        Ok(load_binding_record(&self.connection, snapshot, claim)?
            .map(|(receipt, _, _, _)| receipt))
    }

    fn cleanup_binding(
        &mut self,
        snapshot: Identity,
        claim: EntityRef,
    ) -> Result<(), ProviderError> {
        let Some((receipt, cleaned, _, _)) =
            load_binding_record(&self.connection, snapshot, claim)?
        else {
            // Cleanup is idempotent even after a partial prepare was rolled
            // back and left no binding.
            return Ok(());
        };
        if !cleaned {
            self.connection
                .execute(
                    "UPDATE binding SET cleaned = 1
                     WHERE snapshot_id = ?1 AND claim_id = ?2 AND claim_generation = ?3",
                    params![
                        snapshot.0.as_slice(),
                        claim.identity.0.as_slice(),
                        generation(claim.generation)
                    ],
                )
                .map_err(database_error)?;
        }
        self.timers.retain(|_, timer| timer.resource != claim || timer.owner != receipt.node);
        Ok(())
    }
}

type StoredBinding = (BindingReceipt, bool, i64, Option<Identity>);

fn load_binding_record(
    connection: &rusqlite::Connection,
    snapshot: Identity,
    claim: EntityRef,
) -> Result<Option<StoredBinding>, ProviderError> {
    let stored = connection
        .query_row(
            "SELECT receipt, cleaned, kind, namespace_id FROM binding
             WHERE snapshot_id = ?1 AND claim_id = ?2 AND claim_generation = ?3",
            params![
                snapshot.0.as_slice(),
                claim.identity.0.as_slice(),
                generation(claim.generation)
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?;
    stored
        .map(|(receipt, cleaned, kind, namespace)| {
            let receipt = deserialize(&receipt)?;
            let namespace =
                namespace.map(crate::decode_identity).transpose().map_err(database_error)?;
            Ok((receipt, cleaned, kind, namespace))
        })
        .transpose()
}

fn binding_storage_kind(kind: BindingKind) -> (i64, Option<Identity>) {
    match kind {
        BindingKind::PausedDurationTimer => (0, None),
        BindingKind::KeyValueNamespace { namespace } => (1, Some(namespace)),
    }
}

pub(crate) fn install_kv_resource(
    connection: &rusqlite::Connection,
    resource: EntityRef,
    namespace: Identity,
) -> Result<(), ProviderError> {
    let existing = connection
        .query_row(
            "SELECT namespace_id FROM kv_resource
             WHERE resource_id = ?1 AND resource_generation = ?2",
            params![resource.identity.0.as_slice(), generation(resource.generation)],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(database_error)?;
    if let Some(existing) = existing {
        let existing = crate::decode_identity(existing).map_err(database_error)?;
        return if existing == namespace {
            Ok(())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    connection
        .execute(
            "INSERT INTO kv_resource(
                 resource_id, resource_generation, namespace_id
             ) VALUES (?1, ?2, ?3)",
            params![
                resource.identity.0.as_slice(),
                generation(resource.generation),
                namespace.0.as_slice()
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

fn install_kv_availability(
    connection: &rusqlite::Connection,
    node: contract_core::NodeIdentity,
    namespace: Identity,
) -> Result<(), ProviderError> {
    connection
        .execute(
            "INSERT OR IGNORE INTO kv_namespace_availability(node_id, namespace_id)
             VALUES (?1, ?2)",
            params![node.0.0.as_slice(), namespace.0.as_slice()],
        )
        .map_err(database_error)?;
    Ok(())
}

fn validate_kv_binding(
    connection: &rusqlite::Connection,
    resource: EntityRef,
    expected_namespace: Identity,
    node: contract_core::NodeIdentity,
) -> Result<(), ProviderError> {
    let existing = connection
        .query_row(
            "SELECT namespace_id FROM kv_resource
             WHERE resource_id = ?1 AND resource_generation = ?2",
            params![resource.identity.0.as_slice(), generation(resource.generation)],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(database_error)?
        .map(crate::decode_identity)
        .transpose()
        .map_err(database_error)?
        .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;
    if existing != expected_namespace {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    let available: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM kv_namespace_availability
                 WHERE node_id = ?1 AND namespace_id = ?2
             )",
            params![node.0.0.as_slice(), expected_namespace.0.as_slice()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !available {
        return Err(error(ProviderErrorKind::NotFound, false));
    }
    Ok(())
}
