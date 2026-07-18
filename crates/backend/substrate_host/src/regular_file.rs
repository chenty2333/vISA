use contract_core::{
    EffectKind, EffectOutcome, EffectRequest, EffectResult, EntityRef, Extension, Identity,
    ProfileAccess,
};
#[cfg(target_os = "linux")]
use rusqlite::TransactionBehavior;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use substrate_api::{
    EffectRequestBinding, ProfileDispatchAuthorization, ProfilePort, ProviderError,
    ProviderErrorKind,
};
use visa_profile::{
    FileAccessMode, FileDurability, FileLockState, LOGICAL_REQUEST_EXTENSION_ID,
    REGULAR_FILE_EXTENSION_ID, RegularFileOperation, RegularFileResult, RegularFileState,
    encode_regular_file_result, regular_file_extension, regular_file_state,
    validate_profile_effect,
};

use crate::{
    FaultPoint, SqliteProvider, authority::authorize_effect_on, database_error, deserialize, error,
    generation, lease::check_lease_on, load_operation_by_idempotency, load_operation_by_identity,
    number, serialize, write_outcome,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFilePlan {
    operation: RegularFileOperation,
    pre_state: RegularFileState,
    post_state: RegularFileState,
    outcome: EffectOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredFile {
    namespace: Identity,
    identity: NativeObjectIdentity,
    state: RegularFileState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeObjectIdentity {
    device: u64,
    inode: u64,
    btime_seconds: i64,
    btime_nanoseconds: u32,
}

fn decode_native_identity(
    device: Vec<u8>,
    inode: Vec<u8>,
    btime_seconds: Vec<u8>,
    btime_nanoseconds: Vec<u8>,
) -> Result<NativeObjectIdentity, ProviderError> {
    let device = u64::from_be_bytes(
        device.try_into().map_err(|_| error(ProviderErrorKind::Integrity, false))?,
    );
    let inode = u64::from_be_bytes(
        inode.try_into().map_err(|_| error(ProviderErrorKind::Integrity, false))?,
    );
    let btime_seconds = i64::from_be_bytes(
        btime_seconds.try_into().map_err(|_| error(ProviderErrorKind::Integrity, false))?,
    );
    let btime_nanoseconds = u32::from_be_bytes(
        btime_nanoseconds.try_into().map_err(|_| error(ProviderErrorKind::Integrity, false))?,
    );
    validate_btime_nanoseconds(btime_nanoseconds)?;
    Ok(NativeObjectIdentity { device, inode, btime_seconds, btime_nanoseconds })
}

const fn validate_btime_nanoseconds(value: u32) -> Result<(), ProviderError> {
    if value < 1_000_000_000 { Ok(()) } else { Err(error(ProviderErrorKind::Integrity, false)) }
}

#[cfg(test)]
struct RegularFileFencePause {
    reached: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
static REGULAR_FILE_FENCE_PAUSES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<Identity, RegularFileFencePause>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn install_regular_file_fence_pause(
    operation: Identity,
) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::SyncSender<()>) {
    let (reached_sender, reached_receiver) = std::sync::mpsc::sync_channel(1);
    let (resume_sender, resume_receiver) = std::sync::mpsc::sync_channel(1);
    let previous = REGULAR_FILE_FENCE_PAUSES
        .get_or_init(Default::default)
        .lock()
        .expect("regular-file fence pause lock")
        .insert(
            operation,
            RegularFileFencePause { reached: reached_sender, resume: resume_receiver },
        );
    assert!(previous.is_none(), "regular-file fence pause operation must be unique");
    (reached_receiver, resume_sender)
}

#[cfg(test)]
fn pause_before_regular_file_effect_fence(operation: Identity) {
    let pause = REGULAR_FILE_FENCE_PAUSES
        .get_or_init(Default::default)
        .lock()
        .expect("regular-file fence pause lock")
        .remove(&operation);
    if let Some(pause) = pause {
        pause.reached.send(()).expect("regular-file fence pause announces");
        pause.resume.recv().expect("regular-file fence pause resumes");
    }
}

#[cfg(not(test))]
fn pause_before_regular_file_effect_fence(_operation: Identity) {}

impl SqliteProvider {
    /// Provision one bounded regular-file claim and the current node's secure
    /// namespace root. The pathname is deployment-local and never enters the
    /// portable profile state.
    #[cfg(target_os = "linux")]
    pub fn provision_regular_file(
        &mut self,
        state: &RegularFileState,
        root: impl AsRef<std::path::Path>,
    ) -> Result<(), ProviderError> {
        regular_file_extension(state).map_err(profile_payload_error)?;
        let root = provisioned_root(root.as_ref())?;
        let file =
            open_regular_at(&root.file, &state.claim.relative_path, state.claim.access_mode)?;
        let identity = file_identity(&file)?;
        ensure_file_matches(&file, identity, state)?;

        let node = self.scope.node;
        let transaction = self.immediate_transaction()?;
        install_root_on(&transaction, node, state.claim.namespace, &root)?;
        install_file_on(&transaction, state, identity)?;
        transaction.commit().map_err(database_error)?;

        if state.lock_state == FileLockState::Held {
            lock_exclusive(&file)?;
            self.regular_files.insert(state.claim.resource, file);
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn provision_regular_file(
        &mut self,
        _state: &RegularFileState,
        _root: impl AsRef<std::path::Path>,
    ) -> Result<(), ProviderError> {
        Err(error(ProviderErrorKind::Unsupported, false))
    }

    /// Make an already-provisioned logical namespace available on another
    /// node under a node-local root directory.
    #[cfg(target_os = "linux")]
    pub fn provision_regular_file_namespace_availability(
        &mut self,
        node: contract_core::NodeIdentity,
        namespace: Identity,
        root: impl AsRef<std::path::Path>,
    ) -> Result<(), ProviderError> {
        if node.is_zero() || namespace.is_zero() {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        let root = provisioned_root(root.as_ref())?;
        install_root_on(&self.connection, node, namespace, &root)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn provision_regular_file_namespace_availability(
        &mut self,
        _node: contract_core::NodeIdentity,
        _namespace: Identity,
        _root: impl AsRef<std::path::Path>,
    ) -> Result<(), ProviderError> {
        Err(error(ProviderErrorKind::Unsupported, false))
    }
}

impl ProfilePort for SqliteProvider {
    fn require_profile_dispatch_authorization(
        &mut self,
        profile: Identity,
    ) -> Result<(), ProviderError> {
        if profile.is_zero() {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        self.profile_dispatch.required.insert(profile);
        Ok(())
    }

    fn arm_profile_dispatch(
        &mut self,
        authorization: ProfileDispatchAuthorization,
    ) -> Result<(), ProviderError> {
        let profile = authorization.profile();
        if !self.profile_dispatch.required.contains(&profile) {
            return Err(error(ProviderErrorKind::Denied, false));
        }
        if self.profile_dispatch.armed.is_some() || self.profile_dispatch.consumed.is_some() {
            return Err(error(ProviderErrorKind::Conflict, false));
        }
        self.profile_dispatch.armed = Some((profile, authorization.binding()));
        Ok(())
    }

    fn finish_profile_dispatch(
        &mut self,
        binding: EffectRequestBinding,
    ) -> Result<bool, ProviderError> {
        if let Some((_, consumed)) = self.profile_dispatch.consumed.take() {
            self.profile_dispatch.armed = None;
            return if consumed == binding {
                Ok(true)
            } else {
                Err(error(ProviderErrorKind::Conflict, false))
            };
        }
        if let Some((_, armed)) = self.profile_dispatch.armed.take() {
            return if armed == binding {
                Ok(false)
            } else {
                Err(error(ProviderErrorKind::Conflict, false))
            };
        }
        Err(error(ProviderErrorKind::Denied, false))
    }

    fn execute_profile(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
    ) -> Result<EffectOutcome, ProviderError> {
        let EffectKind::Profile { profile, access, .. } = request.kind else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };
        if profile == LOGICAL_REQUEST_EXTENSION_ID {
            if access == ProfileAccess::Write && self.profile_dispatch.required.contains(&profile) {
                let armed = self
                    .profile_dispatch
                    .armed
                    .take()
                    .ok_or_else(|| error(ProviderErrorKind::Denied, false))?;
                self.profile_dispatch.consumed = Some(armed);
                let requested = EffectRequestBinding::from_effect(request)
                    .map_err(|_| error(ProviderErrorKind::InvalidRequest, false))?;
                if armed != (profile, requested) {
                    return Err(error(ProviderErrorKind::Denied, false));
                }
            }
            return self.execute_logical_request(request, extension);
        }
        if profile != REGULAR_FILE_EXTENSION_ID {
            return Err(error(ProviderErrorKind::Unsupported, false));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (request, extension);
            return Err(error(ProviderErrorKind::Unsupported, false));
        }

        #[cfg(target_os = "linux")]
        self.execute_regular_file(request, extension)
    }

    fn query_profile_operation(
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

    fn reconcile_profile_operation(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        let EffectKind::Profile { profile, .. } = request.kind else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };
        if profile == LOGICAL_REQUEST_EXTENSION_ID {
            return self.query_profile_operation(request.operation, request.idempotency_key);
        }
        if profile != REGULAR_FILE_EXTENSION_ID {
            return Err(error(ProviderErrorKind::Unsupported, false));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = extension;
            return Err(error(ProviderErrorKind::Unsupported, false));
        }
        #[cfg(target_os = "linux")]
        self.reconcile_regular_file_operation(request, extension)
    }

    fn cleanup_profile_operation(&mut self, request: &EffectRequest) -> Result<(), ProviderError> {
        let EffectKind::Profile { profile, .. } = request.kind else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };
        if profile == LOGICAL_REQUEST_EXTENSION_ID {
            return self.cleanup_logical_request_operation(request);
        }
        if profile != REGULAR_FILE_EXTENSION_ID {
            return Err(error(ProviderErrorKind::Unsupported, false));
        }
        let transaction = self.immediate_transaction()?;
        let observation = crate::ensure_intent(&transaction, request)?;
        if observation.record.outcome.as_ref().is_none_or(EffectOutcome::is_indeterminate) {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        transaction
            .execute(
                "DELETE FROM regular_file_plan WHERE operation = ?1",
                params![request.operation.0.as_slice()],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }
}

#[cfg(target_os = "linux")]
impl SqliteProvider {
    fn reconcile_regular_file_operation(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        if let Some(outcome) =
            self.query_profile_operation(request.operation, request.idempotency_key)?
            && !outcome.is_indeterminate()
        {
            return Ok(Some(outcome));
        }
        let state = regular_file_state(extension).map_err(profile_payload_error)?;
        let plan = load_plan_on(&self.connection, request.operation)?
            .ok_or_else(|| error(ProviderErrorKind::OutcomeUnknown, true))?;
        if plan.pre_state != state {
            return Err(error(ProviderErrorKind::Conflict, false));
        }

        let EffectKind::Profile { profile, access, payload } = &request.kind else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };
        let required = validate_profile_effect(
            std::slice::from_ref(extension),
            *profile,
            request.resource,
            *access,
            payload,
        )
        .map_err(profile_payload_error)?;

        if self.take_fault(FaultPoint::BeforeProfileEffect) {
            return Err(error(ProviderErrorKind::Unavailable, true));
        }
        pause_before_regular_file_effect_fence(request.operation);
        self.apply_file_plan_under_fence(request, &plan, required, FilePlanFinalization::Reconcile)
            .map(Some)
    }

    fn execute_regular_file(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
    ) -> Result<EffectOutcome, ProviderError> {
        let EffectKind::Profile { profile, access, payload } = &request.kind else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };
        if *profile != REGULAR_FILE_EXTENSION_ID {
            return Err(error(ProviderErrorKind::Unsupported, false));
        }
        let required = validate_profile_effect(
            std::slice::from_ref(extension),
            *profile,
            request.resource,
            *access,
            payload,
        )
        .map_err(profile_payload_error)?;
        let state = regular_file_state(extension).map_err(profile_payload_error)?;
        let operation = contract_core::canonical_from_bytes::<RegularFileOperation>(payload)
            .map_err(|_| error(ProviderErrorKind::InvalidRequest, false))?;

        let plan = {
            let transaction = self.immediate_transaction()?;
            let intent = crate::ensure_intent(&transaction, request)?;
            if let Some(outcome) = intent.record.outcome {
                transaction.commit().map_err(database_error)?;
                return Ok(outcome);
            }
            authorize_effect_on(&transaction, request, required)?;
            check_lease_on(&transaction, request.resource, request.node, request.lease_epoch)?;
            let stored = require_file_on(&transaction, request.resource)?;
            if stored.state != state || stored.namespace != state.claim.namespace {
                return Err(error(ProviderErrorKind::Conflict, false));
            }
            let plan = match load_plan_on(&transaction, request.operation)? {
                Some(plan)
                    if plan.operation == operation
                        && plan.pre_state == state
                        && plan.pre_state.claim.resource == request.resource =>
                {
                    plan
                }
                Some(_) => return Err(error(ProviderErrorKind::Conflict, false)),
                None => {
                    let plan = build_plan_on(&transaction, request, extension, operation, &stored)?;
                    transaction
                        .execute(
                            "INSERT INTO regular_file_plan(operation, plan) VALUES (?1, ?2)",
                            params![request.operation.0.as_slice(), serialize(&plan)?],
                        )
                        .map_err(database_error)?;
                    plan
                }
            };
            transaction.commit().map_err(database_error)?;
            plan
        };

        pause_before_regular_file_effect_fence(request.operation);
        if self.take_fault(FaultPoint::BeforeProfileEffect) {
            return Err(error(ProviderErrorKind::Unavailable, true));
        }
        let outcome = self.apply_file_plan_under_fence(
            request,
            &plan,
            required,
            FilePlanFinalization::Execute,
        )?;

        if self.take_fault(FaultPoint::AfterProfileCommit) {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        Ok(outcome)
    }

    fn apply_file_plan_under_fence(
        &mut self,
        request: &EffectRequest,
        plan: &StoredFilePlan,
        required: contract_core::Rights,
        finalization: FilePlanFinalization,
    ) -> Result<EffectOutcome, ProviderError> {
        let connection = &mut self.connection;
        let regular_files = &mut self.regular_files;
        let faults = &mut self.faults;
        let mut take_fault = |point| {
            if faults.next == Some(point) {
                faults.next = None;
                faults.last_fired = Some(point);
                faults.fired_count = faults.fired_count.saturating_add(1);
                true
            } else {
                false
            }
        };
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let intent = crate::ensure_intent(&transaction, request)?;
        if let Some(outcome) = intent.record.outcome.as_ref() {
            let terminal = matches!(finalization, FilePlanFinalization::Execute)
                || !outcome.is_indeterminate();
            if terminal {
                if outcome != &plan.outcome {
                    return Err(error(ProviderErrorKind::Conflict, false));
                }
                let outcome = outcome.clone();
                transaction.commit().map_err(database_error)?;
                return Ok(outcome);
            }
        }

        // This second authorization/epoch check is deliberately performed only
        // after acquiring SQLite's writer lock. Handoff commit uses the same
        // transactional domain, so either the lease transfer commits first and
        // this source is fenced, or this lock remains held through the external
        // file effect and its provider-state finalization.
        authorize_effect_on(&transaction, request, required)?;
        check_lease_on(&transaction, request.resource, request.node, request.lease_epoch)?;
        let stored = require_file_on(&transaction, request.resource)?;
        if stored.state != plan.pre_state {
            return Err(match finalization {
                FilePlanFinalization::Execute => error(ProviderErrorKind::OutcomeUnknown, true),
                FilePlanFinalization::Reconcile => error(ProviderErrorKind::Conflict, false),
            });
        }

        let inject_after_mutation = take_fault(FaultPoint::AfterRegularFileMutation);
        let applied = apply_file_plan_on(
            &transaction,
            regular_files,
            request,
            plan,
            &stored,
            inject_after_mutation,
        )?;
        if take_fault(FaultPoint::AfterProfileEffect) {
            finish_applied_file_on(
                regular_files,
                request.resource,
                &plan.post_state,
                applied,
                false,
            );
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }

        let finalization_result = match finalization {
            FilePlanFinalization::Execute => finalize_file_plan_on(&transaction, request, plan),
            FilePlanFinalization::Reconcile => {
                finalize_reconciled_file_plan_on(&transaction, request, plan)
            }
        };
        let outcome = match finalization_result {
            Ok(outcome) => outcome,
            Err(_) => {
                finish_applied_file_on(
                    regular_files,
                    request.resource,
                    &plan.post_state,
                    applied,
                    false,
                );
                return Err(error(ProviderErrorKind::OutcomeUnknown, true));
            }
        };
        if transaction.commit().is_err() {
            finish_applied_file_on(
                regular_files,
                request.resource,
                &plan.post_state,
                applied,
                false,
            );
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        finish_applied_file_on(regular_files, request.resource, &plan.post_state, applied, true);
        Ok(outcome)
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum FilePlanFinalization {
    Execute,
    Reconcile,
}

#[cfg(target_os = "linux")]
fn finalize_file_plan_on(
    connection: &rusqlite::Connection,
    request: &EffectRequest,
    plan: &StoredFilePlan,
) -> Result<EffectOutcome, ProviderError> {
    let intent = crate::ensure_intent(connection, request)?;
    if let Some(outcome) = intent.record.outcome {
        return if outcome == plan.outcome {
            Ok(outcome)
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    let stored = require_file_on(connection, request.resource)?;
    if stored.state != plan.pre_state {
        return Err(error(ProviderErrorKind::OutcomeUnknown, true));
    }
    connection
        .execute(
            "UPDATE regular_file_resource SET state = ?3
             WHERE resource_id = ?1 AND resource_generation = ?2",
            params![
                request.resource.identity.0.as_slice(),
                generation(request.resource.generation),
                serialize(&plan.post_state)?
            ],
        )
        .map_err(database_error)?;
    write_outcome(connection, request.operation, &plan.outcome)?;
    Ok(plan.outcome.clone())
}

#[cfg(target_os = "linux")]
fn finalize_reconciled_file_plan_on(
    connection: &rusqlite::Connection,
    request: &EffectRequest,
    plan: &StoredFilePlan,
) -> Result<EffectOutcome, ProviderError> {
    let intent = crate::ensure_intent(connection, request)?;
    if let Some(outcome) = intent.record.outcome.as_ref()
        && !outcome.is_indeterminate()
    {
        return if outcome == &plan.outcome {
            Ok(outcome.clone())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    let stored = require_file_on(connection, request.resource)?;
    if stored.state != plan.pre_state && stored.state != plan.post_state {
        return Err(error(ProviderErrorKind::OutcomeUnknown, true));
    }
    if stored.state == plan.pre_state {
        connection
            .execute(
                "UPDATE regular_file_resource SET state = ?3
                 WHERE resource_id = ?1 AND resource_generation = ?2",
                params![
                    request.resource.identity.0.as_slice(),
                    generation(request.resource.generation),
                    serialize(&plan.post_state)?
                ],
            )
            .map_err(database_error)?;
    }
    // The coordinator owns the canonical Indeterminate -> Reconciled
    // transition and will append the final journal outcome after this
    // provider-state repair commits.
    Ok(plan.outcome.clone())
}

#[cfg(target_os = "linux")]
fn apply_file_plan_on(
    connection: &rusqlite::Connection,
    regular_files: &mut std::collections::BTreeMap<EntityRef, std::fs::File>,
    request: &EffectRequest,
    plan: &StoredFilePlan,
    stored: &StoredFile,
    inject_after_mutation: bool,
) -> Result<AppliedFile, ProviderError> {
    let root = open_root_on(connection, request.node, stored.namespace)?;
    let (mut file, already_renamed) = match regular_files.remove(&request.resource) {
        Some(file) => (file, false),
        None => open_plan_file(&root, stored, plan)?,
    };
    ensure_identity(&file, stored.identity)?;

    let preheld = plan.pre_state.lock_state == FileLockState::Held;
    let mut locked = preheld;
    if preheld {
        lock_exclusive(&file)?;
    } else if operation_needs_exclusive_lock(&plan.operation) {
        lock_exclusive(&file)?;
        locked = true;
    }

    let result =
        apply_operation(&root, &mut file, stored, plan, already_renamed, inject_after_mutation);
    if let Err(failure) = result {
        if preheld {
            regular_files.insert(request.resource, file);
        }
        return Err(failure);
    }
    Ok(AppliedFile { file, locked })
}

#[cfg(target_os = "linux")]
fn finish_applied_file_on(
    regular_files: &mut std::collections::BTreeMap<EntityRef, std::fs::File>,
    resource: EntityRef,
    post_state: &RegularFileState,
    applied: AppliedFile,
    finalized: bool,
) {
    if finalized && post_state.lock_state == FileLockState::Held {
        regular_files.insert(resource, applied.file);
    } else if applied.locked {
        let _ = rustix::fs::flock(&applied.file, rustix::fs::FlockOperation::Unlock);
    }
}

#[cfg(target_os = "linux")]
struct AppliedFile {
    file: std::fs::File,
    locked: bool,
}

#[cfg(target_os = "linux")]
struct ProvisionedRoot {
    file: std::fs::File,
    path: Vec<u8>,
    identity: NativeObjectIdentity,
}

#[cfg(target_os = "linux")]
fn provisioned_root(path: &std::path::Path) -> Result<ProvisionedRoot, ProviderError> {
    use std::os::unix::ffi::OsStrExt as _;

    if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    let file = open_root_path(path)?;
    let identity = directory_identity(&file)?;
    Ok(ProvisionedRoot { file, path: path.as_os_str().as_bytes().to_vec(), identity })
}

#[cfg(target_os = "linux")]
fn install_root_on(
    connection: &rusqlite::Connection,
    node: contract_core::NodeIdentity,
    namespace: Identity,
    root: &ProvisionedRoot,
) -> Result<(), ProviderError> {
    let existing = connection
        .query_row(
            "SELECT root_path, device, inode, btime_seconds, btime_nanoseconds
             FROM regular_file_namespace_root
             WHERE node_id = ?1 AND namespace_id = ?2",
            params![node.0.0.as_slice(), namespace.0.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?;
    let existing = existing
        .map(|(path, device, inode, btime_seconds, btime_nanoseconds)| {
            Ok((path, decode_native_identity(device, inode, btime_seconds, btime_nanoseconds)?))
        })
        .transpose()?;
    if let Some(existing) = existing {
        return if existing == (root.path.clone(), root.identity) {
            Ok(())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    connection
        .execute(
            "INSERT INTO regular_file_namespace_root(
                 node_id, namespace_id, root_path, device, inode,
                 btime_seconds, btime_nanoseconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                node.0.0.as_slice(),
                namespace.0.as_slice(),
                &root.path,
                number(root.identity.device),
                number(root.identity.inode),
                root.identity.btime_seconds.to_be_bytes(),
                root.identity.btime_nanoseconds.to_be_bytes(),
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_file_on(
    connection: &rusqlite::Connection,
    state: &RegularFileState,
    identity: NativeObjectIdentity,
) -> Result<(), ProviderError> {
    let existing = load_file_on(connection, state.claim.resource)?;
    if let Some(existing) = existing {
        return if existing.namespace == state.claim.namespace
            && existing.identity == identity
            && existing.state == *state
        {
            Ok(())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    let identity_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM regular_file_resource WHERE resource_id = ?1
             )",
            params![state.claim.resource.identity.0.as_slice()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if identity_exists {
        return Err(error(ProviderErrorKind::StaleGeneration, false));
    }
    connection
        .execute(
            "INSERT INTO regular_file_resource(
                 resource_id, resource_generation, namespace_id,
                 device, inode, btime_seconds, btime_nanoseconds, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                state.claim.resource.identity.0.as_slice(),
                generation(state.claim.resource.generation),
                state.claim.namespace.0.as_slice(),
                number(identity.device),
                number(identity.inode),
                identity.btime_seconds.to_be_bytes(),
                identity.btime_nanoseconds.to_be_bytes(),
                serialize(state)?
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

fn load_file_on(
    connection: &rusqlite::Connection,
    resource: EntityRef,
) -> Result<Option<StoredFile>, ProviderError> {
    let stored = connection
        .query_row(
            "SELECT namespace_id, device, inode, btime_seconds, btime_nanoseconds, state
             FROM regular_file_resource
             WHERE resource_id = ?1 AND resource_generation = ?2",
            params![resource.identity.0.as_slice(), generation(resource.generation)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?;
    stored
        .map(|(namespace, device, inode, btime_seconds, btime_nanoseconds, state)| {
            Ok(StoredFile {
                namespace: crate::decode_identity(namespace).map_err(database_error)?,
                identity: decode_native_identity(device, inode, btime_seconds, btime_nanoseconds)?,
                state: deserialize(&state)?,
            })
        })
        .transpose()
}

fn require_file_on(
    connection: &rusqlite::Connection,
    resource: EntityRef,
) -> Result<StoredFile, ProviderError> {
    if let Some(stored) = load_file_on(connection, resource)? {
        return Ok(stored);
    }
    let identity_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM regular_file_resource WHERE resource_id = ?1
             )",
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

fn load_plan_on(
    connection: &rusqlite::Connection,
    operation: Identity,
) -> Result<Option<StoredFilePlan>, ProviderError> {
    let bytes = connection
        .query_row(
            "SELECT plan FROM regular_file_plan WHERE operation = ?1",
            params![operation.0.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(database_error)?;
    bytes.map(|bytes| deserialize(&bytes)).transpose()
}

#[cfg(target_os = "linux")]
fn build_plan_on(
    connection: &rusqlite::Connection,
    request: &EffectRequest,
    extension: &Extension,
    operation: RegularFileOperation,
    stored: &StoredFile,
) -> Result<StoredFilePlan, ProviderError> {
    let root = open_root_on(connection, request.node, stored.namespace)?;
    let file =
        open_regular_at(&root, &stored.state.claim.relative_path, stored.state.claim.access_mode)?;
    ensure_identity(&file, stored.identity)?;
    let bytes = read_all(&file, stored.state.claim.max_size)?;
    ensure_content_matches(&bytes, &stored.state)?;

    let result = planned_result(&stored.state, &operation, &bytes)?;
    let result_payload = encode_regular_file_result(&result).map_err(profile_payload_error)?;
    let result =
        EffectResult::Profile { profile: REGULAR_FILE_EXTENSION_ID, payload: result_payload };
    let outcome = EffectOutcome::Succeeded {
        evidence: crate::effect_evidence(connection, request, &result)?,
        result: result.clone(),
    };
    let mut post_extension = extension.clone();
    visa_profile::apply_profile_result(
        std::slice::from_mut(&mut post_extension),
        &request.kind,
        &result,
        request.operation,
    )
    .map_err(profile_payload_error)?;
    let post_state = regular_file_state(&post_extension).map_err(profile_payload_error)?;
    Ok(StoredFilePlan { operation, pre_state: stored.state.clone(), post_state, outcome })
}

#[cfg(target_os = "linux")]
fn planned_result(
    state: &RegularFileState,
    operation: &RegularFileOperation,
    current: &[u8],
) -> Result<RegularFileResult, ProviderError> {
    let next_version =
        state.version.checked_add(1).ok_or_else(|| error(ProviderErrorKind::Storage, false))?;
    match operation {
        RegularFileOperation::Read { max_bytes } => {
            let start = usize::try_from(state.logical_offset)
                .map_err(|_| error(ProviderErrorKind::InvalidRequest, false))?;
            let end = start.saturating_add(*max_bytes as usize).min(current.len());
            Ok(RegularFileResult::Read {
                bytes: current[start..end].to_vec(),
                logical_offset: end as u64,
                version: state.version,
                size: state.size,
                content_digest: state.content_digest,
            })
        }
        RegularFileOperation::Write { bytes, durability } => {
            let mut expected = current.to_vec();
            let start = usize::try_from(state.logical_offset)
                .map_err(|_| error(ProviderErrorKind::InvalidRequest, false))?;
            let end = start
                .checked_add(bytes.len())
                .ok_or_else(|| error(ProviderErrorKind::InvalidRequest, false))?;
            if end > expected.len() {
                expected.resize(end, 0);
            }
            expected[start..end].copy_from_slice(bytes);
            mutated_result(end as u64, next_version, &expected, *durability)
        }
        RegularFileOperation::Append { bytes, durability } => {
            let mut expected = current.to_vec();
            expected.extend_from_slice(bytes);
            mutated_result(expected.len() as u64, next_version, &expected, *durability)
        }
        RegularFileOperation::Truncate { size, durability } => {
            let size = usize::try_from(*size)
                .map_err(|_| error(ProviderErrorKind::InvalidRequest, false))?;
            let mut expected = current.to_vec();
            expected.resize(size, 0);
            mutated_result(
                state.logical_offset.min(size as u64),
                next_version,
                &expected,
                *durability,
            )
        }
        RegularFileOperation::Rename { relative_path } => Ok(RegularFileResult::Renamed {
            relative_path: relative_path.clone(),
            version: next_version,
            content_digest: state.content_digest,
        }),
        RegularFileOperation::Sync { durability } => {
            Ok(RegularFileResult::Synced { version: state.version, durable_through: *durability })
        }
        RegularFileOperation::AcquireLock => {
            Ok(RegularFileResult::Lock { state: FileLockState::Held })
        }
        RegularFileOperation::ReleaseLock => {
            Ok(RegularFileResult::Lock { state: FileLockState::Unlocked })
        }
    }
}

#[cfg(target_os = "linux")]
fn mutated_result(
    logical_offset: u64,
    version: u64,
    bytes: &[u8],
    durability: FileDurability,
) -> Result<RegularFileResult, ProviderError> {
    Ok(RegularFileResult::Mutated {
        logical_offset,
        version,
        size: bytes.len() as u64,
        content_digest: digest_bytes(bytes)?,
        durable_through: durability,
    })
}

#[cfg(target_os = "linux")]
fn apply_operation(
    root: &std::fs::File,
    file: &mut std::fs::File,
    stored: &StoredFile,
    plan: &StoredFilePlan,
    already_renamed: bool,
    inject_after_mutation: bool,
) -> Result<(), ProviderError> {
    let current = read_all(file, plan.pre_state.claim.max_size)?;
    let current_digest = digest_bytes(&current)?;
    let post_matches = current_digest == plan.post_state.content_digest
        && current.len() as u64 == plan.post_state.size;
    let pre_matches = current_digest == plan.pre_state.content_digest
        && current.len() as u64 == plan.pre_state.size;
    if !pre_matches && !post_matches {
        return Err(error(ProviderErrorKind::OutcomeUnknown, true));
    }

    let mut external_effect_may_have_occurred =
        already_renamed || (post_matches && operation_changes_content(&plan.operation));
    let operation_result = (|| {
        if !post_matches || !operation_changes_content(&plan.operation) {
            match &plan.operation {
                RegularFileOperation::Read { .. } => {}
                RegularFileOperation::Write { bytes, durability } => {
                    external_effect_may_have_occurred = true;
                    write_all_at(file, bytes, plan.pre_state.logical_offset)?;
                    fail_after_mutation_if_requested(inject_after_mutation)?;
                    sync_for(file, *durability)?;
                }
                RegularFileOperation::Append { bytes, durability } => {
                    external_effect_may_have_occurred = true;
                    write_all_at(file, bytes, plan.pre_state.size)?;
                    fail_after_mutation_if_requested(inject_after_mutation)?;
                    sync_for(file, *durability)?;
                }
                RegularFileOperation::Truncate { size, durability } => {
                    file.set_len(*size).map_err(io_error)?;
                    external_effect_may_have_occurred = true;
                    fail_after_mutation_if_requested(inject_after_mutation)?;
                    sync_for(file, *durability)?;
                }
                RegularFileOperation::Rename { relative_path } => {
                    sync_for(file, plan.pre_state.claim.durability)?;
                    if !already_renamed {
                        rename_noreplace(root, &plan.pre_state.claim.relative_path, relative_path)?;
                        external_effect_may_have_occurred = true;
                        fail_after_mutation_if_requested(inject_after_mutation)?;
                    }
                    external_effect_may_have_occurred = true;
                    sync_rename_parents(
                        root,
                        &plan.pre_state.claim.relative_path,
                        relative_path,
                        plan.pre_state.claim.durability,
                    )?;
                }
                RegularFileOperation::Sync { durability } => {
                    external_effect_may_have_occurred = true;
                    sync_for(file, *durability)?;
                }
                RegularFileOperation::AcquireLock => {}
                RegularFileOperation::ReleaseLock => {
                    rustix::fs::flock(&*file, rustix::fs::FlockOperation::Unlock)
                        .map_err(errno_error)?;
                    external_effect_may_have_occurred = true;
                }
            }
        } else {
            // The bytes may have reached their post-state before a crash while
            // the requested durability barrier did not. Reissue the barrier
            // before turning the durable plan into a successful outcome.
            match &plan.operation {
                RegularFileOperation::Write { durability, .. }
                | RegularFileOperation::Append { durability, .. }
                | RegularFileOperation::Truncate { durability, .. } => {
                    fail_after_mutation_if_requested(inject_after_mutation)?;
                    sync_for(file, *durability)?;
                }
                _ => {}
            }
        }
        Ok(())
    })();
    if let Err(failure) = operation_result {
        return Err(indeterminate_after_external_effect(
            failure,
            external_effect_may_have_occurred,
        ));
    }

    let validation = (|| {
        ensure_identity(file, stored.identity)?;
        let observed = read_all(file, plan.post_state.claim.max_size)?;
        ensure_content_matches(&observed, &plan.post_state)?;
        // Reopen the claimed pathname after the effect. The retained descriptor
        // alone is insufficient because an external rename/replace can leave it
        // referring to an unlinked object while the claimed path names another.
        let rebound = open_regular_at(
            root,
            &plan.post_state.claim.relative_path,
            plan.post_state.claim.access_mode,
        )?;
        ensure_identity(&rebound, stored.identity)?;
        ensure_content_matches(
            &read_all(&rebound, plan.post_state.claim.max_size)?,
            &plan.post_state,
        )
    })();
    validation.map_err(|failure| {
        indeterminate_after_external_effect(failure, external_effect_may_have_occurred)
    })
}

#[cfg(target_os = "linux")]
fn fail_after_mutation_if_requested(requested: bool) -> Result<(), ProviderError> {
    if requested { Err(error(ProviderErrorKind::OutcomeUnknown, true)) } else { Ok(()) }
}

#[cfg(target_os = "linux")]
fn indeterminate_after_external_effect(
    failure: ProviderError,
    external_effect_may_have_occurred: bool,
) -> ProviderError {
    if external_effect_may_have_occurred {
        error(ProviderErrorKind::OutcomeUnknown, true)
    } else {
        failure
    }
}

#[cfg(target_os = "linux")]
fn operation_changes_content(operation: &RegularFileOperation) -> bool {
    matches!(
        operation,
        RegularFileOperation::Write { .. }
            | RegularFileOperation::Append { .. }
            | RegularFileOperation::Truncate { .. }
    )
}

#[cfg(target_os = "linux")]
fn operation_needs_exclusive_lock(operation: &RegularFileOperation) -> bool {
    !matches!(operation, RegularFileOperation::Read { .. })
}

#[cfg(target_os = "linux")]
fn open_plan_file(
    root: &std::fs::File,
    stored: &StoredFile,
    plan: &StoredFilePlan,
) -> Result<(std::fs::File, bool), ProviderError> {
    match open_regular_at(
        root,
        &plan.pre_state.claim.relative_path,
        plan.pre_state.claim.access_mode,
    ) {
        Ok(file) if file_identity(&file)? == stored.identity => Ok((file, false)),
        Ok(_) if matches!(plan.operation, RegularFileOperation::Rename { .. }) => {
            open_renamed_plan_file(root, stored, plan)
        }
        Ok(_) => Err(error(ProviderErrorKind::Conflict, false)),
        Err(source)
            if matches!(plan.operation, RegularFileOperation::Rename { .. })
                && source.kind == ProviderErrorKind::NotFound =>
        {
            open_renamed_plan_file(root, stored, plan)
        }
        Err(source) => Err(source),
    }
}

#[cfg(target_os = "linux")]
fn open_renamed_plan_file(
    root: &std::fs::File,
    stored: &StoredFile,
    plan: &StoredFilePlan,
) -> Result<(std::fs::File, bool), ProviderError> {
    let file = open_regular_at(
        root,
        &plan.post_state.claim.relative_path,
        plan.post_state.claim.access_mode,
    )?;
    ensure_identity(&file, stored.identity)?;
    Ok((file, true))
}

#[cfg(target_os = "linux")]
fn open_root_on(
    connection: &rusqlite::Connection,
    node: contract_core::NodeIdentity,
    namespace: Identity,
) -> Result<std::fs::File, ProviderError> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt as _, path::PathBuf};

    let stored = connection
        .query_row(
            "SELECT root_path, device, inode, btime_seconds, btime_nanoseconds
             FROM regular_file_namespace_root
             WHERE node_id = ?1 AND namespace_id = ?2",
            params![node.0.0.as_slice(), namespace.0.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;
    let path = PathBuf::from(OsString::from_vec(stored.0));
    let identity = decode_native_identity(stored.1, stored.2, stored.3, stored.4)?;
    let root = open_root_path(&path)?;
    if directory_identity(&root)? != identity {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    Ok(root)
}

#[cfg(target_os = "linux")]
fn open_root_path(path: &std::path::Path) -> Result<std::fs::File, ProviderError> {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};

    let descriptor = openat2(
        CWD,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(errno_error)?;
    let file: std::fs::File = descriptor.into();
    directory_identity(&file)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_regular_at(
    root: &std::fs::File,
    path: &[u8],
    access: FileAccessMode,
) -> Result<std::fs::File, ProviderError> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};

    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

    validate_relative_path(path)?;
    let access = match access {
        FileAccessMode::ReadOnly => OFlags::RDONLY,
        FileAccessMode::ReadWrite | FileAccessMode::AppendOnly => OFlags::RDWR,
    };
    let descriptor = openat2(
        root,
        OsStr::from_bytes(path),
        access | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(errno_error)?;
    let file: std::fs::File = descriptor.into();
    file_identity(&file)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn validate_relative_path(path: &[u8]) -> Result<(), ProviderError> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _, path::Component};

    if path.is_empty() || path.contains(&0) {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    let mut count = 0_usize;
    for component in std::path::Path::new(OsStr::from_bytes(path)).components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        count += 1;
    }
    if count == 0 {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn file_identity(file: &std::fs::File) -> Result<NativeObjectIdentity, ProviderError> {
    native_object_identity(file, NativeObjectKind::RegularFile)
}

#[cfg(target_os = "linux")]
fn directory_identity(file: &std::fs::File) -> Result<NativeObjectIdentity, ProviderError> {
    native_object_identity(file, NativeObjectKind::Directory)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum NativeObjectKind {
    RegularFile,
    Directory,
}

#[cfg(target_os = "linux")]
fn native_object_identity(
    file: &std::fs::File,
    expected_kind: NativeObjectKind,
) -> Result<NativeObjectIdentity, ProviderError> {
    use rustix::fs::{AtFlags, FileType, StatxFlags, makedev, statx};

    let metadata =
        statx(file, c"", AtFlags::EMPTY_PATH, StatxFlags::BASIC_STATS | StatxFlags::BTIME)
            .map_err(errno_error)?;
    let present = StatxFlags::from_bits_retain(metadata.stx_mask);
    validate_statx_identity_metadata(present, metadata.stx_btime.tv_nsec)?;

    let observed_kind = FileType::from_raw_mode(metadata.stx_mode as _);
    let expected_kind_matches = match expected_kind {
        NativeObjectKind::RegularFile => observed_kind.is_file(),
        NativeObjectKind::Directory => observed_kind.is_dir(),
    };
    if !expected_kind_matches {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    Ok(NativeObjectIdentity {
        device: makedev(metadata.stx_dev_major, metadata.stx_dev_minor) as u64,
        inode: metadata.stx_ino,
        btime_seconds: metadata.stx_btime.tv_sec,
        btime_nanoseconds: metadata.stx_btime.tv_nsec,
    })
}

#[cfg(target_os = "linux")]
fn validate_statx_identity_metadata(
    present: rustix::fs::StatxFlags,
    btime_nanoseconds: u32,
) -> Result<(), ProviderError> {
    use rustix::fs::StatxFlags;

    if !present.contains(StatxFlags::TYPE | StatxFlags::INO | StatxFlags::BTIME) {
        return Err(error(ProviderErrorKind::Unsupported, false));
    }
    validate_btime_nanoseconds(btime_nanoseconds)
}

#[cfg(target_os = "linux")]
fn ensure_identity(
    file: &std::fs::File,
    expected: NativeObjectIdentity,
) -> Result<(), ProviderError> {
    if file_identity(file)? != expected {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_file_matches(
    file: &std::fs::File,
    identity: NativeObjectIdentity,
    state: &RegularFileState,
) -> Result<(), ProviderError> {
    ensure_identity(file, identity)?;
    let bytes = read_all(file, state.claim.max_size)?;
    ensure_content_matches(&bytes, state)
}

#[cfg(target_os = "linux")]
fn ensure_content_matches(bytes: &[u8], state: &RegularFileState) -> Result<(), ProviderError> {
    if bytes.len() as u64 != state.size || digest_bytes(bytes)? != state.content_digest {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_all(file: &std::fs::File, max_size: u64) -> Result<Vec<u8>, ProviderError> {
    use std::os::unix::fs::FileExt as _;

    let metadata = file.metadata().map_err(io_error)?;
    if metadata.len() > max_size {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    let length =
        usize::try_from(metadata.len()).map_err(|_| error(ProviderErrorKind::Storage, false))?;
    let mut bytes = vec![0_u8; length];
    let mut read = 0_usize;
    while read < bytes.len() {
        let count = file.read_at(&mut bytes[read..], read as u64).map_err(io_error)?;
        if count == 0 {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        read += count;
    }
    let after = file.metadata().map_err(io_error)?;
    if after.len() != metadata.len() {
        return Err(error(ProviderErrorKind::OutcomeUnknown, true));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn write_all_at(file: &std::fs::File, bytes: &[u8], offset: u64) -> Result<(), ProviderError> {
    use std::os::unix::fs::FileExt as _;

    let mut written = 0_usize;
    while written < bytes.len() {
        let position = offset
            .checked_add(written as u64)
            .ok_or_else(|| error(ProviderErrorKind::InvalidRequest, false))?;
        let count = file.write_at(&bytes[written..], position).map_err(io_error)?;
        if count == 0 {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        written += count;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_for(file: &std::fs::File, durability: FileDurability) -> Result<(), ProviderError> {
    match durability {
        FileDurability::Visible => Ok(()),
        FileDurability::Data => rustix::fs::fdatasync(file).map_err(errno_error),
        FileDurability::DataAndMetadata => rustix::fs::fsync(file).map_err(errno_error),
    }
}

#[cfg(target_os = "linux")]
fn lock_exclusive(file: &std::fs::File) -> Result<(), ProviderError> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |source| {
            if source == rustix::io::Errno::AGAIN {
                error(ProviderErrorKind::Conflict, true)
            } else {
                errno_error(source)
            }
        },
    )
}

#[cfg(target_os = "linux")]
fn rename_noreplace(
    root: &std::fs::File,
    old_path: &[u8],
    new_path: &[u8],
) -> Result<(), ProviderError> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};

    use rustix::fs::RenameFlags;

    let (old_parent, old_name) = parent_and_name(old_path)?;
    let (new_parent, new_name) = parent_and_name(new_path)?;
    let old_directory = open_parent(root, old_parent)?;
    let new_directory = open_parent(root, new_parent)?;
    rustix::fs::renameat_with(
        &old_directory,
        OsStr::from_bytes(old_name),
        &new_directory,
        OsStr::from_bytes(new_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(errno_error)
}

#[cfg(target_os = "linux")]
fn sync_rename_parents(
    root: &std::fs::File,
    old_path: &[u8],
    new_path: &[u8],
    durability: FileDurability,
) -> Result<(), ProviderError> {
    let (old_parent, _) = parent_and_name(old_path)?;
    let (new_parent, _) = parent_and_name(new_path)?;
    let old_directory = open_parent(root, old_parent)?;
    let new_directory = open_parent(root, new_parent)?;
    if durability == FileDurability::DataAndMetadata {
        rustix::fs::fsync(&old_directory).map_err(errno_error)?;
        if old_parent != new_parent {
            rustix::fs::fsync(&new_directory).map_err(errno_error)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parent_and_name(path: &[u8]) -> Result<(&[u8], &[u8]), ProviderError> {
    validate_relative_path(path)?;
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(index) if index > 0 && index + 1 < path.len() => {
            Ok((&path[..index], &path[index + 1..]))
        }
        Some(_) => Err(error(ProviderErrorKind::InvalidRequest, false)),
        None => Ok((b".", path)),
    }
}

#[cfg(target_os = "linux")]
fn open_parent(root: &std::fs::File, path: &[u8]) -> Result<std::fs::File, ProviderError> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};

    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

    let descriptor = openat2(
        root,
        OsStr::from_bytes(path),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(errno_error)?;
    Ok(descriptor.into())
}

#[cfg(target_os = "linux")]
fn digest_bytes(bytes: &[u8]) -> Result<contract_core::Digest, ProviderError> {
    contract_core::canonical_digest(bytes).map_err(|_| error(ProviderErrorKind::Integrity, false))
}

#[cfg(target_os = "linux")]
fn errno_error(source: rustix::io::Errno) -> ProviderError {
    use rustix::io::Errno;

    match source {
        Errno::NOENT | Errno::NOTDIR => error(ProviderErrorKind::NotFound, false),
        Errno::ACCESS | Errno::PERM => error(ProviderErrorKind::Denied, false),
        Errno::EXIST | Errno::LOOP | Errno::XDEV => error(ProviderErrorKind::Conflict, false),
        Errno::AGAIN | Errno::BUSY => error(ProviderErrorKind::Unavailable, true),
        Errno::NOSYS | Errno::INVAL => error(ProviderErrorKind::Unsupported, false),
        _ => error(ProviderErrorKind::Storage, false),
    }
}

#[cfg(target_os = "linux")]
fn io_error(source: std::io::Error) -> ProviderError {
    match source.kind() {
        std::io::ErrorKind::NotFound => error(ProviderErrorKind::NotFound, false),
        std::io::ErrorKind::PermissionDenied => error(ProviderErrorKind::Denied, false),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {
            error(ProviderErrorKind::Unavailable, true)
        }
        _ => error(ProviderErrorKind::Storage, false),
    }
}

fn profile_payload_error(error_value: visa_profile::ProfilePayloadError) -> ProviderError {
    use visa_profile::ProfilePayloadError;

    match error_value {
        ProfilePayloadError::UnknownProfile
        | ProfilePayloadError::VersionMismatch
        | ProfilePayloadError::UnsupportedContinuity => {
            error(ProviderErrorKind::Unsupported, false)
        }
        ProfilePayloadError::AccessMismatch => error(ProviderErrorKind::Denied, false),
        ProfilePayloadError::ResourceMismatch | ProfilePayloadError::StateConflict => {
            error(ProviderErrorKind::Conflict, false)
        }
        ProfilePayloadError::MissingExtension
        | ProfilePayloadError::DuplicateExtension
        | ProfilePayloadError::InvalidPayload => error(ProviderErrorKind::InvalidRequest, false),
    }
}

pub(crate) fn validate_profile_binding_on(
    connection: &rusqlite::Connection,
    resource: EntityRef,
    profile: Identity,
    node: contract_core::NodeIdentity,
) -> Result<(), ProviderError> {
    if profile == LOGICAL_REQUEST_EXTENSION_ID {
        return crate::logical_request::validate_binding_on(connection, resource, node);
    }
    if profile != REGULAR_FILE_EXTENSION_ID {
        return Err(error(ProviderErrorKind::Unsupported, false));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (connection, resource, node);
        Err(error(ProviderErrorKind::Unsupported, false))
    }
    #[cfg(target_os = "linux")]
    {
        let stored = require_file_on(connection, resource)?;
        let root = open_root_on(connection, node, stored.namespace)?;
        let file = open_regular_at(
            &root,
            &stored.state.claim.relative_path,
            stored.state.claim.access_mode,
        )?;
        ensure_identity(&file, stored.identity)?;
        ensure_file_matches(&file, stored.identity, &stored.state)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use contract_core::{
        AuthorityGrant, CONTRACT_VERSION, Digest, Event, EventKind, Generation, IdempotencyKey,
        JournalEntry, JournalPosition, LeaseEpoch, NodeIdentity, ProfileAccess, Rights,
    };
    use substrate_api::{
        AuthorityPort, BindingKind, BindingPort, BindingRequest, CommitBundle, JournalPort,
        JournalScope, LeasePort, LeaseRecord, LeaseTransition, ReauthorizationRequest,
    };
    use visa_profile::{
        ContinuityDisposition, FileLockPolicy, RegularFileClaim, encode_regular_file_operation,
    };

    use super::*;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    struct TestPaths {
        root: PathBuf,
        db: PathBuf,
    }

    impl TestPaths {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("visa-regular-file-{label}-{}-{sequence}", std::process::id()));
            std::fs::create_dir(&root).expect("root creates");
            Self { db: root.join("provider.sqlite3"), root }
        }
    }

    impl Drop for TestPaths {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn id(value: u128) -> Identity {
        Identity::from_u128(value)
    }

    fn entity(value: u128) -> EntityRef {
        EntityRef::initial(id(value))
    }

    fn digest(bytes: &[u8]) -> Digest {
        digest_bytes(bytes).expect("content hashes")
    }

    struct Fixture {
        provider: SqliteProvider,
        state: RegularFileState,
        node: NodeIdentity,
        subject: EntityRef,
        authority: EntityRef,
    }

    fn fixture(paths: &TestPaths, bytes: &[u8]) -> Fixture {
        std::fs::write(paths.root.join("data.bin"), bytes).expect("file writes");
        let node = NodeIdentity::new(id(1));
        let subject = entity(2);
        let resource = entity(3);
        let authority = entity(4);
        let rights = Rights::PROFILE_READ
            .union(Rights::PROFILE_WRITE)
            .union(Rights::PROFILE_CONTROL)
            .union(Rights::REBIND);
        let state = RegularFileState {
            claim: RegularFileClaim {
                resource,
                namespace: id(5),
                relative_path: b"data.bin".to_vec(),
                required_rights: rights,
                access_mode: FileAccessMode::ReadWrite,
                durability: FileDurability::Visible,
                lock_policy: FileLockPolicy::ExclusiveLease,
                max_size: 1024,
            },
            logical_offset: 0,
            version: 1,
            size: bytes.len() as u64,
            content_digest: digest(bytes),
            durable_through: FileDurability::Visible,
            lock_state: FileLockState::Unlocked,
            disposition: ContinuityDisposition::Revalidate,
            last_operation: None,
        };
        let mut provider =
            SqliteProvider::open(&paths.db, JournalScope { node, component: subject.identity })
                .expect("provider opens");
        provider
            .install_policy(substrate_api::AuthorityPolicy {
                subject,
                resource,
                allowed_rights: rights,
            })
            .expect("policy installs");
        provider
            .install_grant(&AuthorityGrant::active_root(authority, subject, resource, rights))
            .expect("grant installs");
        provider
            .initialize_lease(LeaseRecord { resource, owner: node, epoch: LeaseEpoch(1) })
            .expect("lease installs");
        provider.provision_regular_file(&state, &paths.root).expect("file provisions");
        Fixture { provider, state, node, subject, authority }
    }

    fn request(
        fixture: &Fixture,
        operation_id: u128,
        operation: RegularFileOperation,
    ) -> EffectRequest {
        let access = match operation {
            RegularFileOperation::Read { .. } => ProfileAccess::Read,
            RegularFileOperation::Write { .. }
            | RegularFileOperation::Append { .. }
            | RegularFileOperation::Truncate { .. }
            | RegularFileOperation::Rename { .. } => ProfileAccess::Write,
            _ => ProfileAccess::Control,
        };
        EffectRequest {
            operation: id(operation_id),
            idempotency_key: IdempotencyKey::from_u128(operation_id + 1000),
            causal_parent: None,
            node: fixture.node,
            subject: fixture.subject,
            resource: fixture.state.claim.resource,
            authority: fixture.authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: Digest::ZERO,
            kind: EffectKind::Profile {
                profile: REGULAR_FILE_EXTENSION_ID,
                access,
                payload: encode_regular_file_operation(&operation).expect("operation encodes"),
            },
        }
    }

    fn append_intent(provider: &mut SqliteProvider, position: u64, request: &EffectRequest) {
        provider
            .append_entry(&JournalEntry {
                version: CONTRACT_VERSION,
                position: JournalPosition(position),
                input_state: Digest::from_bytes([position as u8 - 1; 32]),
                output_state: Digest::from_bytes([position as u8; 32]),
                event: Event::new(
                    id(10_000 + position as u128),
                    EventKind::EffectPrepared { request: request.clone() },
                ),
            })
            .expect("intent appends");
    }

    fn result_state(
        state: &RegularFileState,
        request: &EffectRequest,
        outcome: &EffectOutcome,
    ) -> RegularFileState {
        let mut extension = regular_file_extension(state).expect("extension encodes");
        let EffectOutcome::Succeeded { result, .. } = outcome else { panic!("success") };
        visa_profile::apply_profile_result(
            std::slice::from_mut(&mut extension),
            &request.kind,
            result,
            request.operation,
        )
        .expect("result applies");
        regular_file_state(&extension).expect("state decodes")
    }

    #[test]
    fn write_append_truncate_and_rename_are_versioned_and_bounded() {
        let paths = TestPaths::new("mutations");
        let mut fixture = fixture(&paths, b"abcd");

        let write = request(
            &fixture,
            20,
            RegularFileOperation::Write {
                bytes: b"XY".to_vec(),
                durability: FileDurability::Visible,
            },
        );
        append_intent(&mut fixture.provider, 1, &write);
        let outcome = fixture
            .provider
            .execute_profile(&write, &regular_file_extension(&fixture.state).unwrap())
            .expect("write succeeds");
        fixture.state = result_state(&fixture.state, &write, &outcome);
        assert_eq!(std::fs::read(paths.root.join("data.bin")).unwrap(), b"XYcd");
        assert_eq!(fixture.state.version, 2);

        let append = request(
            &fixture,
            21,
            RegularFileOperation::Append { bytes: b"!".to_vec(), durability: FileDurability::Data },
        );
        append_intent(&mut fixture.provider, 2, &append);
        let outcome = fixture
            .provider
            .execute_profile(&append, &regular_file_extension(&fixture.state).unwrap())
            .expect("append succeeds");
        fixture.state = result_state(&fixture.state, &append, &outcome);
        assert_eq!(std::fs::read(paths.root.join("data.bin")).unwrap(), b"XYcd!");

        let truncate = request(
            &fixture,
            22,
            RegularFileOperation::Truncate { size: 3, durability: FileDurability::DataAndMetadata },
        );
        append_intent(&mut fixture.provider, 3, &truncate);
        let outcome = fixture
            .provider
            .execute_profile(&truncate, &regular_file_extension(&fixture.state).unwrap())
            .expect("truncate succeeds");
        fixture.state = result_state(&fixture.state, &truncate, &outcome);
        assert_eq!(std::fs::read(paths.root.join("data.bin")).unwrap(), b"XYc");

        let rename = request(
            &fixture,
            23,
            RegularFileOperation::Rename { relative_path: b"renamed.bin".to_vec() },
        );
        append_intent(&mut fixture.provider, 4, &rename);
        let outcome = fixture
            .provider
            .execute_profile(&rename, &regular_file_extension(&fixture.state).unwrap())
            .expect("rename succeeds");
        fixture.state = result_state(&fixture.state, &rename, &outcome);
        assert!(!paths.root.join("data.bin").exists());
        assert_eq!(std::fs::read(paths.root.join("renamed.bin")).unwrap(), b"XYc");
        assert_eq!(fixture.state.version, 5);
    }

    #[test]
    fn rename_never_replaces_an_existing_target() {
        let paths = TestPaths::new("rename-noreplace");
        let mut fixture = fixture(&paths, b"source");
        std::fs::write(paths.root.join("occupied.bin"), b"occupied").unwrap();
        let rename = request(
            &fixture,
            24,
            RegularFileOperation::Rename { relative_path: b"occupied.bin".to_vec() },
        );
        append_intent(&mut fixture.provider, 1, &rename);

        let failure = fixture
            .provider
            .execute_profile(&rename, &regular_file_extension(&fixture.state).unwrap())
            .unwrap_err();

        assert_eq!(failure.kind, ProviderErrorKind::Conflict);
        assert_eq!(std::fs::read(paths.root.join("data.bin")).unwrap(), b"source");
        assert_eq!(std::fs::read(paths.root.join("occupied.bin")).unwrap(), b"occupied");
    }

    #[test]
    fn post_commit_fault_reconciles_without_repeating_append() {
        let paths = TestPaths::new("reconcile");
        let mut fixture = fixture(&paths, b"a");
        let append = request(
            &fixture,
            30,
            RegularFileOperation::Append { bytes: b"b".to_vec(), durability: FileDurability::Data },
        );
        append_intent(&mut fixture.provider, 1, &append);
        fixture.provider.inject_failure_once(FaultPoint::AfterProfileCommit);
        let failure = fixture
            .provider
            .execute_profile(&append, &regular_file_extension(&fixture.state).unwrap())
            .expect_err("acknowledgement is lost");
        assert_eq!(failure.kind, ProviderErrorKind::OutcomeUnknown);
        assert_eq!(std::fs::read(paths.root.join("data.bin")).unwrap(), b"ab");

        let observed = fixture
            .provider
            .query_profile_operation(append.operation, append.idempotency_key)
            .expect("query succeeds")
            .expect("outcome is durable");
        let retried = fixture
            .provider
            .execute_profile(&append, &regular_file_extension(&fixture.state).unwrap())
            .expect("retry deduplicates");
        assert_eq!(retried, observed);
        assert_eq!(std::fs::read(paths.root.join("data.bin")).unwrap(), b"ab");
    }

    #[test]
    fn committed_lease_epoch_fences_source_between_plan_and_file_effect() {
        let paths = TestPaths::new("lease-effect-fence");
        let mut fixture = fixture(&paths, b"a");
        let append = request(
            &fixture,
            1_000_000 + u128::from(NEXT_TEST.fetch_add(1, Ordering::Relaxed)),
            RegularFileOperation::Append { bytes: b"b".to_vec(), durability: FileDurability::Data },
        );
        append_intent(&mut fixture.provider, 1, &append);
        let extension = regular_file_extension(&fixture.state).expect("extension encodes");
        let resource = fixture.state.claim.resource;
        let source_node = fixture.node;
        let destination_node = NodeIdentity::new(id(90));
        let destination_subject = EntityRef::new(fixture.subject.identity, Generation(1));
        let destination_authority = entity(91);
        let handoff_resource = entity(92);
        let handoff_authority = entity(93);
        let handoff = id(94);
        let snapshot = id(95);
        fixture
            .provider
            .install_policy(substrate_api::AuthorityPolicy {
                subject: destination_subject,
                resource,
                allowed_rights: fixture.state.claim.required_rights,
            })
            .expect("destination file policy installs");
        fixture
            .provider
            .reauthorize(ReauthorizationRequest {
                handoff,
                snapshot,
                source_authority: fixture.authority,
                destination_authority,
                destination_subject,
                resource,
                required_rights: fixture.state.claim.required_rights,
            })
            .expect("destination file authority prepares");
        fixture
            .provider
            .install_policy(substrate_api::AuthorityPolicy {
                subject: destination_subject,
                resource: handoff_resource,
                allowed_rights: Rights::HANDOFF,
            })
            .expect("destination handoff policy installs");
        fixture
            .provider
            .install_grant(&AuthorityGrant::active_root(
                handoff_authority,
                destination_subject,
                handoff_resource,
                Rights::HANDOFF,
            ))
            .expect("destination handoff authority installs");
        let lease_commit = EffectRequest {
            operation: id(96),
            idempotency_key: IdempotencyKey::from_u128(10_096),
            causal_parent: None,
            node: destination_node,
            subject: destination_subject,
            resource: handoff_resource,
            authority: handoff_authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: Digest::ZERO,
            kind: EffectKind::LeaseCommit {
                handoff,
                snapshot,
                destination: destination_node,
                expected_epoch: LeaseEpoch(1),
                next_epoch: LeaseEpoch(2),
            },
        };
        append_intent(&mut fixture.provider, 2, &lease_commit);
        let prepared = fixture
            .provider
            .prepare_transitions(&lease_commit, &[resource])
            .expect("lease transition prepares");
        let bundle = CommitBundle {
            entry: JournalEntry {
                version: CONTRACT_VERSION,
                position: JournalPosition(3),
                input_state: Digest::from_bytes([2; 32]),
                output_state: Digest::from_bytes([3; 32]),
                event: Event::new(
                    id(20_003),
                    EventKind::HandoffCommitted {
                        operation: lease_commit.operation,
                        handoff,
                        snapshot,
                        source: source_node,
                        destination: destination_node,
                        previous_epoch: LeaseEpoch(1),
                        new_epoch: LeaseEpoch(2),
                        outcome: prepared.outcome.clone(),
                    },
                ),
            },
            lease_transitions: prepared.transitions,
            final_authorities: vec![destination_authority],
        };
        let scope = fixture.provider.scope;
        let (fence_reached, resume_source) = install_regular_file_fence_pause(append.operation);

        let mut source = fixture.provider;
        let source_thread = std::thread::spawn(move || {
            source.execute_profile(&append, &extension).expect_err("old source is fenced")
        });
        fence_reached
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("source persists its plan before the effect fence");

        let mut committer = SqliteProvider::open(&paths.db, scope)
            .expect("lease committer opens shared provider database");
        committer.commit_bundle(&bundle).expect("handoff and lease epoch commit atomically");
        assert_eq!(
            committer.current_lease(resource).expect("lease reads"),
            Some(LeaseRecord { resource, owner: destination_node, epoch: LeaseEpoch(2) })
        );

        resume_source.send(()).expect("source resumes after lease commit");
        let failure = source_thread.join().expect("source thread joins");
        assert_eq!(failure.kind, ProviderErrorKind::StaleEpoch);
        assert_eq!(
            std::fs::read(paths.root.join("data.bin")).expect("file remains readable"),
            b"a",
            "a source fenced by a committed epoch must not mutate the file"
        );
    }

    #[test]
    fn committed_lease_epoch_also_fences_durable_plan_reconciliation() {
        let paths = TestPaths::new("lease-reconcile-fence");
        let mut fixture = fixture(&paths, b"a");
        let append = request(
            &fixture,
            34,
            RegularFileOperation::Append { bytes: b"b".to_vec(), durability: FileDurability::Data },
        );
        append_intent(&mut fixture.provider, 1, &append);
        fixture.provider.inject_failure_once(FaultPoint::BeforeProfileEffect);
        assert_eq!(
            fixture
                .provider
                .execute_profile(&append, &regular_file_extension(&fixture.state).unwrap())
                .expect_err("durable plan pauses before the effect")
                .kind,
            ProviderErrorKind::Unavailable
        );

        let destination_node = NodeIdentity::new(id(92));
        let transaction = fixture.provider.immediate_transaction().expect("lease transaction");
        crate::lease::apply_transition(
            &transaction,
            LeaseTransition {
                resource: fixture.state.claim.resource,
                expected_owner: fixture.node,
                next_owner: destination_node,
                expected_epoch: LeaseEpoch(1),
                next_epoch: LeaseEpoch(2),
            },
        )
        .expect("lease transition applies");
        transaction.commit().expect("lease transition commits");

        assert_eq!(
            fixture
                .provider
                .reconcile_profile_operation(
                    &append,
                    &regular_file_extension(&fixture.state).unwrap(),
                )
                .expect_err("old source cannot replay a durable plan after transfer")
                .kind,
            ProviderErrorKind::StaleEpoch
        );
        assert_eq!(std::fs::read(paths.root.join("data.bin")).unwrap(), b"a");
    }

    #[test]
    fn effect_before_outcome_fault_recovers_from_the_durable_plan() {
        let paths = TestPaths::new("effect-recovery");
        let mut fixture = fixture(&paths, b"a");
        let append = request(
            &fixture,
            35,
            RegularFileOperation::Append { bytes: b"b".to_vec(), durability: FileDurability::Data },
        );
        append_intent(&mut fixture.provider, 1, &append);
        fixture.provider.inject_failure_once(FaultPoint::AfterProfileEffect);
        let failure = fixture
            .provider
            .execute_profile(&append, &regular_file_extension(&fixture.state).unwrap())
            .expect_err("effect completion is initially unknown");
        assert_eq!(failure.kind, ProviderErrorKind::OutcomeUnknown);
        assert_eq!(std::fs::read(paths.root.join("data.bin")).unwrap(), b"ab");
        assert_eq!(
            fixture
                .provider
                .query_profile_operation(append.operation, append.idempotency_key)
                .expect("query succeeds"),
            None
        );

        let recovered = fixture
            .provider
            .reconcile_profile_operation(&append, &regular_file_extension(&fixture.state).unwrap())
            .expect("reconciliation completes the durable plan")
            .expect("reconciled outcome is durable");
        assert!(matches!(recovered, EffectOutcome::Succeeded { .. }));
        assert_eq!(std::fs::read(paths.root.join("data.bin")).unwrap(), b"ab");
    }

    #[test]
    fn indeterminate_operation_cleanup_preserves_the_reconciliation_plan() {
        let paths = TestPaths::new("indeterminate-cleanup");
        let mut fixture = fixture(&paths, b"a");
        let append = request(
            &fixture,
            35_001,
            RegularFileOperation::Append { bytes: b"b".to_vec(), durability: FileDurability::Data },
        );
        append_intent(&mut fixture.provider, 1, &append);
        fixture.provider.inject_failure_once(FaultPoint::BeforeProfileEffect);
        fixture
            .provider
            .execute_profile(&append, &regular_file_extension(&fixture.state).unwrap())
            .expect_err("the durable plan pauses before its effect");
        crate::write_outcome(
            &fixture.provider.connection,
            append.operation,
            &EffectOutcome::Indeterminate { evidence: None },
        )
        .expect("indeterminate truth records");

        assert_eq!(
            fixture.provider.cleanup_profile_operation(&append).unwrap_err(),
            error(ProviderErrorKind::OutcomeUnknown, true)
        );
        assert!(
            load_plan_on(&fixture.provider.connection, append.operation)
                .expect("plan query succeeds")
                .is_some(),
            "cleanup rejection must retain the only reconciliation plan"
        );
    }

    #[test]
    fn post_mutation_write_and_rename_faults_reconcile_from_the_durable_plan() {
        let write_paths = TestPaths::new("post-mutation-write");
        let mut write_fixture = fixture(&write_paths, b"abcd");
        let write = request(
            &write_fixture,
            36,
            RegularFileOperation::Write { bytes: b"XY".to_vec(), durability: FileDurability::Data },
        );
        append_intent(&mut write_fixture.provider, 1, &write);
        write_fixture.provider.inject_failure_once(FaultPoint::AfterRegularFileMutation);
        assert_eq!(
            write_fixture
                .provider
                .execute_profile(&write, &regular_file_extension(&write_fixture.state).unwrap(),)
                .unwrap_err()
                .kind,
            ProviderErrorKind::OutcomeUnknown
        );
        assert_eq!(std::fs::read(write_paths.root.join("data.bin")).unwrap(), b"XYcd");
        let write_outcome = write_fixture
            .provider
            .reconcile_profile_operation(
                &write,
                &regular_file_extension(&write_fixture.state).unwrap(),
            )
            .unwrap()
            .unwrap();
        write_fixture.state = result_state(&write_fixture.state, &write, &write_outcome);
        assert_eq!(write_fixture.state.version, 2);

        let rename_paths = TestPaths::new("post-mutation-rename");
        let mut rename_fixture = fixture(&rename_paths, b"rename");
        let rename = request(
            &rename_fixture,
            37,
            RegularFileOperation::Rename { relative_path: b"renamed.bin".to_vec() },
        );
        append_intent(&mut rename_fixture.provider, 1, &rename);
        rename_fixture.provider.inject_failure_once(FaultPoint::AfterRegularFileMutation);
        assert_eq!(
            rename_fixture
                .provider
                .execute_profile(&rename, &regular_file_extension(&rename_fixture.state).unwrap(),)
                .unwrap_err()
                .kind,
            ProviderErrorKind::OutcomeUnknown
        );
        assert!(!rename_paths.root.join("data.bin").exists());
        assert_eq!(std::fs::read(rename_paths.root.join("renamed.bin")).unwrap(), b"rename");
        let rename_outcome = rename_fixture
            .provider
            .reconcile_profile_operation(
                &rename,
                &regular_file_extension(&rename_fixture.state).unwrap(),
            )
            .unwrap()
            .unwrap();
        rename_fixture.state = result_state(&rename_fixture.state, &rename, &rename_outcome);
        assert_eq!(rename_fixture.state.claim.relative_path, b"renamed.bin");
        assert_eq!(rename_fixture.state.version, 2);
    }

    #[test]
    fn replacement_symlink_escape_and_external_content_change_fail_closed() {
        use std::os::unix::fs::symlink;

        let paths = TestPaths::new("revalidate");
        let mut fixture = fixture(&paths, b"original");
        std::fs::write(paths.root.join("data.bin"), b"changed").unwrap();
        let read = request(&fixture, 40, RegularFileOperation::Read { max_bytes: 8 });
        append_intent(&mut fixture.provider, 1, &read);
        assert_eq!(
            fixture
                .provider
                .execute_profile(&read, &regular_file_extension(&fixture.state).unwrap())
                .expect_err("external change rejects")
                .kind,
            ProviderErrorKind::Conflict
        );

        std::fs::write(paths.root.join("replacement.bin"), b"original").unwrap();
        std::fs::rename(paths.root.join("replacement.bin"), paths.root.join("data.bin")).unwrap();
        let replacement = request(&fixture, 41, RegularFileOperation::Read { max_bytes: 8 });
        append_intent(&mut fixture.provider, 2, &replacement);
        assert_eq!(
            fixture
                .provider
                .execute_profile(&replacement, &regular_file_extension(&fixture.state).unwrap())
                .expect_err("same-content inode replacement rejects")
                .kind,
            ProviderErrorKind::Conflict
        );

        std::fs::remove_file(paths.root.join("data.bin")).unwrap();
        symlink("/etc/passwd", paths.root.join("data.bin")).unwrap();
        let second = request(&fixture, 42, RegularFileOperation::Read { max_bytes: 8 });
        append_intent(&mut fixture.provider, 3, &second);
        assert!(matches!(
            fixture
                .provider
                .execute_profile(&second, &regular_file_extension(&fixture.state).unwrap())
                .expect_err("symlink rejects")
                .kind,
            ProviderErrorKind::Conflict | ProviderErrorKind::NotFound
        ));
    }

    #[test]
    fn statx_identity_includes_birth_time_on_the_current_file_system() {
        use rustix::fs::fstat;

        let paths = TestPaths::new("statx-btime");
        std::fs::write(paths.root.join("data.bin"), b"identity").unwrap();
        let root = open_root_path(&paths.root).expect("root statx identity is supported");
        let file = open_regular_at(&root, b"data.bin", FileAccessMode::ReadWrite)
            .expect("file statx identity is supported");
        let root_identity = directory_identity(&root).unwrap();
        let file_identity = file_identity(&file).unwrap();
        let root_stat = fstat(&root).unwrap();
        let file_stat = fstat(&file).unwrap();

        assert_eq!(root_identity.device, root_stat.st_dev as u64);
        assert_eq!(root_identity.inode, root_stat.st_ino as u64);
        assert_eq!(file_identity.device, file_stat.st_dev as u64);
        assert_eq!(file_identity.inode, file_stat.st_ino as u64);
        assert!(root_identity.btime_nanoseconds < 1_000_000_000);
        assert!(file_identity.btime_nanoseconds < 1_000_000_000);
        assert_eq!(directory_identity(&root).unwrap(), root_identity);
        assert_eq!(super::file_identity(&file).unwrap(), file_identity);
    }

    #[test]
    fn statx_identity_fails_closed_on_missing_fields_and_invalid_time() {
        use rustix::fs::StatxFlags;

        let required = StatxFlags::TYPE | StatxFlags::INO | StatxFlags::BTIME;
        for missing in [StatxFlags::TYPE, StatxFlags::INO, StatxFlags::BTIME] {
            assert_eq!(
                validate_statx_identity_metadata(required - missing, 0)
                    .expect_err("every native identity field is mandatory")
                    .kind,
                ProviderErrorKind::Unsupported
            );
        }
        assert_eq!(
            validate_statx_identity_metadata(required, 1_000_000_000)
                .expect_err("invalid statx birth time is corrupt")
                .kind,
            ProviderErrorKind::Integrity
        );
    }

    #[test]
    fn birth_time_mismatch_rejects_same_device_and_inode_for_file_and_root() {
        let file_paths = TestPaths::new("file-btime-mismatch");
        let file_fixture = fixture(&file_paths, b"same native numbers");
        let stored_file =
            require_file_on(&file_fixture.provider.connection, file_fixture.state.claim.resource)
                .unwrap();
        let mismatched_file_btime = stored_file.identity.btime_seconds.wrapping_add(1);
        file_fixture
            .provider
            .connection
            .execute(
                "UPDATE regular_file_resource SET btime_seconds = ?3
                 WHERE resource_id = ?1 AND resource_generation = ?2",
                params![
                    file_fixture.state.claim.resource.identity.0.as_slice(),
                    generation(file_fixture.state.claim.resource.generation),
                    mismatched_file_btime.to_be_bytes(),
                ],
            )
            .unwrap();
        let mismatched_file =
            require_file_on(&file_fixture.provider.connection, file_fixture.state.claim.resource)
                .unwrap();
        assert_eq!(mismatched_file.identity.device, stored_file.identity.device);
        assert_eq!(mismatched_file.identity.inode, stored_file.identity.inode);
        assert_ne!(mismatched_file.identity.btime_seconds, stored_file.identity.btime_seconds);
        assert_eq!(
            validate_profile_binding_on(
                &file_fixture.provider.connection,
                file_fixture.state.claim.resource,
                REGULAR_FILE_EXTENSION_ID,
                file_fixture.node,
            )
            .expect_err("same dev+ino with a different file btime is rejected")
            .kind,
            ProviderErrorKind::Conflict
        );

        let root_paths = TestPaths::new("root-btime-mismatch");
        let root_fixture = fixture(&root_paths, b"same root native numbers");
        let root = open_root_path(&root_paths.root).unwrap();
        let root_identity = directory_identity(&root).unwrap();
        let mismatched_root_btime = root_identity.btime_seconds.wrapping_add(1);
        root_fixture
            .provider
            .connection
            .execute(
                "UPDATE regular_file_namespace_root SET btime_seconds = ?3
                 WHERE node_id = ?1 AND namespace_id = ?2",
                params![
                    root_fixture.node.0.0.as_slice(),
                    root_fixture.state.claim.namespace.0.as_slice(),
                    mismatched_root_btime.to_be_bytes(),
                ],
            )
            .unwrap();
        assert_eq!(
            validate_profile_binding_on(
                &root_fixture.provider.connection,
                root_fixture.state.claim.resource,
                REGULAR_FILE_EXTENSION_ID,
                root_fixture.node,
            )
            .expect_err("same dev+ino with a different root btime is rejected")
            .kind,
            ProviderErrorKind::Conflict
        );
    }

    #[test]
    fn invalid_stored_birth_time_fails_integrity_closed() {
        let paths = TestPaths::new("invalid-btime");
        let fixture = fixture(&paths, b"identity");
        fixture
            .provider
            .connection
            .execute(
                "UPDATE regular_file_resource SET btime_nanoseconds = ?3
                 WHERE resource_id = ?1 AND resource_generation = ?2",
                params![
                    fixture.state.claim.resource.identity.0.as_slice(),
                    generation(fixture.state.claim.resource.generation),
                    1_000_000_000_u32.to_be_bytes(),
                ],
            )
            .unwrap();
        assert_eq!(
            require_file_on(&fixture.provider.connection, fixture.state.claim.resource)
                .expect_err("an impossible birth-time nanosecond value is corrupt")
                .kind,
            ProviderErrorKind::Integrity
        );
    }

    #[test]
    fn profile_binding_requires_a_provisioned_target_root_and_revalidates_identity() {
        let paths = TestPaths::new("binding");
        let mut fixture = fixture(&paths, b"bound");
        let destination = NodeIdentity::new(id(60));
        let destination_subject = EntityRef::new(fixture.subject.identity, Generation(1));
        let destination_authority = entity(61);
        let handoff = id(62);
        let snapshot = id(63);
        let rights = fixture.state.claim.required_rights;
        fixture
            .provider
            .install_policy(substrate_api::AuthorityPolicy {
                subject: destination_subject,
                resource: fixture.state.claim.resource,
                allowed_rights: rights,
            })
            .expect("destination policy installs");
        fixture
            .provider
            .reauthorize(ReauthorizationRequest {
                handoff,
                snapshot,
                source_authority: fixture.authority,
                destination_authority,
                destination_subject,
                resource: fixture.state.claim.resource,
                required_rights: rights,
            })
            .expect("destination authority prepares");
        assert_eq!(
            validate_profile_binding_on(
                &fixture.provider.connection,
                fixture.state.claim.resource,
                REGULAR_FILE_EXTENSION_ID,
                destination,
            )
            .expect_err("unavailable destination root rejects")
            .kind,
            ProviderErrorKind::NotFound
        );
        fixture
            .provider
            .provision_regular_file_namespace_availability(
                destination,
                fixture.state.claim.namespace,
                &paths.root,
            )
            .expect("destination root provisions");
        validate_profile_binding_on(
            &fixture.provider.connection,
            fixture.state.claim.resource,
            REGULAR_FILE_EXTENSION_ID,
            destination,
        )
        .expect("target identity revalidates");
        let request = BindingRequest {
            handoff,
            snapshot,
            claim: fixture.state.claim.resource,
            authority: destination_authority,
            exposed_rights: rights,
            expected_owner: fixture.node,
            expected_epoch: LeaseEpoch(1),
            candidate_owner: destination,
            candidate_epoch: LeaseEpoch(2),
            kind: BindingKind::Profile { profile: REGULAR_FILE_EXTENSION_ID },
        };
        let receipt = fixture.provider.prepare_binding(request).expect("profile binding prepares");
        assert_eq!(receipt.node, destination);
        assert_eq!(
            fixture.provider.prepare_binding(request).expect("binding retry deduplicates"),
            receipt
        );
    }

    #[test]
    fn exclusive_lock_is_held_until_release_and_cleanup_is_idempotent() {
        let paths = TestPaths::new("lock");
        let mut fixture = fixture(&paths, b"locked");
        let acquire = request(&fixture, 50, RegularFileOperation::AcquireLock);
        append_intent(&mut fixture.provider, 1, &acquire);
        let outcome = fixture
            .provider
            .execute_profile(&acquire, &regular_file_extension(&fixture.state).unwrap())
            .expect("lock acquires");
        fixture.state = result_state(&fixture.state, &acquire, &outcome);

        let competing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(paths.root.join("data.bin"))
            .unwrap();
        assert!(
            rustix::fs::flock(&competing, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .is_err()
        );
        fixture.provider.cleanup_profile_operation(&acquire).expect("cleanup succeeds");
        fixture.provider.cleanup_profile_operation(&acquire).expect("cleanup repeats");

        let release = request(&fixture, 51, RegularFileOperation::ReleaseLock);
        append_intent(&mut fixture.provider, 2, &release);
        let outcome = fixture
            .provider
            .execute_profile(&release, &regular_file_extension(&fixture.state).unwrap())
            .expect("lock releases");
        fixture.state = result_state(&fixture.state, &release, &outcome);
        rustix::fs::flock(&competing, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("competing lock can acquire");
        assert_eq!(fixture.state.lock_state, FileLockState::Unlocked);
    }

    #[test]
    fn schema_three_database_migrates_without_losing_stage_one_tables() {
        let paths = TestPaths::new("migration");
        let scope = JournalScope { node: NodeIdentity::new(id(80)), component: id(81) };
        let provider = SqliteProvider::open(&paths.db, scope).expect("fresh provider opens");
        provider.connection.pragma_update(None, "user_version", 3).unwrap();
        provider
            .connection
            .execute_batch(
                "DROP TABLE logical_request_effect;
                 DROP TABLE logical_request_ledger;
                 DROP TABLE logical_request_peer;
                 DROP TABLE logical_request_resource;
                 DROP TABLE regular_file_plan;
                 DROP TABLE regular_file_resource;
                 DROP TABLE regular_file_namespace_root;
                 ALTER TABLE binding RENAME TO binding_v4;
                 CREATE TABLE binding (
                     snapshot_id BLOB NOT NULL CHECK (length(snapshot_id) = 16),
                     claim_id BLOB NOT NULL CHECK (length(claim_id) = 16),
                     claim_generation BLOB NOT NULL CHECK (length(claim_generation) = 8),
                     kind INTEGER NOT NULL CHECK (kind IN (0, 1)),
                     namespace_id BLOB,
                     receipt BLOB NOT NULL,
                     cleaned INTEGER NOT NULL DEFAULT 0 CHECK (cleaned IN (0, 1)),
                     CHECK ((kind = 0 AND namespace_id IS NULL)
                         OR (kind = 1 AND length(namespace_id) = 16)),
                     PRIMARY KEY(snapshot_id, claim_id, claim_generation)
                 ) WITHOUT ROWID;
                 INSERT INTO binding SELECT * FROM binding_v4;
                 DROP TABLE binding_v4;",
            )
            .unwrap();
        drop(provider);

        let reopened = SqliteProvider::open(&paths.db, scope).expect("v3 migrates");
        let version: i64 =
            reopened.connection.query_row("PRAGMA user_version", [], |row| row.get(0)).unwrap();
        assert_eq!(version, 5);
        let profile_kind: bool = reopened
            .connection
            .query_row(
                "SELECT sql LIKE '%kind IN (0, 1, 2)%' FROM sqlite_schema
                 WHERE type = 'table' AND name = 'binding'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(profile_kind);
        let hardened_identity_columns: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM (
                     SELECT name FROM pragma_table_info('regular_file_namespace_root')
                     UNION ALL
                     SELECT name FROM pragma_table_info('regular_file_resource')
                 ) WHERE name IN ('btime_seconds', 'btime_nanoseconds')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(hardened_identity_columns, 4);
    }

    #[test]
    fn old_v4_or_v5_schema_without_birth_time_is_rejected_without_path_backfill() {
        let paths = TestPaths::new("old-v4-identity");
        let scope = JournalScope { node: NodeIdentity::new(id(82)), component: id(83) };
        let provider = SqliteProvider::open(&paths.db, scope).expect("fresh provider opens");
        provider
            .connection
            .execute_batch(
                "DROP TABLE logical_request_effect;
                 DROP TABLE logical_request_ledger;
                 DROP TABLE logical_request_peer;
                 DROP TABLE logical_request_resource;
                 DROP TABLE regular_file_plan;
                 DROP TABLE regular_file_resource;
                 DROP TABLE regular_file_namespace_root;
                 CREATE TABLE regular_file_namespace_root (
                     node_id BLOB NOT NULL CHECK (length(node_id) = 16),
                     namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 16),
                     root_path BLOB NOT NULL CHECK (length(root_path) > 0),
                     device BLOB NOT NULL CHECK (length(device) = 8),
                     inode BLOB NOT NULL CHECK (length(inode) = 8),
                     PRIMARY KEY(node_id, namespace_id)
                 ) WITHOUT ROWID;
                 CREATE TABLE regular_file_resource (
                     resource_id BLOB NOT NULL CHECK (length(resource_id) = 16),
                     resource_generation BLOB NOT NULL CHECK (length(resource_generation) = 8),
                     namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 16),
                     device BLOB NOT NULL CHECK (length(device) = 8),
                     inode BLOB NOT NULL CHECK (length(inode) = 8),
                     state BLOB NOT NULL,
                     PRIMARY KEY(resource_id, resource_generation),
                     UNIQUE(namespace_id, device, inode)
                 ) WITHOUT ROWID;
                 CREATE TABLE regular_file_plan (
                     operation BLOB PRIMARY KEY CHECK (length(operation) = 16),
                     plan BLOB NOT NULL,
                     FOREIGN KEY(operation) REFERENCES provider_operation(operation)
                 ) WITHOUT ROWID;
                 PRAGMA user_version = 4;",
            )
            .unwrap();
        drop(provider);

        assert_eq!(
            SqliteProvider::open(&paths.db, scope)
                .err()
                .expect("an unpublished pre-hardening v4 schema must be rebuilt")
                .kind,
            ProviderErrorKind::Integrity
        );
        let raw = rusqlite::Connection::open(&paths.db).unwrap();
        let version: i64 = raw.query_row("PRAGMA user_version", [], |row| row.get(0)).unwrap();
        let btime_columns: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('regular_file_resource')
                 WHERE name IN ('btime_seconds', 'btime_nanoseconds')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 4, "preflight rejects before the v4-to-v5 migration");
        assert_eq!(btime_columns, 0, "missing identity is never inferred from a pathname");
        raw.pragma_update(None, "user_version", 5).unwrap();
        drop(raw);

        assert_eq!(
            SqliteProvider::open(&paths.db, scope)
                .err()
                .expect("an unpublished pre-hardening v5 schema must be rebuilt")
                .kind,
            ProviderErrorKind::Integrity
        );
        let raw = rusqlite::Connection::open(&paths.db).unwrap();
        let logical_tables: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table'
                 AND name LIKE 'logical_request_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(logical_tables, 0, "v5 preflight runs before any schema mutation");
    }
}
