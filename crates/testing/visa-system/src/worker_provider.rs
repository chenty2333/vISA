use std::{os::unix::ffi::OsStrExt, path::Path};

use contract_core::{
    AuthorityGrant, BindingReceipt, EffectOutcome, EffectRequest, EntityRef, Extension,
    IdempotencyKey, Identity, JournalEntry, JournalPosition, LeaseEpoch, NodeIdentity, Rights,
    VersionedValue,
};
use substrate_api::{
    ActivationBundle, AuthorityPolicy, AuthorityPort, BindingPort, BindingRequest, CommitBundle,
    EffectRequestBinding, JournalPort, JournalScope, KvPort, LeasePort, LeaseRecord,
    OperationObservation, PreparedLeaseTransitions, ProfileDispatchAuthorization, ProfilePort,
    ProviderError, ProviderErrorKind, ReauthorizationRequest, TimerObservation, TimerPort,
    TimerRecovery,
};
use substrate_host::{FaultObservation, FaultPoint, SqliteProvider};

use crate::provider_rpc::{NetworkProvider, ProviderLocator};

macro_rules! dispatch {
    ($this:expr, $provider:ident => $call:expr) => {
        match $this {
            WorkerProvider::Local($provider) => $call,
            WorkerProvider::Network($provider) => $call,
        }
    };
}

/// Provider selected by the worker's existing `database_path` locator.
///
/// Ordinary paths retain the in-process SQLite implementation. Only the
/// versioned provider-RPC prefix selects the network client, so malformed
/// network locators fail instead of silently becoming local filenames.
pub(crate) enum WorkerProvider {
    Local(Box<SqliteProvider>),
    Network(NetworkProvider),
}

impl WorkerProvider {
    pub(crate) fn open(
        locator: impl AsRef<Path>,
        scope: JournalScope,
    ) -> Result<Self, ProviderError> {
        let locator = locator.as_ref();
        if is_network_locator(locator) {
            let locator = locator
                .to_str()
                .ok_or_else(|| ProviderError::new(ProviderErrorKind::InvalidRequest, false))?;
            let parsed = ProviderLocator::parse(locator)
                .map_err(|_| ProviderError::new(ProviderErrorKind::InvalidRequest, false))?;
            NetworkProvider::connect(parsed.as_str(), scope).map(Self::Network).map_err(Into::into)
        } else {
            SqliteProvider::open(locator, scope).map(Box::new).map(Self::Local)
        }
    }

    pub(crate) fn provision_key_value_namespace(
        &mut self,
        resource: EntityRef,
        namespace: Identity,
    ) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.provision_key_value_namespace(resource, namespace))
    }

    pub(crate) fn provision_key_value_namespace_availability(
        &mut self,
        node: NodeIdentity,
        namespace: Identity,
    ) -> Result<(), ProviderError> {
        dispatch!(
            self,
            provider => provider.provision_key_value_namespace_availability(node, namespace)
        )
    }

    pub(crate) fn inject_failure_once(&mut self, point: FaultPoint) -> Result<(), ProviderError> {
        match self {
            Self::Local(provider) => {
                provider.inject_failure_once(point);
                Ok(())
            }
            Self::Network(provider) => provider.inject_failure_once(point),
        }
    }

    pub(crate) fn fault_observation(&self) -> Result<Option<FaultObservation>, ProviderError> {
        match self {
            Self::Local(provider) => Ok(provider.fault_observation()),
            Self::Network(provider) => provider.fault_observation(),
        }
    }

    pub(crate) fn inspect_key_value(
        &self,
        resource: EntityRef,
        key: &[u8],
    ) -> Result<Option<VersionedValue>, ProviderError> {
        dispatch!(self, provider => provider.inspect_key_value(resource, key))
    }
}

fn is_network_locator(locator: &Path) -> bool {
    locator.as_os_str().as_bytes().starts_with(ProviderLocator::PREFIX.as_bytes())
}

impl JournalPort for WorkerProvider {
    fn append_entry(&mut self, entry: &JournalEntry) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.append_entry(entry))
    }

    fn commit_activation(&mut self, bundle: &ActivationBundle) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.commit_activation(bundle))
    }

    fn commit_bundle(&mut self, bundle: &CommitBundle) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.commit_bundle(bundle))
    }

    fn entry(&self, position: JournalPosition) -> Result<Option<JournalEntry>, ProviderError> {
        dispatch!(self, provider => provider.entry(position))
    }

    fn operation(
        &self,
        operation: Identity,
    ) -> Result<Option<OperationObservation>, ProviderError> {
        dispatch!(self, provider => provider.operation(operation))
    }

    fn idempotency(
        &self,
        key: IdempotencyKey,
    ) -> Result<Option<OperationObservation>, ProviderError> {
        dispatch!(self, provider => provider.idempotency(key))
    }

    fn replay_from(
        &self,
        after: Option<JournalPosition>,
    ) -> Result<Vec<JournalEntry>, ProviderError> {
        dispatch!(self, provider => provider.replay_from(after))
    }
}

impl KvPort for WorkerProvider {
    fn read(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        dispatch!(self, provider => provider.read(request))
    }

    fn compare_and_set(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        dispatch!(self, provider => provider.compare_and_set(request))
    }

    fn query_operation(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        dispatch!(
            self,
            provider => provider.query_operation(operation, idempotency_key)
        )
    }
}

impl ProfilePort for WorkerProvider {
    fn require_profile_dispatch_authorization(
        &mut self,
        profile: Identity,
    ) -> Result<(), ProviderError> {
        dispatch!(
            self,
            provider => provider.require_profile_dispatch_authorization(profile)
        )
    }

    fn arm_profile_dispatch(
        &mut self,
        authorization: ProfileDispatchAuthorization,
    ) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.arm_profile_dispatch(authorization))
    }

    fn finish_profile_dispatch(
        &mut self,
        binding: EffectRequestBinding,
    ) -> Result<bool, ProviderError> {
        dispatch!(self, provider => provider.finish_profile_dispatch(binding))
    }

    fn execute_profile(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
    ) -> Result<EffectOutcome, ProviderError> {
        dispatch!(self, provider => provider.execute_profile(request, extension))
    }

    fn query_profile_operation(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        dispatch!(
            self,
            provider => provider.query_profile_operation(operation, idempotency_key)
        )
    }

    fn reconcile_profile_operation(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        dispatch!(
            self,
            provider => provider.reconcile_profile_operation(request, extension)
        )
    }

    fn cleanup_profile_operation(&mut self, request: &EffectRequest) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.cleanup_profile_operation(request))
    }
}

impl TimerPort for WorkerProvider {
    fn arm(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        dispatch!(self, provider => provider.arm(request))
    }

    fn cancel(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        dispatch!(self, provider => provider.cancel(request))
    }

    fn restore_timer_binding(
        &mut self,
        arm_request: &EffectRequest,
        recovery: TimerRecovery,
    ) -> Result<(), ProviderError> {
        dispatch!(
            self,
            provider => provider.restore_timer_binding(arm_request, recovery)
        )
    }

    fn observe(&mut self, arm_operation: Identity) -> Result<TimerObservation, ProviderError> {
        dispatch!(self, provider => provider.observe(arm_operation))
    }

    fn suspend_timer(
        &mut self,
        arm_operation: Identity,
    ) -> Result<TimerObservation, ProviderError> {
        dispatch!(self, provider => provider.suspend_timer(arm_operation))
    }

    fn resume_suspended(&mut self, arm_operation: Identity) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.resume_suspended(arm_operation))
    }

    fn cleanup_timer(&mut self, arm_operation: Identity) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.cleanup_timer(arm_operation))
    }
}

impl AuthorityPort for WorkerProvider {
    fn install_policy(&mut self, policy: AuthorityPolicy) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.install_policy(policy))
    }

    fn install_grant(&mut self, grant: &AuthorityGrant) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.install_grant(grant))
    }

    fn attenuate(
        &mut self,
        handoff: Identity,
        snapshot: Identity,
        parent: EntityRef,
        derived: &AuthorityGrant,
    ) -> Result<AuthorityGrant, ProviderError> {
        dispatch!(
            self,
            provider => provider.attenuate(handoff, snapshot, parent, derived)
        )
    }

    fn revoke(&mut self, authority: EntityRef) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.revoke(authority))
    }

    fn reauthorize(
        &mut self,
        request: ReauthorizationRequest,
    ) -> Result<AuthorityGrant, ProviderError> {
        dispatch!(self, provider => provider.reauthorize(request))
    }

    fn authorize_effect(
        &self,
        request: &EffectRequest,
        required_rights: Rights,
    ) -> Result<Rights, ProviderError> {
        dispatch!(
            self,
            provider => provider.authorize_effect(request, required_rights)
        )
    }

    fn revoke_prepared(&mut self, snapshot: Identity) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.revoke_prepared(snapshot))
    }
}

impl LeasePort for WorkerProvider {
    fn initialize_lease(&mut self, lease: LeaseRecord) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.initialize_lease(lease))
    }

    fn prepare_transitions(
        &mut self,
        request: &EffectRequest,
        resources: &[EntityRef],
    ) -> Result<PreparedLeaseTransitions, ProviderError> {
        dispatch!(
            self,
            provider => provider.prepare_transitions(request, resources)
        )
    }

    fn current_lease(&self, resource: EntityRef) -> Result<Option<LeaseRecord>, ProviderError> {
        dispatch!(self, provider => provider.current_lease(resource))
    }

    fn check_lease(
        &self,
        resource: EntityRef,
        owner: NodeIdentity,
        epoch: LeaseEpoch,
    ) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.check_lease(resource, owner, epoch))
    }
}

impl BindingPort for WorkerProvider {
    fn prepare_binding(
        &mut self,
        request: BindingRequest,
    ) -> Result<BindingReceipt, ProviderError> {
        dispatch!(self, provider => provider.prepare_binding(request))
    }

    fn binding(
        &self,
        snapshot: Identity,
        claim: EntityRef,
    ) -> Result<Option<BindingReceipt>, ProviderError> {
        dispatch!(self, provider => provider.binding(snapshot, claim))
    }

    fn cleanup_binding(
        &mut self,
        snapshot: Identity,
        claim: EntityRef,
    ) -> Result<(), ProviderError> {
        dispatch!(self, provider => provider.cleanup_binding(snapshot, claim))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_versioned_provider_prefix_selects_network_transport() {
        assert!(is_network_locator(Path::new(ProviderLocator::PREFIX)));
        assert!(is_network_locator(Path::new("visa-provider+unix-v1:not-yet-valid")));
        assert!(!is_network_locator(Path::new("visa-provider+unix-v0:not-a-network-locator")));
        assert!(!is_network_locator(Path::new(
            "prefix-visa-provider+unix-v1:not-a-network-locator"
        )));
    }

    #[test]
    fn malformed_network_locator_never_falls_back_to_a_local_file() {
        let locator = format!("{}not-valid", ProviderLocator::PREFIX);
        let error = WorkerProvider::open(
            locator,
            JournalScope {
                node: NodeIdentity::new(Identity::from_bytes([1; 16])),
                component: Identity::from_bytes([2; 16]),
            },
        )
        .err()
        .expect("the malformed network locator must be rejected");
        assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
        assert!(!error.retryable);
    }
}
