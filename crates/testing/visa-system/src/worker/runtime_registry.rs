use std::marker::PhantomData;

use contract_core::Identity;
use substrate_host::SqliteProvider;
use visa_component_adapter::{
    ActivationRequest, AdapterError, ComponentSafePoint, ComponentStatus,
    CooperativeRuntimeFactory, CooperativeRuntimeInstance, PortableComponentState,
    PreflightExpectations, RecoverableInstantiation, RuntimeIdentity,
};
use visa_jco_node::{
    JcoNodeAdapter, JcoNodeRuntime, JcoTranslationProvenance, PreparedJcoComponent,
};
use visa_profile::{CooperativeHandoffProfile, ProviderSupport};
use visa_runtime::Coordinator;
use visa_wacogo::{PreparedWacogoComponent, WacogoAdapter, WacogoProvenance, WacogoRuntime};
use visa_wasmtime::{ComponentAdapter, PreparedComponent, WasmtimeRuntime};

use crate::protocol::RuntimeImplementation;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RuntimeMetadata {
    pub(super) identity: RuntimeIdentity,
    pub(super) translation_provenance: Option<JcoTranslationProvenance>,
    pub(super) implementation_lineage: Option<WacogoProvenance>,
}

trait RuntimeInstanceMetadata {
    fn translation_provenance(&self) -> Option<JcoTranslationProvenance>;
    fn implementation_lineage(&self) -> Option<WacogoProvenance>;
    fn into_coordinator_boxed(
        self: Box<Self>,
    ) -> Result<Coordinator<SqliteProvider>, Box<RecoverableInstantiation<SqliteProvider>>>;
    fn inject_unsupported_live_resource(&mut self) -> Result<(), AdapterError>;
    fn clear_unsupported_live_resource(&mut self) -> Result<(), AdapterError>;
}

impl RuntimeInstanceMetadata for ComponentAdapter<SqliteProvider> {
    fn translation_provenance(&self) -> Option<JcoTranslationProvenance> {
        None
    }

    fn implementation_lineage(&self) -> Option<WacogoProvenance> {
        None
    }

    fn into_coordinator_boxed(
        self: Box<Self>,
    ) -> Result<Coordinator<SqliteProvider>, Box<RecoverableInstantiation<SqliteProvider>>> {
        Ok(ComponentAdapter::into_coordinator(*self))
    }

    fn inject_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        ComponentAdapter::inject_unsupported_live_resource(self)
    }

    fn clear_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        ComponentAdapter::clear_unsupported_live_resource(self)
    }
}

impl RuntimeInstanceMetadata for JcoNodeAdapter<SqliteProvider> {
    fn translation_provenance(&self) -> Option<JcoTranslationProvenance> {
        Some(JcoNodeAdapter::translation_provenance(self).clone())
    }

    fn implementation_lineage(&self) -> Option<WacogoProvenance> {
        None
    }

    fn into_coordinator_boxed(
        self: Box<Self>,
    ) -> Result<Coordinator<SqliteProvider>, Box<RecoverableInstantiation<SqliteProvider>>> {
        Ok(JcoNodeAdapter::into_coordinator(*self))
    }

    fn inject_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        JcoNodeAdapter::inject_unsupported_live_resource(self)
    }

    fn clear_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        JcoNodeAdapter::clear_unsupported_live_resource(self)
    }
}

impl RuntimeInstanceMetadata for WacogoAdapter<SqliteProvider> {
    fn translation_provenance(&self) -> Option<JcoTranslationProvenance> {
        None
    }

    fn implementation_lineage(&self) -> Option<WacogoProvenance> {
        Some(WacogoAdapter::provenance(self).clone())
    }

    fn into_coordinator_boxed(
        self: Box<Self>,
    ) -> Result<Coordinator<SqliteProvider>, Box<RecoverableInstantiation<SqliteProvider>>> {
        WacogoAdapter::into_coordinator(*self)
    }

    fn inject_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        WacogoAdapter::inject_unsupported_live_resource(self)
    }

    fn clear_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        WacogoAdapter::clear_unsupported_live_resource(self)
    }
}

trait ErasedRuntimeInstance:
    CooperativeRuntimeInstance<SqliteProvider> + RuntimeInstanceMetadata
{
}

impl<T> ErasedRuntimeInstance for T where
    T: CooperativeRuntimeInstance<SqliteProvider> + RuntimeInstanceMetadata
{
}

/// A live runtime behind the one shared cooperative lifecycle. Runtime-local
/// metadata and negative-test controls are the only extension methods here.
pub(super) struct Adapter {
    inner: Option<Box<dyn ErasedRuntimeInstance>>,
}

impl Adapter {
    fn inner(&self) -> &dyn ErasedRuntimeInstance {
        self.inner.as_deref().expect("live runtime has not been consumed")
    }

    fn inner_mut(&mut self) -> &mut dyn ErasedRuntimeInstance {
        self.inner.as_deref_mut().expect("live runtime has not been consumed")
    }

    pub(super) fn runtime_metadata(&self) -> RuntimeMetadata {
        RuntimeMetadata {
            identity: self.inner().runtime_identity(),
            translation_provenance: self.inner().translation_provenance(),
            implementation_lineage: self.inner().implementation_lineage(),
        }
    }

    pub(super) fn coordinator(&self) -> &Coordinator<SqliteProvider> {
        self.inner().coordinator()
    }

    pub(super) fn coordinator_mut(&mut self) -> &mut Coordinator<SqliteProvider> {
        self.inner_mut().coordinator_mut()
    }

    pub(super) fn activate(&mut self, request: &ActivationRequest) -> Result<(), AdapterError> {
        self.inner_mut().activate(request)
    }

    pub(super) fn safe_point(
        &mut self,
        command: Identity,
    ) -> Result<ComponentSafePoint, AdapterError> {
        self.inner_mut().safe_point(command)
    }

    pub(super) fn restore(
        &mut self,
        state: &PortableComponentState,
        remaining_duration_ns: u64,
    ) -> Result<(), AdapterError> {
        self.inner_mut().restore(state, remaining_duration_ns)
    }

    pub(super) fn thaw(&mut self, state: &PortableComponentState) -> Result<(), AdapterError> {
        self.inner_mut().thaw(state)
    }

    pub(super) fn timer_fired(&mut self, operation: Identity) -> Result<(), AdapterError> {
        self.inner_mut().timer_fired(operation)
    }

    pub(super) fn cancel_pending(&mut self) -> Result<(), AdapterError> {
        self.inner_mut().cancel_pending()
    }

    pub(super) fn status(&mut self) -> Result<Option<ComponentStatus>, AdapterError> {
        self.inner_mut().status()
    }

    pub(super) fn inject_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        self.inner_mut().inject_unsupported_live_resource()
    }

    pub(super) fn clear_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        self.inner_mut().clear_unsupported_live_resource()
    }

    pub(super) fn teardown(&mut self) -> Result<(), AdapterError> {
        let Some(inner) = self.inner.take() else {
            return Ok(());
        };
        match inner.into_coordinator_boxed() {
            Ok(coordinator) => {
                drop(coordinator);
                Ok(())
            }
            Err(failure) => Err(failure.error),
        }
    }

    #[cfg(test)]
    pub(super) const fn is_consumed(&self) -> bool {
        self.inner.is_none()
    }

    #[cfg(test)]
    fn into_coordinator(
        mut self,
    ) -> Result<Coordinator<SqliteProvider>, Box<RecoverableInstantiation<SqliteProvider>>> {
        let inner = self.inner.take().expect("live runtime has not been consumed");
        inner.into_coordinator_boxed()
    }
}

trait RegisteredRuntime: CooperativeRuntimeFactory<SqliteProvider>
where
    Self::Instance: ErasedRuntimeInstance + 'static,
    Self::Prepared: 'static,
{
    const IMPLEMENTATION: RuntimeImplementation;

    fn prepared_runtime_metadata(prepared: &Self::Prepared) -> RuntimeMetadata;

    fn teardown_prepared(prepared: Self::Prepared) -> Result<(), AdapterError> {
        drop(prepared);
        Ok(())
    }
}

impl RegisteredRuntime for WasmtimeRuntime {
    const IMPLEMENTATION: RuntimeImplementation = RuntimeImplementation::Wasmtime;

    fn prepared_runtime_metadata(prepared: &PreparedComponent<SqliteProvider>) -> RuntimeMetadata {
        RuntimeMetadata {
            identity: prepared.runtime_identity(),
            translation_provenance: None,
            implementation_lineage: None,
        }
    }
}

impl RegisteredRuntime for JcoNodeRuntime {
    const IMPLEMENTATION: RuntimeImplementation = RuntimeImplementation::JcoNode;

    fn prepared_runtime_metadata(prepared: &PreparedJcoComponent) -> RuntimeMetadata {
        RuntimeMetadata {
            identity: prepared.runtime_identity().clone(),
            translation_provenance: Some(prepared.translation_provenance()),
            implementation_lineage: None,
        }
    }
}

impl RegisteredRuntime for WacogoRuntime {
    const IMPLEMENTATION: RuntimeImplementation = RuntimeImplementation::Wacogo;

    fn prepared_runtime_metadata(prepared: &PreparedWacogoComponent) -> RuntimeMetadata {
        RuntimeMetadata {
            identity: prepared.runtime_identity().clone(),
            translation_provenance: None,
            implementation_lineage: Some(prepared.provenance().clone()),
        }
    }

    fn teardown_prepared(prepared: PreparedWacogoComponent) -> Result<(), AdapterError> {
        prepared.shutdown()
    }
}

trait ErasedPrepared: 'static {
    fn runtime_metadata(&self) -> RuntimeMetadata;
    fn teardown(self: Box<Self>) -> Result<(), AdapterError>;
    fn instantiate(
        self: Box<Self>,
        coordinator: Coordinator<SqliteProvider>,
    ) -> Result<Adapter, Box<RecoverableInstantiation<SqliteProvider>>>;
}

struct TypedPrepared<F>
where
    F: RegisteredRuntime,
    F::Instance: ErasedRuntimeInstance + 'static,
    F::Prepared: 'static,
{
    prepared: F::Prepared,
    marker: PhantomData<F>,
}

impl<F> ErasedPrepared for TypedPrepared<F>
where
    F: RegisteredRuntime + 'static,
    F::Instance: ErasedRuntimeInstance + 'static,
    F::Prepared: 'static,
{
    fn runtime_metadata(&self) -> RuntimeMetadata {
        F::prepared_runtime_metadata(&self.prepared)
    }

    fn teardown(self: Box<Self>) -> Result<(), AdapterError> {
        F::teardown_prepared(self.prepared)
    }

    fn instantiate(
        self: Box<Self>,
        coordinator: Coordinator<SqliteProvider>,
    ) -> Result<Adapter, Box<RecoverableInstantiation<SqliteProvider>>> {
        let prepared_metadata = F::prepared_runtime_metadata(&self.prepared);
        let instance = F::instantiate_prepared_recoverable(self.prepared, coordinator)?;
        let live_metadata = RuntimeMetadata {
            identity: instance.runtime_identity(),
            translation_provenance: instance.translation_provenance(),
            implementation_lineage: instance.implementation_lineage(),
        };
        let instance: Box<dyn ErasedRuntimeInstance> = Box::new(instance);
        if prepared_metadata != live_metadata {
            let coordinator = match instance.into_coordinator_boxed() {
                Ok(coordinator) => coordinator,
                Err(failure) => failure.coordinator,
            };
            return Err(Box::new(RecoverableInstantiation {
                error: AdapterError::UnsupportedRuntimeFeature(format!(
                    "prepared/live runtime metadata drift: prepared {prepared_metadata:?}, live {live_metadata:?}"
                )),
                coordinator,
            }));
        }
        Ok(Adapter { inner: Some(instance) })
    }
}

/// An erased prepared token whose concrete factory remains encoded in its
/// private `TypedPrepared<F>`. Instantiation deliberately accepts no runtime
/// selector, so a caller cannot pair the token with a different engine.
pub(super) struct PreparedAdapter {
    inner: Option<Box<dyn ErasedPrepared>>,
}

impl PreparedAdapter {
    pub(super) fn runtime_metadata(&self) -> RuntimeMetadata {
        self.inner.as_ref().expect("prepared runtime has not been consumed").runtime_metadata()
    }

    pub(super) fn teardown(&mut self) -> Result<(), AdapterError> {
        let Some(inner) = self.inner.take() else {
            return Ok(());
        };
        inner.teardown()
    }
}

#[derive(Clone, Copy)]
struct RuntimeRegistration {
    implementation: RuntimeImplementation,
    identity: fn() -> RuntimeIdentity,
    preflight: fn(
        &[u8],
        &CooperativeHandoffProfile,
        &ProviderSupport,
        PreflightExpectations,
    ) -> Result<PreparedAdapter, AdapterError>,
}

impl RuntimeRegistration {
    fn identity(self) -> RuntimeIdentity {
        (self.identity)()
    }

    fn preflight(
        self,
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        expectations: PreflightExpectations,
    ) -> Result<PreparedAdapter, AdapterError> {
        let prepared = (self.preflight)(component_bytes, profile, support, expectations)?;
        let expected = self.identity();
        let actual = prepared.runtime_metadata().identity;
        if actual != expected {
            return Err(AdapterError::UnsupportedRuntimeFeature(format!(
                "registered runtime identity drift: selector {:?} expected {expected:?}, prepared {actual:?}",
                self.implementation
            )));
        }
        Ok(prepared)
    }
}

const REGISTRY: [RuntimeRegistration; 3] = [
    registration::<WasmtimeRuntime>(),
    registration::<JcoNodeRuntime>(),
    registration::<WacogoRuntime>(),
];

const fn registration<F>() -> RuntimeRegistration
where
    F: RegisteredRuntime + 'static,
    F::Instance: ErasedRuntimeInstance + 'static,
    F::Prepared: 'static,
{
    RuntimeRegistration {
        implementation: F::IMPLEMENTATION,
        identity: F::identity,
        preflight: typed_preflight::<F>,
    }
}

fn typed_preflight<F>(
    component_bytes: &[u8],
    profile: &CooperativeHandoffProfile,
    support: &ProviderSupport,
    expectations: PreflightExpectations,
) -> Result<PreparedAdapter, AdapterError>
where
    F: RegisteredRuntime + 'static,
    F::Instance: ErasedRuntimeInstance + 'static,
    F::Prepared: 'static,
{
    F::preflight(component_bytes, profile, support, expectations).map(|prepared| PreparedAdapter {
        inner: Some(Box::new(TypedPrepared::<F> { prepared, marker: PhantomData })),
    })
}

fn select(runtime: RuntimeImplementation) -> Result<RuntimeRegistration, AdapterError> {
    REGISTRY.iter().copied().find(|registration| registration.implementation == runtime).ok_or_else(
        || {
            AdapterError::UnsupportedRuntimeFeature(format!(
                "runtime selector {runtime:?} is not registered"
            ))
        },
    )
}

pub(super) fn preflight_adapter(
    runtime: RuntimeImplementation,
    component_bytes: &[u8],
    profile: &CooperativeHandoffProfile,
    support: &ProviderSupport,
    expectations: PreflightExpectations,
) -> Result<PreparedAdapter, AdapterError> {
    select(runtime)?.preflight(component_bytes, profile, support, expectations)
}

pub(super) fn instantiate_prepared_adapter(
    mut prepared: PreparedAdapter,
    coordinator: Coordinator<SqliteProvider>,
) -> Result<Adapter, Box<RecoverableInstantiation<SqliteProvider>>> {
    prepared.inner.take().expect("prepared runtime has not been consumed").instantiate(coordinator)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Cursor,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
    };

    use visa_component_adapter::ResourceBindingError;

    use super::*;
    use crate::{
        fixture::FixtureSpec,
        protocol::{CrashMode, RequestEnvelope, WorkerCommand},
        worker::{
            DestinationPending, RunExit, SourceWorker, Worker, WorkerState,
            run_json_lines_with_worker,
        },
    };

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);
    static FAKE_FACTORY_CALLED: AtomicBool = AtomicBool::new(false);

    struct FakeFactory;
    struct FakePrepared;
    struct MetadataDriftFactory;
    struct TrackingFactory;

    struct TrackingPrepared {
        prepared_identity: RuntimeIdentity,
        live_identity: RuntimeIdentity,
        prepared_teardowns: Arc<AtomicU64>,
        live_teardowns: Arc<AtomicU64>,
        prepared_teardown_fails: bool,
        live_teardown_fails: bool,
    }

    struct TrackingInstance {
        coordinator: Option<Coordinator<SqliteProvider>>,
        identity: RuntimeIdentity,
        teardowns: Arc<AtomicU64>,
        teardown_fails: bool,
    }

    impl CooperativeRuntimeInstance<SqliteProvider> for TrackingInstance {
        fn runtime_identity(&self) -> RuntimeIdentity {
            self.identity.clone()
        }

        fn verified_component_digest(&self) -> contract_core::Digest {
            self.coordinator().state().component_digest
        }

        fn coordinator(&self) -> &Coordinator<SqliteProvider> {
            self.coordinator.as_ref().expect("tracking coordinator has not been consumed")
        }

        fn coordinator_mut(&mut self) -> &mut Coordinator<SqliteProvider> {
            self.coordinator.as_mut().expect("tracking coordinator has not been consumed")
        }

        fn invoke_activate(&mut self, _: &ActivationRequest) -> Result<(), AdapterError> {
            Err(tracking_lifecycle_error())
        }

        fn invoke_freeze(
            &mut self,
        ) -> Result<visa_component_adapter::ComponentState, AdapterError> {
            Err(tracking_lifecycle_error())
        }

        fn invoke_thaw(
            &mut self,
            _: &visa_component_adapter::ComponentState,
        ) -> Result<(), AdapterError> {
            Err(tracking_lifecycle_error())
        }

        fn invoke_restore(
            &mut self,
            _: &visa_component_adapter::ComponentState,
            _: u64,
        ) -> Result<(), AdapterError> {
            Err(tracking_lifecycle_error())
        }

        fn invoke_timer_fired(&mut self, _: &str) -> Result<(), AdapterError> {
            Err(tracking_lifecycle_error())
        }

        fn invoke_cancel_pending(&mut self) -> Result<(), AdapterError> {
            Err(tracking_lifecycle_error())
        }

        fn invoke_status(&mut self) -> Result<Option<ComponentStatus>, AdapterError> {
            Err(tracking_lifecycle_error())
        }

        fn has_live_resources(&self) -> bool {
            false
        }

        fn set_completion_parent(&mut self, _: Identity) -> Result<(), AdapterError> {
            Ok(())
        }

        fn clear_completion_parent(&mut self) {}
    }

    impl RuntimeInstanceMetadata for TrackingInstance {
        fn translation_provenance(&self) -> Option<JcoTranslationProvenance> {
            None
        }

        fn implementation_lineage(&self) -> Option<WacogoProvenance> {
            None
        }

        fn into_coordinator_boxed(
            mut self: Box<Self>,
        ) -> Result<Coordinator<SqliteProvider>, Box<RecoverableInstantiation<SqliteProvider>>>
        {
            self.teardowns.fetch_add(1, Ordering::SeqCst);
            let coordinator =
                self.coordinator.take().expect("tracking coordinator is torn down only once");
            if self.teardown_fails {
                Err(Box::new(RecoverableInstantiation {
                    error: tracking_lifecycle_error(),
                    coordinator,
                }))
            } else {
                Ok(coordinator)
            }
        }

        fn inject_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
            Err(tracking_lifecycle_error())
        }

        fn clear_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
            Err(tracking_lifecycle_error())
        }
    }

    fn tracking_lifecycle_error() -> AdapterError {
        AdapterError::UnsupportedRuntimeFeature(
            "tracking instance exposes teardown only; it is not an end-to-end runtime".into(),
        )
    }

    impl CooperativeRuntimeFactory<SqliteProvider> for TrackingFactory {
        type Instance = TrackingInstance;
        type Prepared = TrackingPrepared;

        fn identity() -> RuntimeIdentity {
            RuntimeIdentity::new("tracking", "1", "tracking-engine", "1")
        }

        fn preflight(
            _: &[u8],
            _: &CooperativeHandoffProfile,
            _: &ProviderSupport,
            _: PreflightExpectations,
        ) -> Result<Self::Prepared, AdapterError> {
            Err(AdapterError::UnsupportedRuntimeFeature(
                "tracking factory requires a test-constructed prepared token".into(),
            ))
        }

        fn instantiate_prepared_recoverable(
            prepared: Self::Prepared,
            coordinator: Coordinator<SqliteProvider>,
        ) -> Result<Self::Instance, Box<RecoverableInstantiation<SqliteProvider>>> {
            Ok(TrackingInstance {
                coordinator: Some(coordinator),
                identity: prepared.live_identity,
                teardowns: prepared.live_teardowns,
                teardown_fails: prepared.live_teardown_fails,
            })
        }
    }

    impl RegisteredRuntime for TrackingFactory {
        const IMPLEMENTATION: RuntimeImplementation = RuntimeImplementation::Wasmtime;

        fn prepared_runtime_metadata(prepared: &TrackingPrepared) -> RuntimeMetadata {
            RuntimeMetadata {
                identity: prepared.prepared_identity.clone(),
                translation_provenance: None,
                implementation_lineage: None,
            }
        }

        fn teardown_prepared(prepared: TrackingPrepared) -> Result<(), AdapterError> {
            prepared.prepared_teardowns.fetch_add(1, Ordering::SeqCst);
            if prepared.prepared_teardown_fails { Err(tracking_lifecycle_error()) } else { Ok(()) }
        }
    }

    impl CooperativeRuntimeFactory<SqliteProvider> for FakeFactory {
        type Instance = ComponentAdapter<SqliteProvider>;
        type Prepared = FakePrepared;

        fn identity() -> RuntimeIdentity {
            RuntimeIdentity::new("fake", "1", "fake-engine", "1")
        }

        fn preflight(
            _: &[u8],
            _: &CooperativeHandoffProfile,
            _: &ProviderSupport,
            _: PreflightExpectations,
        ) -> Result<Self::Prepared, AdapterError> {
            Ok(FakePrepared)
        }

        fn instantiate_prepared_recoverable(
            _: Self::Prepared,
            coordinator: Coordinator<SqliteProvider>,
        ) -> Result<Self::Instance, Box<RecoverableInstantiation<SqliteProvider>>> {
            FAKE_FACTORY_CALLED.store(true, Ordering::SeqCst);
            Err(Box::new(RecoverableInstantiation {
                error: AdapterError::ResourceBinding(ResourceBindingError::Inactive),
                coordinator,
            }))
        }
    }

    impl RegisteredRuntime for FakeFactory {
        const IMPLEMENTATION: RuntimeImplementation = RuntimeImplementation::Wasmtime;

        fn prepared_runtime_metadata(_: &FakePrepared) -> RuntimeMetadata {
            RuntimeMetadata {
                identity: Self::identity(),
                translation_provenance: None,
                implementation_lineage: None,
            }
        }
    }

    impl CooperativeRuntimeFactory<SqliteProvider> for MetadataDriftFactory {
        type Instance = ComponentAdapter<SqliteProvider>;
        type Prepared = PreparedComponent<SqliteProvider>;

        fn identity() -> RuntimeIdentity {
            <WasmtimeRuntime as CooperativeRuntimeFactory<SqliteProvider>>::identity()
        }

        fn preflight(
            component_bytes: &[u8],
            profile: &CooperativeHandoffProfile,
            support: &ProviderSupport,
            expectations: PreflightExpectations,
        ) -> Result<Self::Prepared, AdapterError> {
            <WasmtimeRuntime as CooperativeRuntimeFactory<SqliteProvider>>::preflight(
                component_bytes,
                profile,
                support,
                expectations,
            )
        }

        fn instantiate_prepared_recoverable(
            prepared: Self::Prepared,
            coordinator: Coordinator<SqliteProvider>,
        ) -> Result<Self::Instance, Box<RecoverableInstantiation<SqliteProvider>>> {
            <WasmtimeRuntime as CooperativeRuntimeFactory<SqliteProvider>>::instantiate_prepared_recoverable(
                prepared,
                coordinator,
            )
        }
    }

    impl RegisteredRuntime for MetadataDriftFactory {
        const IMPLEMENTATION: RuntimeImplementation = RuntimeImplementation::Wasmtime;

        fn prepared_runtime_metadata(_: &PreparedComponent<SqliteProvider>) -> RuntimeMetadata {
            RuntimeMetadata {
                identity: RuntimeIdentity::new("drifted", "1", "drifted-engine", "1"),
                translation_provenance: None,
                implementation_lineage: None,
            }
        }
    }

    #[test]
    fn registry_has_one_unique_entry_for_each_supported_runtime() {
        assert_eq!(REGISTRY.len(), 3);
        for (index, registration) in REGISTRY.iter().enumerate() {
            assert!(
                REGISTRY[index + 1..]
                    .iter()
                    .all(|other| other.implementation != registration.implementation)
            );
            assert!(!registration.identity().implementation.is_empty());
        }
        let wasmtime = select(RuntimeImplementation::Wasmtime).unwrap().identity();
        assert_eq!(wasmtime.implementation, "visa_wasmtime");
        assert_eq!(wasmtime.engine, "wasmtime");
        let jco = select(RuntimeImplementation::JcoNode).unwrap().identity();
        assert!(jco.implementation.starts_with("visa_jco_node+"));
        assert_eq!(jco.engine, "node+v8");
        let wacogo = select(RuntimeImplementation::Wacogo).unwrap().identity();
        assert_eq!(wacogo.implementation, "visa_wacogo");
        assert_eq!(wacogo.engine, "partite-ai/wacogo+wazero");
    }

    #[test]
    fn real_wacogo_selector_rejects_preflight_mismatch_without_fallback() {
        let fixture = FixtureSpec::new("wacogo-selector-no-fallback").unwrap();
        let support =
            ProviderSupport::cooperative_handoff_v1(fixture.profile.required_extensions.clone());
        let error = preflight_adapter(
            RuntimeImplementation::Wacogo,
            crate::component::bytes(),
            &fixture.profile,
            &support,
            PreflightExpectations {
                component_digest: contract_core::Digest::ZERO,
                profile_digest: fixture.profile_digest,
            },
        )
        .err()
        .expect("the real Wacogo registration must reject a mismatched component digest");
        assert_eq!(
            error.kind(),
            visa_component_adapter::AdapterFailureKind::ComponentDigestMismatch
        );
        let selected = select(RuntimeImplementation::Wacogo).unwrap();
        assert_eq!(selected.identity().implementation, "visa_wacogo");
        assert_eq!(selected.identity().engine, "partite-ai/wacogo+wazero");
    }

    #[test]
    fn prepared_token_uses_its_origin_factory_and_returns_the_coordinator_on_failure() {
        FAKE_FACTORY_CALLED.store(false, Ordering::SeqCst);
        let fixture = FixtureSpec::new("registry-recoverable-failure").unwrap();
        let database = std::env::temp_dir().join(format!(
            "visa-system-registry-{}-{}.sqlite",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ));
        let providers = fixture.open_providers(&database).unwrap();
        let coordinator =
            Coordinator::recover(fixture.source_state.clone(), providers.source).unwrap();
        let expected_state = coordinator.state().clone();
        let expected_digest = coordinator.state_digest().unwrap();
        let expected_journal_position = coordinator.journal_position();
        let prepared = PreparedAdapter {
            inner: Some(Box::new(TypedPrepared::<FakeFactory> {
                prepared: FakePrepared,
                marker: PhantomData,
            })),
        };

        // There is intentionally no runtime selector at this boundary: the
        // concrete FakeFactory travels inside the prepared token.
        let failure = instantiate_prepared_adapter(prepared, coordinator)
            .err()
            .expect("the fake factory always rejects instantiation");
        assert!(FAKE_FACTORY_CALLED.load(Ordering::SeqCst));
        assert_eq!(
            failure.error.kind(),
            visa_component_adapter::AdapterFailureKind::ResourceBinding
        );
        assert_eq!(failure.coordinator.state(), &expected_state);
        assert_eq!(failure.coordinator.state_digest().unwrap(), expected_digest);
        assert_eq!(failure.coordinator.journal_position(), expected_journal_position);
        assert!(failure.coordinator.provider().fault_observation().is_none());

        drop(providers.destination);
        drop(failure);
        let _ = fs::remove_file(&database);
        let _ = fs::remove_file(database.with_extension("sqlite-wal"));
        let _ = fs::remove_file(database.with_extension("sqlite-shm"));
    }

    #[test]
    fn prepared_live_metadata_drift_fails_closed_and_returns_the_coordinator() {
        let fixture = FixtureSpec::new("registry-metadata-drift").unwrap();
        let database = std::env::temp_dir().join(format!(
            "visa-system-registry-{}-{}.sqlite",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ));
        let providers = fixture.open_providers(&database).unwrap();
        let coordinator =
            Coordinator::recover(fixture.source_state.clone(), providers.source).unwrap();
        let expected_state = coordinator.state().clone();
        let expected_digest = coordinator.state_digest().unwrap();
        let support =
            ProviderSupport::cooperative_handoff_v1(fixture.profile.required_extensions.clone());
        let prepared =
            <MetadataDriftFactory as CooperativeRuntimeFactory<SqliteProvider>>::preflight(
                crate::component::bytes(),
                &fixture.profile,
                &support,
                PreflightExpectations {
                    component_digest: fixture.component_digest,
                    profile_digest: fixture.profile_digest,
                },
            )
            .unwrap();
        let prepared = PreparedAdapter {
            inner: Some(Box::new(TypedPrepared::<MetadataDriftFactory> {
                prepared,
                marker: PhantomData,
            })),
        };

        let failure = instantiate_prepared_adapter(prepared, coordinator)
            .err()
            .expect("prepared/live metadata drift must fail closed");
        assert_eq!(
            failure.error.kind(),
            visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
        );
        assert_eq!(failure.coordinator.state(), &expected_state);
        assert_eq!(failure.coordinator.state_digest().unwrap(), expected_digest);

        drop(providers.destination);
        drop(failure);
        let _ = fs::remove_file(&database);
        let _ = fs::remove_file(database.with_extension("sqlite-wal"));
        let _ = fs::remove_file(database.with_extension("sqlite-shm"));
    }

    #[test]
    fn normal_eof_tears_down_a_live_adapter_once_but_immediate_crash_does_not() {
        let normal_count = Arc::new(AtomicU64::new(0));
        let fixture = FixtureSpec::new("tracking-normal-eof").unwrap();
        let database = test_database("tracking-normal-eof");
        let providers = fixture.open_providers(&database).unwrap();
        let coordinator =
            Coordinator::recover(fixture.source_state.clone(), providers.source).unwrap();
        let adapter = tracking_adapter(coordinator, Arc::clone(&normal_count), "tracking-normal");
        let mut worker = Worker {
            fixture: None,
            database_path: None,
            state: WorkerState::Source(Box::new(SourceWorker { adapter, portable_state: None })),
        };
        let mut output = Vec::new();
        assert_eq!(
            run_json_lines_with_worker(&mut worker, Cursor::new(Vec::<u8>::new()), &mut output)
                .unwrap(),
            RunExit::EndOfInput
        );
        assert!(output.is_empty());
        assert_eq!(normal_count.load(Ordering::SeqCst), 1);
        worker.teardown_normal().unwrap();
        assert_eq!(normal_count.load(Ordering::SeqCst), 1);
        drop(worker);
        assert_eq!(normal_count.load(Ordering::SeqCst), 1);
        drop(providers.destination);
        remove_test_database(&database);

        let crash_count = Arc::new(AtomicU64::new(0));
        let fixture = FixtureSpec::new("tracking-immediate-crash").unwrap();
        let database = test_database("tracking-immediate-crash");
        let providers = fixture.open_providers(&database).unwrap();
        let coordinator =
            Coordinator::recover(fixture.source_state.clone(), providers.source).unwrap();
        let adapter = tracking_adapter(coordinator, Arc::clone(&crash_count), "tracking-crash");
        let mut worker = Worker {
            fixture: None,
            database_path: None,
            state: WorkerState::Source(Box::new(SourceWorker { adapter, portable_state: None })),
        };
        let request = serde_json::to_vec(&RequestEnvelope::new(
            "tracking-crash",
            WorkerCommand::Crash { mode: CrashMode::Immediate, exit_code: 23 },
        ))
        .unwrap();
        let mut input = request;
        input.push(b'\n');
        assert_eq!(
            run_json_lines_with_worker(&mut worker, Cursor::new(input), Vec::new()).unwrap(),
            RunExit::Requested(23)
        );
        assert_eq!(crash_count.load(Ordering::SeqCst), 0);
        drop(worker);
        assert_eq!(crash_count.load(Ordering::SeqCst), 0);
        drop(providers.destination);
        remove_test_database(&database);
    }

    #[test]
    fn destination_pending_eof_and_explicit_into_do_not_double_teardown() {
        let prepared_count = Arc::new(AtomicU64::new(0));
        let live_count = Arc::new(AtomicU64::new(0));
        let fixture = FixtureSpec::new("tracking-pending-eof").unwrap();
        let database = test_database("tracking-pending-eof");
        let providers = fixture.open_providers(&database).unwrap();
        drop(providers.source);
        let mut worker = Worker {
            fixture: None,
            database_path: None,
            state: WorkerState::DestinationPending(Box::new(DestinationPending {
                provider: Some(providers.destination),
                prepared: Some(tracking_prepared(
                    Arc::clone(&prepared_count),
                    Arc::clone(&live_count),
                    TrackingFactory::identity(),
                    TrackingFactory::identity(),
                )),
                runtime: RuntimeImplementation::Wasmtime,
            })),
        };
        assert_eq!(
            run_json_lines_with_worker(&mut worker, Cursor::new(Vec::<u8>::new()), Vec::new())
                .unwrap(),
            RunExit::EndOfInput
        );
        assert_eq!(prepared_count.load(Ordering::SeqCst), 1);
        assert_eq!(live_count.load(Ordering::SeqCst), 0);
        worker.teardown_normal().unwrap();
        drop(worker);
        assert_eq!(prepared_count.load(Ordering::SeqCst), 1);
        remove_test_database(&database);

        let explicit_count = Arc::new(AtomicU64::new(0));
        let fixture = FixtureSpec::new("tracking-explicit-into").unwrap();
        let database = test_database("tracking-explicit-into");
        let providers = fixture.open_providers(&database).unwrap();
        let coordinator =
            Coordinator::recover(fixture.source_state.clone(), providers.source).unwrap();
        let adapter =
            tracking_adapter(coordinator, Arc::clone(&explicit_count), "tracking-explicit");
        let coordinator = match adapter.into_coordinator() {
            Ok(coordinator) => coordinator,
            Err(_) => panic!("tracking explicit teardown is infallible"),
        };
        assert_eq!(explicit_count.load(Ordering::SeqCst), 1);
        drop(coordinator);
        assert_eq!(explicit_count.load(Ordering::SeqCst), 1);
        drop(providers.destination);
        remove_test_database(&database);
    }

    #[test]
    fn replacement_discards_each_prepared_token_once_and_accepts_a_retry_token() {
        let initial_count = Arc::new(AtomicU64::new(0));
        let retry_count = Arc::new(AtomicU64::new(0));
        let live_count = Arc::new(AtomicU64::new(0));
        let mut pending = DestinationPending {
            provider: None,
            prepared: Some(tracking_prepared(
                Arc::clone(&initial_count),
                Arc::clone(&live_count),
                RuntimeIdentity::new("initial-prepared", "1", "tracking-engine", "1"),
                RuntimeIdentity::new("initial-live", "1", "tracking-engine", "1"),
            )),
            runtime: RuntimeImplementation::Wacogo,
        };

        pending.teardown_prepared().unwrap();
        pending.teardown_prepared().unwrap();
        assert_eq!(initial_count.load(Ordering::SeqCst), 1);
        assert!(pending.prepared.is_none());

        pending.prepared = Some(tracking_prepared(
            Arc::clone(&retry_count),
            Arc::clone(&live_count),
            RuntimeIdentity::new("retry-prepared", "1", "tracking-engine", "1"),
            RuntimeIdentity::new("retry-live", "1", "tracking-engine", "1"),
        ));
        assert_eq!(
            pending.prepared.as_ref().unwrap().runtime_metadata().identity.implementation,
            "retry-prepared"
        );
        assert_eq!(retry_count.load(Ordering::SeqCst), 0);
        pending.teardown_prepared().unwrap();
        pending.teardown_prepared().unwrap();
        assert_eq!(retry_count.load(Ordering::SeqCst), 1);
        assert_eq!(live_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn metadata_drift_tears_down_the_tracking_instance_exactly_once() {
        let prepared_count = Arc::new(AtomicU64::new(0));
        let live_count = Arc::new(AtomicU64::new(0));
        let fixture = FixtureSpec::new("tracking-metadata-drift").unwrap();
        let database = test_database("tracking-metadata-drift");
        let providers = fixture.open_providers(&database).unwrap();
        let coordinator =
            Coordinator::recover(fixture.source_state.clone(), providers.source).unwrap();
        let prepared = tracking_prepared(
            Arc::clone(&prepared_count),
            Arc::clone(&live_count),
            RuntimeIdentity::new("tracking-prepared", "1", "tracking-engine", "1"),
            RuntimeIdentity::new("tracking-live", "1", "tracking-engine", "1"),
        );

        let failure = instantiate_prepared_adapter(prepared, coordinator)
            .err()
            .expect("tracking metadata drift must fail closed");
        assert_eq!(
            failure.error.kind(),
            visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
        );
        assert_eq!(prepared_count.load(Ordering::SeqCst), 0);
        assert_eq!(live_count.load(Ordering::SeqCst), 1);
        drop(failure);
        assert_eq!(live_count.load(Ordering::SeqCst), 1);
        drop(providers.destination);
        remove_test_database(&database);
    }

    #[test]
    fn normal_eof_and_replacement_propagate_tracking_teardown_failures() {
        let live_count = Arc::new(AtomicU64::new(0));
        let fixture = FixtureSpec::new("tracking-eof-failure").unwrap();
        let database = test_database("tracking-eof-failure");
        let providers = fixture.open_providers(&database).unwrap();
        let coordinator =
            Coordinator::recover(fixture.source_state.clone(), providers.source).unwrap();
        let adapter = Adapter {
            inner: Some(Box::new(TrackingInstance {
                coordinator: Some(coordinator),
                identity: RuntimeIdentity::new("tracking-eof-failure", "1", "tracking-engine", "1"),
                teardowns: Arc::clone(&live_count),
                teardown_fails: true,
            })),
        };
        let mut worker = Worker {
            fixture: None,
            database_path: None,
            state: WorkerState::Source(Box::new(SourceWorker { adapter, portable_state: None })),
        };
        let error =
            run_json_lines_with_worker(&mut worker, Cursor::new(Vec::<u8>::new()), Vec::new())
                .expect_err("normal EOF must propagate a runtime teardown failure");
        assert!(error.to_string().contains("normal worker EOF teardown failed"));
        assert_eq!(live_count.load(Ordering::SeqCst), 1);
        worker.teardown_normal().unwrap();
        assert_eq!(live_count.load(Ordering::SeqCst), 1);
        drop(worker);
        drop(providers.destination);
        remove_test_database(&database);

        let prepared_count = Arc::new(AtomicU64::new(0));
        let mut pending = DestinationPending {
            provider: None,
            prepared: Some(PreparedAdapter {
                inner: Some(Box::new(TypedPrepared::<TrackingFactory> {
                    prepared: TrackingPrepared {
                        prepared_identity: TrackingFactory::identity(),
                        live_identity: TrackingFactory::identity(),
                        prepared_teardowns: Arc::clone(&prepared_count),
                        live_teardowns: Arc::new(AtomicU64::new(0)),
                        prepared_teardown_fails: true,
                        live_teardown_fails: false,
                    },
                    marker: PhantomData,
                })),
            }),
            runtime: RuntimeImplementation::Wacogo,
        };
        let error = pending
            .teardown_prepared()
            .expect_err("replacement must propagate prepared-token teardown failure");
        assert_eq!(
            error.kind(),
            visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
        );
        assert_eq!(prepared_count.load(Ordering::SeqCst), 1);
        assert!(pending.prepared.is_none());
        pending.teardown_prepared().unwrap();
        assert_eq!(prepared_count.load(Ordering::SeqCst), 1);
    }

    fn tracking_adapter(
        coordinator: Coordinator<SqliteProvider>,
        teardowns: Arc<AtomicU64>,
        label: &str,
    ) -> Adapter {
        Adapter {
            inner: Some(Box::new(TrackingInstance {
                coordinator: Some(coordinator),
                identity: RuntimeIdentity::new(label, "1", "tracking-engine", "1"),
                teardowns,
                teardown_fails: false,
            })),
        }
    }

    fn tracking_prepared(
        prepared_teardowns: Arc<AtomicU64>,
        live_teardowns: Arc<AtomicU64>,
        prepared_identity: RuntimeIdentity,
        live_identity: RuntimeIdentity,
    ) -> PreparedAdapter {
        PreparedAdapter {
            inner: Some(Box::new(TypedPrepared::<TrackingFactory> {
                prepared: TrackingPrepared {
                    prepared_identity,
                    live_identity,
                    prepared_teardowns,
                    live_teardowns,
                    prepared_teardown_fails: false,
                    live_teardown_fails: false,
                },
                marker: PhantomData,
            })),
        }
    }

    fn test_database(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "visa-system-{label}-{}-{}.sqlite",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn remove_test_database(database: &std::path::Path) {
        let _ = fs::remove_file(database);
        let _ = fs::remove_file(format!("{}-wal", database.display()));
        let _ = fs::remove_file(format!("{}-shm", database.display()));
    }

    #[test]
    #[ignore = "requires VISA_WACOGO_BIN pointing to the pinned production sidecar"]
    fn real_wacogo_instantiation_failure_returns_the_unchanged_coordinator() {
        assert!(
            std::env::var_os("VISA_WACOGO_BIN").is_some(),
            "set VISA_WACOGO_BIN before explicitly running this live focused test"
        );
        let fixture = FixtureSpec::new("wacogo-recoverable-instantiation").unwrap();
        let database = std::env::temp_dir().join(format!(
            "visa-system-registry-{}-{}.sqlite",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ));
        let providers = fixture.open_providers(&database).unwrap();
        let support =
            ProviderSupport::cooperative_handoff_v1(fixture.profile.required_extensions.clone());
        let prepared = preflight_adapter(
            RuntimeImplementation::Wacogo,
            crate::component::bytes(),
            &fixture.profile,
            &support,
            PreflightExpectations {
                component_digest: fixture.component_digest,
                profile_digest: fixture.profile_digest,
            },
        )
        .expect("the pinned Wacogo derivative must produce a real typed prepared token");
        let prepared_metadata = prepared.runtime_metadata();
        assert_eq!(prepared_metadata.identity.implementation, "visa_wacogo");
        assert!(prepared_metadata.translation_provenance.is_none());
        assert!(prepared_metadata.implementation_lineage.is_some());

        let mut mismatched_state = fixture.source_state.clone();
        mismatched_state.component_digest = contract_core::Digest::ZERO;
        let coordinator = Coordinator::recover(mismatched_state, providers.source).unwrap();
        let expected_state = coordinator.state().clone();
        let expected_digest = coordinator.state_digest().unwrap();
        let expected_journal_position = coordinator.journal_position();

        let failure = instantiate_prepared_adapter(prepared, coordinator)
            .err()
            .expect("the real Wacogo factory must return a recoverable digest mismatch");
        assert_eq!(
            failure.error.kind(),
            visa_component_adapter::AdapterFailureKind::ComponentDigestMismatch
        );
        assert_eq!(failure.coordinator.state(), &expected_state);
        assert_eq!(failure.coordinator.state_digest().unwrap(), expected_digest);
        assert_eq!(failure.coordinator.journal_position(), expected_journal_position);
        assert!(failure.coordinator.provider().fault_observation().is_none());

        drop(providers.destination);
        drop(failure);
        let _ = fs::remove_file(&database);
        let _ = fs::remove_file(database.with_extension("sqlite-wal"));
        let _ = fs::remove_file(database.with_extension("sqlite-shm"));
    }
}
