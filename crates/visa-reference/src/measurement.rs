//! Opt-in release control-path measurements for the reference vertical.
//!
//! The measurement path is intentionally outside the normal runtime/provider
//! path.  It wraps the coordinator ports, records elapsed time only while a
//! control operation is in flight, and reports the coordinator remainder as
//! the total coordinator step time minus the timed external ports.  No guest
//! increment/value call is made by this module.

use std::{fmt, time::Instant};

use visa_coordinator::{
    self as coordinator, ActivateRequest, AuthorityPort, CallOutcome, CaptureDurability,
    CapturedRuntime, CapturedSnapshot, Coordinator, CoordinatorControlCounts, DriveResult,
    FreezeSourceRequest, FrozenRuntime, PrepareDestinationRequest, QueryActivationRequest,
    QueryCaptureRequest, QueryOutcome, RestoreDestinationRequest, RestoreSourceRequest,
    RuntimePort,
};
use visa_core::{
    AuthorityId, ContinuationId, ContinuationIntent, Digest, ExternalCoordinate, LineageAdvance,
    LineageId, LineagePoint, ScopeId, SnapshotId,
};
use visa_profile::DurableKvProfile;
use visa_wasi::SnapshotContext;

use crate::{
    ReferenceDatabase, ReferenceDatabaseError,
    adapters::CoordinatorAuthorityAdapter,
    authority::{Authority, AuthorityError, Rights},
    provider::{DurableKvProvider, ProviderError},
    runtime::{CoordinatorRuntimeAdapter, ReferenceInstance, RuntimeError, WasmtimeVertical},
    store::RecordStore,
};

/// The phases measured by [`run_reference_measurement`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MeasurementStage {
    ComponentPreflightCompile,
    FreshInstantiate,
    DurableCapture,
    RecordReducerCoordinator,
    AuthorityPrepare,
    ResourceRebindRestore,
    AuthorityCommit,
    Activation,
    LostAckExactQuery,
}

impl fmt::Display for MeasurementStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ComponentPreflightCompile => "component preflight/compile",
            Self::FreshInstantiate => "fresh instantiate",
            Self::DurableCapture => "durable capture lifecycle",
            Self::RecordReducerCoordinator => "record/reducer/coordinator self",
            Self::AuthorityPrepare => "authority prepare",
            Self::ResourceRebindRestore => "resource rebind+restore",
            Self::AuthorityCommit => "authority commit",
            Self::Activation => "activation",
            Self::LostAckExactQuery => "lost-ack exact query",
        };
        formatter.write_str(name)
    }
}

/// Deterministic order used by text reports and callers that need a stable
/// stage list.
pub const MEASUREMENT_STAGES: [MeasurementStage; 9] = [
    MeasurementStage::ComponentPreflightCompile,
    MeasurementStage::FreshInstantiate,
    MeasurementStage::DurableCapture,
    MeasurementStage::RecordReducerCoordinator,
    MeasurementStage::AuthorityPrepare,
    MeasurementStage::ResourceRebindRestore,
    MeasurementStage::AuthorityCommit,
    MeasurementStage::Activation,
    MeasurementStage::LostAckExactQuery,
];

/// Configuration for the release control-path runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeasurementConfig {
    pub warmup: usize,
    pub samples: usize,
}

impl Default for MeasurementConfig {
    fn default() -> Self {
        Self { warmup: 1, samples: 5 }
    }
}

/// Summary of one latency series, in nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LatencyStats {
    pub count: usize,
    pub min_ns: u128,
    pub median_ns: u128,
    pub p95_ns: u128,
    pub max_ns: u128,
}

impl LatencyStats {
    /// Build a deterministic summary.  Percentiles use nearest-rank, with
    /// p95 selecting `ceil(0.95 * n)` (and therefore never an interpolated
    /// wall-clock value).
    pub fn from_samples(samples: &[u128]) -> Result<Self, MeasurementError> {
        if samples.is_empty() {
            return Err(MeasurementError::EmptySamples);
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let count = sorted.len();
        let median_index = (count - 1) / 2;
        let p95_rank = (count * 95).div_ceil(100).max(1);
        let p95_index = p95_rank - 1;
        Ok(Self {
            count,
            min_ns: sorted[0],
            median_ns: sorted[median_index],
            p95_ns: sorted[p95_index],
            max_ns: sorted[count - 1],
        })
    }
}

/// Summary of the coordinator remainder divided by timed external control
/// work.  The ratio is a percentage, not a claim about guest/application
/// latency.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RatioStats {
    pub count: usize,
    pub min_percent: f64,
    pub median_percent: f64,
    pub p95_percent: f64,
    pub max_percent: f64,
}

impl RatioStats {
    fn from_samples(samples: &[f64]) -> Result<Self, MeasurementError> {
        if samples.is_empty() {
            return Err(MeasurementError::EmptySamples);
        }
        if let Some(value) =
            samples.iter().copied().find(|value| !value.is_finite() || *value < 0.0)
        {
            return Err(MeasurementError::InvalidRatio(value));
        }
        let mut sorted = samples.to_vec();
        sorted.sort_by(f64::total_cmp);
        let count = sorted.len();
        let median_index = (count - 1) / 2;
        let p95_rank = (count * 95).div_ceil(100).max(1);
        let p95_index = p95_rank - 1;
        Ok(Self {
            count,
            min_percent: sorted[0],
            median_percent: sorted[median_index],
            p95_percent: sorted[p95_index],
            max_percent: sorted[count - 1],
        })
    }
}

/// One stage's latency summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageReport {
    pub stage: MeasurementStage,
    pub latency: LatencyStats,
}

/// Completed report for one reference vertical and one coordinator flow.
#[derive(Clone, Debug, PartialEq)]
pub struct MeasurementReport {
    pub warmup: usize,
    pub samples: usize,
    pub stages: Vec<StageReport>,
    pub external_control_work: LatencyStats,
    pub in_flow_external_control_work: LatencyStats,
    pub coordinator_overhead: LatencyStats,
    pub coordinator_over_external: RatioStats,
    pub coordinator_over_in_flow_external: RatioStats,
    pub coordinator_counts: CoordinatorControlCounts,
}

impl MeasurementReport {
    /// Return a release-gate error when the p95 coordinator ratio is above the
    /// requested threshold.  This is deliberately a caller/CLI decision and
    /// is not used by ordinary tests, where wall-clock assertions are avoided.
    pub fn validate_coordinator_ratio(&self, max_percent: f64) -> Result<(), MeasurementError> {
        if !max_percent.is_finite() || max_percent < 0.0 {
            return Err(MeasurementError::InvalidThreshold(max_percent));
        }
        if !self.coordinator_over_external.p95_percent.is_finite()
            || self.coordinator_over_external.p95_percent < 0.0
        {
            return Err(MeasurementError::InvalidRatio(self.coordinator_over_external.p95_percent));
        }
        if self.coordinator_over_external.p95_percent > max_percent {
            return Err(MeasurementError::CoordinatorRatioExceeded {
                p95_percent: self.coordinator_over_external.p95_percent,
                max_percent,
            });
        }
        Ok(())
    }

    /// Render a compact, stable report suitable for a release log.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut output =
            format!("reference control path: warmup={} samples={}\n", self.warmup, self.samples);
        for stage in &self.stages {
            let _ = fmt::Write::write_fmt(
                &mut output,
                format_args!(
                    "  {:<34} median={:>10} ns p95={:>10} ns min={:>10} ns max={:>10} ns\n",
                    stage.stage,
                    stage.latency.median_ns,
                    stage.latency.p95_ns,
                    stage.latency.min_ns,
                    stage.latency.max_ns
                ),
            );
        }
        let _ = fmt::Write::write_fmt(
            &mut output,
            format_args!(
                "  external control work              median={:>10} ns p95={:>10} ns\n",
                self.external_control_work.median_ns, self.external_control_work.p95_ns
            ),
        );
        let _ = fmt::Write::write_fmt(
            &mut output,
            format_args!(
                "  in-flow external work               median={:>10} ns p95={:>10} ns\n",
                self.in_flow_external_control_work.median_ns,
                self.in_flow_external_control_work.p95_ns
            ),
        );
        let _ = fmt::Write::write_fmt(
            &mut output,
            format_args!(
                "  coordinator overhead               median={:>10} ns p95={:>10} ns\n",
                self.coordinator_overhead.median_ns, self.coordinator_overhead.p95_ns
            ),
        );
        let _ = fmt::Write::write_fmt(
            &mut output,
            format_args!(
                "  coordinator/aggregate external     median={:.2}% p95={:.2}%\n",
                self.coordinator_over_external.median_percent,
                self.coordinator_over_external.p95_percent
            ),
        );
        let _ = fmt::Write::write_fmt(
            &mut output,
            format_args!(
                "  coordinator/in-flow external       median={:.2}% p95={:.2}%\n",
                self.coordinator_over_in_flow_external.median_percent,
                self.coordinator_over_in_flow_external.p95_percent
            ),
        );
        let _ = fmt::Write::write_fmt(
            &mut output,
            format_args!(
                "  coordinator counts                 drive={} recover={} reducer={} cas={} calls={} queries={}\n",
                self.coordinator_counts.drive,
                self.coordinator_counts.recover,
                self.coordinator_counts.reducer,
                self.coordinator_counts.cas,
                self.coordinator_counts.external_call,
                self.coordinator_counts.query,
            ),
        );
        output
    }
}

/// Errors returned by deterministic statistics and the opt-in runner.
#[derive(Debug)]
pub enum MeasurementError {
    EmptySamples,
    InvalidThreshold(f64),
    InvalidRatio(f64),
    CoordinatorRatioExceeded { p95_percent: f64, max_percent: f64 },
    NoExternalControlWork,
    AccountingMismatch { coordinator_total_ns: u128, external_ns: u128 },
    Database(ReferenceDatabaseError),
    Authority(AuthorityError),
    Provider(ProviderError),
    Runtime(RuntimeError),
    Wasi(visa_wasi::WasiError),
    Coordinator(String),
    Flow(String),
}

impl fmt::Display for MeasurementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySamples => formatter.write_str("measurement requires at least one sample"),
            Self::InvalidThreshold(value) => {
                write!(formatter, "invalid coordinator ratio threshold {value}")
            }
            Self::InvalidRatio(value) => write!(formatter, "invalid coordinator ratio {value}"),
            Self::CoordinatorRatioExceeded { p95_percent, max_percent } => write!(
                formatter,
                "coordinator p95 ratio {p95_percent:.2}% exceeds threshold {max_percent:.2}%"
            ),
            Self::NoExternalControlWork => {
                formatter.write_str("measurement recorded no external control work")
            }
            Self::AccountingMismatch { coordinator_total_ns, external_ns } => write!(
                formatter,
                "measurement accounting mismatch: coordinator interval {coordinator_total_ns} ns is smaller than nested external work {external_ns} ns"
            ),
            Self::Database(error) => write!(formatter, "reference database error: {error}"),
            Self::Authority(error) => write!(formatter, "reference authority error: {error}"),
            Self::Provider(error) => write!(formatter, "reference provider error: {error}"),
            Self::Runtime(error) => write!(formatter, "reference runtime error: {error}"),
            Self::Wasi(error) => write!(formatter, "WASI frontend error: {error}"),
            Self::Coordinator(error) => write!(formatter, "coordinator error: {error}"),
            Self::Flow(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for MeasurementError {}

impl From<ReferenceDatabaseError> for MeasurementError {
    fn from(error: ReferenceDatabaseError) -> Self {
        Self::Database(error)
    }
}
impl From<AuthorityError> for MeasurementError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}
impl From<ProviderError> for MeasurementError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}
impl From<RuntimeError> for MeasurementError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}
impl From<visa_wasi::WasiError> for MeasurementError {
    fn from(error: visa_wasi::WasiError) -> Self {
        Self::Wasi(error)
    }
}

#[derive(Clone, Debug, Default)]
struct RuntimeTimings {
    capture_ns: u128,
    capture_queries_ns: Vec<u128>,
    resource_prepare_ns: u128,
    resource_restore_ns: u128,
    activation_ns: u128,
    activation_queries_ns: u128,
}

/// Opt-in runtime-port timer.  It is intended for this module and other
/// embedding-side experiments; it does not alter `CoordinatorRuntimeAdapter`.
pub struct InstrumentedRuntime {
    inner: CoordinatorRuntimeAdapter,
    timings: RuntimeTimings,
}

impl InstrumentedRuntime {
    #[must_use]
    pub fn new(inner: CoordinatorRuntimeAdapter) -> Self {
        Self { inner, timings: RuntimeTimings::default() }
    }

    fn elapsed(start: Instant) -> u128 {
        start.elapsed().as_nanos()
    }

    fn timings(&self) -> &RuntimeTimings {
        &self.timings
    }
}

impl RuntimePort for InstrumentedRuntime {
    type Frozen = ();
    type Prepared = crate::runtime::PreparedDestination;
    type Restored = crate::runtime::RestoredDestination;
    type ActivationRejection = crate::runtime::CoordinatorRuntimeError;
    type Error = crate::runtime::CoordinatorRuntimeError;

    fn capture_durability(&self) -> CaptureDurability {
        self.inner.capture_durability()
    }

    fn capture(
        &mut self,
        request: coordinator::CaptureRequest,
    ) -> CallOutcome<CapturedRuntime<Self::Frozen>, Self::Error> {
        let start = Instant::now();
        let result = self.inner.capture(request);
        self.timings.capture_ns += Self::elapsed(start);
        result
    }

    fn query_capture(
        &mut self,
        request: QueryCaptureRequest,
    ) -> QueryOutcome<CapturedSnapshot, Self::Error> {
        let start = Instant::now();
        let result = self.inner.query_capture(request);
        self.timings.capture_queries_ns.push(Self::elapsed(start));
        result
    }

    fn retire_capture(&mut self, receipt: &visa_core::CaptureReceipt) -> Result<(), Self::Error> {
        let start = Instant::now();
        let result = self.inner.retire_capture(receipt);
        self.timings.capture_ns += Self::elapsed(start);
        result
    }

    fn freeze_source(
        &mut self,
        request: FreezeSourceRequest,
    ) -> CallOutcome<FrozenRuntime<Self::Frozen>, Self::Error> {
        self.inner.freeze_source(request)
    }

    fn restore_source(
        &mut self,
        request: RestoreSourceRequest,
    ) -> CallOutcome<visa_core::SourceRestorationReceipt, Self::Error> {
        self.inner.restore_source(request)
    }

    fn prepare_destination(
        &mut self,
        request: PrepareDestinationRequest,
    ) -> CallOutcome<Self::Prepared, Self::Error> {
        let start = Instant::now();
        let result = self.inner.prepare_destination(request);
        self.timings.resource_prepare_ns += Self::elapsed(start);
        result
    }

    fn restore_destination(
        &mut self,
        request: RestoreDestinationRequest<Self::Prepared>,
    ) -> CallOutcome<Self::Restored, Self::Error> {
        let start = Instant::now();
        let result = self.inner.restore_destination(request);
        self.timings.resource_restore_ns += Self::elapsed(start);
        result
    }

    fn activate(
        &mut self,
        request: ActivateRequest<Self::Restored>,
    ) -> CallOutcome<visa_core::ActivationReceipt, Self::ActivationRejection> {
        let start = Instant::now();
        let result = self.inner.activate(request);
        self.timings.activation_ns += Self::elapsed(start);
        result
    }

    fn query_activation(
        &mut self,
        request: QueryActivationRequest,
    ) -> QueryOutcome<visa_core::ActivationReceipt, Self::ActivationRejection> {
        let start = Instant::now();
        let result = self.inner.query_activation(request);
        self.timings.activation_queries_ns += Self::elapsed(start);
        result
    }
}

#[derive(Clone, Debug, Default)]
struct AuthorityTimings {
    prepare_ns: u128,
    prepare_queries_ns: u128,
    commit_ns: u128,
    commit_queries_ns: u128,
}

/// Opt-in authority-port timer used only by the release measurement runner.
pub struct InstrumentedAuthority {
    inner: CoordinatorAuthorityAdapter,
    timings: AuthorityTimings,
}

impl InstrumentedAuthority {
    #[must_use]
    pub fn new(inner: CoordinatorAuthorityAdapter) -> Self {
        Self { inner, timings: AuthorityTimings::default() }
    }

    fn elapsed(start: Instant) -> u128 {
        start.elapsed().as_nanos()
    }

    fn timings(&self) -> &AuthorityTimings {
        &self.timings
    }
}

impl AuthorityPort for InstrumentedAuthority {
    type PrepareRejection = crate::adapters::CoordinatorRejection;
    type CommitRejection = crate::adapters::CoordinatorRejection;
    type AbortRejection = crate::adapters::CoordinatorRejection;

    fn prepare(
        &mut self,
        request: coordinator::PrepareRequest,
    ) -> CallOutcome<visa_core::BindingPreparationReceipt, Self::PrepareRejection> {
        let start = Instant::now();
        let result = self.inner.prepare(request);
        self.timings.prepare_ns += Self::elapsed(start);
        result
    }

    fn query_prepare(
        &mut self,
        request: coordinator::QueryPrepareRequest,
    ) -> QueryOutcome<visa_core::BindingPreparationReceipt, Self::PrepareRejection> {
        let start = Instant::now();
        let result = self.inner.query_prepare(request);
        self.timings.prepare_queries_ns += Self::elapsed(start);
        result
    }

    fn commit(
        &mut self,
        request: coordinator::CommitRequest,
    ) -> CallOutcome<visa_core::AuthorityCommitReceipt, Self::CommitRejection> {
        let start = Instant::now();
        let result = self.inner.commit(request);
        self.timings.commit_ns += Self::elapsed(start);
        result
    }

    fn query_commit(
        &mut self,
        request: coordinator::QueryCommitRequest,
    ) -> QueryOutcome<visa_core::AuthorityCommitReceipt, Self::CommitRejection> {
        let start = Instant::now();
        let result = self.inner.query_commit(request);
        self.timings.commit_queries_ns += Self::elapsed(start);
        result
    }

    fn abort_preparation(
        &mut self,
        request: coordinator::AbortPreparationRequest,
    ) -> CallOutcome<visa_core::AbortPreparationReceipt, Self::AbortRejection> {
        self.inner.abort_preparation(request)
    }

    fn query_abort(
        &mut self,
        request: coordinator::QueryAbortRequest,
    ) -> QueryOutcome<visa_core::AbortPreparationReceipt, Self::AbortRejection> {
        self.inner.query_abort(request)
    }
}

struct SampleTimings {
    stages: [u128; 9],
    external_work_ns: u128,
    in_flow_external_work_ns: u128,
    coordinator_overhead_ns: u128,
    coordinator_ratio_percent: f64,
    coordinator_in_flow_ratio_percent: f64,
    counts: CoordinatorControlCounts,
}

fn coordinate(value: Vec<u8>) -> ExternalCoordinate {
    ExternalCoordinate { authority: AuthorityId::from_u128(1), value }
}

fn flow_error(message: impl Into<String>) -> MeasurementError {
    MeasurementError::Flow(message.into())
}

fn run_sample(sample: usize) -> Result<SampleTimings, MeasurementError> {
    let database = ReferenceDatabase::in_memory()?;
    let authority = Authority::new(database.clone())?;
    let owner = format!("measurement-source-{sample}");
    let source = authority.bootstrap(owner, 0, Rights::READ | Rights::WRITE)?;
    let provider = DurableKvProvider::new(database.clone());
    let source_binding = provider.bind_bootstrap_source(&authority, &source.binding_id)?;

    let preflight_start = Instant::now();
    let vertical = WasmtimeVertical::new()?;
    let preflight_ns = preflight_start.elapsed().as_nanos();

    let continuation = ContinuationId::from_u128((sample as u128) + 1);
    let scope = ScopeId::from_u128((sample as u128) + 1001);
    let lineage_parent = LineagePoint {
        lineage: LineageId::from_u128((sample as u128) + 2001),
        generation: 0,
        state_digest: Digest::ZERO,
    };
    let source_coordinate = coordinate(source.binding_id.as_bytes().to_vec());
    let intent = ContinuationIntent {
        id: continuation,
        scope,
        source: source_coordinate.clone(),
        destination: coordinate(format!("measurement-destination-{sample}").into_bytes()),
        lineage_parent: lineage_parent.clone(),
        profile: DurableKvProfile.profile_ref(),
    };
    let instantiate_start = Instant::now();
    let source_instance = ReferenceInstance::source_with_context(
        &vertical.prepared,
        provider.clone(),
        source_binding,
        SnapshotContext {
            snapshot: SnapshotId::from_u128((sample as u128) + 3001),
            continuation,
            scope,
            lineage: LineageAdvance { parent: lineage_parent, successor_generation: 1 },
            runtime: source_coordinate,
            cut_sequence: 0,
            receipt_digest: Digest::ZERO,
        },
    )?;
    let instantiate_ns = instantiate_start.elapsed().as_nanos();

    let mut runtime = CoordinatorRuntimeAdapter::new(authority.clone(), provider, vertical);
    runtime.install_source(source_instance);
    runtime.inject_capture_lost_ack_once();
    let mut coordinator = Coordinator::new(
        RecordStore::new(database),
        InstrumentedAuthority::new(CoordinatorAuthorityAdapter::new(authority)),
        InstrumentedRuntime::new(runtime),
    );

    let begin_start = Instant::now();
    coordinator.begin(intent).map_err(|error| flow_error(format!("begin failed: {error:?}")))?;
    let mut coordinator_total_ns = begin_start.elapsed().as_nanos();

    let first_start = Instant::now();
    let first = coordinator
        .drive(&continuation)
        .map_err(|error| flow_error(format!("capture drive failed: {error:?}")))?;
    coordinator_total_ns += first_start.elapsed().as_nanos();
    if first != DriveResult::Waiting {
        return Err(flow_error(format!("capture lost-ack path returned {first:?}")));
    }

    let recover_start = Instant::now();
    let recovered = coordinator
        .recover(&continuation)
        .map_err(|error| flow_error(format!("capture query failed: {error:?}")))?;
    coordinator_total_ns += recover_start.elapsed().as_nanos();
    if recovered != DriveResult::DurableBoundary {
        return Err(flow_error(format!("capture exact query returned {recovered:?}")));
    }

    let mut activated = false;
    for _ in 0..32 {
        let step_start = Instant::now();
        let result = coordinator
            .drive(&continuation)
            .map_err(|error| flow_error(format!("continuation drive failed: {error:?}")))?;
        coordinator_total_ns += step_start.elapsed().as_nanos();
        if result == DriveResult::Activated {
            activated = true;
            break;
        }
    }
    if !activated {
        return Err(flow_error("reference continuation did not reach activation"));
    }

    let runtime_timings = coordinator.runtime.timings();
    let authority_timings = coordinator.authority.timings();
    let counts = coordinator.read_control_counts();
    // The normal capture's initial absent query is internal to the reference
    // adapter. The wrapper sees the restart/recovery query, which is the
    // exact lost-ack query we report here.
    let lost_ack_query_ns = runtime_timings
        .capture_queries_ns
        .first()
        .copied()
        .ok_or_else(|| flow_error("capture lost-ack path did not perform an exact query"))?;
    let durable_capture_ns = runtime_timings.capture_ns;
    let authority_prepare_ns = authority_timings.prepare_ns + authority_timings.prepare_queries_ns;
    let resource_rebind_restore_ns =
        runtime_timings.resource_prepare_ns + runtime_timings.resource_restore_ns;
    let authority_commit_ns = authority_timings.commit_ns + authority_timings.commit_queries_ns;
    let activation_ns = runtime_timings.activation_ns + runtime_timings.activation_queries_ns;
    let in_flow_external_work_ns = durable_capture_ns
        .saturating_add(authority_prepare_ns)
        .saturating_add(resource_rebind_restore_ns)
        .saturating_add(authority_commit_ns)
        .saturating_add(activation_ns)
        .saturating_add(lost_ack_query_ns);
    // Component compilation and a fresh instance are external runtime
    // preparation. They happen before `Coordinator::begin`, so they are not
    // subtracted from coordinator step time, but they belong in the aggregate
    // denominator used for the release control-path comparison.
    let external_work_ns =
        preflight_ns.saturating_add(instantiate_ns).saturating_add(in_flow_external_work_ns);
    if external_work_ns == 0 || in_flow_external_work_ns == 0 {
        return Err(MeasurementError::NoExternalControlWork);
    }
    let coordinator_overhead_ns = coordinator_total_ns
        .checked_sub(in_flow_external_work_ns)
        .ok_or(MeasurementError::AccountingMismatch {
            coordinator_total_ns,
            external_ns: in_flow_external_work_ns,
        })?;
    let coordinator_ratio_percent =
        (coordinator_overhead_ns as f64 / external_work_ns as f64) * 100.0;
    let coordinator_in_flow_ratio_percent =
        (coordinator_overhead_ns as f64 / in_flow_external_work_ns as f64) * 100.0;

    Ok(SampleTimings {
        stages: [
            preflight_ns,
            instantiate_ns,
            durable_capture_ns,
            coordinator_overhead_ns,
            authority_prepare_ns,
            resource_rebind_restore_ns,
            authority_commit_ns,
            activation_ns,
            lost_ack_query_ns,
        ],
        external_work_ns,
        in_flow_external_work_ns,
        coordinator_overhead_ns,
        coordinator_ratio_percent,
        coordinator_in_flow_ratio_percent,
        counts,
    })
}

/// Run one real reference vertical after `warmup` discarded runs and return
/// median/p95 summaries for the requested samples.  This function is opt-in;
/// ordinary library use does not instantiate Wasmtime or add timers.
pub fn run_reference_measurement(
    config: MeasurementConfig,
) -> Result<MeasurementReport, MeasurementError> {
    if config.samples == 0 {
        return Err(MeasurementError::EmptySamples);
    }
    for warmup in 0..config.warmup {
        let _ = run_sample(warmup)?;
    }
    let mut samples = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        samples.push(run_sample(sample + config.warmup)?);
    }

    let mut stage_reports = Vec::with_capacity(MEASUREMENT_STAGES.len());
    for (index, stage) in MEASUREMENT_STAGES.iter().copied().enumerate() {
        let values: Vec<u128> = samples.iter().map(|sample| sample.stages[index]).collect();
        stage_reports.push(StageReport { stage, latency: LatencyStats::from_samples(&values)? });
    }
    let external_values: Vec<u128> = samples.iter().map(|sample| sample.external_work_ns).collect();
    let in_flow_external_values: Vec<u128> =
        samples.iter().map(|sample| sample.in_flow_external_work_ns).collect();
    let coordinator_values: Vec<u128> =
        samples.iter().map(|sample| sample.coordinator_overhead_ns).collect();
    let ratios: Vec<f64> = samples.iter().map(|sample| sample.coordinator_ratio_percent).collect();
    let in_flow_ratios: Vec<f64> =
        samples.iter().map(|sample| sample.coordinator_in_flow_ratio_percent).collect();
    let mut counts = CoordinatorControlCounts::default();
    for sample in &samples {
        counts.drive += sample.counts.drive;
        counts.recover += sample.counts.recover;
        counts.load += sample.counts.load;
        counts.cas += sample.counts.cas;
        counts.reducer += sample.counts.reducer;
        counts.arm += sample.counts.arm;
        counts.external_call += sample.counts.external_call;
        counts.query += sample.counts.query;
        counts.capture += sample.counts.capture;
        counts.prepare += sample.counts.prepare;
        counts.commit += sample.counts.commit;
        counts.abort += sample.counts.abort;
        counts.activation += sample.counts.activation;
    }
    Ok(MeasurementReport {
        warmup: config.warmup,
        samples: config.samples,
        stages: stage_reports,
        external_control_work: LatencyStats::from_samples(&external_values)?,
        in_flow_external_control_work: LatencyStats::from_samples(&in_flow_external_values)?,
        coordinator_overhead: LatencyStats::from_samples(&coordinator_values)?,
        coordinator_over_external: RatioStats::from_samples(&ratios)?,
        coordinator_over_in_flow_external: RatioStats::from_samples(&in_flow_ratios)?,
        coordinator_counts: counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_stats_use_nearest_rank_p95() {
        let stats = LatencyStats::from_samples(&[9, 1, 5, 3, 7]).unwrap();
        assert_eq!(stats.count, 5);
        assert_eq!(stats.min_ns, 1);
        assert_eq!(stats.median_ns, 5);
        assert_eq!(stats.p95_ns, 9);
        assert_eq!(stats.max_ns, 9);
    }

    #[test]
    fn stats_reject_empty_samples() {
        assert!(matches!(LatencyStats::from_samples(&[]), Err(MeasurementError::EmptySamples)));
        assert!(matches!(RatioStats::from_samples(&[]), Err(MeasurementError::EmptySamples)));
    }

    #[test]
    fn ratio_gate_rejects_invalid_and_excessive_thresholds() {
        let stats = RatioStats::from_samples(&[2.0, 4.0]).unwrap();
        assert_eq!(stats.p95_percent, 4.0);
        assert!(matches!(
            RatioStats::from_samples(&[f64::NAN]),
            Err(MeasurementError::InvalidRatio(value)) if value.is_nan()
        ));

        let latency = LatencyStats::from_samples(&[1]).unwrap();
        let mut report = MeasurementReport {
            warmup: 0,
            samples: 1,
            stages: Vec::new(),
            external_control_work: latency,
            in_flow_external_control_work: latency,
            coordinator_overhead: latency,
            coordinator_over_external: stats,
            coordinator_over_in_flow_external: stats,
            coordinator_counts: CoordinatorControlCounts::default(),
        };
        assert!(matches!(
            report.validate_coordinator_ratio(-1.0),
            Err(MeasurementError::InvalidThreshold(-1.0))
        ));
        assert!(matches!(
            report.validate_coordinator_ratio(3.0),
            Err(MeasurementError::CoordinatorRatioExceeded { p95_percent: 4.0, max_percent: 3.0 })
        ));
        report.coordinator_over_external.p95_percent = f64::NAN;
        assert!(matches!(
            report.validate_coordinator_ratio(100.0),
            Err(MeasurementError::InvalidRatio(value)) if value.is_nan()
        ));
    }
}
