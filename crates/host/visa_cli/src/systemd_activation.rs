//! Small, auditable systemd user-manager activation primitives.
//!
//! This module deliberately stops below the cohort ledger.  It owns the
//! frozen Manager call/JobRemoved choreography and a pure unit-state
//! evaluator; the caller still has to bind the result to a launch manifest,
//! perform product RPC health checks, and publish no authority receipt here.

use std::{
    fmt,
    future::poll_fn,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use async_io::Timer;
use futures_lite::FutureExt;
use rustix::process::geteuid;
use zbus::{
    Connection, OwnedGuid,
    export::futures_core::Stream,
    fdo::DBusProxy,
    names::{BusName, OwnedUniqueName, WellKnownName},
    proxy,
    zvariant::OwnedObjectPath,
};

pub const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
pub const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
pub const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
pub const START_MODE: &str = "replace";
pub const STOP_MODE: &str = "replace";
/// Maximum time to wait for a matching systemd JobRemoved signal.
///
/// A missing terminal signal is an unknown activation outcome. The caller
/// must query/reconcile that state rather than leaving the controller lease
/// blocked indefinitely.
pub const JOB_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum wall-clock time for one stable five-unit observation.
pub const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(30);

const FROZEN_UNITS: [FrozenUnit; 5] = [
    FrozenUnit::Target,
    FrozenUnit::Ownershipd,
    FrozenUnit::Nexusd,
    FrozenUnit::SourceAgent,
    FrozenUnit::DestinationAgent,
];

const PREPARE_OPEN: u8 = 0;
const PREPARE_INFLIGHT: u8 = 1;
const PREPARE_SUBSCRIBED: u8 = 2;
const PREPARE_DONE: u8 = 3;
const PREPARE_POISONED: u8 = 4;

/// The five frozen systemd units in the 0.1 launch contract.
///
/// The native Nexus effect peer is intentionally absent: it is a retained
/// child of `visa-nexusd`, not a sixth systemd unit.  Its liveness belongs to
/// the Nexus adapter health response after this layer returns.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FrozenUnit {
    Target,
    Ownershipd,
    Nexusd,
    SourceAgent,
    DestinationAgent,
}

impl FrozenUnit {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Target => "visa-local.target",
            Self::Ownershipd => "visa-ownershipd.service",
            Self::Nexusd => "visa-nexusd.service",
            Self::SourceAgent => "visa-agent@source.service",
            Self::DestinationAgent => "visa-agent@destination.service",
        }
    }

    pub const fn expected_sub_state(self) -> &'static str {
        match self {
            Self::Target => "active",
            Self::Ownershipd | Self::Nexusd | Self::SourceAgent | Self::DestinationAgent => {
                "running"
            }
        }
    }

    pub const fn all() -> &'static [Self; 5] {
        &FROZEN_UNITS
    }

    pub const fn is_service(self) -> bool {
        !matches!(self, Self::Target)
    }
}

/// A row returned by `ListUnitsByNames` (`a(ssssssouso)`).
pub type ListUnitRow =
    (String, String, String, String, String, String, OwnedObjectPath, u32, String, OwnedObjectPath);

/// The subset of Unit/Service properties needed by the pure evaluator and
/// the later product-health layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitSnapshot {
    pub unit: FrozenUnit,
    pub id: String,
    pub unit_path: OwnedObjectPath,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub job_id: u32,
    pub job_type: String,
    pub job_path: OwnedObjectPath,
    pub active_enter_timestamp: u64,
    pub invocation_id: Option<Vec<u8>>,
    pub main_pid: Option<u32>,
    pub result: Option<String>,
}

impl UnitSnapshot {
    pub fn missing(unit: FrozenUnit) -> Self {
        Self {
            unit,
            id: unit.name().to_owned(),
            unit_path: root_object_path(),
            load_state: "not-found".to_owned(),
            active_state: "inactive".to_owned(),
            sub_state: "dead".to_owned(),
            job_id: 0,
            job_type: String::new(),
            job_path: root_object_path(),
            active_enter_timestamp: 0,
            invocation_id: None,
            main_pid: None,
            result: None,
        }
    }

    pub fn from_row(unit: FrozenUnit, row: &ListUnitRow) -> Self {
        Self {
            unit,
            id: row.0.clone(),
            unit_path: row.6.clone(),
            load_state: row.2.clone(),
            active_state: row.3.clone(),
            sub_state: row.4.clone(),
            job_id: row.7,
            job_type: row.8.clone(),
            job_path: row.9.clone(),
            active_enter_timestamp: 0,
            invocation_id: None,
            main_pid: None,
            result: None,
        }
    }

    pub fn state(&self) -> UnitState {
        if self.id != self.unit.name() {
            return UnitState::Malformed;
        }
        if self.load_state == "not-found" {
            return UnitState::Missing;
        }
        if self.load_state != "loaded" {
            return UnitState::Unloaded;
        }
        match self.active_state.as_str() {
            "inactive" => UnitState::Inactive,
            "activating" => UnitState::Activating,
            "deactivating" => UnitState::Deactivating,
            "failed" => UnitState::Failed,
            "active" if self.sub_state == self.unit.expected_sub_state() => UnitState::Active,
            "active" => UnitState::Malformed,
            _ => UnitState::Malformed,
        }
    }

    pub fn healthy(&self) -> bool {
        self.state() == UnitState::Active
            && (!self.unit.is_service()
                || (self.main_pid.unwrap_or(0) != 0
                    && self.invocation_id.as_deref().is_some_and(|value| {
                        value.len() == 16 && value.iter().any(|byte| *byte != 0)
                    })))
            && (!self.unit.is_service() || self.result.as_deref() == Some("success"))
    }

    pub fn has_pending_job(&self) -> bool {
        self.job_id != 0 || !self.job_type.is_empty() || self.job_path.as_str() != "/"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnitState {
    Missing,
    Inactive,
    Activating,
    Deactivating,
    Active,
    Failed,
    Unloaded,
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NexusMarker {
    /// No registry-attempt marker exists for this cohort.
    Absent,
    /// The caller has already verified the marker's exact cohort/boot binding
    /// and the currently observed healthy `visa-nexusd` process identity.
    PresentWithHealthyProcess,
    /// A marker exists, but the caller has not established a matching healthy
    /// process.  This is a terminal retry boundary, not a start hint.
    PresentWithoutHealthyProcess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CohortMatch {
    /// No product cohort is active; a first create may proceed when all units
    /// are inactive or missing.
    NoActiveCohort,
    /// The observed active cohort is the exact manifest being retried.
    Exact,
    /// A different active cohort is present.
    Different,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationContext {
    pub exact_retry: bool,
    pub cohort: CohortMatch,
    pub nexus_marker: NexusMarker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationDecision {
    AlreadyHealthy,
    Start(Vec<FrozenUnit>),
    Conflict(ActivationConflict),
    Invalid(FrozenUnit, UnitState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationConflict {
    DifferentCohort,
    MalformedObservation,
    UnitBusy(FrozenUnit),
    FailedUnit(FrozenUnit),
    UnhealthyUnit(FrozenUnit),
    NexusMarkerMismatch,
    NexusMarkerLost,
}

/// Purely classify the five-unit observation before any `StartUnit` call.
///
/// This function does not inspect manifests or stores.  The caller supplies
/// those bindings in `ActivationContext`, so a fake proxy can exercise all
/// D-Bus edge cases without a user manager.
pub fn evaluate_activation(
    snapshots: &[UnitSnapshot],
    context: ActivationContext,
) -> ActivationDecision {
    let mut seen = [false; 5];
    let valid_set = snapshots.len() == FrozenUnit::all().len()
        && snapshots.iter().all(|snapshot| {
            let Some(index) = FrozenUnit::all().iter().position(|unit| *unit == snapshot.unit)
            else {
                return false;
            };
            if seen[index] {
                return false;
            }
            seen[index] = true;
            true
        })
        && seen.into_iter().all(|value| value);
    if !valid_set {
        return ActivationDecision::Conflict(ActivationConflict::MalformedObservation);
    }
    let mut ordered = Vec::with_capacity(FrozenUnit::all().len());
    for unit in FrozenUnit::all() {
        let Some(snapshot) = snapshots.iter().find(|value| value.unit == *unit) else {
            return ActivationDecision::Invalid(*unit, UnitState::Missing);
        };
        let state = snapshot.state();
        if matches!(state, UnitState::Malformed | UnitState::Unloaded) {
            return ActivationDecision::Invalid(*unit, state);
        }
        ordered.push((snapshot, state));
    }

    if context.cohort == CohortMatch::Different {
        return ActivationDecision::Conflict(ActivationConflict::DifferentCohort);
    }

    let any_active = ordered.iter().any(|(_, state)| *state == UnitState::Active);
    if context.exact_retry && context.cohort != CohortMatch::Exact {
        return ActivationDecision::Conflict(ActivationConflict::DifferentCohort);
    }
    if context.cohort == CohortMatch::NoActiveCohort && any_active {
        return ActivationDecision::Conflict(ActivationConflict::DifferentCohort);
    }

    if let Some((snapshot, _)) = ordered.iter().find(|(snapshot, _)| snapshot.has_pending_job()) {
        return ActivationDecision::Conflict(ActivationConflict::UnitBusy(snapshot.unit));
    }

    let nexusd = ordered
        .iter()
        .find(|(snapshot, _)| snapshot.unit == FrozenUnit::Nexusd)
        .expect("frozen unit list includes nexusd");
    let nexusd_healthy = nexusd.0.healthy();
    match (context.nexus_marker, nexusd_healthy) {
        (NexusMarker::Absent, true) | (NexusMarker::PresentWithoutHealthyProcess, true) => {
            return ActivationDecision::Conflict(ActivationConflict::NexusMarkerMismatch);
        }
        (NexusMarker::PresentWithHealthyProcess, false)
        | (NexusMarker::PresentWithoutHealthyProcess, false) => {
            return ActivationDecision::Conflict(ActivationConflict::NexusMarkerLost);
        }
        (NexusMarker::Absent, false) | (NexusMarker::PresentWithHealthyProcess, true) => {}
    }

    if let Some((snapshot, _)) = ordered
        .iter()
        .find(|(_, state)| matches!(state, UnitState::Activating | UnitState::Deactivating))
    {
        return ActivationDecision::Conflict(ActivationConflict::UnitBusy(snapshot.unit));
    }
    if any_active && !context.exact_retry {
        return ActivationDecision::Conflict(
            ordered
                .iter()
                .find(|(_, state)| *state == UnitState::Active)
                .map(|(snapshot, _)| ActivationConflict::UnitBusy(snapshot.unit))
                .unwrap_or(ActivationConflict::UnitBusy(FrozenUnit::Target)),
        );
    }

    if let Some((snapshot, _)) =
        ordered.iter().find(|(snapshot, state)| *state == UnitState::Active && !snapshot.healthy())
    {
        return ActivationDecision::Conflict(ActivationConflict::UnhealthyUnit(snapshot.unit));
    }

    if ordered.iter().all(|(snapshot, _)| snapshot.healthy()) {
        return ActivationDecision::AlreadyHealthy;
    }

    let failed = ordered
        .iter()
        .filter_map(|(snapshot, state)| (*state == UnitState::Failed).then_some(snapshot.unit))
        .collect::<Vec<_>>();
    if let Some(unit) = failed.iter().copied().find(|unit| !failed_restart_allowed(*unit, context))
    {
        return ActivationDecision::Conflict(ActivationConflict::FailedUnit(unit));
    }

    let mut start = ordered
        .iter()
        .filter_map(|(snapshot, state)| {
            let restartable_failed =
                *state == UnitState::Failed && failed_restart_allowed(snapshot.unit, context);
            matches!(state, UnitState::Inactive | UnitState::Missing)
                .then_some(snapshot.unit)
                .or_else(|| restartable_failed.then_some(snapshot.unit))
        })
        .collect::<Vec<_>>();
    // Start authorities before agents.  The unit graph still supplies the
    // authoritative ordering; this order only makes partial exact retries
    // deterministic and avoids asking systemd to recover a failed target.
    start.sort_by_key(|unit| match unit {
        FrozenUnit::Ownershipd => 0,
        FrozenUnit::Nexusd => 1,
        FrozenUnit::SourceAgent => 2,
        FrozenUnit::DestinationAgent => 3,
        FrozenUnit::Target => 4,
    });
    ActivationDecision::Start(start)
}

fn failed_restart_allowed(unit: FrozenUnit, context: ActivationContext) -> bool {
    context.exact_retry
        && (matches!(
            unit,
            FrozenUnit::Ownershipd | FrozenUnit::SourceAgent | FrozenUnit::DestinationAgent
        ) || (unit == FrozenUnit::Nexusd && context.nexus_marker == NexusMarker::Absent))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobRemovedEvent {
    pub id: u32,
    pub job: String,
    pub unit: String,
    pub result: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobOutcome {
    Done,
    Failed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobTrackerError {
    WrongUnit { expected: String, actual: String },
    Duplicate,
}

/// Matches a returned job path, including events already queued before the
/// `StartUnit` reply was observed.  Unrelated jobs are ignored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobTracker {
    expected_job: String,
    expected_unit: String,
    matched: bool,
}

impl JobTracker {
    pub fn new(expected_job: impl Into<String>, expected_unit: impl Into<String>) -> Self {
        Self {
            expected_job: expected_job.into(),
            expected_unit: expected_unit.into(),
            matched: false,
        }
    }

    pub fn observe(
        &mut self,
        event: JobRemovedEvent,
    ) -> Result<Option<JobOutcome>, JobTrackerError> {
        if event.job != self.expected_job {
            return Ok(None);
        }
        if self.matched {
            return Err(JobTrackerError::Duplicate);
        }
        if event.unit != self.expected_unit {
            return Err(JobTrackerError::WrongUnit {
                expected: self.expected_unit.clone(),
                actual: event.unit,
            });
        }
        self.matched = true;
        Ok(Some(if event.result == "done" {
            JobOutcome::Done
        } else {
            JobOutcome::Failed(event.result)
        }))
    }

    pub fn matched(&self) -> bool {
        self.matched
    }
}

#[derive(Debug)]
pub enum ActivationError {
    Bus(zbus::Error),
    Fdo(zbus::fdo::Error),
    AlreadyPrepared,
    SessionPoisoned,
    WrongManagerUid,
    BusChanged,
    ManagerChanged,
    ObservationChanged,
    ObservationTimeout,
    PendingJob(FrozenUnit),
    UnitPathChanged(FrozenUnit),
    /// The method reply or terminal signal was not observed. The operation is
    /// unknown; call `PreparedActivation::query_unit` before any retry.
    JobTimeout,
    /// A previous mutating call may have been accepted, but its terminal
    /// outcome is not known yet. Reconciliation is required before mutation.
    OutcomeUnknown(FrozenUnit),
    JobFailed {
        unit: FrozenUnit,
        result: String,
    },
    JobMessage(zbus::Error),
    Job(JobTrackerError),
}

impl fmt::Display for ActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bus(error) => write!(formatter, "systemd user-bus activation failed: {error}"),
            Self::Fdo(error) => {
                write!(formatter, "systemd user-bus daemon rejected activation: {error}")
            }
            Self::AlreadyPrepared => {
                formatter.write_str("activation session already subscribed to JobRemoved")
            }
            Self::SessionPoisoned => {
                formatter.write_str("activation session setup failed and is permanently poisoned")
            }
            Self::WrongManagerUid => {
                formatter.write_str("systemd user manager is not owned by the current uid")
            }
            Self::BusChanged => {
                formatter.write_str("D-Bus server identity changed during activation")
            }
            Self::ManagerChanged => {
                formatter.write_str("systemd user manager owner changed during activation")
            }
            Self::ObservationChanged => {
                formatter.write_str("systemd unit observation changed during activation")
            }
            Self::ObservationTimeout => {
                write!(formatter, "systemd unit observation exceeded {OBSERVATION_TIMEOUT:?}")
            }
            Self::PendingJob(unit) => {
                write!(formatter, "systemd unit {unit:?} has a pending job")
            }
            Self::UnitPathChanged(unit) => {
                write!(formatter, "systemd unit {unit:?} object path changed during observation")
            }
            Self::JobTimeout => {
                write!(formatter, "systemd job did not complete within {JOB_WAIT_TIMEOUT:?}")
            }
            Self::OutcomeUnknown(unit) => {
                write!(formatter, "systemd activation outcome for {unit:?} is unknown")
            }
            Self::JobFailed { unit, result } => {
                write!(formatter, "systemd job for {unit:?} failed with result {result:?}")
            }
            Self::JobMessage(error) => {
                write!(formatter, "malformed systemd JobRemoved signal: {error}")
            }
            Self::Job(error) => write!(formatter, "systemd job did not complete: {error:?}"),
        }
    }
}

impl std::error::Error for ActivationError {}

impl From<zbus::Error> for ActivationError {
    fn from(error: zbus::Error) -> Self {
        Self::Bus(error)
    }
}

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1",
    gen_blocking = false
)]
pub(crate) trait SystemdManager {
    #[zbus(name = "Subscribe", no_autostart)]
    fn subscribe(&self) -> zbus::Result<()>;

    #[zbus(name = "StartUnit", no_autostart)]
    fn start_unit(&self, name: String, mode: String) -> zbus::Result<OwnedObjectPath>;

    #[zbus(name = "StopUnit", no_autostart)]
    fn stop_unit(&self, name: String, mode: String) -> zbus::Result<OwnedObjectPath>;

    #[zbus(name = "GetUnit", no_autostart)]
    fn get_unit(&self, name: String) -> zbus::Result<OwnedObjectPath>;

    #[zbus(name = "ListUnitsByNames", no_autostart)]
    fn list_units_by_names(&self, names: &[&str]) -> zbus::Result<Vec<ListUnitRow>>;

    #[zbus(signal, name = "JobRemoved")]
    fn job_removed(
        &self,
        id: u32,
        job: zbus::zvariant::ObjectPath<'_>,
        unit: &str,
        result: &str,
    ) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1",
    gen_blocking = false
)]
trait SystemdUnit {
    #[zbus(property, name = "Id")]
    fn id(&self) -> zbus::Result<String>;
    #[zbus(property, name = "ActiveEnterTimestamp")]
    fn active_enter_timestamp(&self) -> zbus::Result<u64>;
    #[zbus(property, name = "InvocationID")]
    fn invocation_id(&self) -> zbus::Result<Vec<u8>>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Service",
    default_service = "org.freedesktop.systemd1",
    gen_blocking = false
)]
trait SystemdService {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> zbus::Result<u32>;
    #[zbus(property, name = "Result")]
    fn result(&self) -> zbus::Result<String>;
}

/// A connection-scoped activation handle.  `prepare` performs exactly one
/// Manager `Subscribe` and installs the JobRemoved match before any start.
#[derive(Clone, Debug)]
pub struct ActivationSession {
    connection: Connection,
    server_guid: OwnedGuid,
    manager_owner: OwnedUniqueName,
    prepare_state: Arc<AtomicU8>,
}

impl ActivationSession {
    pub async fn connect() -> Result<Self, ActivationError> {
        let connection = zbus::connection::Builder::session()
            .map_err(ActivationError::Bus)?
            .method_timeout(JOB_WAIT_TIMEOUT)
            .build()
            .await
            .map_err(ActivationError::Bus)?;
        let server_guid = connection.server_guid().clone();
        let dbus = DBusProxy::new(&connection).await.map_err(ActivationError::Bus)?;
        let systemd_name: WellKnownName<'_> =
            SYSTEMD_SERVICE.try_into().expect("frozen systemd service name is valid");
        let manager_owner =
            dbus.get_name_owner(BusName::from(systemd_name)).await.map_err(ActivationError::Fdo)?;
        let credentials = dbus
            .get_connection_credentials(manager_owner.as_ref().into())
            .await
            .map_err(ActivationError::Fdo)?;
        if credentials.unix_user_id() != Some(geteuid().as_raw()) {
            return Err(ActivationError::WrongManagerUid);
        }
        Ok(Self {
            connection,
            server_guid,
            manager_owner,
            prepare_state: Arc::new(AtomicU8::new(PREPARE_OPEN)),
        })
    }

    pub async fn prepare(&self) -> Result<PreparedActivation<'_>, ActivationError> {
        match self.prepare_state.compare_exchange(
            PREPARE_OPEN,
            PREPARE_INFLIGHT,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(PREPARE_POISONED) => return Err(ActivationError::SessionPoisoned),
            Err(PREPARE_INFLIGHT) => return Err(ActivationError::SessionPoisoned),
            Err(PREPARE_SUBSCRIBED) => return Err(ActivationError::SessionPoisoned),
            Err(_) => return Err(ActivationError::AlreadyPrepared),
        }
        let result = self.prepare_inner().await;
        if result.is_err() {
            // Failures before the Subscribe call is attempted may be retried.
            // Once the call is attempted, or if the future is cancelled, the
            // connection is never reused for another subscription.
            let _ = self.prepare_state.compare_exchange(
                PREPARE_SUBSCRIBED,
                PREPARE_POISONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            let _ = self.prepare_state.compare_exchange(
                PREPARE_INFLIGHT,
                PREPARE_OPEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        result
    }

    async fn prepare_inner(&self) -> Result<PreparedActivation<'_>, ActivationError> {
        self.require_manager_owner().await?;
        let manager = SystemdManagerProxy::builder(&self.connection)
            .destination(self.manager_owner.clone())
            .map_err(ActivationError::Bus)?
            .path(SYSTEMD_MANAGER_PATH)
            .map_err(ActivationError::Bus)?
            .build()
            .await
            .map_err(ActivationError::Bus)?;
        // Mark the connection non-retryable before sending the call. A method
        // timeout is ambiguous: systemd may have accepted Subscribe even when
        // its reply was lost, so a second attempt must never be issued.
        self.prepare_state.store(PREPARE_SUBSCRIBED, Ordering::Release);
        manager.subscribe().await.map_err(ActivationError::Bus)?;
        // `receive_job_removed` awaits AddMatch registration.  Keeping this
        // stream alive is the active subscription required by the contract.
        let jobs = manager.receive_job_removed().await.map_err(ActivationError::Bus)?;
        self.require_manager_owner().await?;
        self.prepare_state.store(PREPARE_DONE, Ordering::Release);
        Ok(PreparedActivation {
            connection: &self.connection,
            server_guid: self.server_guid.clone(),
            manager,
            manager_owner: self.manager_owner.clone(),
            jobs,
            unknown_unit: None,
        })
    }

    async fn require_manager_owner(&self) -> Result<(), ActivationError> {
        let dbus = DBusProxy::new(&self.connection).await.map_err(ActivationError::Bus)?;
        if self.connection.server_guid() != &self.server_guid {
            return Err(ActivationError::BusChanged);
        }
        let systemd_name: WellKnownName<'_> =
            SYSTEMD_SERVICE.try_into().expect("frozen systemd service name is valid");
        let owner =
            dbus.get_name_owner(BusName::from(systemd_name)).await.map_err(ActivationError::Fdo)?;
        if owner != self.manager_owner {
            return Err(ActivationError::ManagerChanged);
        }
        if self.connection.server_guid() != &self.server_guid {
            return Err(ActivationError::BusChanged);
        }
        Ok(())
    }
}

pub struct PreparedActivation<'a> {
    connection: &'a Connection,
    server_guid: OwnedGuid,
    manager: SystemdManagerProxy<'a>,
    manager_owner: OwnedUniqueName,
    jobs: JobRemovedStream,
    unknown_unit: Option<FrozenUnit>,
}

impl<'a> PreparedActivation<'a> {
    /// Issue one low-level start operation after the caller has completed
    /// cohort/manifest evaluation. A timeout is unknown and must be queried
    /// before another mutation.
    pub async fn start_unit(&mut self, unit: FrozenUnit) -> Result<JobOutcome, ActivationError> {
        self.require_known_outcome()?;
        self.require_manager_owner().await?;
        let job = match self.manager.start_unit(unit.name().to_owned(), START_MODE.to_owned()).await
        {
            Ok(job) => job,
            Err(error) => {
                self.unknown_unit = Some(unit);
                return Err(ActivationError::Bus(error));
            }
        };
        self.wait_for_job(job, unit).await
    }

    /// Issue one low-level stop operation after the caller has completed
    /// retirement evaluation. A timeout is unknown and must be queried before
    /// another mutation.
    pub async fn stop_unit(&mut self, unit: FrozenUnit) -> Result<JobOutcome, ActivationError> {
        self.require_known_outcome()?;
        self.require_manager_owner().await?;
        let job = match self.manager.stop_unit(unit.name().to_owned(), STOP_MODE.to_owned()).await {
            Ok(job) => job,
            Err(error) => {
                self.unknown_unit = Some(unit);
                return Err(ActivationError::Bus(error));
            }
        };
        self.wait_for_job(job, unit).await
    }

    fn require_known_outcome(&self) -> Result<(), ActivationError> {
        self.unknown_unit.map_or(Ok(()), |unit| Err(ActivationError::OutcomeUnknown(unit)))
    }

    fn mark_unknown(&mut self, unit: FrozenUnit) {
        self.unknown_unit = Some(unit);
    }

    async fn wait_for_job(
        &mut self,
        job: OwnedObjectPath,
        unit: FrozenUnit,
    ) -> Result<JobOutcome, ActivationError> {
        let mut tracker = JobTracker::new(job.as_str(), unit.name());
        let deadline =
            Instant::now().checked_add(JOB_WAIT_TIMEOUT).expect("activation job deadline overflow");
        loop {
            enum WaitResult<T> {
                Event(Option<T>),
                Timeout,
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.mark_unknown(unit);
                self.require_manager_owner().await?;
                return Err(ActivationError::JobTimeout);
            }
            let wait = async { WaitResult::Event(next_stream_item(&mut self.jobs).await) }
                .or(async move {
                    Timer::after(remaining).await;
                    WaitResult::Timeout
                })
                .await;
            match wait {
                WaitResult::Timeout => {
                    self.mark_unknown(unit);
                    self.require_manager_owner().await?;
                    return Err(ActivationError::JobTimeout);
                }
                WaitResult::Event(None) => {
                    self.mark_unknown(unit);
                    self.require_manager_owner().await?;
                    return Err(ActivationError::Bus(zbus::Error::Failure(
                        "JobRemoved stream ended before the matching job".to_owned(),
                    )));
                }
                WaitResult::Event(Some(message)) => {
                    let event = match decode_job_removed(message) {
                        Ok(event) => event,
                        Err(error) => {
                            self.mark_unknown(unit);
                            return Err(ActivationError::JobMessage(error));
                        }
                    };
                    let outcome = match tracker.observe(event) {
                        Ok(outcome) => outcome,
                        Err(error) => {
                            self.mark_unknown(unit);
                            return Err(ActivationError::Job(error));
                        }
                    };
                    if let Some(outcome) = outcome {
                        if let Err(error) = self.require_manager_owner().await {
                            self.mark_unknown(unit);
                            return Err(error);
                        }
                        return match outcome {
                            JobOutcome::Done => Ok(JobOutcome::Done),
                            JobOutcome::Failed(result) => {
                                Err(ActivationError::JobFailed { unit, result })
                            }
                        };
                    }
                }
            }
        }
    }

    pub async fn list_units(&self) -> Result<Vec<UnitSnapshot>, ActivationError> {
        let (first, second) = self.stable_unit_observation(true).await?;
        if first != second {
            return Err(ActivationError::ObservationChanged);
        }
        Ok(second)
    }

    async fn stable_unit_observation(
        &self,
        reject_pending: bool,
    ) -> Result<(Vec<UnitSnapshot>, Vec<UnitSnapshot>), ActivationError> {
        let observation = async {
            let first = self.list_units_once(reject_pending).await?;
            let second = self.list_units_once(reject_pending).await?;
            self.require_manager_owner().await?;
            Ok::<_, ActivationError>((first, second))
        };
        observation
            .or(async {
                Timer::after(OBSERVATION_TIMEOUT).await;
                Err(ActivationError::ObservationTimeout)
            })
            .await
    }

    /// Re-observe one unit through the same stable two-pass check used by the
    /// activation preflight. This is the required read path after a lost
    /// JobRemoved outcome. Pending jobs are returned as evidence instead of
    /// being treated as an idle unit.
    pub async fn query_unit(&mut self, unit: FrozenUnit) -> Result<UnitSnapshot, ActivationError> {
        let (first, second) = self.stable_unit_observation(false).await?;
        if first != second {
            return Err(ActivationError::ObservationChanged);
        }
        let snapshot = second
            .into_iter()
            .find(|snapshot| snapshot.unit == unit)
            .ok_or(ActivationError::ObservationChanged)?;
        if !snapshot.has_pending_job() && self.unknown_unit == Some(unit) {
            self.unknown_unit = None;
        }
        Ok(snapshot)
    }

    async fn list_units_once(
        &self,
        reject_pending: bool,
    ) -> Result<Vec<UnitSnapshot>, ActivationError> {
        self.require_manager_owner().await?;
        let names = FrozenUnit::all().iter().map(|unit| unit.name()).collect::<Vec<_>>();
        let rows = self.manager.list_units_by_names(&names).await.map_err(ActivationError::Bus)?;
        for row in &rows {
            let Some(_) = FrozenUnit::all().iter().find(|unit| unit.name() == row.0) else {
                return Err(ActivationError::ObservationChanged);
            };
            if rows.iter().filter(|candidate| candidate.0 == row.0).count() != 1 {
                return Err(ActivationError::ObservationChanged);
            }
        }
        let mut result = Vec::with_capacity(names.len());
        for unit in FrozenUnit::all() {
            let Some(row) = rows.iter().find(|row| row.0 == unit.name()) else {
                // ListUnitsByNames omits names that are not loaded; this is
                // the systemd-defined representation of a missing unit.
                result.push(UnitSnapshot::missing(*unit));
                continue;
            };
            let pending = row.7 != 0 || !row.8.is_empty() || row.9.as_str() != "/";
            if reject_pending && pending {
                return Err(ActivationError::PendingJob(*unit));
            }
            if row.2 == "not-found" {
                if pending || row.6.as_str() != "/" || row.3 != "inactive" || row.4 != "dead" {
                    return Err(ActivationError::ObservationChanged);
                }
                result.push(UnitSnapshot::missing(*unit));
                continue;
            }
            let mut snapshot = UnitSnapshot::from_row(*unit, row);
            let path = self
                .manager
                .get_unit(unit.name().to_owned())
                .await
                .map_err(ActivationError::Bus)?;
            if path != row.6 {
                return Err(ActivationError::UnitPathChanged(*unit));
            }
            let unit_proxy = SystemdUnitProxy::builder(self.connection)
                .destination(self.manager_owner.clone())
                .map_err(ActivationError::Bus)?
                .path(&path)
                .map_err(ActivationError::Bus)?
                .build()
                .await
                .map_err(ActivationError::Bus)?;
            snapshot.id = unit_proxy.id().await.map_err(ActivationError::Bus)?;
            snapshot.active_enter_timestamp =
                unit_proxy.active_enter_timestamp().await.map_err(ActivationError::Bus)?;
            snapshot.invocation_id =
                Some(unit_proxy.invocation_id().await.map_err(ActivationError::Bus)?);
            if unit.is_service() {
                let service = SystemdServiceProxy::builder(self.connection)
                    .destination(self.manager_owner.clone())
                    .map_err(ActivationError::Bus)?
                    .path(&path)
                    .map_err(ActivationError::Bus)?
                    .build()
                    .await
                    .map_err(ActivationError::Bus)?;
                snapshot.main_pid = Some(service.main_pid().await.map_err(ActivationError::Bus)?);
                snapshot.result = Some(service.result().await.map_err(ActivationError::Bus)?);
            }
            result.push(snapshot);
        }
        self.require_manager_owner().await?;
        Ok(result)
    }

    async fn require_manager_owner(&self) -> Result<(), ActivationError> {
        let dbus = DBusProxy::new(self.connection).await.map_err(ActivationError::Bus)?;
        if self.connection.server_guid() != &self.server_guid {
            return Err(ActivationError::BusChanged);
        }
        let systemd_name: WellKnownName<'_> =
            SYSTEMD_SERVICE.try_into().expect("frozen systemd service name is valid");
        let owner =
            dbus.get_name_owner(BusName::from(systemd_name)).await.map_err(ActivationError::Fdo)?;
        if owner != self.manager_owner {
            return Err(ActivationError::ManagerChanged);
        }
        if self.connection.server_guid() != &self.server_guid {
            return Err(ActivationError::BusChanged);
        }
        Ok(())
    }
}

async fn next_stream_item<S>(stream: &mut S) -> Option<S::Item>
where
    S: Stream + Unpin,
{
    poll_fn(|context| Pin::new(&mut *stream).poll_next(context)).await
}

fn decode_job_removed(signal: JobRemoved) -> zbus::Result<JobRemovedEvent> {
    let args = signal.args()?;
    Ok(JobRemovedEvent {
        id: *args.id(),
        job: args.job().to_string(),
        unit: args.unit().to_string(),
        result: args.result().to_string(),
    })
}

fn root_object_path() -> OwnedObjectPath {
    "/".try_into().expect("frozen root object path is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(unit: FrozenUnit, active: &str, sub: &str) -> UnitSnapshot {
        let mut value = UnitSnapshot::missing(unit);
        value.load_state = "loaded".to_owned();
        value.active_state = active.to_owned();
        value.sub_state = sub.to_owned();
        value.main_pid = unit.is_service().then_some(42);
        value.result = unit.is_service().then(|| "success".to_owned());
        value.invocation_id = unit.is_service().then(|| vec![0x42; 16]);
        value
    }

    fn healthy_set() -> Vec<UnitSnapshot> {
        FrozenUnit::all()
            .iter()
            .map(|unit| snapshot(*unit, "active", unit.expected_sub_state()))
            .collect()
    }

    #[test]
    fn exact_healthy_set_is_idempotent() {
        assert_eq!(
            evaluate_activation(
                &healthy_set(),
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::AlreadyHealthy
        );
    }

    #[test]
    fn different_live_cohort_is_rejected_before_start() {
        assert_eq!(
            evaluate_activation(
                &healthy_set(),
                ActivationContext {
                    exact_retry: false,
                    cohort: CohortMatch::Different,
                    nexus_marker: NexusMarker::Absent,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::DifferentCohort)
        );
    }

    #[test]
    fn first_create_with_no_active_cohort_can_start_in_order() {
        let values = FrozenUnit::all()
            .iter()
            .map(|unit| snapshot(*unit, "inactive", "dead"))
            .collect::<Vec<_>>();
        assert_eq!(
            evaluate_activation(
                &values,
                ActivationContext {
                    exact_retry: false,
                    cohort: CohortMatch::NoActiveCohort,
                    nexus_marker: NexusMarker::Absent,
                },
            ),
            ActivationDecision::Start(vec![
                FrozenUnit::Ownershipd,
                FrozenUnit::Nexusd,
                FrozenUnit::SourceAgent,
                FrozenUnit::DestinationAgent,
                FrozenUnit::Target,
            ])
        );
    }

    #[test]
    fn no_active_cohort_with_a_live_unit_is_a_conflict() {
        assert_eq!(
            evaluate_activation(
                &healthy_set(),
                ActivationContext {
                    exact_retry: false,
                    cohort: CohortMatch::NoActiveCohort,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::DifferentCohort)
        );
    }

    #[test]
    fn pending_job_is_busy_even_when_unit_state_is_inactive() {
        let mut values = healthy_set();
        let source = values.iter_mut().find(|value| value.unit == FrozenUnit::SourceAgent).unwrap();
        source.active_state = "inactive".to_owned();
        source.sub_state = "dead".to_owned();
        source.job_id = 7;
        source.job_type = "start".to_owned();
        source.job_path = "/org/freedesktop/systemd1/job/7".try_into().unwrap();
        assert_eq!(
            evaluate_activation(
                &values,
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::UnitBusy(FrozenUnit::SourceAgent))
        );
    }

    #[test]
    fn evaluator_rejects_duplicate_or_missing_unit_entries() {
        let mut duplicate = healthy_set();
        duplicate[4] = duplicate[3].clone();
        assert_eq!(
            evaluate_activation(
                &duplicate,
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::MalformedObservation)
        );

        let missing = healthy_set();
        assert_eq!(
            evaluate_activation(
                &missing[..4],
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::MalformedObservation)
        );
    }

    #[test]
    fn partial_exact_retry_starts_authorities_before_agents() {
        let mut values = healthy_set();
        values
            .iter_mut()
            .find(|value| value.unit == FrozenUnit::SourceAgent)
            .unwrap()
            .active_state = "inactive".to_owned();
        values.iter_mut().find(|value| value.unit == FrozenUnit::SourceAgent).unwrap().sub_state =
            "dead".to_owned();
        assert_eq!(
            evaluate_activation(
                &values,
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Start(vec![FrozenUnit::SourceAgent])
        );
    }

    #[test]
    fn exact_retry_restarts_allowed_failed_roles_but_not_target() {
        let mut values = healthy_set();
        values
            .iter_mut()
            .find(|value| value.unit == FrozenUnit::Ownershipd)
            .unwrap()
            .active_state = "failed".to_owned();
        values.iter_mut().find(|value| value.unit == FrozenUnit::Ownershipd).unwrap().sub_state =
            "failed".to_owned();
        assert_eq!(
            evaluate_activation(
                &values,
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Start(vec![FrozenUnit::Ownershipd])
        );

        let mut target_failed = healthy_set();
        target_failed
            .iter_mut()
            .find(|value| value.unit == FrozenUnit::Target)
            .unwrap()
            .active_state = "failed".to_owned();
        target_failed
            .iter_mut()
            .find(|value| value.unit == FrozenUnit::Target)
            .unwrap()
            .sub_state = "failed".to_owned();
        assert_eq!(
            evaluate_activation(
                &target_failed,
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::FailedUnit(FrozenUnit::Target))
        );
    }

    #[test]
    fn nexus_marker_must_match_live_process_both_directions() {
        let values = healthy_set();
        for marker in [NexusMarker::Absent, NexusMarker::PresentWithoutHealthyProcess] {
            assert_eq!(
                evaluate_activation(
                    &values,
                    ActivationContext {
                        exact_retry: true,
                        cohort: CohortMatch::Exact,
                        nexus_marker: marker
                    },
                ),
                ActivationDecision::Conflict(ActivationConflict::NexusMarkerMismatch)
            );
        }

        let mut dead = healthy_set();
        let nexusd = dead.iter_mut().find(|value| value.unit == FrozenUnit::Nexusd).unwrap();
        nexusd.active_state = "inactive".to_owned();
        nexusd.sub_state = "dead".to_owned();
        assert_eq!(
            evaluate_activation(
                &dead,
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::NexusMarkerLost)
        );
    }

    #[test]
    fn nexus_tombstone_without_live_process_burns_retry() {
        let mut values = healthy_set();
        let nexusd = values.iter_mut().find(|value| value.unit == FrozenUnit::Nexusd).unwrap();
        nexusd.active_state = "inactive".to_owned();
        nexusd.sub_state = "dead".to_owned();
        assert_eq!(
            evaluate_activation(
                &values,
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithoutHealthyProcess,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::NexusMarkerLost)
        );
    }

    #[test]
    fn activating_unit_is_busy_even_for_an_exact_retry() {
        let mut values = healthy_set();
        let source = values.iter_mut().find(|value| value.unit == FrozenUnit::SourceAgent).unwrap();
        source.active_state = "activating".to_owned();
        source.sub_state = "start".to_owned();
        assert_eq!(
            evaluate_activation(
                &values,
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::UnitBusy(FrozenUnit::SourceAgent))
        );
    }

    #[test]
    fn active_but_unhealthy_member_is_not_silently_accepted() {
        let mut values = healthy_set();
        let source = values.iter_mut().find(|value| value.unit == FrozenUnit::SourceAgent).unwrap();
        source.main_pid = Some(0);
        assert_eq!(
            evaluate_activation(
                &values,
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::UnhealthyUnit(
                FrozenUnit::SourceAgent
            ))
        );
    }

    #[test]
    fn zero_invocation_id_is_not_healthy() {
        let mut values = healthy_set();
        let source = values.iter_mut().find(|value| value.unit == FrozenUnit::SourceAgent).unwrap();
        source.invocation_id = Some(vec![0; 16]);
        assert_eq!(
            evaluate_activation(
                &values,
                ActivationContext {
                    exact_retry: true,
                    cohort: CohortMatch::Exact,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::UnhealthyUnit(
                FrozenUnit::SourceAgent
            ))
        );
    }

    #[test]
    fn job_tracker_accepts_buffered_event_and_requires_done() {
        let mut tracker = JobTracker::new("/org/freedesktop/systemd1/job/7", "visa-local.target");
        assert_eq!(
            tracker.observe(JobRemovedEvent {
                id: 6,
                job: "/org/freedesktop/systemd1/job/6".to_owned(),
                unit: "other.service".to_owned(),
                result: "done".to_owned(),
            }),
            Ok(None)
        );
        assert_eq!(
            tracker.observe(JobRemovedEvent {
                id: 7,
                job: "/org/freedesktop/systemd1/job/7".to_owned(),
                unit: "visa-local.target".to_owned(),
                result: "done".to_owned(),
            }),
            Ok(Some(JobOutcome::Done))
        );
    }

    #[test]
    fn matching_failed_result_is_not_success() {
        let mut tracker = JobTracker::new("/job/9", "visa-nexusd.service");
        assert_eq!(
            tracker.observe(JobRemovedEvent {
                id: 9,
                job: "/job/9".to_owned(),
                unit: "visa-nexusd.service".to_owned(),
                result: "timeout".to_owned(),
            }),
            Ok(Some(JobOutcome::Failed("timeout".to_owned())))
        );
    }

    #[test]
    fn matching_job_with_wrong_unit_is_integrity_error() {
        let mut tracker = JobTracker::new("/job/10", "visa-local.target");
        assert_eq!(
            tracker.observe(JobRemovedEvent {
                id: 10,
                job: "/job/10".to_owned(),
                unit: "visa-nexusd.service".to_owned(),
                result: "done".to_owned(),
            }),
            Err(JobTrackerError::WrongUnit {
                expected: "visa-local.target".to_owned(),
                actual: "visa-nexusd.service".to_owned(),
            })
        );
    }
}
