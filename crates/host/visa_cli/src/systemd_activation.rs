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
        atomic::{AtomicBool, Ordering},
    },
};

use rustix::process::geteuid;
use zbus::{
    Connection,
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

const FROZEN_UNITS: [FrozenUnit; 5] = [
    FrozenUnit::Target,
    FrozenUnit::Ownershipd,
    FrozenUnit::Nexusd,
    FrozenUnit::SourceAgent,
    FrozenUnit::DestinationAgent,
];

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
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
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
            load_state: "not-found".to_owned(),
            active_state: "inactive".to_owned(),
            sub_state: "dead".to_owned(),
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
            load_state: row.2.clone(),
            active_state: row.3.clone(),
            sub_state: row.4.clone(),
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
                    && self.invocation_id.as_deref().is_some_and(|value| value.len() == 16)))
            && self.result.as_deref().is_none_or(|value| value == "success")
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
    Absent,
    PresentWithHealthyProcess,
    PresentWithoutHealthyProcess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationContext {
    pub exact_retry: bool,
    pub cohort_matches: bool,
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
    UnitBusy(FrozenUnit),
    FailedUnit(FrozenUnit),
    UnhealthyUnit(FrozenUnit),
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

    if !context.cohort_matches {
        return ActivationDecision::Conflict(ActivationConflict::DifferentCohort);
    }

    if let Some((snapshot, _)) = ordered
        .iter()
        .find(|(_, state)| matches!(state, UnitState::Activating | UnitState::Deactivating))
    {
        return ActivationDecision::Conflict(ActivationConflict::UnitBusy(snapshot.unit));
    }
    let any_active = ordered.iter().any(|(_, state)| *state == UnitState::Active);
    if any_active && !context.exact_retry {
        return ActivationDecision::Conflict(if context.cohort_matches {
            ActivationConflict::UnitBusy(
                ordered
                    .iter()
                    .find(|(_, state)| *state == UnitState::Active)
                    .map(|(snapshot, _)| snapshot.unit)
                    .unwrap_or(FrozenUnit::Target),
            )
        } else {
            ActivationConflict::DifferentCohort
        });
    }

    let nexusd = ordered
        .iter()
        .find(|(snapshot, _)| snapshot.unit == FrozenUnit::Nexusd)
        .expect("frozen unit list includes nexusd");
    if context.nexus_marker == NexusMarker::PresentWithoutHealthyProcess && !nexusd.0.healthy() {
        return ActivationDecision::Conflict(ActivationConflict::NexusMarkerLost);
    }

    if let Some((snapshot, _)) =
        ordered.iter().find(|(snapshot, state)| *state == UnitState::Active && !snapshot.healthy())
    {
        return ActivationDecision::Conflict(ActivationConflict::UnhealthyUnit(snapshot.unit));
    }

    if ordered.iter().all(|(snapshot, _)| snapshot.healthy()) {
        return ActivationDecision::AlreadyHealthy;
    }

    let mut start = ordered
        .iter()
        .filter_map(|(snapshot, state)| {
            matches!(state, UnitState::Inactive | UnitState::Missing).then_some(snapshot.unit)
        })
        .collect::<Vec<_>>();
    if let Some(unit) = ordered
        .iter()
        .find_map(|(snapshot, state)| (*state == UnitState::Failed).then_some(snapshot.unit))
    {
        return ActivationDecision::Conflict(ActivationConflict::FailedUnit(unit));
    }
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
    WrongManagerUid,
    ManagerChanged,
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
            Self::WrongManagerUid => {
                formatter.write_str("systemd user manager is not owned by the current uid")
            }
            Self::ManagerChanged => {
                formatter.write_str("systemd user manager owner changed during activation")
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
pub trait SystemdManager {
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
    manager_owner: OwnedUniqueName,
    prepared: Arc<AtomicBool>,
}

impl ActivationSession {
    pub async fn connect() -> Result<Self, ActivationError> {
        let connection = Connection::session().await?;
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
        Ok(Self { connection, manager_owner, prepared: Arc::new(AtomicBool::new(false)) })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn prepare(&self) -> Result<PreparedActivation<'_>, ActivationError> {
        if self.prepared.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            return Err(ActivationError::AlreadyPrepared);
        }
        let result = self.prepare_inner().await;
        if result.is_err() {
            // A failed setup did not leave a usable stream.  Permit a retry
            // on the same connection; once setup succeeds the gate remains
            // closed for the lifetime of that connection.
            self.prepared.store(false, Ordering::Release);
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
        manager.subscribe().await.map_err(ActivationError::Bus)?;
        // `receive_job_removed` awaits AddMatch registration.  Keeping this
        // stream alive is the active subscription required by the contract.
        let jobs = manager.receive_job_removed().await.map_err(ActivationError::Bus)?;
        self.require_manager_owner().await?;
        Ok(PreparedActivation {
            connection: &self.connection,
            manager,
            manager_owner: self.manager_owner.clone(),
            jobs,
        })
    }

    async fn require_manager_owner(&self) -> Result<(), ActivationError> {
        let dbus = DBusProxy::new(&self.connection).await.map_err(ActivationError::Bus)?;
        let systemd_name: WellKnownName<'_> =
            SYSTEMD_SERVICE.try_into().expect("frozen systemd service name is valid");
        let owner =
            dbus.get_name_owner(BusName::from(systemd_name)).await.map_err(ActivationError::Fdo)?;
        if owner != self.manager_owner {
            return Err(ActivationError::ManagerChanged);
        }
        Ok(())
    }
}

pub struct PreparedActivation<'a> {
    connection: &'a Connection,
    manager: SystemdManagerProxy<'a>,
    manager_owner: OwnedUniqueName,
    jobs: JobRemovedStream,
}

impl<'a> PreparedActivation<'a> {
    pub async fn start_unit(&mut self, unit: FrozenUnit) -> Result<JobOutcome, ActivationError> {
        self.require_manager_owner().await?;
        let job = self
            .manager
            .start_unit(unit.name().to_owned(), START_MODE.to_owned())
            .await
            .map_err(ActivationError::Bus)?;
        self.wait_for_job(job, unit).await
    }

    pub async fn stop_unit(&mut self, unit: FrozenUnit) -> Result<JobOutcome, ActivationError> {
        self.require_manager_owner().await?;
        let job = self
            .manager
            .stop_unit(unit.name().to_owned(), STOP_MODE.to_owned())
            .await
            .map_err(ActivationError::Bus)?;
        self.wait_for_job(job, unit).await
    }

    async fn wait_for_job(
        &mut self,
        job: OwnedObjectPath,
        unit: FrozenUnit,
    ) -> Result<JobOutcome, ActivationError> {
        let mut tracker = JobTracker::new(job.as_str(), unit.name());
        loop {
            let Some(message) = next_stream_item(&mut self.jobs).await else {
                return Err(ActivationError::Bus(zbus::Error::Failure(
                    "JobRemoved stream ended before the matching job".to_owned(),
                )));
            };
            let event = decode_job_removed(message).map_err(ActivationError::JobMessage)?;
            if let Some(outcome) = tracker.observe(event).map_err(ActivationError::Job)? {
                self.require_manager_owner().await?;
                return Ok(outcome);
            }
        }
    }

    pub async fn list_units(&self) -> Result<Vec<UnitSnapshot>, ActivationError> {
        self.require_manager_owner().await?;
        let names = FrozenUnit::all().iter().map(|unit| unit.name()).collect::<Vec<_>>();
        let rows = self.manager.list_units_by_names(&names).await.map_err(ActivationError::Bus)?;
        let mut result = Vec::with_capacity(names.len());
        for unit in FrozenUnit::all() {
            let Some(row) = rows.iter().find(|row| row.0 == unit.name()) else {
                result.push(UnitSnapshot::missing(*unit));
                continue;
            };
            let mut snapshot = UnitSnapshot::from_row(*unit, row);
            let path = self
                .manager
                .get_unit(unit.name().to_owned())
                .await
                .map_err(ActivationError::Bus)?;
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
        let systemd_name: WellKnownName<'_> =
            SYSTEMD_SERVICE.try_into().expect("frozen systemd service name is valid");
        let owner =
            dbus.get_name_owner(BusName::from(systemd_name)).await.map_err(ActivationError::Fdo)?;
        if owner != self.manager_owner {
            return Err(ActivationError::ManagerChanged);
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
                    cohort_matches: true,
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
                    cohort_matches: false,
                    nexus_marker: NexusMarker::Absent,
                },
            ),
            ActivationDecision::Conflict(ActivationConflict::DifferentCohort)
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
                    cohort_matches: true,
                    nexus_marker: NexusMarker::PresentWithHealthyProcess,
                },
            ),
            ActivationDecision::Start(vec![FrozenUnit::SourceAgent])
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
                    cohort_matches: true,
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
                    cohort_matches: true,
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
                    cohort_matches: true,
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
