#![cfg(target_os = "linux")]

use std::{
    env,
    process::Command,
    sync::{Arc, Mutex},
};

use visa_cli::{
    ActivationError, ActivationSession, FrozenUnit, JobOutcome, ListUnitRow,
    systemd_activation::{SYSTEMD_MANAGER_PATH, SYSTEMD_SERVICE},
};
use zbus::{
    interface,
    message::{Flags, Header},
    object_server::SignalEmitter,
    zvariant::{ObjectPath, OwnedObjectPath},
};

const INNER_ENV: &str = "VISA_CLI_SYSTEMD_PRIVATE_BUS_INNER";

const TARGET_PATH: &str = "/org/freedesktop/systemd1/unit/visa_2dlocal_2etarget";
const OWNERSHIPD_PATH: &str = "/org/freedesktop/systemd1/unit/visa_2downershipd_2eservice";
const NEXUSD_PATH: &str = "/org/freedesktop/systemd1/unit/visa_2dnexusd_2eservice";
const SOURCE_PATH: &str = "/org/freedesktop/systemd1/unit/visa_2dagent_40source_2eservice";
const DESTINATION_PATH: &str =
    "/org/freedesktop/systemd1/unit/visa_2dagent_40destination_2eservice";

#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    Subscribe { no_autostart: bool },
    Start { unit: String, mode: String, no_autostart: bool },
    Stop { unit: String, mode: String, no_autostart: bool },
    List { units: Vec<String>, no_autostart: bool },
    Get { unit: String, no_autostart: bool },
}

#[derive(Debug)]
struct FakeState {
    calls: Vec<Call>,
    subscribed: bool,
    next_job: u32,
    missing_rows: bool,
}

impl FakeState {
    fn new() -> Self {
        Self { calls: Vec::new(), subscribed: false, next_job: 1, missing_rows: false }
    }

    fn next_job(&mut self) -> (u32, OwnedObjectPath) {
        let id = self.next_job;
        self.next_job = self.next_job.checked_add(1).expect("fake job id overflow");
        let path: OwnedObjectPath =
            format!("/org/freedesktop/systemd1/job/{id}").try_into().expect("valid job path");
        (id, path)
    }
}

#[derive(Clone)]
struct FakeManager(Arc<Mutex<FakeState>>);

#[interface(name = "org.freedesktop.systemd1.Manager")]
impl FakeManager {
    #[zbus(name = "Subscribe")]
    fn subscribe(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<()> {
        let mut state = self.0.lock().expect("fake systemd state");
        state.calls.push(Call::Subscribe {
            no_autostart: header.primary().flags().contains(Flags::NoAutoStart),
        });
        state.subscribed = true;
        Ok(())
    }

    #[zbus(name = "StartUnit")]
    async fn start_unit(
        &self,
        unit: String,
        mode: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let (id, job) = {
            let mut state = self.0.lock().expect("fake systemd state");
            state.calls.push(Call::Start {
                unit: unit.clone(),
                mode,
                no_autostart: header.primary().flags().contains(Flags::NoAutoStart),
            });
            if !state.subscribed {
                return Err(zbus::fdo::Error::Failed(
                    "StartUnit called before Subscribe".to_owned(),
                ));
            }
            state.next_job()
        };
        // Emit before returning the method reply. The client must have
        // installed its JobRemoved match already and retain the event while
        // it learns the returned job object path.
        Self::job_removed(&emitter, id, job.as_ref(), &unit, "done")
            .await
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        Ok(job)
    }

    #[zbus(name = "StopUnit")]
    async fn stop_unit(
        &self,
        unit: String,
        mode: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let (id, job) = {
            let mut state = self.0.lock().expect("fake systemd state");
            state.calls.push(Call::Stop {
                unit: unit.clone(),
                mode,
                no_autostart: header.primary().flags().contains(Flags::NoAutoStart),
            });
            if !state.subscribed {
                return Err(zbus::fdo::Error::Failed(
                    "StopUnit called before Subscribe".to_owned(),
                ));
            }
            state.next_job()
        };
        Self::job_removed(&emitter, id, job.as_ref(), &unit, "done")
            .await
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        Ok(job)
    }

    #[zbus(name = "ListUnitsByNames")]
    fn list_units_by_names(
        &self,
        units: Vec<String>,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<Vec<ListUnitRow>> {
        let mut state = self.0.lock().expect("fake systemd state");
        let missing_rows = state.missing_rows;
        state.calls.push(Call::List {
            units,
            no_autostart: header.primary().flags().contains(Flags::NoAutoStart),
        });
        Ok(FrozenUnit::all()
            .iter()
            .map(|unit| {
                if missing_rows {
                    (
                        unit.name().to_owned(),
                        format!("missing {}", unit.name()),
                        "not-found".to_owned(),
                        "inactive".to_owned(),
                        "dead".to_owned(),
                        String::new(),
                        unit_path(*unit),
                        0,
                        String::new(),
                        root_path(),
                    )
                } else {
                    (
                        unit.name().to_owned(),
                        format!("fake {}", unit.name()),
                        "loaded".to_owned(),
                        "active".to_owned(),
                        unit.expected_sub_state().to_owned(),
                        String::new(),
                        unit_path(*unit),
                        0,
                        String::new(),
                        root_path(),
                    )
                }
            })
            .collect())
    }

    #[zbus(name = "GetUnit")]
    fn get_unit(
        &self,
        unit: String,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let mut state = self.0.lock().expect("fake systemd state");
        state.calls.push(Call::Get {
            unit: unit.clone(),
            no_autostart: header.primary().flags().contains(Flags::NoAutoStart),
        });
        if state.missing_rows {
            return Err(zbus::fdo::Error::Failed("unit was collected before GetUnit".to_owned()));
        }
        FrozenUnit::all()
            .iter()
            .find(|candidate| candidate.name() == unit)
            .map(|candidate| unit_path(*candidate))
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("unknown frozen unit".to_owned()))
    }

    #[zbus(signal)]
    async fn job_removed(
        emitter: &SignalEmitter<'_>,
        id: u32,
        job: ObjectPath<'_>,
        unit: &str,
        result: &str,
    ) -> zbus::Result<()>;
}

#[derive(Clone, Copy)]
struct FakeUnit(FrozenUnit);

#[interface(name = "org.freedesktop.systemd1.Unit")]
impl FakeUnit {
    #[zbus(property, name = "Id")]
    fn id(&self) -> String {
        self.0.name().to_owned()
    }

    #[zbus(property, name = "ActiveEnterTimestamp")]
    fn active_enter_timestamp(&self) -> u64 {
        1_000 + self.0 as u64
    }

    #[zbus(property, name = "InvocationID")]
    fn invocation_id(&self) -> Vec<u8> {
        vec![self.0 as u8 + 1; 16]
    }
}

#[derive(Clone, Copy)]
struct FakeService(FrozenUnit);

#[interface(name = "org.freedesktop.systemd1.Service")]
impl FakeService {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> u32 {
        10_000 + self.0 as u32
    }

    #[zbus(property, name = "Result")]
    fn result(&self) -> String {
        "success".to_owned()
    }
}

#[test]
fn private_bus_systemd_activation_round_trip() {
    if env::var_os(INNER_ENV).is_none() {
        let status = Command::new("dbus-run-session")
            .arg("--")
            .arg(env::current_exe().expect("current integration-test executable"))
            .arg("--exact")
            .arg("private_bus_systemd_activation_round_trip")
            .arg("--nocapture")
            .env(INNER_ENV, "1")
            .status()
            .expect("start isolated D-Bus session");
        assert!(status.success(), "nested private-bus test failed: {status}");
        return;
    }

    zbus::block_on(async {
        let state = Arc::new(Mutex::new(FakeState::new()));
        let mut services = Vec::new();
        let manager = zbus::connection::Builder::session()
            .expect("private session builder")
            .name(SYSTEMD_SERVICE)
            .expect("valid systemd service name")
            .serve_at(SYSTEMD_MANAGER_PATH, FakeManager(state.clone()))
            .expect("serve fake systemd manager");
        let manager = {
            let mut manager = manager;
            for unit in FrozenUnit::all() {
                let path = unit_path_str(*unit);
                manager = manager.serve_at(path, FakeUnit(*unit)).expect("serve fake unit");
                if unit.is_service() {
                    manager =
                        manager.serve_at(path, FakeService(*unit)).expect("serve fake service");
                }
            }
            manager
        };
        services.push(manager.build().await.expect("start fake systemd service"));

        let session = ActivationSession::connect().await.expect("connect to fake manager");
        let mut activation = session.prepare().await.expect("prepare activation session");
        let snapshots = activation.list_units().await.expect("list fake units");
        assert_eq!(snapshots.len(), FrozenUnit::all().len());
        for snapshot in &snapshots {
            assert_eq!(snapshot.id, snapshot.unit.name());
            assert_eq!(snapshot.active_enter_timestamp, 1_000 + snapshot.unit as u64);
            if snapshot.unit.is_service() {
                assert_eq!(snapshot.main_pid, Some(10_000 + snapshot.unit as u32));
                assert_eq!(snapshot.result.as_deref(), Some("success"));
                assert_eq!(
                    snapshot.invocation_id.as_deref(),
                    Some(&vec![snapshot.unit as u8 + 1; 16][..])
                );
            }
            assert!(snapshot.healthy(), "healthy fake snapshot: {snapshot:?}");
        }

        assert_eq!(
            activation.start_unit(FrozenUnit::Target).await.expect("start target"),
            JobOutcome::Done
        );
        assert_eq!(
            activation.stop_unit(FrozenUnit::Target).await.expect("stop target"),
            JobOutcome::Done
        );

        let get_calls_before_missing = {
            let state = state.lock().expect("fake systemd state");
            state.calls.iter().filter(|call| matches!(call, Call::Get { .. })).count()
        };
        state.lock().expect("fake systemd state").missing_rows = true;
        let missing = activation.list_units().await.expect("list missing fake units");
        assert_eq!(missing.len(), FrozenUnit::all().len());
        assert!(missing.iter().all(|snapshot| snapshot.state() == visa_cli::UnitState::Missing));
        let get_calls_after_missing = {
            let state = state.lock().expect("fake systemd state");
            state.calls.iter().filter(|call| matches!(call, Call::Get { .. })).count()
        };
        assert_eq!(get_calls_after_missing, get_calls_before_missing);

        drop(activation);
        assert!(matches!(session.prepare().await, Err(ActivationError::AlreadyPrepared)));

        let state = state.lock().expect("fake systemd state");
        assert!(state.subscribed);
        assert!(matches!(state.calls.first(), Some(Call::Subscribe { no_autostart: true })));
        assert!(state.calls.iter().any(|call| matches!(
            call,
            Call::Start { unit, mode, no_autostart }
                if unit == "visa-local.target" && mode == "replace" && *no_autostart
        )));
        assert!(state.calls.iter().any(|call| matches!(
            call,
            Call::Stop { unit, mode, no_autostart }
                if unit == "visa-local.target" && mode == "replace" && *no_autostart
        )));
        assert!(state.calls.iter().any(|call| matches!(
            call,
            Call::List { units, no_autostart }
                if units.len() == FrozenUnit::all().len() && *no_autostart
        )));
        assert_eq!(
            state
                .calls
                .iter()
                .filter(|call| matches!(call, Call::Get { no_autostart: true, .. }))
                .count(),
            FrozenUnit::all().len() * 2
        );
        assert!(state.calls.iter().all(|call| match call {
            Call::Subscribe { no_autostart }
            | Call::Start { no_autostart, .. }
            | Call::Stop { no_autostart, .. }
            | Call::List { no_autostart, .. }
            | Call::Get { no_autostart, .. } => *no_autostart,
        }));
        drop(state);
        drop(services);
    });
}

fn root_path() -> OwnedObjectPath {
    "/".try_into().expect("valid root object path")
}

fn unit_path(unit: FrozenUnit) -> OwnedObjectPath {
    unit_path_str(unit).try_into().expect("valid fake unit path")
}

fn unit_path_str(unit: FrozenUnit) -> &'static str {
    match unit {
        FrozenUnit::Target => TARGET_PATH,
        FrozenUnit::Ownershipd => OWNERSHIPD_PATH,
        FrozenUnit::Nexusd => NEXUSD_PATH,
        FrozenUnit::SourceAgent => SOURCE_PATH,
        FrozenUnit::DestinationAgent => DESTINATION_PATH,
    }
}
