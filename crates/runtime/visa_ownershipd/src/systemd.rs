//! Narrow systemd agent-invocation attestation over zbus.

use rustix::process::geteuid;
use visa_local_rpc::common::{AgentBinding, AgentRole};
use zbus::{
    Connection,
    fdo::DBusProxy,
    names::{BusName, OwnedUniqueName, WellKnownName},
    zvariant::OwnedObjectPath,
};

const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SOURCE_AGENT_UNIT: &str = "visa-agent@source.service";
const DESTINATION_AGENT_UNIT: &str = "visa-agent@destination.service";

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1",
    gen_blocking = false
)]
trait SystemdManager {
    #[zbus(name = "GetUnit", no_autostart)]
    fn get_unit(&self, name: String) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1",
    gen_blocking = false
)]
trait SystemdUnit {
    #[zbus(property, name = "Id")]
    fn id(&self) -> zbus::Result<String>;

    #[zbus(property, name = "InvocationID")]
    fn invocation_id(&self) -> zbus::Result<Vec<u8>>;
}

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Service",
    default_service = "org.freedesktop.systemd1",
    gen_blocking = false
)]
trait SystemdService {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> zbus::Result<u32>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SystemdAttestationError {
    WrongManagerUid,
    ManagerChanged,
    UnitMismatch,
    InvocationMismatch,
    MainPidMismatch,
    Bus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SystemdObservation {
    manager_owner: OwnedUniqueName,
    unit_path: OwnedObjectPath,
    invocation_id: [u8; 16],
    main_pid: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct SystemdAgentAttestor {
    connection: Connection,
    bus_guid: String,
}

impl SystemdAgentAttestor {
    pub(crate) fn new(connection: &Connection) -> Self {
        Self {
            connection: connection.clone(),
            bus_guid: connection.server_guid().as_str().to_owned(),
        }
    }

    pub(crate) async fn observe(
        &self,
        process_id: u32,
        caller: AgentBinding,
    ) -> Result<SystemdObservation, SystemdAttestationError> {
        self.require_bus_epoch()?;
        let dbus =
            DBusProxy::new(&self.connection).await.map_err(|_| SystemdAttestationError::Bus)?;
        let systemd_name: WellKnownName<'_> =
            SYSTEMD_SERVICE.try_into().expect("frozen systemd service name is valid");
        let manager_owner = dbus
            .get_name_owner(BusName::from(systemd_name.clone()))
            .await
            .map_err(|_| SystemdAttestationError::Bus)?;
        let credentials = dbus
            .get_connection_credentials(manager_owner.as_ref().into())
            .await
            .map_err(|_| SystemdAttestationError::Bus)?;
        if credentials.unix_user_id() != Some(geteuid().as_raw()) {
            return Err(SystemdAttestationError::WrongManagerUid);
        }

        let manager = SystemdManagerProxy::builder(&self.connection)
            .destination(manager_owner.clone())
            .map_err(|_| SystemdAttestationError::Bus)?
            .path(SYSTEMD_MANAGER_PATH)
            .map_err(|_| SystemdAttestationError::Bus)?
            .build()
            .await
            .map_err(|_| SystemdAttestationError::Bus)?;
        let expected_unit = role_unit(caller.role);
        let unit_path = manager
            .get_unit(expected_unit.to_owned())
            .await
            .map_err(|_| SystemdAttestationError::Bus)?;

        let unit = SystemdUnitProxy::builder(&self.connection)
            .destination(manager_owner.clone())
            .map_err(|_| SystemdAttestationError::Bus)?
            .path(unit_path.clone())
            .map_err(|_| SystemdAttestationError::Bus)?
            .build()
            .await
            .map_err(|_| SystemdAttestationError::Bus)?;
        if unit.id().await.map_err(|_| SystemdAttestationError::Bus)? != expected_unit {
            return Err(SystemdAttestationError::UnitMismatch);
        }
        let invocation_id: [u8; 16] = unit
            .invocation_id()
            .await
            .map_err(|_| SystemdAttestationError::Bus)?
            .try_into()
            .map_err(|_| SystemdAttestationError::InvocationMismatch)?;
        if invocation_id != caller.process_nonce.0 {
            return Err(SystemdAttestationError::InvocationMismatch);
        }

        let service = SystemdServiceProxy::builder(&self.connection)
            .destination(manager_owner.clone())
            .map_err(|_| SystemdAttestationError::Bus)?
            .path(unit_path.clone())
            .map_err(|_| SystemdAttestationError::Bus)?
            .build()
            .await
            .map_err(|_| SystemdAttestationError::Bus)?;
        let main_pid = service.main_pid().await.map_err(|_| SystemdAttestationError::Bus)?;
        if main_pid != process_id {
            return Err(SystemdAttestationError::MainPidMismatch);
        }

        self.require_bus_epoch()?;
        let final_owner = dbus
            .get_name_owner(BusName::from(systemd_name))
            .await
            .map_err(|_| SystemdAttestationError::Bus)?;
        if final_owner != manager_owner {
            return Err(SystemdAttestationError::ManagerChanged);
        }
        Ok(SystemdObservation { manager_owner, unit_path, invocation_id, main_pid })
    }

    fn require_bus_epoch(&self) -> Result<(), SystemdAttestationError> {
        if self.connection.server_guid().as_str() == self.bus_guid {
            Ok(())
        } else {
            Err(SystemdAttestationError::ManagerChanged)
        }
    }
}

pub(crate) const fn role_unit(role: AgentRole) -> &'static str {
    match role {
        AgentRole::Source => SOURCE_AGENT_UNIT,
        AgentRole::Destination => DESTINATION_AGENT_UNIT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_units_match_the_release_contract() {
        assert_eq!(role_unit(AgentRole::Source), "visa-agent@source.service");
        assert_eq!(role_unit(AgentRole::Destination), "visa-agent@destination.service");
    }
}
