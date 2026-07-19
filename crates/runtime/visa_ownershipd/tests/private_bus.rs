#![cfg(target_os = "linux")]

use std::{
    env, fs,
    io::Write,
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixDatagram,
    },
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::json;
use sha2::{Digest as _, Sha256};
use tempfile::tempdir;
use visa_local_rpc::{
    MAX_INNER_REQUEST_BYTES, agent_control,
    common::{
        AgentBinding, AgentRole, BootId, CohortId, ContinuityUnitId, EntityRefWire,
        LogicalIncarnation, NodeId, PRODUCT_VERSION, ProcessNonce, RequestId, RuntimeSessionId,
    },
    ownership,
};
use zbus::{
    fdo::{RequestNameFlags, RequestNameReply},
    message::{Flags, Header},
    zvariant::OwnedObjectPath,
};

#[zbus::proxy(
    interface = "io.github.chenty2333.vISA.Ownership1",
    default_service = "io.github.chenty2333.vISA.Ownership1",
    default_path = "/io/github/chenty2333/vISA/Ownership"
)]
trait OwnershipRpc {
    #[zbus(name = "Execute")]
    fn execute(&self, request_bytes: Vec<u8>) -> zbus::Result<Vec<u8>>;
}

const INNER_ENV: &str = "VISA_OWNERSHIPD_PRIVATE_BUS_INNER";
const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SOURCE_UNIT: &str = "visa-agent@source.service";
const DESTINATION_UNIT: &str = "visa-agent@destination.service";
const SOURCE_UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/visa_2dagent_40source_2eservice";
const ALTERNATE_SOURCE_UNIT_PATH: &str =
    "/org/freedesktop/systemd1/unit/visa_2dagent_40source_2eservice_5frestarted";

#[derive(Clone, Debug)]
struct FakeSystemdState {
    unit_property_id: String,
    unit_property_invocation_id: Vec<u8>,
    main_pid: u32,
    saw_no_autostart: bool,
    saw_expected_unit_name: bool,
    manager_calls: u64,
    alternate_path_on_second_call: bool,
}

#[derive(Clone)]
struct FakeSystemdManager(Arc<Mutex<FakeSystemdState>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl FakeSystemdManager {
    #[zbus(name = "GetUnit")]
    fn get_unit(
        &self,
        name: String,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let mut state = self.0.lock().expect("fake systemd state");
        state.saw_no_autostart = header.primary().flags().contains(Flags::NoAutoStart);
        if !state.saw_no_autostart {
            return Err(zbus::fdo::Error::Failed(
                "GetUnit must suppress D-Bus activation".to_owned(),
            ));
        }
        state.saw_expected_unit_name = name == SOURCE_UNIT;
        if !state.saw_expected_unit_name {
            return Err(zbus::fdo::Error::InvalidArgs(
                "GetUnit must receive the exact source role unit".to_owned(),
            ));
        }
        state.manager_calls = state.manager_calls.checked_add(1).expect("fake call count");
        let unit_path = if state.alternate_path_on_second_call && state.manager_calls == 2 {
            ALTERNATE_SOURCE_UNIT_PATH
        } else {
            SOURCE_UNIT_PATH
        };
        Ok(unit_path.try_into().expect("valid fake unit path"))
    }
}

#[derive(Clone)]
struct FakeSystemdUnit(Arc<Mutex<FakeSystemdState>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl FakeSystemdUnit {
    #[zbus(property, name = "Id")]
    fn id(&self) -> String {
        self.0.lock().expect("fake systemd state").unit_property_id.clone()
    }

    #[zbus(property, name = "InvocationID")]
    fn invocation_id(&self) -> Vec<u8> {
        self.0.lock().expect("fake systemd state").unit_property_invocation_id.clone()
    }
}

#[derive(Clone)]
struct FakeSystemdService(Arc<Mutex<FakeSystemdState>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl FakeSystemdService {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> u32 {
        self.0.lock().expect("fake systemd state").main_pid
    }
}

#[test]
fn private_bus_readiness_exposes_the_frozen_interface() {
    if env::var_os(INNER_ENV).is_none() {
        let status = Command::new("dbus-run-session")
            .arg("--")
            .arg(env::current_exe().expect("current integration-test executable"))
            .arg("--exact")
            .arg("private_bus_readiness_exposes_the_frozen_interface")
            .arg("--nocapture")
            .env(INNER_ENV, "1")
            .status()
            .expect("start isolated D-Bus session");
        assert!(status.success(), "nested private-bus test failed: {status}");
        return;
    }

    let root = tempdir().expect("private ownershipd fixture");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("private fixture mode");
    let database_path = root.path().join("ownership.sqlite");
    let bootstrap_path = root.path().join("ownershipd.json");
    let notify_path = root.path().join("notify.sock");
    let notify = UnixDatagram::bind(&notify_path).expect("bind readiness socket");
    notify.set_read_timeout(Some(Duration::from_secs(10))).expect("bound readiness timeout");
    let systemd_state = Arc::new(Mutex::new(FakeSystemdState {
        unit_property_id: SOURCE_UNIT.to_owned(),
        unit_property_invocation_id: vec![0x51; 16],
        main_pid: std::process::id(),
        saw_no_autostart: false,
        saw_expected_unit_name: false,
        manager_calls: 0,
        alternate_path_on_second_call: false,
    }));
    let _systemd = start_fake_systemd(systemd_state.clone());
    let manager_xml = introspect_fake_systemd_manager();
    let method_start =
        manager_xml.find("<method name=\"GetUnit\">").expect("fake manager exposes GetUnit");
    let method_tail = &manager_xml[method_start..];
    let method_end = method_tail.find("</method>").expect("complete manager method XML");
    let method_xml = &method_tail[..method_end];
    assert!(method_xml.contains("type=\"s\" direction=\"in\""));
    assert!(method_xml.contains("type=\"o\" direction=\"out\""));

    let ownership_issuer = issuer(0x10);
    let source_executable_sha256 = lower_hex(&Sha256::digest(
        fs::read(env::current_exe().expect("current test executable path"))
            .expect("read current test executable"),
    ));
    let document = json!({
        "schema": "visa.ownershipd.bootstrap.v2",
        "store_open_policy": "create_if_missing_exact",
        "database_path": database_path.to_str().expect("UTF-8 fixture path"),
        "store_binding": {
            "cohort": hex16(0x01),
            "boot": hex16(0x02),
            "runtime_session": hex16(0x03)
        },
        "ownership_identity": {
            "service_incarnation": ownership_issuer["issuer_incarnation"],
            "issuer": ownership_issuer["issuer"],
            "key_id": ownership_issuer["key_id"],
            "log_namespace": ownership_issuer["log_id"]
        },
        "store_limits": {
            "max_exchanges": 1024,
            "max_exchange_bytes": 8 * 1024 * 1024,
            "max_database_bytes": 64 * 1024 * 1024
        },
        "joint_issuers": {
            "ownership": ownership_issuer,
            "visa_source": issuer(0x20),
            "visa_destination": issuer(0x30),
            "effect_closure": issuer(0x40)
        },
        "source_agent": agent("source", 0x50, &source_executable_sha256),
        "destination_agent": agent("destination", 0x60, &lower_hex(&[0x9a; 32]))
    });
    let bootstrap = serde_json_canonicalizer::to_vec(&document).expect("canonical bootstrap");
    let bootstrap_sha256 = lower_hex(&Sha256::digest(&bootstrap));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&bootstrap_path)
        .expect("create private bootstrap");
    file.write_all(&bootstrap).expect("write private bootstrap");
    file.sync_all().expect("sync private bootstrap");

    let mut daemon = Command::new(env!("CARGO_BIN_EXE_visa-ownershipd"))
        .arg("--bootstrap")
        .arg(&bootstrap_path)
        .arg("--bootstrap-sha256")
        .arg(&bootstrap_sha256)
        .env("NOTIFY_SOCKET", &notify_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start ownership daemon");

    let mut readiness = [0_u8; 256];
    let received = notify.recv(&mut readiness).unwrap_or_else(|error| {
        let _ = daemon.kill();
        let status = daemon.wait().expect("reap failed daemon");
        panic!("ownershipd did not become ready ({status}): {error}");
    });
    let readiness = std::str::from_utf8(&readiness[..received]).expect("UTF-8 readiness payload");
    assert!(readiness.split('\n').any(|line| line == "READY=1"));

    let request = ownership::Request::new(
        RequestId::from_u128(0x7001),
        source_binding(),
        ownership::Operation::InitializeUnit(ownership::InitializeUnitRequest {
            continuity_unit: EntityRefWire {
                identity: ContinuityUnitId::from_u128(0x7002),
                generation: 1,
            },
            owner: NodeId::from_u128(0x7003),
            epoch: 1,
        }),
    );
    let request_bytes = ownership::encode_request(&request).expect("canonical ownership request");
    let (xml, first_response, replay_response) = zbus::block_on(async {
        let connection = zbus::Connection::session().await.expect("private session connection");
        let name_reply = connection
            .request_name_with_flags(
                agent_control::SOURCE_WELL_KNOWN_NAME,
                RequestNameFlags::DoNotQueue.into(),
            )
            .await
            .expect("acquire source-agent role name");
        assert!(matches!(
            name_reply,
            RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner
        ));
        let proxy = zbus::fdo::IntrospectableProxy::builder(&connection)
            .destination(ownership::WELL_KNOWN_NAME)
            .expect("ownership destination")
            .path(ownership::OBJECT_PATH)
            .expect("ownership object path")
            .build()
            .await
            .expect("ownership introspection proxy");
        let xml = proxy.introspect().await.expect("introspect ownership service");
        let ownership = OwnershipRpcProxy::new(&connection).await.expect("ownership RPC proxy");
        ownership
            .execute(vec![0; MAX_INNER_REQUEST_BYTES + 1])
            .await
            .expect_err("oversized ownership request must fail before admission");
        ownership
            .execute(vec![0])
            .await
            .expect_err("noncanonical ownership request must fail before O1");

        let non_owner = zbus::Connection::session().await.expect("non-owner agent connection");
        let non_owner_proxy =
            OwnershipRpcProxy::new(&non_owner).await.expect("non-owner ownership RPC proxy");
        non_owner_proxy
            .execute(request_bytes.clone())
            .await
            .expect_err("caller connection must own the exact role name");

        mutate_systemd(&systemd_state, |state| {
            state.unit_property_id = DESTINATION_UNIT.to_owned();
        });
        ownership
            .execute(request_bytes.clone())
            .await
            .expect_err("wrong unit Id property must fail before O1");
        reset_source_systemd(&systemd_state);

        mutate_systemd(&systemd_state, |state| {
            state.unit_property_invocation_id = vec![0x53; 16];
        });
        ownership
            .execute(request_bytes.clone())
            .await
            .expect_err("wrong unit invocation property must fail before O1");
        reset_source_systemd(&systemd_state);

        for malformed_length in [0, 15, 17] {
            mutate_systemd(&systemd_state, |state| {
                state.unit_property_invocation_id = vec![0x51; malformed_length];
            });
            ownership
                .execute(request_bytes.clone())
                .await
                .expect_err("malformed unit invocation id must fail before O1");
            reset_source_systemd(&systemd_state);
        }

        mutate_systemd(&systemd_state, |state| {
            state.main_pid = std::process::id().checked_add(1).expect("test pid increment");
        });
        ownership
            .execute(request_bytes.clone())
            .await
            .expect_err("non-main service process must fail before O1");
        reset_source_systemd(&systemd_state);

        mutate_systemd(&systemd_state, |state| {
            state.main_pid = 0;
        });
        ownership
            .execute(request_bytes.clone())
            .await
            .expect_err("service without a main process must fail before O1");
        reset_source_systemd(&systemd_state);

        mutate_systemd(&systemd_state, |state| {
            state.alternate_path_on_second_call = true;
        });
        ownership
            .execute(request_bytes.clone())
            .await
            .expect_err("unit replacement during admission must fail before O1");
        reset_source_systemd(&systemd_state);

        let first = ownership
            .execute(request_bytes.clone())
            .await
            .expect("execute admitted ownership request");
        let replay = ownership
            .execute(request_bytes.clone())
            .await
            .expect("replay admitted ownership request");
        (xml, first, replay)
    });
    assert!(xml.contains(&format!("<interface name=\"{}\">", ownership::INTERFACE)));
    assert!(xml.contains("<method name=\"Execute\">"));
    assert!(xml.contains("<arg name=\"request_bytes\" type=\"ay\" direction=\"in\"/>"));
    assert!(xml.contains("<arg type=\"ay\" direction=\"out\"/>"));
    assert_eq!(replay_response, first_response, "O1 replay must be byte-identical");
    assert!(
        systemd_state.lock().expect("fake systemd state").saw_no_autostart,
        "systemd control-plane calls must not activate a missing manager"
    );
    assert!(
        systemd_state.lock().expect("fake systemd state").saw_expected_unit_name,
        "systemd lookup must use the exact role unit"
    );
    let response = ownership::decode_response_for(&request, &first_response)
        .expect("decode admitted ownership response");
    assert!(matches!(
        response.outcome,
        ownership::Outcome::Success(ownership::Success::Initialized(_))
    ));

    // A second healthy store must fail immediately instead of queueing for or
    // replacing the frozen well-known name. It must not send READY.
    let second_database_path = root.path().join("second-ownership.sqlite");
    let second_bootstrap_path = root.path().join("second-ownershipd.json");
    let mut second_document = document;
    second_document["database_path"] =
        json!(second_database_path.to_str().expect("UTF-8 second database path"));
    let second_bootstrap =
        serde_json_canonicalizer::to_vec(&second_document).expect("second canonical bootstrap");
    let second_sha256 = lower_hex(&Sha256::digest(&second_bootstrap));
    write_private(&second_bootstrap_path, &second_bootstrap);
    let mut second = Command::new(env!("CARGO_BIN_EXE_visa-ownershipd"))
        .arg("--bootstrap")
        .arg(&second_bootstrap_path)
        .arg("--bootstrap-sha256")
        .arg(&second_sha256)
        .env("NOTIFY_SOCKET", &notify_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start competing ownership daemon");
    let second_status = wait_for_exit(&mut second, Duration::from_secs(5));
    assert_eq!(second_status.code(), Some(78), "competing daemon must fail as configuration");
    assert!(daemon.try_wait().expect("inspect primary daemon").is_none());
    notify.set_read_timeout(Some(Duration::from_millis(100))).expect("short readiness timeout");
    let mut unexpected = [0_u8; 256];
    let no_second_ready = notify.recv(&mut unexpected).expect_err("competing daemon sent READY");
    assert!(matches!(
        no_second_ready.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));

    daemon.kill().expect("stop ownership daemon");
    let status = daemon.wait().expect("reap ownership daemon");
    assert!(!status.success(), "test cleanup must terminate the long-running daemon");
}

fn start_fake_systemd(state: Arc<Mutex<FakeSystemdState>>) -> zbus::Connection {
    zbus::block_on(async {
        zbus::connection::Builder::session()
            .expect("private session builder")
            .name(SYSTEMD_SERVICE)
            .expect("valid systemd service name")
            .serve_at(SYSTEMD_MANAGER_PATH, FakeSystemdManager(state.clone()))
            .expect("serve fake systemd manager")
            .serve_at(SOURCE_UNIT_PATH, FakeSystemdUnit(state.clone()))
            .expect("serve fake systemd unit")
            .serve_at(SOURCE_UNIT_PATH, FakeSystemdService(state.clone()))
            .expect("serve fake systemd service")
            .serve_at(ALTERNATE_SOURCE_UNIT_PATH, FakeSystemdUnit(state.clone()))
            .expect("serve replacement fake systemd unit")
            .serve_at(ALTERNATE_SOURCE_UNIT_PATH, FakeSystemdService(state))
            .expect("serve replacement fake systemd service")
            .build()
            .await
            .expect("start fake systemd service")
    })
}

fn introspect_fake_systemd_manager() -> String {
    zbus::block_on(async {
        let connection = zbus::Connection::session().await.expect("systemd introspection client");
        zbus::fdo::IntrospectableProxy::builder(&connection)
            .destination(SYSTEMD_SERVICE)
            .expect("systemd introspection destination")
            .path(SYSTEMD_MANAGER_PATH)
            .expect("systemd introspection path")
            .build()
            .await
            .expect("systemd introspection proxy")
            .introspect()
            .await
            .expect("introspect fake systemd manager")
    })
}

fn mutate_systemd(
    state: &Arc<Mutex<FakeSystemdState>>,
    mutation: impl FnOnce(&mut FakeSystemdState),
) {
    mutation(&mut state.lock().expect("fake systemd state"));
}

fn reset_source_systemd(state: &Arc<Mutex<FakeSystemdState>>) {
    mutate_systemd(state, |state| {
        state.unit_property_id = SOURCE_UNIT.to_owned();
        state.unit_property_invocation_id = vec![0x51; 16];
        state.main_pid = std::process::id();
        state.saw_expected_unit_name = false;
        state.manager_calls = 0;
        state.alternate_path_on_second_call = false;
    });
}

fn issuer(base: u8) -> serde_json::Value {
    json!({
        "issuer": hex16(base),
        "issuer_incarnation": hex16(base + 1),
        "key_id": hex16(base + 2),
        "log_id": hex16(base + 3)
    })
}

fn agent(role: &str, logical: u8, executable_sha256: &str) -> serde_json::Value {
    json!({
        "stable_identity": {
            "product_version": { "major": 0, "minor": 1, "patch": 0 },
            "cohort": hex16(0x01),
            "boot": hex16(0x02),
            "runtime_session": hex16(0x03),
            "role": role,
            "logical_incarnation": hex16(logical)
        },
        "executable_sha256": executable_sha256
    })
}

fn source_binding() -> AgentBinding {
    AgentBinding {
        product_version: PRODUCT_VERSION,
        cohort: CohortId::from_bytes([0x01; 16]),
        boot: BootId::from_bytes([0x02; 16]),
        runtime_session: RuntimeSessionId::from_bytes([0x03; 16]),
        role: AgentRole::Source,
        logical_incarnation: LogicalIncarnation::from_bytes([0x50; 16]),
        process_nonce: ProcessNonce::from_bytes([0x51; 16]),
        process_generation: 1,
    }
}

fn hex16(value: u8) -> String {
    lower_hex(&[value; 16])
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create private file");
    file.write_all(bytes).expect("write private file");
    file.sync_all().expect("sync private file");
}

fn wait_for_exit(child: &mut std::process::Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("inspect child status") {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let status = child.wait().expect("reap timed-out child");
            panic!("child did not exit before timeout: {status}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
