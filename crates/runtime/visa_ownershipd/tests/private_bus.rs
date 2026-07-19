#![cfg(target_os = "linux")]

use std::{
    env, fs,
    io::Write,
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixDatagram,
    },
    process::{Command, Stdio},
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
use zbus::fdo::{RequestNameFlags, RequestNameReply};

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

    let ownership_issuer = issuer(0x10);
    let source_executable_sha256 = lower_hex(&Sha256::digest(
        fs::read(env::current_exe().expect("current test executable path"))
            .expect("read current test executable"),
    ));
    let document = json!({
        "schema": "visa.ownershipd.bootstrap.v1",
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
        "source_agent": agent("source", 0x50, 0x51, &source_executable_sha256),
        "destination_agent": agent("destination", 0x60, 0x61, &lower_hex(&[0x9a; 32]))
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

fn issuer(base: u8) -> serde_json::Value {
    json!({
        "issuer": hex16(base),
        "issuer_incarnation": hex16(base + 1),
        "key_id": hex16(base + 2),
        "log_id": hex16(base + 3)
    })
}

fn agent(role: &str, logical: u8, nonce: u8, executable_sha256: &str) -> serde_json::Value {
    json!({
        "binding": {
            "product_version": { "major": 0, "minor": 1, "patch": 0 },
            "cohort": hex16(0x01),
            "boot": hex16(0x02),
            "runtime_session": hex16(0x03),
            "role": role,
            "logical_incarnation": hex16(logical),
            "process_nonce": hex16(nonce),
            "process_generation": 1
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
