use std::{
    fs,
    io::Write,
    net::Shutdown,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use tempfile::TempDir;
use visa_wasi_host::{CreateConfig, create_provider, send_admin, send_completion, send_guest};
use visa_wasi_protocol::{
    AdminCapability, AdminOperation, AdminRequest, BarrierPhase, BarrierReleaseAction,
    BarrierToken, ClientId, EffectId, GuestCapability, GuestCompletion, GuestRequest, HostcallKind,
    HostcallPredicate, Operation, OperationResult, OutcomePredicate, OwnerId, PROTOCOL_VERSION,
    ResourceSelector, SessionId, WireRequest, encode_request, errno, rights,
};

const SESSION: SessionId = SessionId([31; 16]);
const OWNER: OwnerId = OwnerId([32; 16]);
const CLIENT: ClientId = ClientId([33; 16]);
const RESTARTED_CLIENT: ClientId = ClientId([36; 16]);
const ADMIN: AdminCapability = AdminCapability([34; 32]);
const GUEST: GuestCapability = GuestCapability([35; 32]);
const BARRIER: BarrierToken = BarrierToken([37; 16]);

fn temporary() -> TempDir {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temporary
}

fn start(database: &Path, socket: &Path) -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_visa_wasi_host"))
        .arg("serve")
        .arg(database)
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..400 {
        if socket.exists() {
            return child;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("provider socket did not appear")
}

fn request(sequence: u64, effect: u8, operation: Operation) -> GuestRequest {
    request_for(CLIENT, sequence, effect, operation)
}

fn request_for(client: ClientId, sequence: u64, effect: u8, operation: Operation) -> GuestRequest {
    GuestRequest {
        version: PROTOCOL_VERSION,
        session: SESSION,
        owner: OWNER,
        client,
        capability: GUEST,
        sequence,
        effect: EffectId([effect; 16]),
        authority_epoch: 1,
        operation,
    }
}

fn complete(socket: &Path, request: &GuestRequest) {
    let response = send_completion(
        socket,
        &GuestCompletion {
            version: PROTOCOL_VERSION,
            session: request.session,
            owner: request.owner,
            client: request.client,
            capability: request.capability,
            sequence: request.sequence,
            effect: request.effect,
            authority_epoch: request.authority_epoch,
        },
    )
    .unwrap();
    assert_eq!(response.errno, errno::SUCCESS);
}

fn admin(socket: &Path, operation: AdminOperation) -> visa_wasi_protocol::AdminResponse {
    send_admin(socket, &AdminRequest { version: PROTOCOL_VERSION, capability: ADMIN, operation })
        .unwrap()
}

fn drop_response(socket: &Path, request: &GuestRequest) {
    let encoded = encode_request(&WireRequest::Guest(request.clone())).unwrap();
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(&(encoded.len() as u32).to_be_bytes()).unwrap();
    stream.write_all(&encoded).unwrap();
    stream.flush().unwrap();
    stream.shutdown(Shutdown::Both).unwrap();
}

fn send_partial_frame(socket: &Path) {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(&128_u32.to_be_bytes()).unwrap();
    stream.write_all(b"partial").unwrap();
    stream.shutdown(Shutdown::Both).unwrap();
}

fn wait_for_effects(socket: &Path, expected: u64) {
    for _ in 0..400 {
        if admin(socket, AdminOperation::Status)
            .status
            .is_some_and(|status| status.effects == expected)
        {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("provider did not commit the dropped response")
}

fn kill(mut child: Child, socket: &Path) {
    child.kill().unwrap();
    child.wait().unwrap();
    fs::remove_file(socket).unwrap();
}

#[test]
fn response_loss_then_provider_kill_reopen_replays_exactly_once() {
    let temporary = temporary();
    let database = temporary.path().join("provider.sqlite");
    let socket = temporary.path().join("provider.sock");
    create_provider(&CreateConfig {
        database: database.clone(),
        session: SESSION,
        capability: ADMIN,
        guest_capability: GUEST,
        authority_epoch: 1,
        imports: Vec::new(),
    })
    .unwrap();

    let first_server = start(&database, &socket);
    let open = request(
        1,
        41,
        Operation::PathOpen {
            dir_fd: 3,
            lookup_flags: 0,
            path: b"database".to_vec(),
            open_flags: 1 | 8,
            rights_base: rights::FD_READ | rights::FD_WRITE | rights::FD_SEEK,
            rights_inheriting: 0,
            fd_flags: 0,
        },
    );
    let opened = send_guest(&socket, &open).unwrap();
    let OperationResult::FileDescriptor(fd) = opened.result else {
        panic!("path_open did not return a descriptor")
    };
    complete(&socket, &open);

    assert!(
        admin(
            &socket,
            AdminOperation::BarrierArm {
                token: BARRIER,
                predicate: HostcallPredicate {
                    kind: HostcallKind::FdWrite,
                    resource: ResourceSelector::ExactPath(b"database".to_vec()),
                    outcome: OutcomePredicate::Success,
                    occurrence: 1,
                },
            },
        )
        .ok
    );
    send_partial_frame(&socket);
    assert_eq!(admin(&socket, AdminOperation::Status).status.unwrap().effects, 1);

    let uncertain = request(
        2,
        42,
        Operation::FdWrite { fd, bytes: b"committed-before-response-loss".to_vec() },
    );
    drop_response(&socket, &uncertain);
    wait_for_effects(&socket, 2);
    kill(first_server, &socket);

    let second_server = start(&database, &socket);
    let recovered = admin(&socket, AdminOperation::Status).status.unwrap();
    assert_eq!(recovered.barrier, BarrierPhase::Triggered);
    assert_eq!(recovered.barrier_effect, Some(uncertain.effect));
    let blocked_arm = admin(
        &socket,
        AdminOperation::BarrierArm {
            token: BARRIER,
            predicate: HostcallPredicate {
                kind: HostcallKind::Any,
                resource: ResourceSelector::Any,
                outcome: OutcomePredicate::Any,
                occurrence: 1,
            },
        },
    );
    assert!(!blocked_arm.ok, "an uncertain delivery survived restart and must block drain");

    let replay = send_guest(&socket, &uncertain).unwrap();
    assert_eq!(replay.errno, errno::SUCCESS);
    assert_eq!(
        replay.result,
        OperationResult::Count(b"committed-before-response-loss".len() as u32)
    );
    assert_eq!(admin(&socket, AdminOperation::Status).status.unwrap().effects, 2);
    complete(&socket, &uncertain);
    assert_eq!(admin(&socket, AdminOperation::Status).status.unwrap().barrier, BarrierPhase::Held);
    assert!(
        admin(
            &socket,
            AdminOperation::BarrierRelease {
                token: BARRIER,
                action: BarrierReleaseAction::Continue,
            },
        )
        .ok
    );

    let restarted = request_for(RESTARTED_CLIENT, 1, 42, uncertain.operation.clone());
    let replay = send_guest(&socket, &restarted).unwrap();
    assert_eq!(replay.errno, errno::SUCCESS);
    assert_eq!(
        replay.result,
        OperationResult::Count(b"committed-before-response-loss".len() as u32)
    );
    assert_eq!(admin(&socket, AdminOperation::Status).status.unwrap().effects, 2);

    let still_blocked = admin(
        &socket,
        AdminOperation::BarrierArm {
            token: BARRIER,
            predicate: HostcallPredicate {
                kind: HostcallKind::Any,
                resource: ResourceSelector::Any,
                outcome: OutcomePredicate::Any,
                occurrence: 1,
            },
        },
    );
    assert!(
        !still_blocked.ok,
        "the fresh-client delivery of a stable effect must also complete before drain"
    );
    complete(&socket, &restarted);

    assert!(
        admin(
            &socket,
            AdminOperation::BarrierArm {
                token: BARRIER,
                predicate: HostcallPredicate {
                    kind: HostcallKind::Any,
                    resource: ResourceSelector::Any,
                    outcome: OutcomePredicate::Any,
                    occurrence: 1,
                },
            },
        )
        .ok,
        "drain opens only after every delivery of the stable effect is complete"
    );

    let output = temporary.path().join("materialized");
    assert!(
        admin(
            &socket,
            AdminOperation::Materialize {
                guest_path: b"database".to_vec(),
                host_path: output.display().to_string(),
            },
        )
        .ok
    );
    assert_eq!(fs::read(output).unwrap(), b"committed-before-response-loss");
    assert_eq!(admin(&socket, AdminOperation::Status).status.unwrap().effects, 2);

    assert!(admin(&socket, AdminOperation::Shutdown).ok);
    let mut second_server = second_server;
    assert!(second_server.wait().unwrap().success());
}

#[test]
fn fd_sync_and_datasync_survive_provider_kill_reopen_in_process_crash_model() {
    let temporary = temporary();
    let database = temporary.path().join("provider.sqlite");
    let socket = temporary.path().join("provider.sock");
    create_provider(&CreateConfig {
        database: database.clone(),
        session: SESSION,
        capability: ADMIN,
        guest_capability: GUEST,
        authority_epoch: 1,
        imports: Vec::new(),
    })
    .unwrap();
    let first_server = start(&database, &socket);
    let open = request(
        1,
        51,
        Operation::PathOpen {
            dir_fd: 3,
            lookup_flags: 0,
            path: b"sync-file".to_vec(),
            open_flags: 1 | 8,
            rights_base: rights::FD_WRITE | rights::FD_SYNC | rights::FD_DATASYNC,
            rights_inheriting: 0,
            fd_flags: 0,
        },
    );
    let response = send_guest(&socket, &open).unwrap();
    let OperationResult::FileDescriptor(fd) = response.result else {
        panic!("path_open did not return a descriptor")
    };
    complete(&socket, &open);
    for (sequence, effect, operation) in [
        (2, 52, Operation::FdWrite { fd, bytes: b"durable".to_vec() }),
        (3, 53, Operation::FdDataSync { fd }),
        (4, 54, Operation::FdSync { fd }),
    ] {
        let request = request(sequence, effect, operation);
        assert_eq!(send_guest(&socket, &request).unwrap().errno, errno::SUCCESS);
        complete(&socket, &request);
    }
    kill(first_server, &socket);

    let second_server = start(&database, &socket);
    let output = temporary.path().join("sync-file.materialized");
    assert!(
        admin(
            &socket,
            AdminOperation::Materialize {
                guest_path: b"sync-file".to_vec(),
                host_path: output.display().to_string(),
            },
        )
        .ok
    );
    assert_eq!(fs::read(output).unwrap(), b"durable");
    assert!(admin(&socket, AdminOperation::Shutdown).ok);
    let mut second_server = second_server;
    assert!(second_server.wait().unwrap().success());
}
