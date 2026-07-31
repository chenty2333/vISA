use std::{fs, os::unix::fs::PermissionsExt};

use tempfile::TempDir;
use visa_wasi_host::{CreateConfig, Provider, create_provider, open_provider};
use visa_wasi_protocol::{
    AdminCapability, AdminOperation, AdminRequest, BarrierDirective, BarrierPhase,
    BarrierPollRequest, BarrierReleaseAction, BarrierToken, ClientId, EffectId, GuestCapability,
    GuestCompletion, GuestCompletionResponse, GuestRequest, HostcallKind, HostcallPredicate,
    Operation, OperationResult, OutcomePredicate, OwnerId, PROTOCOL_VERSION, ResourceSelector,
    SessionId, decode_namespace_snapshot, errno, rights,
};

const SESSION: SessionId = SessionId([1; 16]);
const OWNER: OwnerId = OwnerId([2; 16]);
const CLIENT_A: ClientId = ClientId([3; 16]);
const CLIENT_B: ClientId = ClientId([4; 16]);
const CLIENT_C: ClientId = ClientId([5; 16]);
const ADMIN: AdminCapability = AdminCapability([6; 32]);
const GUEST: GuestCapability = GuestCapability([7; 32]);
const BARRIER: BarrierToken = BarrierToken([8; 16]);

fn temporary() -> TempDir {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temporary
}

fn provider(temporary: &TempDir) -> Provider {
    let database = temporary.path().join("provider.sqlite");
    create_provider(&CreateConfig {
        database: database.clone(),
        session: SESSION,
        capability: ADMIN,
        guest_capability: GUEST,
        authority_epoch: 1,
        imports: Vec::new(),
    })
    .unwrap();
    open_provider(database).unwrap()
}

fn effect(value: u8) -> EffectId {
    EffectId([value; 16])
}

fn request(
    client: ClientId,
    sequence: u64,
    effect: EffectId,
    operation: Operation,
) -> GuestRequest {
    GuestRequest {
        version: PROTOCOL_VERSION,
        session: SESSION,
        owner: OWNER,
        client,
        capability: GUEST,
        sequence,
        effect,
        authority_epoch: 1,
        operation,
    }
}

fn complete(provider: &mut Provider, request: &GuestRequest) -> GuestCompletionResponse {
    provider.handle_completion(GuestCompletion {
        version: PROTOCOL_VERSION,
        session: request.session,
        owner: request.owner,
        client: request.client,
        capability: request.capability,
        sequence: request.sequence,
        effect: request.effect,
        authority_epoch: request.authority_epoch,
    })
}

fn call(provider: &mut Provider, request: &GuestRequest) -> visa_wasi_protocol::GuestResponse {
    let response = provider.handle_guest(request.clone());
    assert_eq!(response.errno, errno::SUCCESS);
    assert!(response.completion_required);
    assert_eq!(complete(provider, request).errno, errno::SUCCESS);
    response
}

fn admin(provider: &mut Provider, operation: AdminOperation) -> visa_wasi_protocol::AdminResponse {
    provider.handle_admin(AdminRequest { version: PROTOCOL_VERSION, capability: ADMIN, operation })
}

fn open_file(provider: &mut Provider, path: &[u8], client: ClientId, sequence: u64) -> u32 {
    let request = request(
        client,
        sequence,
        effect(sequence as u8),
        Operation::PathOpen {
            dir_fd: 3,
            lookup_flags: 0,
            path: path.to_vec(),
            open_flags: 1 | 8,
            rights_base: rights::FD_READ
                | rights::FD_WRITE
                | rights::FD_SEEK
                | rights::FD_TELL
                | rights::FD_SYNC
                | rights::FD_DATASYNC,
            rights_inheriting: 0,
            fd_flags: 0,
        },
    );
    let OperationResult::FileDescriptor(fd) = call(provider, &request).result else {
        panic!("path_open did not return a descriptor");
    };
    fd
}

#[test]
fn predicate_triggers_only_after_exact_occurrence_and_guest_writeback() {
    let temporary = temporary();
    let mut provider = provider(&temporary);
    let fd = open_file(&mut provider, b"db-journal", CLIENT_A, 1);

    assert!(
        admin(
            &mut provider,
            AdminOperation::BarrierArm {
                token: BARRIER,
                predicate: HostcallPredicate {
                    kind: HostcallKind::FdWrite,
                    resource: ResourceSelector::ExactPath(b"db-journal".to_vec()),
                    outcome: OutcomePredicate::Success,
                    occurrence: 2,
                },
            },
        )
        .ok
    );

    let first = request(CLIENT_A, 2, effect(22), Operation::FdWrite { fd, bytes: b"a".to_vec() });
    assert_eq!(call(&mut provider, &first).result, OperationResult::Count(1));
    let status = admin(&mut provider, AdminOperation::Status).status.unwrap();
    assert_eq!(status.barrier, BarrierPhase::Armed);
    assert_eq!(status.barrier_remaining, Some(1));

    let target = request(CLIENT_A, 3, effect(23), Operation::FdWrite { fd, bytes: b"b".to_vec() });
    let target_response = provider.handle_guest(target.clone());
    assert_eq!(target_response.errno, errno::SUCCESS);
    let triggered = admin(&mut provider, AdminOperation::Status).status.unwrap();
    assert_eq!(triggered.barrier, BarrierPhase::Triggered);
    assert_eq!(triggered.barrier_effect, Some(target.effect));

    let blocked = request(CLIENT_A, 4, effect(24), Operation::FdTell { fd });
    assert_eq!(provider.handle_guest(blocked).errno, errno::AGAIN);
    assert_eq!(provider.handle_guest(target.clone()), target_response);

    let completion = complete(&mut provider, &target);
    assert_eq!(completion.errno, errno::SUCCESS);
    assert_eq!(completion.directive, BarrierDirective::Wait);
    assert_eq!(completion.barrier, Some(BARRIER));
    assert_eq!(
        admin(&mut provider, AdminOperation::Status).status.unwrap().barrier,
        BarrierPhase::Held
    );

    let checkpoint_release = admin(
        &mut provider,
        AdminOperation::BarrierRelease { token: BARRIER, action: BarrierReleaseAction::Checkpoint },
    );
    assert!(checkpoint_release.ok);
    let checkpoint_status = checkpoint_release.status.unwrap();
    assert_eq!(checkpoint_status.barrier, BarrierPhase::CheckpointReleased);
    assert_eq!(checkpoint_status.barrier_effect, Some(target.effect));
    assert_eq!(checkpoint_status.completed_barrier, None);
    assert_eq!(checkpoint_status.completed_barrier_effect, None);
    assert_eq!(
        provider.handle_guest(request(CLIENT_A, 4, effect(24), Operation::FdTell { fd },)).errno,
        errno::AGAIN
    );
    let poll = provider.handle_barrier_poll(BarrierPollRequest {
        version: PROTOCOL_VERSION,
        session: SESSION,
        owner: OWNER,
        client: CLIENT_A,
        capability: GUEST,
        authority_epoch: 1,
        token: BARRIER,
        sequence: target.sequence,
        effect: target.effect,
    });
    assert_eq!(poll.errno, errno::SUCCESS);
    assert_eq!(poll.directive, BarrierDirective::Checkpoint);

    let snapshot_path = temporary.path().join("namespace.snapshot");
    let snapshot = admin(
        &mut provider,
        AdminOperation::SnapshotNamespace { output: snapshot_path.display().to_string() },
    );
    assert!(snapshot.ok);
    let receipt = snapshot.snapshot.unwrap();
    let decoded = decode_namespace_snapshot(&fs::read(snapshot_path).unwrap()).unwrap();
    assert_eq!(decoded.effect_frontier, receipt.effect_frontier);
    assert_eq!(decoded.effects, receipt.effects);
    let journal = decoded
        .paths
        .iter()
        .find(|entry| entry.path == b"db-journal")
        .and_then(|entry| decoded.objects.iter().find(|object| object.object == entry.object))
        .unwrap();
    assert_eq!(journal.bytes, b"ab");
}

#[test]
fn stable_effect_is_exactly_once_across_clients_and_drain_blocks_uncertain_delivery() {
    let temporary = temporary();
    let mut provider = provider(&temporary);
    let fd = open_file(&mut provider, b"database", CLIENT_A, 1);
    let operation = Operation::FdWrite { fd, bytes: b"once".to_vec() };
    let uncertain = request(CLIENT_A, 2, effect(42), operation.clone());
    let first = provider.handle_guest(uncertain.clone());
    assert_eq!(first.errno, errno::SUCCESS);

    let arm = admin(
        &mut provider,
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
    assert!(!arm.ok);

    let replacement = request(CLIENT_B, 1, uncertain.effect, operation.clone());
    let replay = provider.handle_guest(replacement.clone());
    assert_eq!(replay.errno, errno::SUCCESS);
    assert_eq!(replay.result, first.result);

    let incompatible =
        request(CLIENT_C, 1, uncertain.effect, Operation::FdWrite { fd, bytes: b"twice".to_vec() });
    let rejected = provider.handle_guest(incompatible);
    assert_eq!(rejected.errno, errno::INVAL);
    assert!(!rejected.completion_required);

    assert_eq!(complete(&mut provider, &uncertain).errno, errno::SUCCESS);
    assert_eq!(complete(&mut provider, &replacement).errno, errno::SUCCESS);
    assert!(
        admin(
            &mut provider,
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
        .ok
    );
    let target = request(CLIENT_A, 3, effect(43), Operation::FdTell { fd });
    assert_eq!(provider.handle_guest(target.clone()).errno, errno::SUCCESS);
    assert_eq!(complete(&mut provider, &target).directive, BarrierDirective::Wait);
    let held = admin(&mut provider, AdminOperation::Status).status.unwrap();
    let continue_release = admin(
        &mut provider,
        AdminOperation::BarrierRelease { token: BARRIER, action: BarrierReleaseAction::Continue },
    );
    assert!(continue_release.ok);
    let continued = continue_release.status.unwrap();
    assert_eq!(continued.barrier, BarrierPhase::Open);
    assert_eq!(continued.barrier_effect, None);
    assert_eq!(continued.completed_barrier, Some(BARRIER));
    assert_eq!(continued.completed_barrier_effect, Some(target.effect));
    assert_eq!(continued.effects, held.effects);
    assert_eq!(continued.completed_requests, held.completed_requests);

    let released_poll = provider.handle_barrier_poll(BarrierPollRequest {
        version: PROTOCOL_VERSION,
        session: SESSION,
        owner: OWNER,
        client: CLIENT_A,
        capability: GUEST,
        authority_epoch: 1,
        token: BARRIER,
        sequence: target.sequence,
        effect: target.effect,
    });
    assert_eq!(released_poll.errno, errno::SUCCESS);
    assert_eq!(released_poll.directive, BarrierDirective::Continue);

    let output = temporary.path().join("database.materialized");
    assert!(
        admin(
            &mut provider,
            AdminOperation::Materialize {
                guest_path: b"database".to_vec(),
                host_path: output.display().to_string(),
            },
        )
        .ok
    );
    assert_eq!(fs::read(output).unwrap(), b"once");
}

#[test]
fn invalid_predicates_and_wrong_target_polls_fail_closed() {
    let temporary = temporary();
    let mut provider = provider(&temporary);
    for predicate in [
        HostcallPredicate {
            kind: HostcallKind::Any,
            resource: ResourceSelector::Any,
            outcome: OutcomePredicate::Any,
            occurrence: 0,
        },
        HostcallPredicate {
            kind: HostcallKind::PathOpen,
            resource: ResourceSelector::ExactPath(b"../escape".to_vec()),
            outcome: OutcomePredicate::Success,
            occurrence: 1,
        },
    ] {
        assert!(
            !admin(&mut provider, AdminOperation::BarrierArm { token: BARRIER, predicate },).ok
        );
    }
    let poll = provider.handle_barrier_poll(BarrierPollRequest {
        version: PROTOCOL_VERSION,
        session: SESSION,
        owner: OWNER,
        client: CLIENT_A,
        capability: GUEST,
        authority_epoch: 1,
        token: BARRIER,
        sequence: 1,
        effect: effect(99),
    });
    assert_eq!(poll.errno, errno::INVAL);
    assert_eq!(poll.directive, BarrierDirective::Continue);
}
