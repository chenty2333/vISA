use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use tempfile::TempDir;
use visa_wasi_host::{
    CreateConfig, ImportFile, ProviderServer, RestoreConfig, create_provider, open_provider,
    restore_provider, send_admin, send_completion, send_guest,
};
use visa_wasi_protocol::{
    AdminCapability, AdminOperation, AdminRequest, BarrierReleaseAction, BarrierToken, ClientId,
    EffectId, GuestCapability, GuestCompletion, GuestRequest, HostcallKind, HostcallPredicate,
    LockLevel, Operation, OperationResult, OutcomePredicate, OwnerId, PROTOCOL_VERSION,
    ProviderMode, ResourceSelector, SessionId, errno,
};

const SESSION: SessionId = SessionId([1; 16]);
const OWNER: OwnerId = OwnerId([2; 16]);
const SOURCE_CLIENT: ClientId = ClientId([3; 16]);
const DESTINATION_CLIENT: ClientId = ClientId([4; 16]);
const SOURCE_CAPABILITY: AdminCapability = AdminCapability([5; 32]);
const DESTINATION_CAPABILITY: AdminCapability = AdminCapability([6; 32]);
const SOURCE_GUEST_CAPABILITY: GuestCapability = GuestCapability([8; 32]);
const DESTINATION_GUEST_CAPABILITY: GuestCapability = GuestCapability([9; 32]);
const HANDOFF: [u8; 16] = [7; 16];
const BARRIER: BarrierToken = BarrierToken([10; 16]);

struct Guest {
    socket: PathBuf,
    client: ClientId,
    owner: OwnerId,
    capability: GuestCapability,
    epoch: u64,
    sequence: u64,
}

impl Guest {
    fn new(
        socket: &Path,
        client: ClientId,
        owner: OwnerId,
        capability: GuestCapability,
        epoch: u64,
    ) -> Self {
        Self { socket: socket.to_path_buf(), client, owner, capability, epoch, sequence: 1 }
    }

    fn call(&mut self, operation: Operation) -> visa_wasi_protocol::GuestResponse {
        let effect = self.effect(self.sequence);
        let request = GuestRequest {
            version: PROTOCOL_VERSION,
            session: SESSION,
            owner: self.owner,
            client: self.client,
            capability: self.capability,
            sequence: self.sequence,
            effect,
            authority_epoch: self.epoch,
            operation,
        };
        let response = send_guest(&self.socket, &request).unwrap();
        assert_eq!(response.sequence, self.sequence);
        self.complete(&request, &response);
        self.sequence += 1;
        response
    }

    fn exact_replay(
        &self,
        sequence: u64,
        operation: Operation,
    ) -> visa_wasi_protocol::GuestResponse {
        let request = GuestRequest {
            version: PROTOCOL_VERSION,
            session: SESSION,
            owner: self.owner,
            client: self.client,
            capability: self.capability,
            sequence,
            effect: self.effect(sequence),
            authority_epoch: self.epoch,
            operation,
        };
        let response = send_guest(&self.socket, &request).unwrap();
        self.complete(&request, &response);
        response
    }

    fn effect(&self, sequence: u64) -> EffectId {
        let mut bytes = self.client.0;
        for (target, byte) in bytes[8..].iter_mut().zip(sequence.to_be_bytes()) {
            *target ^= byte;
        }
        EffectId(bytes)
    }

    fn complete(&self, request: &GuestRequest, response: &visa_wasi_protocol::GuestResponse) {
        if response.completion_required {
            let completion = GuestCompletion {
                version: PROTOCOL_VERSION,
                session: request.session,
                owner: request.owner,
                client: request.client,
                capability: request.capability,
                sequence: request.sequence,
                effect: request.effect,
                authority_epoch: request.authority_epoch,
            };
            assert_eq!(send_completion(&self.socket, &completion).unwrap().errno, errno::SUCCESS);
        }
    }
}

fn private_temp() -> TempDir {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temporary
}

fn start_provider(database: &Path, socket: &Path) -> thread::JoinHandle<()> {
    let provider = open_provider(database).unwrap();
    let socket = socket.to_path_buf();
    let server_socket = socket.clone();
    let handle = thread::spawn(move || ProviderServer::serve(provider, &server_socket).unwrap());
    for _ in 0..200 {
        if socket.exists() {
            return handle;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("provider socket did not appear")
}

fn admin(
    socket: &Path,
    capability: AdminCapability,
    operation: AdminOperation,
) -> visa_wasi_protocol::AdminResponse {
    send_admin(socket, &AdminRequest { version: PROTOCOL_VERSION, capability, operation }).unwrap()
}

fn expect_fd(response: visa_wasi_protocol::GuestResponse) -> u32 {
    assert_eq!(response.errno, errno::SUCCESS);
    let OperationResult::FileDescriptor(fd) = response.result else {
        panic!("expected file descriptor")
    };
    fd
}

fn expect_bytes(response: visa_wasi_protocol::GuestResponse) -> Vec<u8> {
    assert_eq!(response.errno, errno::SUCCESS);
    let OperationResult::Bytes(bytes) = response.result else { panic!("expected bytes") };
    bytes
}

#[test]
fn fresh_destination_preserves_descriptors_chunks_locks_and_fencing() {
    let temporary = private_temp();
    let input_path = temporary.path().join("input.bin");
    let input =
        (0..(3 * 64 * 1024 + 937)).map(|index| ((index * 37 + 11) % 251) as u8).collect::<Vec<_>>();
    fs::write(&input_path, &input).unwrap();

    let source_database = temporary.path().join("source.sqlite");
    create_provider(&CreateConfig {
        database: source_database.clone(),
        session: SESSION,
        capability: SOURCE_CAPABILITY,
        guest_capability: SOURCE_GUEST_CAPABILITY,
        authority_epoch: 1,
        imports: vec![ImportFile { host_path: input_path, guest_path: b"work/input.bin".to_vec() }],
    })
    .unwrap();

    let source_socket = temporary.path().join("source.sock");
    let source_thread = start_provider(&source_database, &source_socket);
    let mut source = Guest::new(&source_socket, SOURCE_CLIENT, OWNER, SOURCE_GUEST_CAPABILITY, 1);

    let input_fd = expect_fd(source.call(Operation::PathOpen {
        dir_fd: 3,
        lookup_flags: 0,
        path: b"work/input.bin".to_vec(),
        open_flags: 0,
        rights_base: u64::MAX,
        rights_inheriting: u64::MAX,
        fd_flags: 0,
    }));
    let first = expect_bytes(source.call(Operation::FdRead { fd: input_fd, length: 70_000 }));
    assert_eq!(first, input[..70_000]);

    let output_fd = expect_fd(source.call(Operation::PathOpen {
        dir_fd: 3,
        lookup_flags: 0,
        path: b"work/output.bin".to_vec(),
        open_flags: 1 | 8,
        rights_base: u64::MAX,
        rights_inheriting: u64::MAX,
        fd_flags: 0,
    }));
    let prefix = b"source-prefix-".repeat(6_000);
    let write_sequence = source.sequence;
    let write = source.call(Operation::FdWrite { fd: output_fd, bytes: prefix.clone() });
    assert_eq!(write.errno, errno::SUCCESS);
    assert_eq!(
        source.exact_replay(
            write_sequence,
            Operation::FdWrite { fd: output_fd, bytes: prefix.clone() }
        ),
        write
    );

    let renamed = source.call(Operation::PathRename {
        old_dir_fd: 3,
        old_path: b"work/output.bin".to_vec(),
        new_dir_fd: 3,
        new_path: b"work/renamed.bin".to_vec(),
    });
    assert_eq!(renamed.errno, errno::SUCCESS);
    let unlinked =
        source.call(Operation::PathUnlinkFile { dir_fd: 3, path: b"work/renamed.bin".to_vec() });
    assert_eq!(unlinked.errno, errno::SUCCESS);
    assert_eq!(
        source.call(Operation::VfsLock { fd: output_fd, level: LockLevel::Exclusive }).errno,
        errno::SUCCESS
    );

    assert!(
        admin(
            &source_socket,
            SOURCE_CAPABILITY,
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
    assert_eq!(source.call(Operation::FdTell { fd: output_fd }).errno, errno::SUCCESS);
    assert!(
        admin(
            &source_socket,
            SOURCE_CAPABILITY,
            AdminOperation::BarrierRelease {
                token: BARRIER,
                action: BarrierReleaseAction::Checkpoint,
            },
        )
        .ok
    );

    let freeze = admin(
        &source_socket,
        SOURCE_CAPABILITY,
        AdminOperation::Freeze { barrier: BARRIER, handoff: HANDOFF, destination_epoch: 2 },
    );
    assert!(freeze.ok);
    assert_eq!(freeze.status.unwrap().mode, ProviderMode::Frozen);
    let rejected = source.call(Operation::FdTell { fd: output_fd });
    assert_eq!(rejected.errno, errno::PERM);

    let bundle = temporary.path().join("capsule");
    assert!(
        admin(
            &source_socket,
            SOURCE_CAPABILITY,
            AdminOperation::Export { bundle: bundle.display().to_string() }
        )
        .ok
    );
    assert!(
        admin(
            &source_socket,
            SOURCE_CAPABILITY,
            AdminOperation::Fence { handoff: HANDOFF, committed_epoch: 2 }
        )
        .ok
    );
    assert!(admin(&source_socket, SOURCE_CAPABILITY, AdminOperation::Shutdown).ok);
    source_thread.join().unwrap();

    let destination_database = temporary.path().join("destination.sqlite");
    restore_provider(&RestoreConfig {
        bundle,
        database: destination_database.clone(),
        capability: DESTINATION_CAPABILITY,
        guest_capability: DESTINATION_GUEST_CAPABILITY,
    })
    .unwrap();
    let destination_socket = temporary.path().join("destination.sock");
    let destination_thread = start_provider(&destination_database, &destination_socket);
    let mut spoofed_destination =
        Guest::new(&destination_socket, DESTINATION_CLIENT, OWNER, SOURCE_GUEST_CAPABILITY, 2);
    assert_eq!(spoofed_destination.call(Operation::FdTell { fd: output_fd }).errno, errno::ACCES);
    let mut destination =
        Guest::new(&destination_socket, DESTINATION_CLIENT, OWNER, DESTINATION_GUEST_CAPABILITY, 2);

    let blocked = destination.call(Operation::FdTell { fd: output_fd });
    assert_eq!(blocked.errno, errno::AGAIN);
    let activation = admin(
        &destination_socket,
        DESTINATION_CAPABILITY,
        AdminOperation::Activate { handoff: HANDOFF, authority_epoch: 2 },
    );
    assert!(activation.ok);
    assert_eq!(activation.status.unwrap().mode, ProviderMode::Active);
    assert!(
        admin(
            &destination_socket,
            DESTINATION_CAPABILITY,
            AdminOperation::BarrierRelease {
                token: BARRIER,
                action: BarrierReleaseAction::Continue,
            }
        )
        .ok
    );

    let tell = destination.call(Operation::FdTell { fd: output_fd });
    assert_eq!(tell.result, OperationResult::Offset(prefix.len() as u64));
    assert_eq!(
        destination.call(Operation::VfsCheckReserved { fd: output_fd }).result,
        OperationResult::Reserved(true)
    );
    assert_eq!(
        destination.call(Operation::VfsUnlock { fd: output_fd, level: LockLevel::None }).errno,
        errno::SUCCESS
    );
    let suffix = b"destination-suffix".repeat(5_000);
    assert_eq!(
        destination.call(Operation::FdWrite { fd: output_fd, bytes: suffix.clone() }).errno,
        errno::SUCCESS
    );
    let next_input =
        expect_bytes(destination.call(Operation::FdRead { fd: input_fd, length: 80_000 }));
    assert_eq!(next_input, input[70_000..150_000]);

    // The path was unlinked before handoff, but the migrated open description
    // remains bound to the same stable object and can be materialized through
    // a new hard link.
    assert_eq!(
        destination
            .call(Operation::PathLink {
                old_dir_fd: 3,
                old_lookup_flags: 0,
                old_path: b"work/input.bin".to_vec(),
                new_dir_fd: 3,
                new_path: b"work/input-copy.bin".to_vec(),
            })
            .errno,
        errno::SUCCESS
    );
    // Recreate a namespace name for the still-open output using a fresh file
    // would change identity, so inspect it through the descriptor instead.
    assert_eq!(
        destination
            .call(Operation::FdSeek {
                fd: output_fd,
                delta: 0,
                whence: visa_wasi_protocol::SeekWhence::Set
            })
            .errno,
        errno::SUCCESS
    );
    let output = expect_bytes(destination.call(Operation::FdRead {
        fd: output_fd,
        length: u32::try_from(prefix.len() + suffix.len()).unwrap(),
    }));
    assert_eq!(output, [prefix, suffix].concat());

    assert!(admin(&destination_socket, DESTINATION_CAPABILITY, AdminOperation::Shutdown).ok);
    destination_thread.join().unwrap();
}
