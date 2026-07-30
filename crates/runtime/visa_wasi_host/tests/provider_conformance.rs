use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rusqlite::{Connection, params};
use tempfile::TempDir;
use visa_wasi_host::{
    CreateConfig, ImportFile, Provider, RestoreConfig, create_provider, open_provider,
    restore_provider,
};
use visa_wasi_protocol::{
    AdminCapability, AdminOperation, AdminRequest, BarrierPhase, BarrierReleaseAction,
    BarrierToken, ClientId, EffectId, GuestCapability, GuestCompletion, GuestRequest,
    GuestResponse, HostcallKind, HostcallPredicate, LockLevel, Operation, OperationResult,
    OutcomePredicate, OwnerId, PROTOCOL_VERSION, ProviderMode, ResourceSelector, SessionId, errno,
    rights,
};

const SESSION: SessionId = SessionId([11; 16]);
const OWNER_A: OwnerId = OwnerId([12; 16]);
const OWNER_B: OwnerId = OwnerId([13; 16]);
const OWNER_C: OwnerId = OwnerId([21; 16]);
const CLIENT_A: ClientId = ClientId([14; 16]);
const CLIENT_B: ClientId = ClientId([15; 16]);
const CLIENT_C: ClientId = ClientId([22; 16]);
const CAPABILITY_A: AdminCapability = AdminCapability([16; 32]);
const CAPABILITY_B: AdminCapability = AdminCapability([17; 32]);
const GUEST_CAPABILITY_A: GuestCapability = GuestCapability([19; 32]);
const GUEST_CAPABILITY_B: GuestCapability = GuestCapability([20; 32]);
const HANDOFF: [u8; 16] = [18; 16];
const BARRIER_A: BarrierToken = BarrierToken([23; 16]);
const BARRIER_B: BarrierToken = BarrierToken([24; 16]);

struct Guest {
    owner: OwnerId,
    client: ClientId,
    capability: GuestCapability,
    epoch: u64,
    sequence: u64,
}

impl Guest {
    const fn new(
        owner: OwnerId,
        client: ClientId,
        capability: GuestCapability,
        epoch: u64,
    ) -> Self {
        Self { owner, client, capability, epoch, sequence: 1 }
    }

    fn request(&self, sequence: u64, operation: Operation) -> GuestRequest {
        let mut effect = self.client.0;
        for (target, byte) in effect[8..].iter_mut().zip(sequence.to_be_bytes()) {
            *target ^= byte;
        }
        GuestRequest {
            version: PROTOCOL_VERSION,
            session: SESSION,
            owner: self.owner,
            client: self.client,
            capability: self.capability,
            sequence,
            effect: EffectId(effect),
            authority_epoch: self.epoch,
            operation,
        }
    }

    fn call(&mut self, provider: &mut Provider, operation: Operation) -> GuestResponse {
        let request = self.request(self.sequence, operation);
        let response = provider.handle_guest(request.clone());
        assert_eq!(response.sequence, self.sequence);
        if response.completion_required {
            assert_eq!(
                provider
                    .handle_completion(GuestCompletion {
                        version: PROTOCOL_VERSION,
                        session: request.session,
                        owner: request.owner,
                        client: request.client,
                        capability: request.capability,
                        sequence: request.sequence,
                        effect: request.effect,
                        authority_epoch: request.authority_epoch,
                    })
                    .errno,
                errno::SUCCESS
            );
        }
        self.sequence += 1;
        response
    }

    fn replay(
        &self,
        provider: &mut Provider,
        sequence: u64,
        operation: Operation,
    ) -> GuestResponse {
        let request = self.request(sequence, operation);
        let response = provider.handle_guest(request.clone());
        if response.completion_required {
            assert_eq!(
                provider
                    .handle_completion(GuestCompletion {
                        version: PROTOCOL_VERSION,
                        session: request.session,
                        owner: request.owner,
                        client: request.client,
                        capability: request.capability,
                        sequence: request.sequence,
                        effect: request.effect,
                        authority_epoch: request.authority_epoch,
                    })
                    .errno,
                errno::SUCCESS
            );
        }
        response
    }
}

fn temporary() -> TempDir {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temporary
}

fn create(temporary: &TempDir, imports: &[(&[u8], &[u8])]) -> (PathBuf, Provider) {
    let mut configured = Vec::new();
    for (index, (guest_path, bytes)) in imports.iter().enumerate() {
        let host_path = temporary.path().join(format!("import-{index}"));
        fs::write(&host_path, bytes).unwrap();
        configured.push(ImportFile { host_path, guest_path: guest_path.to_vec() });
    }
    let database = temporary.path().join("provider.sqlite");
    create_provider(&CreateConfig {
        database: database.clone(),
        session: SESSION,
        capability: CAPABILITY_A,
        guest_capability: GUEST_CAPABILITY_A,
        authority_epoch: 1,
        imports: configured,
    })
    .unwrap();
    let provider = open_provider(&database).unwrap();
    (database, provider)
}

fn open(
    provider: &mut Provider,
    guest: &mut Guest,
    path: &[u8],
    open_flags: u16,
    base: u64,
    inheriting: u64,
    fd_flags: u16,
) -> u32 {
    let response = guest.call(
        provider,
        Operation::PathOpen {
            dir_fd: 3,
            lookup_flags: 0,
            path: path.to_vec(),
            open_flags,
            rights_base: base,
            rights_inheriting: inheriting,
            fd_flags,
        },
    );
    assert_eq!(response.errno, errno::SUCCESS);
    let OperationResult::FileDescriptor(fd) = response.result else {
        panic!("path_open did not return an fd");
    };
    fd
}

fn bytes(response: GuestResponse) -> Vec<u8> {
    assert_eq!(response.errno, errno::SUCCESS);
    let OperationResult::Bytes(bytes) = response.result else {
        panic!("operation did not return bytes");
    };
    bytes
}

fn admin(
    provider: &mut Provider,
    capability: AdminCapability,
    operation: AdminOperation,
) -> visa_wasi_protocol::AdminResponse {
    provider.handle_admin(AdminRequest { version: PROTOCOL_VERSION, capability, operation })
}

fn hold(provider: &mut Provider, capability: AdminCapability, token: BarrierToken) {
    assert!(
        admin(
            provider,
            capability,
            AdminOperation::BarrierArm {
                token,
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
    let mut barrier_guest = Guest {
        owner: OWNER_C,
        client: CLIENT_C,
        capability: GUEST_CAPABILITY_A,
        epoch: 1,
        sequence: u64::from(token.0[0]),
    };
    assert_eq!(barrier_guest.call(provider, Operation::FdStatGet { fd: 3 }).errno, errno::SUCCESS);
    assert_eq!(
        admin(provider, capability, AdminOperation::Status).status.unwrap().barrier,
        BarrierPhase::Held
    );
    assert!(
        admin(
            provider,
            capability,
            AdminOperation::BarrierRelease { token, action: BarrierReleaseAction::Checkpoint },
        )
        .ok
    );
}

fn release(provider: &mut Provider, capability: AdminCapability, token: BarrierToken) {
    assert!(
        admin(
            provider,
            capability,
            AdminOperation::BarrierRelease { token, action: BarrierReleaseAction::Continue },
        )
        .ok
    );
}

#[test]
fn cursors_positioned_io_and_rights_are_capability_exact() {
    let temporary = temporary();
    let (_, mut provider) = create(&temporary, &[(b"data.bin", b"0123456789")]);
    let mut guest = Guest::new(OWNER_A, CLIENT_A, GUEST_CAPABILITY_A, 1);
    let complete = rights::FD_READ
        | rights::FD_WRITE
        | rights::FD_SEEK
        | rights::FD_TELL
        | rights::FD_FILESTAT_GET;
    let first = open(&mut provider, &mut guest, b"data.bin", 0, complete, 0, 0);
    let second = open(&mut provider, &mut guest, b"data.bin", 0, complete, 0, 0);
    let read_without_seek = open(&mut provider, &mut guest, b"data.bin", 0, rights::FD_READ, 0, 0);
    let write_without_seek =
        open(&mut provider, &mut guest, b"data.bin", 0, rights::FD_WRITE, 0, 0);
    let seek_only = open(&mut provider, &mut guest, b"data.bin", 0, rights::FD_SEEK, 0, 0);
    let tell_only = open(&mut provider, &mut guest, b"data.bin", 0, rights::FD_TELL, 0, 0);

    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::FdPread {
                    fd: read_without_seek,
                    length: 1,
                    offset: 0,
                },
            )
            .errno,
        errno::NOTCAPABLE
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::FdPwrite { fd: write_without_seek, bytes: b"!".to_vec(), offset: 0 },
            )
            .errno,
        errno::NOTCAPABLE
    );
    assert_eq!(
        guest.call(&mut provider, Operation::FdTell { fd: seek_only }).result,
        OperationResult::Offset(0)
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::FdSeek {
                    fd: tell_only,
                    delta: 0,
                    whence: visa_wasi_protocol::SeekWhence::Current,
                },
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::FdSeek {
                    fd: tell_only,
                    delta: 1,
                    whence: visa_wasi_protocol::SeekWhence::Current,
                },
            )
            .errno,
        errno::NOTCAPABLE
    );

    assert_eq!(
        bytes(guest.call(&mut provider, Operation::FdRead { fd: first, length: 3 })),
        b"012"
    );
    assert_eq!(
        bytes(guest.call(&mut provider, Operation::FdRead { fd: second, length: 2 })),
        b"01"
    );
    assert_eq!(
        bytes(guest.call(&mut provider, Operation::FdPread { fd: first, length: 2, offset: 7 })),
        b"78"
    );
    assert_eq!(
        guest.call(&mut provider, Operation::FdTell { fd: first }).result,
        OperationResult::Offset(3)
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::FdPwrite { fd: first, bytes: b"XY".to_vec(), offset: 5 }
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest.call(&mut provider, Operation::FdTell { fd: first }).result,
        OperationResult::Offset(3)
    );

    let reduced = rights::FD_TELL;
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::FdStatSetRights {
                    fd: first,
                    rights_base: reduced,
                    rights_inheriting: 0,
                }
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest.call(&mut provider, Operation::FdRead { fd: first, length: 1 }).errno,
        errno::NOTCAPABLE
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::FdStatSetRights {
                    fd: first,
                    rights_base: complete,
                    rights_inheriting: 0,
                }
            )
            .errno,
        errno::NOTCAPABLE
    );

    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathCreateDirectory { dir_fd: 3, path: b"bounded".to_vec() }
            )
            .errno,
        errno::SUCCESS
    );
    let directory =
        open(&mut provider, &mut guest, b"bounded", 2, rights::PATH_OPEN, rights::FD_READ, 0);
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathOpen {
                    dir_fd: directory,
                    lookup_flags: 0,
                    path: b"child".to_vec(),
                    open_flags: 1,
                    rights_base: rights::FD_WRITE,
                    rights_inheriting: 0,
                    fd_flags: 0,
                }
            )
            .errno,
        errno::NOTCAPABLE
    );
}

#[test]
fn append_replay_sparse_extents_truncate_and_unlinked_identity_are_exact() {
    let temporary = temporary();
    let (_, mut provider) = create(&temporary, &[]);
    let mut guest = Guest::new(OWNER_A, CLIENT_A, GUEST_CAPABILITY_A, 1);
    let base = rights::FD_READ
        | rights::FD_WRITE
        | rights::FD_SEEK
        | rights::FD_TELL
        | rights::FD_ALLOCATE
        | rights::FD_FILESTAT_SET_SIZE;
    let fd = open(&mut provider, &mut guest, b"sparse.bin", 1 | 8, base, 0, 1);

    let append_sequence = guest.sequence;
    let append = guest.call(&mut provider, Operation::FdWrite { fd, bytes: b"head".to_vec() });
    assert_eq!(append.errno, errno::SUCCESS);
    assert_eq!(
        guest.replay(
            &mut provider,
            append_sequence,
            Operation::FdWrite { fd, bytes: b"head".to_vec() }
        ),
        append
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::FdPwrite { fd, bytes: b"tail".to_vec(), offset: 131_079 }
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest
            .call(&mut provider, Operation::FdAllocate { fd, offset: 200_000, length: 4_096 })
            .errno,
        errno::SUCCESS
    );
    let hole =
        bytes(guest.call(&mut provider, Operation::FdPread { fd, length: 16, offset: 100_000 }));
    assert_eq!(hole, vec![0; 16]);
    assert_eq!(
        bytes(guest.call(&mut provider, Operation::FdPread { fd, length: 4, offset: 131_079 })),
        b"tail"
    );
    assert_eq!(
        guest.call(&mut provider, Operation::FdFileStatSetSize { fd, size: 8 }).errno,
        errno::SUCCESS
    );
    assert_eq!(
        bytes(guest.call(&mut provider, Operation::FdPread { fd, length: 32, offset: 0 })),
        b"head\0\0\0\0"
    );

    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathRename {
                    old_dir_fd: 3,
                    old_path: b"sparse.bin".to_vec(),
                    new_dir_fd: 3,
                    new_path: b"renamed.bin".to_vec(),
                }
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathUnlinkFile { dir_fd: 3, path: b"renamed.bin".to_vec() }
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        bytes(guest.call(&mut provider, Operation::FdPread { fd, length: 8, offset: 0 })),
        b"head\0\0\0\0"
    );
    assert_eq!(guest.call(&mut provider, Operation::FdClose { fd }).errno, errno::SUCCESS);
    assert_eq!(guest.call(&mut provider, Operation::FdTell { fd }).errno, errno::BADF);
}

#[test]
fn namespace_and_symlink_escape_are_contained() {
    let temporary = temporary();
    let (_, mut provider) = create(&temporary, &[]);
    let mut guest = Guest::new(OWNER_A, CLIENT_A, GUEST_CAPABILITY_A, 1);
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathFileStatGet { dir_fd: 3, lookup_flags: 2, path: Vec::new() },
            )
            .errno,
        errno::INVAL
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathFileStatSetTimes {
                    dir_fd: 3,
                    lookup_flags: 0,
                    path: Vec::new(),
                    atim: 0,
                    mtim: 0,
                    fst_flags: 0x10,
                },
            )
            .errno,
        errno::INVAL
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathOpen {
                    dir_fd: 3,
                    lookup_flags: 0,
                    path: b"invalid-flags".to_vec(),
                    open_flags: 1,
                    rights_base: rights::FD_WRITE,
                    rights_inheriting: 0,
                    fd_flags: 0x20,
                },
            )
            .errno,
        errno::INVAL
    );
    for path in [b"../escape".as_slice(), b"/absolute".as_slice()] {
        assert_eq!(
            guest
                .call(
                    &mut provider,
                    Operation::PathOpen {
                        dir_fd: 3,
                        lookup_flags: 0,
                        path: path.to_vec(),
                        open_flags: 1,
                        rights_base: rights::FD_WRITE,
                        rights_inheriting: 0,
                        fd_flags: 0,
                    }
                )
                .errno,
            errno::NOTCAPABLE
        );
    }
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathSymlink {
                    old_path: b"../../outside".to_vec(),
                    dir_fd: 3,
                    new_path: b"escape-link".to_vec(),
                }
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathOpen {
                    dir_fd: 3,
                    lookup_flags: 1,
                    path: b"escape-link".to_vec(),
                    open_flags: 0,
                    rights_base: rights::FD_READ,
                    rights_inheriting: 0,
                    fd_flags: 0,
                }
            )
            .errno,
        errno::NOTCAPABLE
    );
    for directory in [b"dir".as_slice(), b"target".as_slice()] {
        assert_eq!(
            guest
                .call(
                    &mut provider,
                    Operation::PathCreateDirectory { dir_fd: 3, path: directory.to_vec() },
                )
                .errno,
            errno::SUCCESS
        );
    }
    let directory =
        open(&mut provider, &mut guest, b"dir", 2, rights::PATH_OPEN, rights::FD_READ, 0);
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathCreateDirectory { dir_fd: 3, path: b"dir".to_vec() },
            )
            .errno,
        errno::EXIST
    );
    let rejected_open = Operation::PathOpen {
        dir_fd: 3,
        lookup_flags: 0,
        path: b"must-remain-absent".to_vec(),
        open_flags: 1 | 2,
        rights_base: rights::FD_READ,
        rights_inheriting: 0,
        fd_flags: 0,
    };
    let rejected_sequence = guest.sequence;
    let rejected = guest.call(&mut provider, rejected_open.clone());
    assert_eq!(rejected.errno, errno::NOTDIR);
    assert_eq!(guest.replay(&mut provider, rejected_sequence, rejected_open), rejected);
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathFileStatGet {
                    dir_fd: 3,
                    lookup_flags: 0,
                    path: b"must-remain-absent".to_vec(),
                },
            )
            .errno,
        errno::NOENT
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathSymlink {
                    old_path: b"../../outside".to_vec(),
                    dir_fd: 3,
                    new_path: b"dir/escape".to_vec(),
                },
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathOpen {
                    dir_fd: 3,
                    lookup_flags: 1,
                    path: b"dir/escape/file".to_vec(),
                    open_flags: 1,
                    rights_base: rights::FD_WRITE,
                    rights_inheriting: 0,
                    fd_flags: 0,
                },
            )
            .errno,
        errno::NOTCAPABLE
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathSymlink {
                    old_path: b"../target".to_vec(),
                    dir_fd: 3,
                    new_path: b"dir/redirect".to_vec(),
                },
            )
            .errno,
        errno::SUCCESS
    );
    let redirected = guest.call(
        &mut provider,
        Operation::PathOpen {
            dir_fd: 3,
            lookup_flags: 1,
            path: b"dir/redirect/file".to_vec(),
            open_flags: 1,
            rights_base: rights::FD_WRITE,
            rights_inheriting: 0,
            fd_flags: 0,
        },
    );
    assert_eq!(redirected.errno, errno::SUCCESS);
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathFileStatGet {
                    dir_fd: 3,
                    lookup_flags: 0,
                    path: b"target/file".to_vec(),
                },
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathSymlink {
                    old_path: b"target".to_vec(),
                    dir_fd: 3,
                    new_path: b"target-link".to_vec(),
                },
            )
            .errno,
        errno::SUCCESS
    );
    let linked_directory = guest.call(
        &mut provider,
        Operation::PathOpen {
            dir_fd: 3,
            lookup_flags: 1,
            path: b"target-link".to_vec(),
            open_flags: 2,
            rights_base: rights::PATH_OPEN,
            rights_inheriting: rights::FD_READ,
            fd_flags: 0,
        },
    );
    assert_eq!(linked_directory.errno, errno::SUCCESS);
    let OperationResult::FileDescriptor(linked_directory) = linked_directory.result else {
        panic!("directory symlink open did not return an fd");
    };
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathOpen {
                    dir_fd: linked_directory,
                    lookup_flags: 0,
                    path: b"file".to_vec(),
                    open_flags: 0,
                    rights_base: rights::FD_READ,
                    rights_inheriting: 0,
                    fd_flags: 0,
                },
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathOpen {
                    dir_fd: directory,
                    lookup_flags: 0,
                    path: b"../target/file".to_vec(),
                    open_flags: 0,
                    rights_base: rights::FD_READ,
                    rights_inheriting: 0,
                    fd_flags: 0,
                },
            )
            .errno,
        errno::NOTCAPABLE
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathOpen {
                    dir_fd: directory,
                    lookup_flags: 1,
                    path: b"redirect/file".to_vec(),
                    open_flags: 0,
                    rights_base: rights::FD_READ,
                    rights_inheriting: 0,
                    fd_flags: 0,
                },
            )
            .errno,
        errno::NOTCAPABLE
    );
}

#[test]
fn rename_between_two_names_for_the_same_object_is_a_noop() {
    let temporary = temporary();
    let (_, mut provider) = create(&temporary, &[(b"original", b"payload")]);
    let mut guest = Guest::new(OWNER_A, CLIENT_A, GUEST_CAPABILITY_A, 1);
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathLink {
                    old_dir_fd: 3,
                    old_lookup_flags: 0,
                    old_path: b"original".to_vec(),
                    new_dir_fd: 3,
                    new_path: b"alias".to_vec(),
                },
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathRename {
                    old_dir_fd: 3,
                    old_path: b"original".to_vec(),
                    new_dir_fd: 3,
                    new_path: b"alias".to_vec(),
                },
            )
            .errno,
        errno::SUCCESS
    );
    for path in [b"original".as_slice(), b"alias".as_slice()] {
        let response = guest.call(
            &mut provider,
            Operation::PathFileStatGet { dir_fd: 3, lookup_flags: 0, path: path.to_vec() },
        );
        assert_eq!(response.errno, errno::SUCCESS);
        let OperationResult::FileStat(stat) = response.result else {
            panic!("path_filestat_get did not return a stat");
        };
        assert_eq!(stat.link_count, 2);
    }
}

#[test]
fn lock_compatibility_stable_owner_and_close_lifecycle_are_enforced() {
    let temporary = temporary();
    let (_, mut provider) = create(&temporary, &[(b"database", b"sqlite")]);
    let mut a = Guest::new(OWNER_A, CLIENT_A, GUEST_CAPABILITY_A, 1);
    let mut b = Guest::new(OWNER_B, CLIENT_B, GUEST_CAPABILITY_A, 1);
    let mut c = Guest::new(OWNER_C, CLIENT_C, GUEST_CAPABILITY_A, 1);
    let base = rights::FD_READ | rights::FD_WRITE | rights::VFS_LOCK;
    let fd_a = open(&mut provider, &mut a, b"database", 0, base, 0, 0);
    let fd_b = open(&mut provider, &mut b, b"database", 0, base, 0, 0);
    let fd_c = open(&mut provider, &mut c, b"database", 0, base, 0, 0);
    assert_eq!(
        a.call(&mut provider, Operation::VfsLock { fd: fd_a, level: LockLevel::Shared }).errno,
        errno::SUCCESS
    );
    assert_eq!(
        b.call(&mut provider, Operation::VfsLock { fd: fd_b, level: LockLevel::Reserved }).errno,
        errno::SUCCESS
    );
    assert_eq!(
        a.call(&mut provider, Operation::VfsLock { fd: fd_a, level: LockLevel::Reserved }).errno,
        errno::AGAIN
    );
    let mut a_after_process_handoff =
        Guest::new(OWNER_A, ClientId([19; 16]), GUEST_CAPABILITY_A, 1);
    assert_eq!(
        a_after_process_handoff
            .call(&mut provider, Operation::VfsCheckReserved { fd: fd_a })
            .result,
        OperationResult::Reserved(true)
    );
    assert_eq!(
        b.call(&mut provider, Operation::VfsLock { fd: fd_b, level: LockLevel::Pending }).errno,
        errno::SUCCESS
    );
    assert_eq!(
        a_after_process_handoff
            .call(&mut provider, Operation::VfsLock { fd: fd_a, level: LockLevel::Shared })
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        c.call(&mut provider, Operation::VfsLock { fd: fd_c, level: LockLevel::Shared }).errno,
        errno::AGAIN
    );
    assert_eq!(
        b.call(&mut provider, Operation::VfsLock { fd: fd_b, level: LockLevel::Exclusive }).errno,
        errno::AGAIN
    );
    assert_eq!(
        a_after_process_handoff.call(&mut provider, Operation::FdClose { fd: fd_a }).errno,
        errno::SUCCESS
    );
    assert_eq!(
        b.call(&mut provider, Operation::VfsLock { fd: fd_b, level: LockLevel::Exclusive }).errno,
        errno::SUCCESS
    );
    assert_eq!(
        b.call(&mut provider, Operation::VfsUnlock { fd: fd_b, level: LockLevel::Shared }).errno,
        errno::SUCCESS
    );
    assert_eq!(
        c.call(&mut provider, Operation::VfsLock { fd: fd_c, level: LockLevel::Shared }).errno,
        errno::SUCCESS
    );
    assert_eq!(b.call(&mut provider, Operation::FdClose { fd: fd_b }).errno, errno::SUCCESS);
    assert_eq!(c.call(&mut provider, Operation::FdClose { fd: fd_c }).errno, errno::SUCCESS);
    let fd_check = open(&mut provider, &mut a, b"database", 0, base, 0, 0);
    assert_eq!(
        a.call(&mut provider, Operation::VfsCheckReserved { fd: fd_check }).result,
        OperationResult::Reserved(false)
    );
}

#[test]
fn locks_follow_unlinked_object_identity_and_reject_directories() {
    let temporary = temporary();
    let (_, mut provider) = create(&temporary, &[(b"database", b"sqlite")]);
    let mut a = Guest::new(OWNER_A, CLIENT_A, GUEST_CAPABILITY_A, 1);
    let mut b = Guest::new(OWNER_B, CLIENT_B, GUEST_CAPABILITY_A, 1);
    let base = rights::FD_READ | rights::VFS_LOCK;
    let fd_a = open(&mut provider, &mut a, b"database", 0, base, 0, 0);
    let fd_b = open(&mut provider, &mut b, b"database", 0, base, 0, 0);

    assert_eq!(
        a.call(&mut provider, Operation::VfsLock { fd: fd_a, level: LockLevel::Shared }).errno,
        errno::SUCCESS
    );
    assert_eq!(
        a.call(&mut provider, Operation::VfsLock { fd: fd_a, level: LockLevel::Reserved }).errno,
        errno::SUCCESS
    );
    assert_eq!(
        a.call(&mut provider, Operation::PathUnlinkFile { dir_fd: 3, path: b"database".to_vec() },)
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        b.call(&mut provider, Operation::VfsCheckReserved { fd: fd_b }).result,
        OperationResult::Reserved(true)
    );
    assert_eq!(
        b.call(&mut provider, Operation::VfsLock { fd: fd_b, level: LockLevel::Exclusive }).errno,
        errno::AGAIN
    );
    assert_eq!(a.call(&mut provider, Operation::FdClose { fd: fd_a }).errno, errno::SUCCESS);
    assert_eq!(
        b.call(&mut provider, Operation::VfsLock { fd: fd_b, level: LockLevel::Exclusive }).errno,
        errno::SUCCESS
    );
    assert_eq!(b.call(&mut provider, Operation::FdClose { fd: fd_b }).errno, errno::SUCCESS);

    assert_eq!(
        a.call(
            &mut provider,
            Operation::PathCreateDirectory { dir_fd: 3, path: b"directory".to_vec() },
        )
        .errno,
        errno::SUCCESS
    );
    let directory = open(&mut provider, &mut a, b"directory", 2, rights::VFS_LOCK, 0, 0);
    for operation in [
        Operation::VfsLock { fd: directory, level: LockLevel::Shared },
        Operation::VfsUnlock { fd: directory, level: LockLevel::None },
        Operation::VfsCheckReserved { fd: directory },
    ] {
        assert_eq!(a.call(&mut provider, operation).errno, errno::BADF);
    }
}

#[test]
fn metadata_is_real_and_survives_capsule_restore() {
    let temporary = temporary();
    let (source_database, mut provider) = create(&temporary, &[(b"file", b"payload")]);
    let mut guest = Guest::new(OWNER_A, CLIENT_A, GUEST_CAPABILITY_A, 1);
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathChmod { dir_fd: 3, path: b"file".to_vec(), mode: 0o640 }
            )
            .errno,
        errno::SUCCESS
    );
    assert_eq!(
        guest
            .call(
                &mut provider,
                Operation::PathChown {
                    dir_fd: 3,
                    path: b"file".to_vec(),
                    uid: u32::MAX,
                    gid: 4242,
                }
            )
            .errno,
        errno::SUCCESS
    );
    hold(&mut provider, CAPABILITY_A, BARRIER_A);
    assert!(
        admin(
            &mut provider,
            CAPABILITY_A,
            AdminOperation::Freeze { barrier: BARRIER_A, handoff: HANDOFF, destination_epoch: 2 }
        )
        .ok
    );
    let bundle = temporary.path().join("capsule");
    assert!(
        admin(
            &mut provider,
            CAPABILITY_A,
            AdminOperation::Export { bundle: bundle.display().to_string() }
        )
        .ok
    );
    drop(provider);
    let source = Connection::open(&source_database).unwrap();
    let source_metadata: (i64, i64, i64) = source
        .query_row(
            "SELECT mode, uid, gid FROM objects o JOIN paths p USING(object_id)
             WHERE p.path = ?1",
            params![b"file".as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(source_metadata.0, 0o640);
    assert_eq!(source_metadata.1, i64::from(fs::metadata(temporary.path()).unwrap().uid()));
    assert_eq!(source_metadata.2, 4242);

    let destination_database = temporary.path().join("destination.sqlite");
    restore_provider(&RestoreConfig {
        bundle,
        database: destination_database.clone(),
        capability: CAPABILITY_B,
        guest_capability: GUEST_CAPABILITY_B,
    })
    .unwrap();
    let destination = Connection::open(destination_database).unwrap();
    let destination_metadata: (i64, i64, i64) = destination
        .query_row(
            "SELECT mode, uid, gid FROM objects o JOIN paths p USING(object_id)
             WHERE p.path = ?1",
            params![b"file".as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(destination_metadata, source_metadata);
}

#[test]
fn capsule_tamper_and_invalid_state_invariants_are_rejected() {
    let temporary = temporary();
    let (_, mut provider) = create(&temporary, &[(b"file", b"payload")]);
    hold(&mut provider, CAPABILITY_A, BARRIER_A);
    assert!(
        admin(
            &mut provider,
            CAPABILITY_A,
            AdminOperation::Freeze { barrier: BARRIER_A, handoff: HANDOFF, destination_epoch: 2 }
        )
        .ok
    );
    let bundle = temporary.path().join("capsule");
    assert!(
        admin(
            &mut provider,
            CAPABILITY_A,
            AdminOperation::Export { bundle: bundle.display().to_string() }
        )
        .ok
    );
    drop(provider);
    let state = bundle.join("state.sqlite");
    let mut bytes = fs::read(&state).unwrap();
    bytes[4096] ^= 0x80;
    fs::write(&state, bytes).unwrap();
    let rejected = restore_provider(&RestoreConfig {
        bundle,
        database: temporary.path().join("tampered.sqlite"),
        capability: CAPABILITY_B,
        guest_capability: GUEST_CAPABILITY_B,
    });
    assert!(rejected.is_err());
}

#[test]
fn database_audit_rejects_chunk_foreign_key_and_transition_corruption() {
    fn corrupt_and_reject(root: &Path, name: &str, mutation: impl FnOnce(&Connection)) {
        let case = root.join(name);
        fs::create_dir(&case).unwrap();
        fs::set_permissions(&case, fs::Permissions::from_mode(0o700)).unwrap();
        let input = case.join("input");
        fs::write(&input, vec![1_u8; 70_000]).unwrap();
        let database = case.join("provider.sqlite");
        create_provider(&CreateConfig {
            database: database.clone(),
            session: SESSION,
            capability: CAPABILITY_A,
            guest_capability: GUEST_CAPABILITY_A,
            authority_epoch: 1,
            imports: vec![ImportFile { host_path: input, guest_path: b"file".to_vec() }],
        })
        .unwrap();
        let connection = Connection::open(&database).unwrap();
        mutation(&connection);
        drop(connection);
        assert!(open_provider(database).is_err(), "{name} corruption was accepted");
    }

    let temporary = temporary();
    corrupt_and_reject(temporary.path(), "chunk", |connection| {
        connection
            .execute("UPDATE object_chunks SET chunk_index = 999999 WHERE chunk_index = 0", [])
            .unwrap();
    });
    corrupt_and_reject(temporary.path(), "foreign-key", |connection| {
        connection.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        connection
            .execute(
                "DELETE FROM objects WHERE object_id =
                   (SELECT object_id FROM paths WHERE path = ?1)",
                params![b"file".as_slice()],
            )
            .unwrap();
    });
    corrupt_and_reject(temporary.path(), "transition", |connection| {
        connection.execute("UPDATE meta SET mode = 1", []).unwrap();
    });
    corrupt_and_reject(temporary.path(), "directory-lock", |connection| {
        connection
            .execute(
                "INSERT INTO locks(object_id, owner, level)
                 SELECT object_id, ?1, 1 FROM paths WHERE path = x''",
                params![OWNER_A.0.as_slice()],
            )
            .unwrap();
    });
}

#[test]
fn prepared_epoch_resume_and_fence_transitions_are_closed() {
    let temporary = temporary();
    let (_, mut source) = create(&temporary, &[]);
    hold(&mut source, CAPABILITY_A, BARRIER_A);
    assert!(
        !admin(
            &mut source,
            CAPABILITY_A,
            AdminOperation::Freeze { barrier: BARRIER_A, handoff: HANDOFF, destination_epoch: 3 }
        )
        .ok
    );
    assert!(
        admin(
            &mut source,
            CAPABILITY_A,
            AdminOperation::Freeze { barrier: BARRIER_A, handoff: HANDOFF, destination_epoch: 2 }
        )
        .ok
    );
    let mut guest = Guest::new(OWNER_A, CLIENT_A, GUEST_CAPABILITY_A, 1);
    assert_eq!(guest.call(&mut source, Operation::FdStatGet { fd: 3 }).errno, errno::PERM);
    assert!(
        !admin(
            &mut source,
            CAPABILITY_A,
            AdminOperation::Resume { handoff: [99; 16], authority_epoch: 1 }
        )
        .ok
    );
    assert!(
        admin(
            &mut source,
            CAPABILITY_A,
            AdminOperation::Resume { handoff: HANDOFF, authority_epoch: 1 }
        )
        .ok
    );
    release(&mut source, CAPABILITY_A, BARRIER_A);
    assert!(
        !admin(
            &mut source,
            CAPABILITY_A,
            AdminOperation::Resume { handoff: [99; 16], authority_epoch: 1 },
        )
        .ok
    );
    assert!(
        admin(
            &mut source,
            CAPABILITY_A,
            AdminOperation::Resume { handoff: HANDOFF, authority_epoch: 1 },
        )
        .ok
    );
    assert_eq!(
        admin(&mut source, CAPABILITY_A, AdminOperation::Status).status.unwrap().mode,
        ProviderMode::Active
    );
    hold(&mut source, CAPABILITY_A, BARRIER_B);
    assert!(
        admin(
            &mut source,
            CAPABILITY_A,
            AdminOperation::Freeze { barrier: BARRIER_B, handoff: HANDOFF, destination_epoch: 2 }
        )
        .ok
    );
    let bundle = temporary.path().join("capsule");
    assert!(
        admin(
            &mut source,
            CAPABILITY_A,
            AdminOperation::Export { bundle: bundle.display().to_string() }
        )
        .ok
    );
    assert!(
        admin(
            &mut source,
            CAPABILITY_A,
            AdminOperation::Fence { handoff: HANDOFF, committed_epoch: 2 }
        )
        .ok
    );
    assert_eq!(guest.call(&mut source, Operation::FdStatGet { fd: 3 }).errno, errno::PERM);
    drop(source);

    let destination_database = temporary.path().join("destination.sqlite");
    restore_provider(&RestoreConfig {
        bundle,
        database: destination_database.clone(),
        capability: CAPABILITY_B,
        guest_capability: GUEST_CAPABILITY_B,
    })
    .unwrap();
    let mut destination = open_provider(destination_database).unwrap();
    let mut destination_guest = Guest::new(OWNER_A, CLIENT_B, GUEST_CAPABILITY_B, 2);
    assert_eq!(
        destination_guest.call(&mut destination, Operation::FdStatGet { fd: 3 }).errno,
        errno::AGAIN
    );
    assert!(
        !admin(
            &mut destination,
            CAPABILITY_B,
            AdminOperation::Activate { handoff: HANDOFF, authority_epoch: 3 }
        )
        .ok
    );
    assert!(
        admin(
            &mut destination,
            CAPABILITY_B,
            AdminOperation::Activate { handoff: HANDOFF, authority_epoch: 2 }
        )
        .ok
    );
    assert!(
        !admin(
            &mut destination,
            CAPABILITY_B,
            AdminOperation::Activate { handoff: [99; 16], authority_epoch: 2 },
        )
        .ok
    );
    assert!(
        admin(
            &mut destination,
            CAPABILITY_B,
            AdminOperation::Activate { handoff: HANDOFF, authority_epoch: 2 },
        )
        .ok
    );
    release(&mut destination, CAPABILITY_B, BARRIER_B);
    assert_eq!(
        destination_guest.call(&mut destination, Operation::FdStatGet { fd: 3 }).errno,
        errno::SUCCESS
    );
    let mut stale = Guest::new(OWNER_A, ClientId([20; 16]), GUEST_CAPABILITY_B, 1);
    assert_eq!(stale.call(&mut destination, Operation::FdStatGet { fd: 3 }).errno, errno::PERM);
}
