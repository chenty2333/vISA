#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion { major: 2, minor: 0 };
pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const ROOT_PREOPEN_FD: u32 = 3;
pub const NAMESPACE_SNAPSHOT_VERSION: u16 = 2;

/// Preview1 `__wasi_rights_t` bits. Keeping the canonical bit assignments in
/// the wire crate lets every runtime adapter and the resource provider make
/// the same capability decision without depending on a particular WASI SDK.
pub mod rights {
    pub const FD_DATASYNC: u64 = 1 << 0;
    pub const FD_READ: u64 = 1 << 1;
    pub const FD_SEEK: u64 = 1 << 2;
    pub const FD_FDSTAT_SET_FLAGS: u64 = 1 << 3;
    pub const FD_SYNC: u64 = 1 << 4;
    pub const FD_TELL: u64 = 1 << 5;
    pub const FD_WRITE: u64 = 1 << 6;
    pub const FD_ADVISE: u64 = 1 << 7;
    pub const FD_ALLOCATE: u64 = 1 << 8;
    pub const PATH_CREATE_DIRECTORY: u64 = 1 << 9;
    pub const PATH_CREATE_FILE: u64 = 1 << 10;
    pub const PATH_LINK_SOURCE: u64 = 1 << 11;
    pub const PATH_LINK_TARGET: u64 = 1 << 12;
    pub const PATH_OPEN: u64 = 1 << 13;
    pub const FD_READDIR: u64 = 1 << 14;
    pub const PATH_READLINK: u64 = 1 << 15;
    pub const PATH_RENAME_SOURCE: u64 = 1 << 16;
    pub const PATH_RENAME_TARGET: u64 = 1 << 17;
    pub const PATH_FILESTAT_GET: u64 = 1 << 18;
    pub const PATH_FILESTAT_SET_SIZE: u64 = 1 << 19;
    pub const PATH_FILESTAT_SET_TIMES: u64 = 1 << 20;
    pub const FD_FILESTAT_GET: u64 = 1 << 21;
    pub const FD_FILESTAT_SET_SIZE: u64 = 1 << 22;
    pub const FD_FILESTAT_SET_TIMES: u64 = 1 << 23;
    pub const PATH_SYMLINK: u64 = 1 << 24;
    pub const PATH_REMOVE_DIRECTORY: u64 = 1 << 25;
    pub const PATH_UNLINK_FILE: u64 = 1 << 26;
    pub const POLL_FD_READWRITE: u64 = 1 << 27;
    pub const SOCK_SHUTDOWN: u64 = 1 << 28;
    pub const SOCK_ACCEPT: u64 = 1 << 29;

    /// vISA filesystem-v2 extension right for Unix ownership and mode metadata.
    pub const VFS_METADATA: u64 = 1 << 62;
    /// vISA filesystem-v2 extension right. Preview1 has no advisory lock
    /// hostcall, so the SQLite VFS extension is separately attenuable.
    pub const VFS_LOCK: u64 = 1 << 63;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const fn is_supported(self) -> bool {
        self.major == PROTOCOL_VERSION.major && self.minor == PROTOCOL_VERSION.minor
    }
}

macro_rules! identity_type {
    ($name:ident, $bytes:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub [u8; $bytes]);

        impl $name {
            pub const ZERO: Self = Self([0; $bytes]);

            pub const fn is_zero(self) -> bool {
                let mut index = 0;
                while index < $bytes {
                    if self.0[index] != 0 {
                        return false;
                    }
                    index += 1;
                }
                true
            }
        }
    };
}

identity_type!(SessionId, 16);
identity_type!(OwnerId, 16);
identity_type!(ClientId, 16);
identity_type!(EffectId, 16);
identity_type!(BarrierToken, 16);
identity_type!(ObjectId, 16);
identity_type!(GuestCapability, 32);
identity_type!(AdminCapability, 32);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRequest {
    pub version: ProtocolVersion,
    pub session: SessionId,
    /// Stable across a source/destination handoff. Locks bind to this identity.
    pub owner: OwnerId,
    /// Fresh for every native runtime process. It disambiguates request counters.
    pub client: ClientId,
    /// Admission secret issued to the exact source or destination process.
    /// This is independent from the administrative transition capability.
    pub capability: GuestCapability,
    pub sequence: u64,
    /// Caller-carried identity of one logical effect. Reusing the same value
    /// preserves provider deduplication across transport retries, client
    /// replacement, and an authority-epoch handoff. A client-scoped generator
    /// must instead drain every completed delivery before replacing the client.
    pub effect: EffectId,
    pub authority_epoch: u64,
    pub operation: Operation,
}

impl GuestRequest {
    pub fn is_well_formed(&self) -> bool {
        self.version.is_supported()
            && !self.session.is_zero()
            && !self.owner.is_zero()
            && !self.client.is_zero()
            && !self.capability.is_zero()
            && self.sequence != 0
            && !self.effect.is_zero()
            && self.authority_epoch != 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestResponse {
    pub version: ProtocolVersion,
    pub sequence: u64,
    pub effect: EffectId,
    /// True only when the provider durably recorded this delivery and the
    /// runtime must acknowledge it after materializing the result in guest
    /// linear memory.
    pub completion_required: bool,
    /// Numeric Preview1 errno. Zero is success.
    pub errno: u16,
    pub result: OperationResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestCompletion {
    pub version: ProtocolVersion,
    pub session: SessionId,
    pub owner: OwnerId,
    pub client: ClientId,
    pub capability: GuestCapability,
    pub sequence: u64,
    pub effect: EffectId,
    pub authority_epoch: u64,
}

impl GuestCompletion {
    pub fn is_well_formed(&self) -> bool {
        self.version.is_supported()
            && !self.session.is_zero()
            && !self.owner.is_zero()
            && !self.client.is_zero()
            && !self.capability.is_zero()
            && self.sequence != 0
            && !self.effect.is_zero()
            && self.authority_epoch != 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestCompletionResponse {
    pub version: ProtocolVersion,
    pub sequence: u64,
    pub effect: EffectId,
    pub errno: u16,
    pub directive: BarrierDirective,
    pub barrier: Option<BarrierToken>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BarrierPollRequest {
    pub version: ProtocolVersion,
    pub session: SessionId,
    pub owner: OwnerId,
    pub client: ClientId,
    pub capability: GuestCapability,
    pub authority_epoch: u64,
    pub token: BarrierToken,
    pub sequence: u64,
    pub effect: EffectId,
}

impl BarrierPollRequest {
    pub fn is_well_formed(&self) -> bool {
        self.version.is_supported()
            && !self.session.is_zero()
            && !self.owner.is_zero()
            && !self.client.is_zero()
            && !self.capability.is_zero()
            && self.authority_epoch != 0
            && !self.token.is_zero()
            && self.sequence != 0
            && !self.effect.is_zero()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BarrierPollResponse {
    pub version: ProtocolVersion,
    pub token: BarrierToken,
    pub errno: u16,
    pub directive: BarrierDirective,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRequest {
    pub version: ProtocolVersion,
    pub capability: AdminCapability,
    pub operation: AdminOperation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminResponse {
    pub version: ProtocolVersion,
    pub ok: bool,
    pub message: String,
    pub status: Option<ProviderStatus>,
    pub snapshot: Option<NamespaceSnapshotReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireRequest {
    Guest(GuestRequest),
    Completion(GuestCompletion),
    BarrierPoll(BarrierPollRequest),
    Admin(AdminRequest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireResponse {
    Guest(GuestResponse),
    Completion(GuestCompletionResponse),
    BarrierPoll(BarrierPollResponse),
    Admin(AdminResponse),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    FdAdvise {
        fd: u32,
        offset: u64,
        length: u64,
        advice: u8,
    },
    FdAllocate {
        fd: u32,
        offset: u64,
        length: u64,
    },
    FdClose {
        fd: u32,
    },
    FdDataSync {
        fd: u32,
    },
    FdStatGet {
        fd: u32,
    },
    FdStatSetFlags {
        fd: u32,
        flags: u16,
    },
    FdStatSetRights {
        fd: u32,
        rights_base: u64,
        rights_inheriting: u64,
    },
    FdFileStatGet {
        fd: u32,
    },
    FdFileStatSetSize {
        fd: u32,
        size: u64,
    },
    FdFileStatSetTimes {
        fd: u32,
        atim: u64,
        mtim: u64,
        fst_flags: u16,
    },
    FdPread {
        fd: u32,
        length: u32,
        offset: u64,
    },
    FdPwrite {
        fd: u32,
        bytes: Vec<u8>,
        offset: u64,
    },
    FdPrestatGet {
        fd: u32,
    },
    FdPrestatDirName {
        fd: u32,
    },
    FdRead {
        fd: u32,
        length: u32,
    },
    FdReadDir {
        fd: u32,
        cookie: u64,
        buffer_len: u32,
    },
    FdRenumber {
        from: u32,
        to: u32,
    },
    FdSeek {
        fd: u32,
        delta: i64,
        whence: SeekWhence,
    },
    FdSync {
        fd: u32,
    },
    FdTell {
        fd: u32,
    },
    FdWrite {
        fd: u32,
        bytes: Vec<u8>,
    },
    PathCreateDirectory {
        dir_fd: u32,
        path: Vec<u8>,
    },
    PathFileStatGet {
        dir_fd: u32,
        lookup_flags: u32,
        path: Vec<u8>,
    },
    PathFileStatSetTimes {
        dir_fd: u32,
        lookup_flags: u32,
        path: Vec<u8>,
        atim: u64,
        mtim: u64,
        fst_flags: u16,
    },
    PathLink {
        old_dir_fd: u32,
        old_lookup_flags: u32,
        old_path: Vec<u8>,
        new_dir_fd: u32,
        new_path: Vec<u8>,
    },
    PathOpen {
        dir_fd: u32,
        lookup_flags: u32,
        path: Vec<u8>,
        open_flags: u16,
        rights_base: u64,
        rights_inheriting: u64,
        fd_flags: u16,
    },
    PathReadLink {
        dir_fd: u32,
        path: Vec<u8>,
        buffer_len: u32,
    },
    PathRemoveDirectory {
        dir_fd: u32,
        path: Vec<u8>,
    },
    PathRename {
        old_dir_fd: u32,
        old_path: Vec<u8>,
        new_dir_fd: u32,
        new_path: Vec<u8>,
    },
    PathSymlink {
        old_path: Vec<u8>,
        dir_fd: u32,
        new_path: Vec<u8>,
    },
    PathUnlinkFile {
        dir_fd: u32,
        path: Vec<u8>,
    },
    /// Collision-safe guest ABI extension used by stock applications whose
    /// libc imports Unix metadata calls not present in Preview1.
    PathChmod {
        dir_fd: u32,
        path: Vec<u8>,
        mode: u32,
    },
    /// `u32::MAX` for either identity means "leave that field unchanged",
    /// matching the Unix `chown(2)` convention.
    PathChown {
        dir_fd: u32,
        path: Vec<u8>,
        uid: u32,
        gid: u32,
    },
    /// vISA lock extension used by a SQLite VFS. Preview1 itself has no lock call.
    VfsLock {
        fd: u32,
        level: LockLevel,
    },
    VfsUnlock {
        fd: u32,
        level: LockLevel,
    },
    VfsCheckReserved {
        fd: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeekWhence {
    Set,
    Current,
    End,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockLevel {
    None,
    Shared,
    Reserved,
    Pending,
    Exclusive,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationResult {
    None,
    Bytes(Vec<u8>),
    Count(u32),
    Offset(u64),
    FileDescriptor(u32),
    FdStat(FdStat),
    FileStat(FileStat),
    Prestat { name: Vec<u8> },
    Directory(Vec<DirectoryEntry>),
    Reserved(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FdStat {
    pub file_type: u8,
    pub flags: u16,
    pub rights_base: u64,
    pub rights_inheriting: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileStat {
    pub device: u64,
    pub inode: u64,
    pub file_type: u8,
    pub link_count: u64,
    pub size: u64,
    pub accessed_ns: u64,
    pub modified_ns: u64,
    pub changed_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    pub next_cookie: u64,
    pub inode: u64,
    pub file_type: u8,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminOperation {
    Status,
    BarrierArm { token: BarrierToken, predicate: HostcallPredicate },
    BarrierRelease { token: BarrierToken, action: BarrierReleaseAction },
    Freeze { barrier: BarrierToken, handoff: [u8; 16], destination_epoch: u64 },
    Export { bundle: String },
    Resume { handoff: [u8; 16], authority_epoch: u64 },
    Fence { handoff: [u8; 16], committed_epoch: u64 },
    Activate { handoff: [u8; 16], authority_epoch: u64 },
    Materialize { guest_path: Vec<u8>, host_path: String },
    SnapshotNamespace { output: String },
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BarrierPhase {
    Open,
    Armed,
    Triggered,
    Held,
    CheckpointReleased,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BarrierReleaseAction {
    Continue,
    Checkpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BarrierDirective {
    Continue,
    Wait,
    Checkpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostcallKind {
    Any,
    FdClose,
    FdDataSync,
    FdPread,
    FdPwrite,
    FdRead,
    FdSync,
    FdWrite,
    PathCreateDirectory,
    PathOpen,
    PathRemoveDirectory,
    PathRename,
    PathUnlinkFile,
    VfsLock,
    VfsUnlock,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceSelector {
    Any,
    Fd(u32),
    ExactPath(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomePredicate {
    Any,
    Success,
    Errno(u16),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostcallPredicate {
    pub kind: HostcallKind,
    pub resource: ResourceSelector,
    pub outcome: OutcomePredicate,
    /// One selects the next matching completed response.
    pub occurrence: u64,
}

impl HostcallPredicate {
    pub const fn is_well_formed(&self) -> bool {
        self.occurrence != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Active,
    Frozen,
    Prepared,
    Fenced,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStatus {
    pub session: SessionId,
    pub mode: ProviderMode,
    pub authority_epoch: u64,
    pub barrier: BarrierPhase,
    pub barrier_remaining: Option<u64>,
    pub barrier_effect: Option<EffectId>,
    pub open_descriptors: u64,
    pub objects: u64,
    pub paths: u64,
    pub locks: u64,
    pub effects: u64,
    pub completed_requests: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceSnapshot {
    pub version: u16,
    pub session: SessionId,
    pub authority_epoch: u64,
    pub mode: ProviderMode,
    pub barrier: BarrierPhase,
    /// Digest of the durable effect ledger at the snapshot transaction.
    pub effect_frontier: [u8; 32],
    pub effects: u64,
    pub objects: Vec<NamespaceObject>,
    pub paths: Vec<NamespacePath>,
    pub descriptors: Vec<NamespaceDescriptor>,
    pub locks: Vec<NamespaceLock>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceObject {
    pub object: ObjectId,
    pub kind: u8,
    pub size: u64,
    pub symlink_target: Option<Vec<u8>>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub accessed_ns: u64,
    pub modified_ns: u64,
    pub changed_ns: u64,
    /// Complete bytes for regular files. Directories and symlinks carry none.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespacePath {
    pub path: Vec<u8>,
    pub object: ObjectId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceDescriptor {
    pub fd: u32,
    pub object: ObjectId,
    pub directory_path: Vec<u8>,
    pub offset: u64,
    pub flags: u16,
    pub rights_base: u64,
    pub rights_inheriting: u64,
    pub preopen: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceLock {
    pub object: ObjectId,
    pub owner: OwnerId,
    pub level: LockLevel,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceSnapshotReceipt {
    pub version: u16,
    pub sha256: [u8; 32],
    pub effect_frontier: [u8; 32],
    pub effects: u64,
    pub encoded_bytes: u64,
    pub objects: u64,
    pub paths: u64,
    pub descriptors: u64,
    pub locks: u64,
    pub unlinked_objects: u64,
}

pub fn encode_request(request: &WireRequest) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_allocvec(request)
}

pub fn decode_request(bytes: &[u8]) -> Result<WireRequest, postcard::Error> {
    postcard::from_bytes(bytes)
}

pub fn encode_response(response: &WireResponse) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_allocvec(response)
}

pub fn decode_response(bytes: &[u8]) -> Result<WireResponse, postcard::Error> {
    postcard::from_bytes(bytes)
}

pub fn encode_namespace_snapshot(snapshot: &NamespaceSnapshot) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_allocvec(snapshot)
}

pub fn decode_namespace_snapshot(bytes: &[u8]) -> Result<NamespaceSnapshot, postcard::Error> {
    postcard::from_bytes(bytes)
}

pub mod errno {
    pub const SUCCESS: u16 = 0;
    pub const ACCES: u16 = 2;
    pub const AGAIN: u16 = 6;
    pub const BADF: u16 = 8;
    pub const BUSY: u16 = 10;
    pub const EXIST: u16 = 20;
    pub const FBIG: u16 = 22;
    pub const INVAL: u16 = 28;
    pub const IO: u16 = 29;
    pub const ISDIR: u16 = 31;
    pub const LOOP: u16 = 32;
    pub const MFILE: u16 = 33;
    pub const NAMETOOLONG: u16 = 37;
    pub const NOENT: u16 = 44;
    pub const NOLCK: u16 = 46;
    pub const NOSPC: u16 = 51;
    pub const NOSYS: u16 = 52;
    pub const NOTDIR: u16 = 54;
    pub const NOTEMPTY: u16 = 55;
    pub const NOTSUP: u16 = 58;
    pub const OVERFLOW: u16 = 61;
    pub const PERM: u16 = 63;
    pub const ROFS: u16 = 69;
    pub const SPIPE: u16 = 70;
    pub const XDEV: u16 = 75;
    pub const NOTCAPABLE: u16 = 76;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> WireRequest {
        WireRequest::Guest(GuestRequest {
            version: PROTOCOL_VERSION,
            session: SessionId([1; 16]),
            owner: OwnerId([2; 16]),
            client: ClientId([3; 16]),
            capability: GuestCapability([4; 32]),
            sequence: 7,
            effect: EffectId([5; 16]),
            authority_epoch: 9,
            operation: Operation::FdWrite { fd: 4, bytes: b"payload".to_vec() },
        })
    }

    #[test]
    fn wire_round_trip_is_exact() {
        let request = request();
        let bytes = encode_request(&request).unwrap();
        assert!(bytes.len() < MAX_FRAME_BYTES);
        assert_eq!(decode_request(&bytes).unwrap(), request);
    }

    #[test]
    fn zero_or_unversioned_guest_identity_is_rejected() {
        let WireRequest::Guest(mut request) = request() else { unreachable!() };
        assert!(request.is_well_formed());
        request.client = ClientId::ZERO;
        assert!(!request.is_well_formed());
        request.client = ClientId([3; 16]);
        request.capability = GuestCapability::ZERO;
        assert!(!request.is_well_formed());
        request.capability = GuestCapability([4; 32]);
        request.effect = EffectId::ZERO;
        assert!(!request.is_well_formed());
        request.effect = EffectId([5; 16]);
        request.version.major += 1;
        assert!(!request.is_well_formed());
        request.version = PROTOCOL_VERSION;
        request.version.minor = request.version.minor.saturating_add(1);
        assert!(!request.is_well_formed());
    }
}
