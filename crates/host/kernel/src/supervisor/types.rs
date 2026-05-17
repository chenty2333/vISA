use alloc::vec::Vec;

use semantic_core::{ResourceHandle, ResourceId};
use service_core::seccomp::SeccompFilterChain;
use vmos_abi::{NodeKind, RestartClass, ServiceRoute};

pub(crate) type TaskId = u32;
// ProcessId / ThreadId from semantic_core (u64) — use for semantic records
// Supervisor runtime uses u32 pid/tid for performance
pub(crate) type Pid = u32;
pub(crate) type Tid = u32;

#[derive(Clone, Debug)]
pub(crate) struct ProcessRuntimeState {
    pub(crate) pid: Pid,
    pub(crate) ppid: Pid,
    pub(crate) pgid: Pid,
    pub(crate) sid: Pid,
    pub(crate) tgid: Tid,
    pub(crate) access: ProcessAccessState,
    pub(crate) dumpable: bool,
    pub(crate) execed: bool,
    pub(crate) exit_signal: Option<u8>,
    pub(crate) state: ProcessRuntimeStateKind,
    pub(crate) exit_code: Option<i32>,
    pub(crate) sigactions: [SigAction; 64],
    pub(crate) rlimits: [Rlimit; 16],
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessAccessState {
    pub(crate) real_uid: u32,
    pub(crate) uid: u32,
    pub(crate) saved_uid: u32,
    pub(crate) fsuid: u32,
    pub(crate) real_gid: u32,
    pub(crate) gid: u32,
    pub(crate) saved_gid: u32,
    pub(crate) fsgid: u32,
    pub(crate) supplementary_groups: Vec<u32>,
    pub(crate) cap_permitted: u64,
    pub(crate) cap_effective: u64,
}

impl ProcessAccessState {
    pub(crate) fn root() -> Self {
        Self {
            real_uid: 0,
            uid: 0,
            saved_uid: 0,
            fsuid: 0,
            real_gid: 0,
            gid: 0,
            saved_gid: 0,
            fsgid: 0,
            supplementary_groups: Vec::new(),
            cap_permitted: LINUX_KNOWN_CAPS,
            cap_effective: LINUX_KNOWN_CAPS,
        }
    }

    pub(crate) fn from_credentials(
        real_uid: u32,
        effective_uid: u32,
        saved_uid: u32,
        fsuid: u32,
        real_gid: u32,
        effective_gid: u32,
        saved_gid: u32,
        fsgid: u32,
        supplementary_groups: Vec<u32>,
        cap_permitted: u64,
        cap_effective: u64,
    ) -> Self {
        Self {
            real_uid,
            uid: effective_uid,
            saved_uid,
            fsuid,
            real_gid,
            gid: effective_gid,
            saved_gid,
            fsgid,
            supplementary_groups,
            cap_permitted,
            cap_effective,
        }
    }

    pub(crate) fn ids(&self) -> AccessIds<'_> {
        AccessIds::with_caps(self.fsuid, self.fsgid, &self.supplementary_groups, self.cap_effective)
    }

    pub(crate) fn credential_ids_differ(&self, other: &Self) -> bool {
        self.real_uid != other.real_uid
            || self.uid != other.uid
            || self.saved_uid != other.saved_uid
            || self.fsuid != other.fsuid
            || self.real_gid != other.real_gid
            || self.gid != other.gid
            || self.saved_gid != other.saved_gid
            || self.fsgid != other.fsgid
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rlimit {
    pub(crate) cur: u64,
    pub(crate) max: u64,
}

impl Default for Rlimit {
    fn default() -> Self {
        Self { cur: u64::MAX, max: u64::MAX }
    }
}

pub(crate) const RLIMIT_NOFILE: usize = 7;
pub(crate) const RLIMIT_AS: usize = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeClockAdjustmentState {
    pub(crate) freq_scaled_ppm: i64,
    pub(crate) maxerror_us: i64,
    pub(crate) esterror_us: i64,
    pub(crate) status: i32,
    pub(crate) constant: i64,
    pub(crate) tick_us: i64,
    pub(crate) tai: i32,
    pub(crate) nano: bool,
}

impl RuntimeClockAdjustmentState {
    pub(crate) const fn default() -> Self {
        Self {
            freq_scaled_ppm: 0,
            maxerror_us: 0,
            esterror_us: 0,
            status: 0,
            constant: 0,
            tick_us: 10_000,
            tai: 0,
            nano: true,
        }
    }
}

pub(crate) const CAP_CHOWN: u64 = 1 << 0;
pub(crate) const CAP_DAC_OVERRIDE: u64 = 1 << 1;
pub(crate) const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
pub(crate) const CAP_FOWNER: u64 = 1 << 3;
pub(crate) const CAP_SETGID: u64 = 1 << 6;
pub(crate) const CAP_SETUID: u64 = 1 << 7;
pub(crate) const CAP_SETPCAP: u64 = 1 << 8;
pub(crate) const CAP_SYS_PTRACE: u64 = 1 << 19;
pub(crate) const CAP_SYS_ADMIN: u64 = 1 << 21;
pub(crate) const CAP_SYS_RESOURCE: u64 = 1 << 24;
pub(crate) const LINUX_KNOWN_CAPS: u64 = CAP_CHOWN
    | CAP_DAC_OVERRIDE
    | CAP_DAC_READ_SEARCH
    | CAP_FOWNER
    | CAP_SETGID
    | CAP_SETUID
    | CAP_SETPCAP
    | CAP_SYS_PTRACE
    | CAP_SYS_ADMIN
    | CAP_SYS_RESOURCE;

pub(crate) const SECBIT_NOROOT: u32 = 1 << 0;
pub(crate) const SECBIT_NOROOT_LOCKED: u32 = 1 << 1;
pub(crate) const SECBIT_NO_SETUID_FIXUP: u32 = 1 << 2;
pub(crate) const SECBIT_NO_SETUID_FIXUP_LOCKED: u32 = 1 << 3;
pub(crate) const SECBIT_KEEP_CAPS: u32 = 1 << 4;
pub(crate) const SECBIT_KEEP_CAPS_LOCKED: u32 = 1 << 5;
pub(crate) const SECBIT_NO_CAP_AMBIENT_RAISE: u32 = 1 << 6;
pub(crate) const SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED: u32 = 1 << 7;
pub(crate) const LINUX_SUPPORTED_SECUREBITS: u32 = SECBIT_NOROOT
    | SECBIT_NOROOT_LOCKED
    | SECBIT_NO_SETUID_FIXUP
    | SECBIT_NO_SETUID_FIXUP_LOCKED
    | SECBIT_KEEP_CAPS
    | SECBIT_KEEP_CAPS_LOCKED
    | SECBIT_NO_CAP_AMBIENT_RAISE
    | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AccessIds<'a> {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) supplementary_groups: &'a [u32],
    pub(crate) cap_effective: u64,
}

impl<'a> AccessIds<'a> {
    pub(crate) const fn new(uid: u32, gid: u32, supplementary_groups: &'a [u32]) -> Self {
        Self { uid, gid, supplementary_groups, cap_effective: 0 }
    }

    pub(crate) const fn with_caps(
        uid: u32,
        gid: u32,
        supplementary_groups: &'a [u32],
        cap_effective: u64,
    ) -> Self {
        Self { uid, gid, supplementary_groups, cap_effective }
    }

    pub(crate) const fn has_capability(self, capability: u64) -> bool {
        self.cap_effective & capability != 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SeccompMode {
    Disabled,
    Strict,
    Filter(SeccompFilterChain),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProcessRuntimeStateKind {
    Running,
    Zombie,
    Dead,
}

#[derive(Clone, Debug)]
pub(crate) struct ThreadRuntimeState {
    pub(crate) tid: Tid,
    pub(crate) task_id: TaskId,
    pub(crate) pid: Pid,
    pub(crate) state: ThreadRuntimeStateKind,
    pub(crate) clear_child_tid: Option<u64>,
    pub(crate) robust_list: Option<RobustListRegistration>,
    pub(crate) sigaltstack: SignalAltStack,
    pub(crate) sigmask: u64,
    pub(crate) sigsuspend_restore_mask: Option<u64>,
    pub(crate) pending_signals: Vec<PendingSignal>,
    pub(crate) seccomp: SeccompMode,
    pub(crate) no_new_privs: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RobustListRegistration {
    pub(crate) head: u64,
    pub(crate) len: u64,
}

pub(crate) const SIGALTSTACK_SS_ONSTACK: u32 = 1;
pub(crate) const SIGALTSTACK_SS_DISABLE: u32 = 2;
pub(crate) const SIGALTSTACK_SS_AUTODISARM: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SignalAltStack {
    pub(crate) sp: u64,
    pub(crate) size: u64,
    pub(crate) flags: u32,
}

impl SignalAltStack {
    pub(crate) const fn disabled() -> Self {
        Self { sp: 0, size: 0, flags: SIGALTSTACK_SS_DISABLE }
    }

    pub(crate) const fn is_disabled(self) -> bool {
        self.flags & SIGALTSTACK_SS_DISABLE != 0
    }

    pub(crate) const fn autodisarm(self) -> bool {
        self.flags & SIGALTSTACK_SS_AUTODISARM != 0
    }

    pub(crate) fn top(self) -> Option<u64> {
        if self.is_disabled() { None } else { self.sp.checked_add(self.size) }
    }

    pub(crate) fn contains(self, rsp: u64) -> bool {
        self.top().is_some_and(|top| rsp >= self.sp && rsp < top)
    }
}

impl Default for SignalAltStack {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ThreadRuntimeStateKind {
    Running,
    Blocked,
    Stopped,
    Dead,
}

// Signal types
pub(crate) const SIG_NUM: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SigAction {
    pub(crate) handler: u64, // 0=SIG_DFL, 1=SIG_IGN, else=handler VA
    pub(crate) flags: u64,   // SA_SIGINFO etc.
    pub(crate) restorer: u64,
    pub(crate) mask: u64,
}

impl Default for SigAction {
    fn default() -> Self {
        Self { handler: 0, flags: 0, restorer: 0, mask: 0 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingSignal {
    pub(crate) signo: u8,
    pub(crate) si_errno: i32,
    pub(crate) si_code: i32,
    pub(crate) si_pid: u32,
    pub(crate) si_uid: u32,
    pub(crate) si_call_addr: u64,
    pub(crate) si_syscall: u32,
    pub(crate) si_arch: u32,
}

impl PendingSignal {
    pub(crate) const fn basic(signo: u8, si_code: i32, si_pid: u32, si_uid: u32) -> Self {
        Self {
            signo,
            si_errno: 0,
            si_code,
            si_pid,
            si_uid,
            si_call_addr: 0,
            si_syscall: 0,
            si_arch: 0,
        }
    }

    pub(crate) const fn seccomp_trap(call_addr: u64, syscall: u32, arch: u32, errno: u16) -> Self {
        Self {
            signo: 31,
            si_errno: errno as i32,
            si_code: 1,
            si_pid: 0,
            si_uid: 0,
            si_call_addr: call_addr,
            si_syscall: syscall,
            si_arch: arch,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UserSignalDelivery {
    pub(crate) signal: PendingSignal,
    pub(crate) action: SigAction,
    pub(crate) old_sigmask: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InjectedFault {
    ProcfsRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitKind {
    Timer,
    Futex,
    Epoll,
    SocketConnect,
    SocketAccept,
    FileLock,
    ChildExit,
    FdReadable,
    FdWritable,
    Signal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WaitToken {
    pub(crate) id: u64,
    pub(crate) owner_task: TaskId,
    pub(crate) kind: WaitKind,
    pub(crate) generation: u64,
}

#[derive(Clone, Debug)]
pub(crate) enum FdResource {
    ServiceNode { route: ServiceRoute, node: NodeKind, path: Vec<u8>, vfs_node_id: Option<u64> },
    EpollInstance { epoll_id: u32 },
    Socket { socket_id: u64, ready_key: u64 },
    PipeEnd { pipe_id: u64, readable: bool, writable: bool },
    SocketPairEnd { pair_id: u64, endpoint: u8 },
    EventFd { eventfd_id: u64 },
}

#[derive(Clone, Debug)]
pub(crate) struct FdEntry {
    pub(crate) resource: FdResource,
    pub(crate) cursor: usize,
    pub(crate) fd_flags: u32,
    pub(crate) status_flags: u32,
    pub(crate) cursor_group: Option<ResourceId>,
}

#[derive(Clone, Debug)]
pub(crate) struct FdTableSnapshot {
    pub(crate) fd_table: Vec<Option<FdEntry>>,
    pub(crate) fd_handles: Vec<Option<ResourceHandle>>,
}

#[derive(Debug)]
pub(crate) struct PipeState {
    pub(crate) id: u64,
    pub(crate) buffer: Vec<u8>,
    pub(crate) capacity: usize,
    pub(crate) read_open: bool,
    pub(crate) write_open: bool,
}

#[derive(Debug)]
pub(crate) struct SocketPairState {
    pub(crate) id: u64,
    pub(crate) a_to_b: Vec<u8>,
    pub(crate) b_to_a: Vec<u8>,
    pub(crate) capacity: usize,
    pub(crate) open_a: bool,
    pub(crate) open_b: bool,
}

#[derive(Debug)]
pub(crate) struct EventFdState {
    pub(crate) id: u64,
    pub(crate) counter: u64,
    pub(crate) semaphore: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LookupInfo {
    pub(crate) route: ServiceRoute,
    pub(crate) node: NodeKind,
}

pub(crate) type WaitRestartClass = RestartClass;

#[derive(Debug)]
pub(crate) enum ServiceCallError {
    Trap(&'static str),
    Errno(i32),
    Invalid(&'static str),
}
