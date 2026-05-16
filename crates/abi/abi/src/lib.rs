#![no_std]

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_POLL: u64 = 7;
pub const SYS_MMAP: u64 = 9;
pub const SYS_RT_SIGACTION: u64 = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const SYS_RT_SIGRETURN: u64 = 15;
pub const SYS_RT_SIGTIMEDWAIT: u64 = 128;
pub const SYS_RT_SIGSUSPEND: u64 = 130;
pub const SYS_SIGALTSTACK: u64 = 131;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_PIPE: u64 = 22;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_BRK: u64 = 12;
pub const SYS_MSYNC: u64 = 26;
pub const SYS_PAUSE: u64 = 34;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_ALARM: u64 = 37;
pub const SYS_GETPID: u64 = 39;
pub const SYS_GETPGID: u64 = 121;
pub const SYS_GETSID: u64 = 124;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_ACCEPT: u64 = 43;
pub const SYS_ACCEPT4: u64 = 288;
pub const SYS_SENDTO: u64 = 44;
pub const SYS_RECVFROM: u64 = 45;
pub const SYS_BIND: u64 = 49;
pub const SYS_LISTEN: u64 = 50;
pub const SYS_GETSOCKNAME: u64 = 51;
pub const SYS_GETPEERNAME: u64 = 52;
pub const SYS_SOCKETPAIR: u64 = 53;
pub const SYS_SETSOCKOPT: u64 = 54;
pub const SYS_GETSOCKOPT: u64 = 55;
pub const SYS_CLONE: u64 = 56;
pub const SYS_FORK: u64 = 57;
pub const SYS_VFORK: u64 = 58;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_KILL: u64 = 62;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_TRUNCATE: u64 = 76;
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_CREAT: u64 = 85;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_CHMOD: u64 = 90;
pub const SYS_CHOWN: u64 = 92;
pub const SYS_LCHOWN: u64 = 94;
pub const SYS_GETTIMEOFDAY: u64 = 96;
pub const SYS_UMASK: u64 = 95;
pub const SYS_TIME: u64 = 201;
pub const SYS_CAPGET: u64 = 125;
pub const SYS_CAPSET: u64 = 126;
pub const SYS_GETUID: u64 = 102;
pub const SYS_GETGID: u64 = 104;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_SETPGID: u64 = 109;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_GETPGRP: u64 = 111;
pub const SYS_SETSID: u64 = 112;
pub const SYS_STATFS: u64 = 137;
pub const SYS_FSTATFS: u64 = 138;
pub const SYS_MOUNT: u64 = 165;
pub const SYS_CHROOT: u64 = 161;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_PRCTL: u64 = 157;
pub const SYS_GETTID: u64 = 186;
pub const SYS_FSETXATTR: u64 = 190;
pub const SYS_FREMOVEXATTR: u64 = 199;
pub const SYS_FUTEX: u64 = 202;
pub const SYS_SCHED_GETAFFINITY: u64 = 204;
pub const SYS_EPOLL_CREATE: u64 = 213;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_CLOCK_GETRES: u64 = 229;
pub const SYS_CLOCK_NANOSLEEP: u64 = 230;
pub const SYS_CLOCK_SETTIME: u64 = 227;
pub const SYS_EPOLL_WAIT: u64 = 232;
pub const SYS_EPOLL_CTL: u64 = 233;
pub const SYS_TGKILL: u64 = 234;
pub const SYS_ADD_KEY: u64 = 248;
pub const SYS_KEYCTL: u64 = 250;
pub const SYS_FALLOCATE: u64 = 285;
pub const SYS_EVENTFD: u64 = 284;
pub const SYS_EVENTFD2: u64 = 290;
pub const SYS_UNAME: u64 = 63;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_EXIT: u64 = 60;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_MKDIRAT: u64 = 258;
pub const SYS_MKNODAT: u64 = 259;
pub const SYS_FCHOWNAT: u64 = 260;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_READLINKAT: u64 = 267;
pub const SYS_FCHMODAT: u64 = 268;
pub const SYS_FACCESSAT: u64 = 269;
pub const SYS_PSELECT6: u64 = 270;
pub const SYS_PPOLL: u64 = 271;
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_GET_ROBUST_LIST: u64 = 274;
pub const SYS_UTIMENSAT: u64 = 280;
pub const SYS_EPOLL_PWAIT: u64 = 281;
pub const SYS_EPOLL_CREATE1: u64 = 291;
pub const SYS_DUP3: u64 = 292;
pub const SYS_PIPE2: u64 = 293;
pub const SYS_PRLIMIT64: u64 = 302;
pub const SYS_CLOCK_ADJTIME: u64 = 305;
pub const SYS_RENAMEAT2: u64 = 316;
pub const SYS_SECCOMP: u64 = 317;
pub const SYS_BPF: u64 = 321;
pub const SYS_CLONE3: u64 = 435;
pub const SYS_GETRANDOM: u64 = 318;
pub const SYS_RSEQ: u64 = 334;
pub const SYS_CLOSE_RANGE: u64 = 436;
pub const SYS_FACCESSAT2: u64 = 439;
pub const SYS_EPOLL_PWAIT2: u64 = 441;

pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;

pub const WAIT_TOKEN_SLEEP: u32 = 1;
pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_REQUEUE: u32 = 3;
pub const FUTEX_CMP_REQUEUE: u32 = 4;
pub const FUTEX_LOCK_PI: u32 = 6;
pub const FUTEX_UNLOCK_PI: u32 = 7;
pub const FUTEX_TRYLOCK_PI: u32 = 8;
pub const FUTEX_WAIT_BITSET: u32 = 9;
pub const FUTEX_WAKE_BITSET: u32 = 10;
pub const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
pub const FUTEX_CMP_REQUEUE_PI: u32 = 12;
pub const FUTEX_LOCK_PI2: u32 = 13;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
pub const FUTEX_CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;

pub const AF_INET: u32 = 2;
pub const AF_UNIX: u32 = 1;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;

pub const ERR_EPERM: i32 = 1;
pub const ERR_ENOENT: i32 = 2;
pub const ERR_ESRCH: i32 = 3;
pub const ERR_EINTR: i32 = 4;
pub const ERR_EIO: i32 = 5;
pub const ERR_E2BIG: i32 = 7;
pub const ERR_EBADF: i32 = 9;
pub const ERR_ECHILD: i32 = 10;
pub const ERR_EAGAIN: i32 = 11;
pub const ERR_ENOMEM: i32 = 12;
pub const ERR_EACCES: i32 = 13;
pub const ERR_EFAULT: i32 = 14;
pub const ERR_EEXIST: i32 = 17;
pub const ERR_ENOTDIR: i32 = 20;
pub const ERR_EISDIR: i32 = 21;
pub const ERR_EINVAL: i32 = 22;
pub const ERR_EMFILE: i32 = 24;
pub const ERR_EDEADLK: i32 = 35;
pub const ERR_ENOSYS: i32 = 38;
pub const ERR_ENAMETOOLONG: i32 = 36;
pub const ERR_ENOTEMPTY: i32 = 39;
pub const ERR_ELOOP: i32 = 40;
pub const ERR_ENOTSOCK: i32 = 88;
pub const ERR_EPROTONOSUPPORT: i32 = 93;
pub const ERR_EOPNOTSUPP: i32 = 95;
pub const ERR_EAFNOSUPPORT: i32 = 97;
pub const ERR_EADDRINUSE: i32 = 98;
pub const ERR_EISCONN: i32 = 106;
pub const ERR_ENOTCONN: i32 = 107;
pub const ERR_ETIMEDOUT: i32 = 110;
pub const ERR_ECONNREFUSED: i32 = 111;
pub const ERR_EALREADY: i32 = 114;
pub const ERR_EINPROGRESS: i32 = 115;

const TAG_SHIFT: u64 = 60;
const AUX_SHIFT: u64 = 32;
const AUX_MASK: u64 = 0x0FFF_FFFF;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallContext {
    pub nr: u64,
    pub args: [u64; 6],
}

impl SyscallContext {
    pub const fn new(nr: u64, args: [u64; 6]) -> Self {
        Self { nr, args }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepTag {
    Ready = 0,
    Pending = 1,
    Plan = 2,
    ConsoleWrite = 3,
    Exit = 4,
    Error = 5,
}

impl StepTag {
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Ready,
            1 => Self::Pending,
            2 => Self::Plan,
            3 => Self::ConsoleWrite,
            4 => Self::Exit,
            _ => Self::Error,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanKind {
    Write = 1,
    OpenAt = 2,
    Read = 3,
    Close = 4,
    GetDents64 = 5,
    ReadLinkAt = 6,
    GetCwd = 7,
    Uname = 8,
    Sleep = 9,
    FutexWait = 10,
    FutexWake = 11,
    EpollCreate1 = 12,
    EpollCtl = 13,
    EpollWait = 14,
    EpollReady = 15,
    Socket = 16,
    Bind = 17,
    Listen = 18,
    Accept = 19,
    Connect = 20,
    SendTo = 21,
    RecvFrom = 22,
    SetSockOpt = 23,
    GetSockOpt = 24,
    Fcntl = 25,
    Mmap = 26,
    Munmap = 27,
    Poll = 28,
    // Process/Thread
    Clone = 29,
    Fork = 30,
    Vfork = 31,
    Execve = 32,
    Wait4 = 33,
    // Signals
    RtSigaction = 34,
    RtSigprocmask = 35,
    Tgkill = 36,
    RtSigreturn = 37,
    Kill = 38,
    Pause = 39,
    // Exit
    Exit = 40,
    // Advanced FS
    RenameAt2 = 41,
    Fsetxattr = 42,
    Fgetxattr = 43,
    Flock = 44,
    FcntlSetlk = 45,
    // Futex
    FutexWaitBitset = 46,
    FutexWakeBitset = 47,
    FutexRequeue = 48,
    FutexCmpRequeue = 49,
    FutexLockPi = 50,
    FutexUnlockPi = 51,
    SetRobustList = 52,
    // rlimit/clock/seccomp
    Getrlimit = 53,
    Setrlimit = 54,
    Prlimit64 = 55,
    TimerfdCreate = 56,
    TimerfdSettime = 57,
    TimerfdGettime = 58,
    ClockAdjtime = 59,
    Seccomp = 60,
    Bpf = 61,
    FutexWaitRequeuePi = 62,
    FcntlGetlk = 63,
}

impl PlanKind {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Write),
            2 => Some(Self::OpenAt),
            3 => Some(Self::Read),
            4 => Some(Self::Close),
            5 => Some(Self::GetDents64),
            6 => Some(Self::ReadLinkAt),
            7 => Some(Self::GetCwd),
            8 => Some(Self::Uname),
            9 => Some(Self::Sleep),
            10 => Some(Self::FutexWait),
            11 => Some(Self::FutexWake),
            12 => Some(Self::EpollCreate1),
            13 => Some(Self::EpollCtl),
            14 => Some(Self::EpollWait),
            15 => Some(Self::EpollReady),
            16 => Some(Self::Socket),
            17 => Some(Self::Bind),
            18 => Some(Self::Listen),
            19 => Some(Self::Accept),
            20 => Some(Self::Connect),
            21 => Some(Self::SendTo),
            22 => Some(Self::RecvFrom),
            23 => Some(Self::SetSockOpt),
            24 => Some(Self::GetSockOpt),
            25 => Some(Self::Fcntl),
            26 => Some(Self::Mmap),
            27 => Some(Self::Munmap),
            28 => Some(Self::Poll),
            29 => Some(Self::Clone),
            30 => Some(Self::Fork),
            31 => Some(Self::Vfork),
            32 => Some(Self::Execve),
            33 => Some(Self::Wait4),
            34 => Some(Self::RtSigaction),
            35 => Some(Self::RtSigprocmask),
            36 => Some(Self::Tgkill),
            37 => Some(Self::RtSigreturn),
            38 => Some(Self::Kill),
            39 => Some(Self::Pause),
            40 => Some(Self::Exit),
            41 => Some(Self::RenameAt2),
            42 => Some(Self::Fsetxattr),
            43 => Some(Self::Fgetxattr),
            44 => Some(Self::Flock),
            45 => Some(Self::FcntlSetlk),
            46 => Some(Self::FutexWaitBitset),
            47 => Some(Self::FutexWakeBitset),
            48 => Some(Self::FutexRequeue),
            49 => Some(Self::FutexCmpRequeue),
            50 => Some(Self::FutexLockPi),
            51 => Some(Self::FutexUnlockPi),
            52 => Some(Self::SetRobustList),
            53 => Some(Self::Getrlimit),
            54 => Some(Self::Setrlimit),
            55 => Some(Self::Prlimit64),
            56 => Some(Self::TimerfdCreate),
            57 => Some(Self::TimerfdSettime),
            58 => Some(Self::TimerfdGettime),
            59 => Some(Self::ClockAdjtime),
            60 => Some(Self::Seccomp),
            61 => Some(Self::Bpf),
            62 => Some(Self::FutexWaitRequeuePi),
            63 => Some(Self::FcntlGetlk),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartClass {
    DriverRestart = 1,
}

impl RestartClass {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::DriverRestart),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceRoute {
    Vfs = 1,
    Procfs = 2,
    Devfs = 3,
}

impl ServiceRoute {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Vfs),
            2 => Some(Self::Procfs),
            3 => Some(Self::Devfs),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    File = 1,
    Directory = 2,
    Symlink = 3,
    CharDevice = 4,
}

impl NodeKind {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::File),
            2 => Some(Self::Directory),
            3 => Some(Self::Symlink),
            4 => Some(Self::CharDevice),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedStep {
    pub tag: StepTag,
    pub aux: u32,
    pub value: i32,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedStep(u64);

impl PackedStep {
    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn ready(value: i32) -> Self {
        Self::pack(StepTag::Ready, 0, value)
    }

    pub const fn pending(token: u32, delay_ms: u32) -> Self {
        Self::pack(StepTag::Pending, token, delay_ms as i32)
    }

    pub const fn plan(kind: PlanKind) -> Self {
        Self::pack(StepTag::Plan, kind as u32, 0)
    }

    pub const fn console_write(ptr: u32, len: u32) -> Self {
        Self::pack(StepTag::ConsoleWrite, ptr, len as i32)
    }

    pub const fn exit(code: i32) -> Self {
        Self::pack(StepTag::Exit, 0, code)
    }

    pub const fn error(errno: i32) -> Self {
        Self::pack(StepTag::Error, 0, errno)
    }

    pub const fn decode(raw: u64) -> DecodedStep {
        DecodedStep {
            tag: StepTag::from_raw((raw >> TAG_SHIFT) as u8),
            aux: ((raw >> AUX_SHIFT) & AUX_MASK) as u32,
            value: raw as u32 as i32,
        }
    }

    const fn pack(tag: StepTag, aux: u32, value: i32) -> Self {
        Self(
            ((tag as u64) << TAG_SHIFT)
                | (((aux as u64) & AUX_MASK) << AUX_SHIFT)
                | value as u32 as u64,
        )
    }
}

pub const fn is_stdio_fd(fd: u64) -> bool {
    fd == FD_STDOUT as u64 || fd == FD_STDERR as u64
}

pub const fn can_pack_console_ptr(ptr: u32) -> bool {
    (ptr as u64) <= AUX_MASK
}
