#![no_std]

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_UNAME: u64 = 63;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_EXIT: u64 = 60;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_READLINKAT: u64 = 267;

pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;

pub const WAIT_TOKEN_SLEEP: u32 = 1;

pub const ERR_ENOENT: i32 = 2;
pub const ERR_EIO: i32 = 5;
pub const ERR_EBADF: i32 = 9;
pub const ERR_ENOTDIR: i32 = 20;
pub const ERR_EISDIR: i32 = 21;
pub const ERR_EINVAL: i32 = 22;
pub const ERR_ENOSYS: i32 = 38;

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
