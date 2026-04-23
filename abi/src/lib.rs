#![no_std]

pub const SYS_WRITE: u64 = 1;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_EXIT: u64 = 60;
pub const SYS_EXIT_GROUP: u64 = 231;

pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;

pub const MSG_WASM_APP: u32 = 1;
pub const MSG_LINUX_WRITE: u32 = 2;
pub const MSG_FAULT_RECOVERY: u32 = 3;
pub const MSG_SLEEP_RESUMED: u32 = 4;

pub const WAIT_TOKEN_SLEEP: u32 = 1;

pub const ERR_EINVAL: i32 = 22;
pub const ERR_ENOSYS: i32 = 38;

const TAG_SHIFT: u64 = 56;
const AUX_SHIFT: u64 = 32;
const AUX_MASK: u64 = 0x00FF_FFFF;

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
    ConsoleWrite = 2,
    Exit = 3,
    Error = 4,
}

impl StepTag {
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Ready,
            1 => Self::Pending,
            2 => Self::ConsoleWrite,
            3 => Self::Exit,
            _ => Self::Error,
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

    pub const fn console_write(fd: u32, message_id: u32) -> Self {
        Self::pack(StepTag::ConsoleWrite, message_id, fd as i32)
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

pub const fn is_known_message(message_id: u32) -> bool {
    matches!(
        message_id,
        MSG_WASM_APP | MSG_LINUX_WRITE | MSG_FAULT_RECOVERY | MSG_SLEEP_RESUMED
    )
}
