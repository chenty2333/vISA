#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo};

use vmos_abi::{SYS_BRK, SYS_EXIT, SYS_SETRLIMIT, SYS_WRITE};

const RLIMIT_AS: u64 = 9;
const PAGE_SIZE: u64 = 4096;

static START_LABEL: &[u8] = b"brk_rlimit_as: probing RLIMIT_AS heap growth denial\n";
static OK_LABEL: &[u8] = b"brk_rlimit_as: brk growth stayed at current break under RLIMIT_AS\n";
static ERROR_LABEL: &[u8] = b"brk_rlimit_as: failed\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => {
            let _ = write_all(ERROR_LABEL);
            code
        }
    };
    exit(code)
}

fn run() -> Result<(), i32> {
    write_all(START_LABEL)?;
    let current = sys_brk(0)?;
    let limit = [0u64, 0u64];
    sys_setrlimit(RLIMIT_AS, &limit)?;

    let requested = current.checked_add(PAGE_SIZE).ok_or(20)?;
    let denied = sys_brk(requested)?;
    if denied != current {
        return Err(21);
    }

    write_all(OK_LABEL)
}

fn sys_brk(addr: u64) -> Result<u64, i32> {
    let rc = syscall1(SYS_BRK, addr);
    if rc < 0 { Err((-rc) as i32) } else { Ok(rc as u64) }
}

fn sys_setrlimit(resource: u64, limit: &[u64; 2]) -> Result<(), i32> {
    let rc = syscall2(SYS_SETRLIMIT, resource, limit.as_ptr() as u64);
    if rc < 0 { Err((-rc) as i32) } else { Ok(()) }
}

fn write_all(mut bytes: &[u8]) -> Result<(), i32> {
    while !bytes.is_empty() {
        let rc = syscall3(SYS_WRITE, 1, bytes.as_ptr() as u64, bytes.len() as u64);
        if rc < 0 {
            return Err((-rc) as i32);
        }
        let written = rc as usize;
        if written == 0 || written > bytes.len() {
            return Err(22);
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

fn exit(code: i32) -> ! {
    let _ = syscall1(SYS_EXIT, code as u64);
    loop {
        core::hint::spin_loop();
    }
}

fn syscall1(nr: u64, a0: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            in("rdi") a0,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

fn syscall2(nr: u64, a0: u64, a1: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            in("rdi") a0,
            in("rsi") a1,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    exit(1)
}
