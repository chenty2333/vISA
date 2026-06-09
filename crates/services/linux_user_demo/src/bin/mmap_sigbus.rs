#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo};

use visa_abi::{SYS_EXIT, SYS_MMAP, SYS_OPENAT, SYS_WRITE};

const AT_FDCWD: i32 = -100;
const O_RDONLY: u32 = 0;
const PROT_READ: u64 = 0x1;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FAILED: i64 = -1;

static FILE_PATH: &[u8] = b"/sandbox/hello.txt\0";
static START_LABEL: &[u8] = b"mmap_sigbus: probing short private file mapping\n";
static UNEXPECTED_LABEL: &[u8] = b"mmap_sigbus: EOF page read unexpectedly succeeded\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let _ = write_all(START_LABEL);
    let fd = match open_readonly(FILE_PATH) {
        Ok(fd) => fd,
        Err(code) => exit(code),
    };
    let mapping = match sys_mmap(8192, PROT_READ, MAP_PRIVATE, fd, 0) {
        Ok(mapping) => mapping,
        Err(code) => exit(code),
    };

    unsafe {
        let base = mapping as *const u8;
        let _ = core::ptr::read_volatile(base);
        let _ = core::ptr::read_volatile(base.add(4096));
    }

    let _ = write_all(UNEXPECTED_LABEL);
    exit(42)
}

fn open_readonly(path: &[u8]) -> Result<i32, i32> {
    let rc = syscall4(SYS_OPENAT, AT_FDCWD as u64, path.as_ptr() as u64, O_RDONLY as u64, 0);
    if rc < 0 { Err(rc as i32) } else { Ok(rc as i32) }
}

fn sys_mmap(len: u64, prot: u64, flags: u64, fd: i32, offset: u64) -> Result<usize, i32> {
    let rc = syscall6(SYS_MMAP, 0, len, prot, flags, fd as u64, offset);
    if rc < 0 || rc == MAP_FAILED { Err(rc as i32) } else { Ok(rc as usize) }
}

fn write_all(bytes: &[u8]) -> Result<(), i32> {
    let rc = syscall3(SYS_WRITE, 1, bytes.as_ptr() as u64, bytes.len() as u64);
    if rc < 0 { Err(rc as i32) } else { Ok(()) }
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

fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
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
