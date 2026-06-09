#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo};

use visa_abi::{SYS_CLOSE, SYS_EXIT, SYS_MMAP, SYS_MREMAP, SYS_OPENAT, SYS_UNLINK, SYS_WRITE};

const AT_FDCWD: i32 = -100;
const O_RDWR: u32 = 0x02;
const O_CREAT: u32 = 0x40;
const O_TRUNC: u32 = 0x200;
const PROT_READ: u64 = 0x1;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FAILED: i64 = -1;
const MREMAP_MAYMOVE: u64 = 0x1;
const PAGE_SIZE: usize = 4096;

static FILE_PATH: &[u8] = b"/tmp/private-mremap-unlink.bin\0";
static FIRST_PAGE: [u8; PAGE_SIZE] = [0x31; PAGE_SIZE];
static TAIL_BYTES: &[u8] = b"private-mremap-tail-after-unlink";
static START_LABEL: &[u8] = b"private_mremap_unlink: probing retained MAP_PRIVATE source\n";
static OK_LABEL: &[u8] = b"private_mremap_unlink: mremap tail survived unlink+close\n";
static ERROR_LABEL: &[u8] = b"private_mremap_unlink: failed\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => {
            let _ = write_all(1, ERROR_LABEL);
            code
        }
    };
    exit(code)
}

fn run() -> Result<(), i32> {
    write_all(1, START_LABEL)?;
    let fd = open_create(FILE_PATH)?;
    write_all(fd, &FIRST_PAGE)?;
    write_all(fd, TAIL_BYTES)?;

    let mapping = sys_mmap(PAGE_SIZE as u64, PROT_READ, MAP_PRIVATE, fd, 0)?;
    close_fd(fd)?;
    unlink_path(FILE_PATH)?;

    let grown = sys_mremap(mapping, PAGE_SIZE as u64, (PAGE_SIZE * 2) as u64, MREMAP_MAYMOVE, 0)?;
    verify_private_tail(grown)?;
    write_all(1, OK_LABEL)
}

fn verify_private_tail(mapping: usize) -> Result<(), i32> {
    unsafe {
        let base = mapping as *const u8;
        if core::ptr::read_volatile(base) != FIRST_PAGE[0] {
            return Err(10);
        }
        for (index, expected) in TAIL_BYTES.iter().copied().enumerate() {
            let actual = core::ptr::read_volatile(base.add(PAGE_SIZE + index));
            if actual != expected {
                return Err(11);
            }
        }
    }
    Ok(())
}

fn open_create(path: &[u8]) -> Result<i32, i32> {
    let flags = O_RDWR | O_CREAT | O_TRUNC;
    let rc = syscall4(SYS_OPENAT, AT_FDCWD as u64, path.as_ptr() as u64, flags as u64, 0o600);
    if rc < 0 { Err((-rc) as i32) } else { Ok(rc as i32) }
}

fn close_fd(fd: i32) -> Result<(), i32> {
    let rc = syscall1(SYS_CLOSE, fd as u64);
    if rc < 0 { Err((-rc) as i32) } else { Ok(()) }
}

fn unlink_path(path: &[u8]) -> Result<(), i32> {
    let rc = syscall1(SYS_UNLINK, path.as_ptr() as u64);
    if rc < 0 { Err((-rc) as i32) } else { Ok(()) }
}

fn sys_mmap(len: u64, prot: u64, flags: u64, fd: i32, offset: u64) -> Result<usize, i32> {
    let rc = syscall6(SYS_MMAP, 0, len, prot, flags, fd as u64, offset);
    if rc < 0 || rc == MAP_FAILED { Err((-rc) as i32) } else { Ok(rc as usize) }
}

fn sys_mremap(
    old_addr: usize,
    old_size: u64,
    new_size: u64,
    flags: u64,
    new_addr: usize,
) -> Result<usize, i32> {
    let rc = syscall5(SYS_MREMAP, old_addr as u64, old_size, new_size, flags, new_addr as u64);
    if rc < 0 { Err((-rc) as i32) } else { Ok(rc as usize) }
}

fn write_all(fd: i32, mut bytes: &[u8]) -> Result<(), i32> {
    while !bytes.is_empty() {
        let rc = syscall3(SYS_WRITE, fd as u64, bytes.as_ptr() as u64, bytes.len() as u64);
        if rc < 0 {
            return Err((-rc) as i32);
        }
        let written = rc as usize;
        if written == 0 || written > bytes.len() {
            return Err(12);
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

fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
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
