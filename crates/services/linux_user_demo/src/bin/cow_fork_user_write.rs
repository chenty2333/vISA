#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo};

use visa_abi::{SYS_EXIT, SYS_FORK, SYS_GETCWD, SYS_MMAP, SYS_WAIT4, SYS_WRITE};

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FAILED: i64 = -1;
const PAGE_SIZE: u64 = 4096;

static SENTINEL: &[u8] = b"parent-cow-sentinel";
static START_LABEL: &[u8] = b"cow_fork_user_write: probing syscall copyout COW break\n";
static OK_LABEL: &[u8] = b"cow_fork_user_write: parent COW page survived child copyout\n";
static ERROR_LABEL: &[u8] = b"cow_fork_user_write: failed\n";

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
    let page = sys_mmap(PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)?;
    write_sentinel(page);

    let pid = sys_fork()?;
    if pid == 0 {
        let rc = syscall2(SYS_GETCWD, page as u64, PAGE_SIZE);
        let code = if rc < 0 { (-rc) as i32 } else { 0 };
        exit(code);
    }

    wait_child_ok(pid)?;
    verify_sentinel(page)?;
    write_all(1, OK_LABEL)
}

fn write_sentinel(page: usize) {
    unsafe {
        let ptr = page as *mut u8;
        for index in 0..SENTINEL.len() {
            core::ptr::write_volatile(ptr.add(index), SENTINEL[index]);
        }
    }
}

fn verify_sentinel(page: usize) -> Result<(), i32> {
    unsafe {
        let ptr = page as *const u8;
        for index in 0..SENTINEL.len() {
            if core::ptr::read_volatile(ptr.add(index)) != SENTINEL[index] {
                return Err(20);
            }
        }
    }
    Ok(())
}

fn sys_mmap(len: u64, prot: u64, flags: u64, fd: i32, offset: u64) -> Result<usize, i32> {
    let rc = syscall6(SYS_MMAP, 0, len, prot, flags, fd as u64, offset);
    if rc < 0 || rc == MAP_FAILED { Err((-rc) as i32) } else { Ok(rc as usize) }
}

fn sys_fork() -> Result<i64, i32> {
    let rc = syscall0(SYS_FORK);
    if rc < 0 { Err((-rc) as i32) } else { Ok(rc) }
}

fn wait_child_ok(pid: i64) -> Result<(), i32> {
    let mut status = 0i32;
    let rc = syscall4(SYS_WAIT4, pid as u64, (&mut status as *mut i32) as u64, 0, 0);
    if rc < 0 {
        return Err((-rc) as i32);
    }
    if rc != pid || status != 0 {
        return Err(22);
    }
    Ok(())
}

fn write_all(fd: i32, mut bytes: &[u8]) -> Result<(), i32> {
    while !bytes.is_empty() {
        let rc = syscall3(SYS_WRITE, fd as u64, bytes.as_ptr() as u64, bytes.len() as u64);
        if rc < 0 {
            return Err((-rc) as i32);
        }
        let written = rc as usize;
        if written == 0 || written > bytes.len() {
            return Err(21);
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

fn syscall0(nr: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
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
