#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;
use core::slice;

use vmos_abi::{
    SYS_CLOSE, SYS_EXIT, SYS_GETCWD, SYS_GETDENTS64, SYS_NANOSLEEP, SYS_OPENAT, SYS_READ,
    SYS_READLINKAT, SYS_UNAME, SYS_WRITE,
};

const AT_FDCWD: i32 = -100;
const O_RDONLY: u32 = 0;

static FILE_LABEL: &[u8] = b"-- /sandbox/hello.txt --\n";
static PROC_LABEL: &[u8] = b"-- /proc/self/status --\n";
static DEV_LABEL: &[u8] = b"/dev/zero returned eight zero bytes\n";
static DENTS_LABEL: &[u8] = b"-- getdents64('/') --\n";
static CWD_LABEL: &[u8] = b"getcwd() -> ";
static LINK_LABEL: &[u8] = b"readlinkat('/sandbox/readme.link') -> ";
static UNAME_LABEL: &[u8] = b"uname() -> ";
static SLEEP_LABEL: &[u8] = b"ring3 ELF resumed after nanosleep\n";
static ERROR_LABEL: &[u8] = b"ring3 ELF demo failed\n";

static ROOT_PATH: &[u8] = b"/\0";
static FILE_PATH: &[u8] = b"/sandbox/hello.txt\0";
static PROC_PATH: &[u8] = b"/proc/self/status\0";
static LINK_PATH: &[u8] = b"/sandbox/readme.link\0";
static DEV_PATH: &[u8] = b"/dev/zero\0";

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
struct UtsName {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

#[repr(C)]
struct LinuxDirent64Head {
    ino: u64,
    off: i64,
    reclen: u16,
    ty: u8,
}

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
    dump_file(FILE_LABEL, FILE_PATH)?;
    dump_file(PROC_LABEL, PROC_PATH)?;
    check_dev_zero()?;
    list_root_dir()?;
    show_getcwd()?;
    show_readlink()?;
    show_uname()?;
    do_sleep()?;
    Ok(())
}

fn dump_file(label: &[u8], path: &[u8]) -> Result<(), i32> {
    let fd = open_readonly(path)?;
    write_all(label)?;

    let mut buffer = [0u8; 256];
    let len = sys_read(fd, &mut buffer)?;
    write_all(&buffer[..len])?;
    if len == 0 || buffer[len - 1] != b'\n' {
        write_all(b"\n")?;
    }

    close_fd(fd)?;
    Ok(())
}

fn check_dev_zero() -> Result<(), i32> {
    let fd = open_readonly(DEV_PATH)?;
    let mut buffer = [0xAAu8; 8];
    let len = sys_read(fd, &mut buffer)?;
    close_fd(fd)?;
    if len != buffer.len() {
        return Err(-1);
    }
    if buffer.iter().any(|byte| *byte != 0) {
        return Err(-1);
    }

    write_all(DEV_LABEL)
}

fn list_root_dir() -> Result<(), i32> {
    let fd = open_readonly(ROOT_PATH)?;
    let mut buffer = [0u8; 256];
    let len = sys_getdents64(fd, &mut buffer)?;
    close_fd(fd)?;

    write_all(DENTS_LABEL)?;
    let mut offset = 0usize;
    while offset < len {
        let head = unsafe { &*(buffer.as_ptr().add(offset) as *const LinuxDirent64Head) };
        let reclen = head.reclen as usize;
        if reclen < 20 || offset + reclen > len {
            return Err(-1);
        }

        let name_ptr = unsafe { buffer.as_ptr().add(offset + 19) };
        let name_bytes = unsafe { slice::from_raw_parts(name_ptr, reclen - 19) };
        let name_len = c_string_len(name_bytes);
        write_all(&name_bytes[..name_len])?;
        write_all(b"\n")?;
        offset += reclen;
    }

    Ok(())
}

fn show_getcwd() -> Result<(), i32> {
    let mut buffer = [0u8; 128];
    let len = sys_getcwd(&mut buffer)?;
    write_all(CWD_LABEL)?;
    write_all(&buffer[..len.saturating_sub(1)])?;
    write_all(b"\n")
}

fn show_readlink() -> Result<(), i32> {
    let mut buffer = [0u8; 128];
    let len = sys_readlinkat(AT_FDCWD, LINK_PATH, &mut buffer)?;
    write_all(LINK_LABEL)?;
    write_all(&buffer[..len])?;
    write_all(b"\n")
}

fn show_uname() -> Result<(), i32> {
    let mut uts = UtsName {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    sys_uname(&mut uts)?;
    write_all(UNAME_LABEL)?;
    write_all(trim_c_string(&uts.sysname))?;
    write_all(b" ")?;
    write_all(trim_c_string(&uts.release))?;
    write_all(b" ")?;
    write_all(trim_c_string(&uts.machine))?;
    write_all(b"\n")
}

fn do_sleep() -> Result<(), i32> {
    let req = Timespec {
        tv_sec: 0,
        tv_nsec: 25_000_000,
    };
    sys_nanosleep(&req)?;
    write_all(SLEEP_LABEL)
}

fn open_readonly(path: &[u8]) -> Result<i32, i32> {
    let rc = syscall4(
        SYS_OPENAT,
        AT_FDCWD as u64,
        path.as_ptr() as u64,
        O_RDONLY as u64,
        0,
    );
    if rc < 0 {
        Err(rc as i32)
    } else {
        Ok(rc as i32)
    }
}

fn close_fd(fd: i32) -> Result<(), i32> {
    let rc = syscall1(SYS_CLOSE, fd as u64);
    if rc < 0 { Err(rc as i32) } else { Ok(()) }
}

fn sys_read(fd: i32, buffer: &mut [u8]) -> Result<usize, i32> {
    let rc = syscall3(
        SYS_READ,
        fd as u64,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    );
    if rc < 0 {
        Err(rc as i32)
    } else {
        Ok(rc as usize)
    }
}

fn sys_getdents64(fd: i32, buffer: &mut [u8]) -> Result<usize, i32> {
    let rc = syscall3(
        SYS_GETDENTS64,
        fd as u64,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    );
    if rc < 0 {
        Err(rc as i32)
    } else {
        Ok(rc as usize)
    }
}

fn sys_getcwd(buffer: &mut [u8]) -> Result<usize, i32> {
    let rc = syscall2(SYS_GETCWD, buffer.as_mut_ptr() as u64, buffer.len() as u64);
    if rc < 0 {
        Err(rc as i32)
    } else {
        Ok(rc as usize)
    }
}

fn sys_readlinkat(dirfd: i32, path: &[u8], buffer: &mut [u8]) -> Result<usize, i32> {
    let rc = syscall4(
        SYS_READLINKAT,
        dirfd as u64,
        path.as_ptr() as u64,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    );
    if rc < 0 {
        Err(rc as i32)
    } else {
        Ok(rc as usize)
    }
}

fn sys_uname(uts: &mut UtsName) -> Result<(), i32> {
    let rc = syscall1(SYS_UNAME, uts as *mut UtsName as u64);
    if rc < 0 { Err(rc as i32) } else { Ok(()) }
}

fn sys_nanosleep(req: &Timespec) -> Result<(), i32> {
    let rc = syscall2(SYS_NANOSLEEP, req as *const Timespec as u64, 0);
    if rc < 0 { Err(rc as i32) } else { Ok(()) }
}

fn write_all(bytes: &[u8]) -> Result<(), i32> {
    let rc = syscall3(SYS_WRITE, 1, bytes.as_ptr() as u64, bytes.len() as u64);
    if rc < 0 { Err(rc as i32) } else { Ok(()) }
}

fn trim_c_string(bytes: &[u8]) -> &[u8] {
    let len = c_string_len(bytes);
    &bytes[..len]
}

fn c_string_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
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

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    exit(1)
}
