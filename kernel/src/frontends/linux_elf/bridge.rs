use alloc::vec::Vec;
use core::slice;

use bootloader_api::BootInfo;

use crate::qemu;
use crate::serial_println;
use crate::substrate::ring3::{self, SyscallFrame};
use crate::supervisor::{LinuxCallResult, PrototypeRuntime, runtime};
use vmos_abi::{
    ERR_EBADF, ERR_EFAULT, ERR_EINVAL, ERR_ENOSYS, NodeKind, SYS_CLOSE, SYS_EXIT, SYS_EXIT_GROUP,
    SYS_GETCWD, SYS_GETDENTS64, SYS_NANOSLEEP, SYS_OPENAT, SYS_READ, SYS_READLINKAT, SYS_UNAME,
    SYS_WRITE, SyscallContext,
};

use super::context::{ActiveUserContext, active_context, install_active_context};
use super::loader::load_demo_program;

const AT_FDCWD: i64 = -100;
const PATH_MAX: usize = 256;
const UTS_FIELD_LEN: usize = 65;

const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

#[repr(C)]
#[derive(Clone, Copy)]
struct GuestTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
struct GuestUtsName {
    sysname: [u8; UTS_FIELD_LEN],
    nodename: [u8; UTS_FIELD_LEN],
    release: [u8; UTS_FIELD_LEN],
    version: [u8; UTS_FIELD_LEN],
    machine: [u8; UTS_FIELD_LEN],
    domainname: [u8; UTS_FIELD_LEN],
}

pub(crate) fn run_demo(boot_info: &BootInfo) -> Result<(), &'static str> {
    serial_println!("== ring3 real ELF demo ==");
    let image = load_demo_program(boot_info)?;
    let mut context = ActiveUserContext::new(runtime()?, image.regions);
    install_active_context(&mut context);

    crate::kinfo!("entering ring3 ELF demo");
    ring3::enter_user_mode(image.entry, image.stack_top);
}

pub(crate) extern "C" fn syscall_dispatch_from_asm(frame: *mut SyscallFrame) {
    let frame = unsafe { &mut *frame };
    match dispatch_syscall(frame) {
        Ok(ret) => frame.rax = ret as u64,
        Err(errno) => frame.rax = (-(errno as i64)) as u64,
    }
}

fn dispatch_syscall(frame: &mut SyscallFrame) -> Result<i64, i32> {
    match frame.rax {
        SYS_WRITE => sys_write(frame),
        SYS_READ => sys_read(frame),
        SYS_OPENAT => sys_openat(frame),
        SYS_CLOSE => sys_close(frame),
        SYS_GETDENTS64 => sys_getdents64(frame),
        SYS_GETCWD => sys_getcwd(frame),
        SYS_READLINKAT => sys_readlinkat(frame),
        SYS_UNAME => sys_uname(frame),
        SYS_NANOSLEEP => sys_nanosleep(frame),
        SYS_EXIT | SYS_EXIT_GROUP => handle_exit(frame.rdi as i32),
        _ => Err(ERR_ENOSYS),
    }
}

fn sys_write(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let bytes = user_slice(frame.rsi, frame.rdx, false)?;
    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor
        .write_linux_arg_bytes(bytes)
        .map_err(|_| ERR_EFAULT)?;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_write",
            SyscallContext::new(SYS_WRITE, [fd as u64, ptr as u64, len as u64, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_read(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let count = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let supervisor = &mut active_context().supervisor;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_read",
            SyscallContext::new(SYS_READ, [fd as u64, 0, count as u64, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Bytes(bytes) => {
            let dest = user_slice_mut(frame.rsi, bytes.len() as u64)?;
            dest.copy_from_slice(&bytes);
            Ok(bytes.len() as i64)
        }
        LinuxCallResult::Ret(0) => Ok(0),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_openat(frame: &SyscallFrame) -> Result<i64, i32> {
    let flags = u32::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let mode = u32::try_from(frame.r10).map_err(|_| ERR_EINVAL)?;
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(frame.rdi as i64, &path)?;

    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor
        .write_linux_arg_bytes(&resolved)
        .map_err(|_| ERR_EFAULT)?;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_openat",
            SyscallContext::new(
                SYS_OPENAT,
                [
                    frame.rdi,
                    ptr as u64,
                    len as u64,
                    flags as u64,
                    mode as u64,
                    0,
                ],
            ),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_close(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let supervisor = &mut active_context().supervisor;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_close",
            SyscallContext::new(SYS_CLOSE, [fd as u64, 0, 0, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_getdents64(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let count = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let supervisor = &mut active_context().supervisor;
    let dir_path = supervisor.fd_path(fd)?;
    let listing = match supervisor
        .dispatch_linux_syscall(
            "ring3_getdents64",
            SyscallContext::new(SYS_GETDENTS64, [fd as u64, 0, count as u64, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Bytes(bytes) => bytes,
        LinuxCallResult::Ret(ret) if ret <= 0 => return Err((-ret) as i32),
        _ => return Err(ERR_EINVAL),
    };

    let packed = pack_dirents(supervisor, &dir_path, &listing, count)?;
    let dest = user_slice_mut(frame.rsi, packed.len() as u64)?;
    dest.copy_from_slice(&packed);
    Ok(packed.len() as i64)
}

fn sys_getcwd(frame: &SyscallFrame) -> Result<i64, i32> {
    let size = usize::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    let supervisor = &mut active_context().supervisor;
    let cwd = match supervisor
        .dispatch_linux_syscall(
            "ring3_getcwd",
            SyscallContext::new(SYS_GETCWD, [0, size as u64, 0, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Bytes(bytes) => bytes,
        LinuxCallResult::Ret(ret) if ret <= 0 => return Err((-ret) as i32),
        _ => return Err(ERR_EINVAL),
    };

    if cwd.len() + 1 > size {
        return Err(ERR_EINVAL);
    }
    let dest = user_slice_mut(frame.rdi, (cwd.len() + 1) as u64)?;
    dest[..cwd.len()].copy_from_slice(&cwd);
    dest[cwd.len()] = 0;
    Ok((cwd.len() + 1) as i64)
}

fn sys_readlinkat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(frame.rdi as i64, &path)?;
    let count = usize::try_from(frame.r10).map_err(|_| ERR_EINVAL)?;
    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor
        .write_linux_arg_bytes(&resolved)
        .map_err(|_| ERR_EFAULT)?;
    let link = match supervisor
        .dispatch_linux_syscall(
            "ring3_readlinkat",
            SyscallContext::new(SYS_READLINKAT, [frame.rdi, ptr as u64, len as u64, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Bytes(bytes) => bytes,
        LinuxCallResult::Ret(ret) if ret <= 0 => return Err((-ret) as i32),
        _ => return Err(ERR_EINVAL),
    };

    let written = core::cmp::min(link.len(), count);
    let dest = user_slice_mut(frame.rdx, written as u64)?;
    dest.copy_from_slice(&link[..written]);
    Ok(written as i64)
}

fn sys_uname(frame: &SyscallFrame) -> Result<i64, i32> {
    let supervisor = &mut active_context().supervisor;
    let payload = match supervisor
        .dispatch_linux_syscall(
            "ring3_uname",
            SyscallContext::new(SYS_UNAME, [0, 0, 0, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Bytes(bytes) => bytes,
        LinuxCallResult::Ret(ret) if ret < 0 => return Err((-ret) as i32),
        _ => return Err(ERR_EINVAL),
    };

    let uts = GuestUtsName {
        sysname: c_field(b"VmOS"),
        nodename: c_field(b"prototype2"),
        release: c_field(&payload),
        version: c_field(b"supervisor-world"),
        machine: c_field(b"x86_64"),
        domainname: [0; UTS_FIELD_LEN],
    };

    let dest = user_slice_mut(frame.rdi, core::mem::size_of::<GuestUtsName>() as u64)?;
    let src = unsafe {
        slice::from_raw_parts(
            (&uts as *const GuestUtsName).cast::<u8>(),
            core::mem::size_of::<GuestUtsName>(),
        )
    };
    dest.copy_from_slice(src);
    Ok(0)
}

fn sys_nanosleep(frame: &SyscallFrame) -> Result<i64, i32> {
    let req = user_struct::<GuestTimespec>(frame.rdi)?;
    if req.tv_sec < 0 || req.tv_nsec < 0 {
        return Err(ERR_EINVAL);
    }
    let millis = (req.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add((req.tv_nsec as u64).div_ceil(1_000_000));
    let supervisor = &mut active_context().supervisor;
    supervisor.sleep_ms(millis).map_err(|_| ERR_EINVAL)?;
    Ok(0)
}

fn handle_exit(status: i32) -> ! {
    if status == 0 {
        serial_println!("vmos: demo completed");
        qemu::exit_success();
    } else {
        serial_println!("vmos: user ELF exited with status {}", status);
        qemu::exit_failed();
    }

    loop {
        x86_64::instructions::hlt();
    }
}

fn user_slice(ptr: u64, len: u64, write: bool) -> Result<&'static [u8], i32> {
    validate_user_range(ptr, len, write)?;
    Ok(unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) })
}

fn user_slice_mut(ptr: u64, len: u64) -> Result<&'static mut [u8], i32> {
    validate_user_range(ptr, len, true)?;
    Ok(unsafe { slice::from_raw_parts_mut(ptr as *mut u8, len as usize) })
}

fn user_struct<T: Copy>(ptr: u64) -> Result<T, i32> {
    let bytes = user_slice(ptr, core::mem::size_of::<T>() as u64, false)?;
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            value.as_mut_ptr().cast::<u8>(),
            core::mem::size_of::<T>(),
        );
        Ok(value.assume_init())
    }
}

fn read_user_c_string(ptr: u64, max_len: usize) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    for index in 0..max_len {
        let byte = user_slice(ptr + index as u64, 1, false)?[0];
        if byte == 0 {
            return Ok(out);
        }
        out.push(byte);
    }
    Err(ERR_EINVAL)
}

fn validate_user_range(ptr: u64, len: u64, write: bool) -> Result<(), i32> {
    let end = ptr.checked_add(len).ok_or(ERR_EFAULT)?;
    let regions = &active_context().regions;
    if regions
        .iter()
        .any(|region| ptr >= region.start && end <= region.end && (!write || region.writable))
    {
        Ok(())
    } else {
        Err(ERR_EFAULT)
    }
}

fn resolve_path(dirfd: i64, path: &[u8]) -> Result<Vec<u8>, i32> {
    if path.starts_with(b"/") {
        return Ok(path.to_vec());
    }

    let base = if dirfd == AT_FDCWD {
        active_context()
            .supervisor
            .getcwd()
            .map_err(|_| ERR_EBADF)?
    } else if dirfd >= 0 {
        active_context()
            .supervisor
            .fd_path(dirfd as u32)
            .map_err(|_| ERR_EBADF)?
    } else {
        return Err(ERR_EBADF);
    };

    let mut resolved = base;
    if !resolved.ends_with(b"/") {
        resolved.push(b'/');
    }
    resolved.extend_from_slice(path);
    Ok(resolved)
}

fn pack_dirents(
    supervisor: &mut PrototypeRuntime<'static>,
    dir_path: &[u8],
    listing: &[u8],
    max_len: usize,
) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    let mut next_off = 1i64;

    for name in listing.split(|byte| *byte == b'\n') {
        if name.is_empty() {
            continue;
        }

        let dtype = node_kind_to_dtype(supervisor.path_kind(&join_path(dir_path, name))?);
        let reclen = align_up(19 + name.len() + 1, 8);
        if reclen > max_len {
            return Err(ERR_EINVAL);
        }
        if out.len() + reclen > max_len {
            break;
        }

        let record_start = out.len();
        out.resize(record_start + reclen, 0);
        out[record_start..record_start + 8].copy_from_slice(&(next_off as u64).to_le_bytes());
        out[record_start + 8..record_start + 16].copy_from_slice(&next_off.to_le_bytes());
        out[record_start + 16..record_start + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
        out[record_start + 18] = dtype;
        out[record_start + 19..record_start + 19 + name.len()].copy_from_slice(name);
        next_off += 1;
    }

    Ok(out)
}

fn join_path(base: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = Vec::with_capacity(base.len() + name.len() + 1);
    path.extend_from_slice(base);
    if !base.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

fn node_kind_to_dtype(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::File => DT_REG,
        NodeKind::Directory => DT_DIR,
        NodeKind::Symlink => DT_LNK,
        NodeKind::CharDevice => DT_CHR,
    }
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn c_field(value: &[u8]) -> [u8; UTS_FIELD_LEN] {
    let mut field = [0u8; UTS_FIELD_LEN];
    let len = core::cmp::min(value.len(), UTS_FIELD_LEN - 1);
    field[..len].copy_from_slice(&value[..len]);
    field
}
