use alloc::vec::Vec;

use bootloader_api::BootInfo;
use semantic_core::ResourceHandle;
use vmos_abi::{
    ERR_EBADF, ERR_EFAULT, ERR_EINVAL, ERR_ENOSYS, ERR_EPERM, SYS_ACCEPT, SYS_BIND, SYS_CLOSE,
    SYS_CONNECT, SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT, SYS_EXIT, SYS_EXIT_GROUP,
    SYS_FCNTL, SYS_FUTEX, SYS_GETCWD, SYS_GETDENTS64, SYS_GETSOCKOPT, SYS_MMAP, SYS_MUNMAP,
    SYS_NANOSLEEP, SYS_OPENAT, SYS_READ, SYS_READLINKAT, SYS_RECVFROM, SYS_SENDTO, SYS_SETSOCKOPT,
    SYS_SOCKET, SYS_UNAME, SYS_WRITE, SyscallContext,
};

use super::{
    context::{ActiveUserContext, active_context, install_active_context},
    loader::load_demo_program,
};
use crate::{
    qemu, serial_println,
    substrate::ring3::{self, SyscallFrame},
    supervisor::{LinuxCallResult, runtime},
};

const AT_FDCWD: i64 = -100;
const PATH_MAX: usize = 256;
const LINUX_TIMESPEC_SIZE: u64 = 16;
const EPOLL_EVENT_SIZE: u64 = 12;

pub(crate) fn run_demo(boot_info: &BootInfo) -> Result<(), &'static str> {
    serial_println!("== ring3 real ELF demo ==");
    let image = load_demo_program(boot_info)?;
    let supervisor = runtime()?;
    let task_id = supervisor.allocate_task();
    let mut context = ActiveUserContext::new(supervisor, image.regions, task_id);
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
    let (task_id, activation_id) = {
        let context = active_context();
        (context.task_id, context.begin_activation())
    };
    active_context().supervisor.set_current_task(task_id);
    let _activation = ActivationGuard { activation_id };
    match frame.rax {
        SYS_WRITE => sys_write(frame),
        SYS_READ => sys_read(frame),
        SYS_OPENAT => sys_openat(frame),
        SYS_CLOSE => sys_close(frame),
        SYS_EPOLL_CREATE1 => sys_epoll_create1(frame),
        SYS_EPOLL_CTL => sys_epoll_ctl(frame),
        SYS_EPOLL_WAIT => sys_epoll_wait(frame),
        SYS_SOCKET => sys_socket(frame),
        SYS_BIND => sys_bind(frame),
        SYS_CONNECT => sys_connect(frame),
        SYS_ACCEPT => sys_accept(frame),
        SYS_SENDTO => sys_sendto(frame),
        SYS_RECVFROM => sys_recvfrom(frame),
        SYS_SETSOCKOPT => sys_setsockopt(frame),
        SYS_GETSOCKOPT => sys_getsockopt(frame),
        SYS_FCNTL => sys_fcntl(frame),
        SYS_MMAP => sys_mmap(frame),
        SYS_MUNMAP => sys_munmap(frame),
        SYS_FUTEX => sys_futex(frame),
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
    let bytes = user_lease(frame.rsi, frame.rdx, false)?;
    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor
        .write_linux_arg_bytes(bytes.bytes().map_err(map_dmw_fault)?)
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
            let mut dest = user_lease(frame.rsi, bytes.len() as u64, true)?;
            dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&bytes);
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
    let (ptr, len) = supervisor.write_linux_arg_bytes(&resolved).map_err(|_| ERR_EFAULT)?;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_openat",
            SyscallContext::new(
                SYS_OPENAT,
                [frame.rdi, ptr as u64, len as u64, flags as u64, mode as u64, 0],
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

fn sys_epoll_create1(frame: &SyscallFrame) -> Result<i64, i32> {
    let flags = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let supervisor = &mut active_context().supervisor;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_epoll_create1",
            SyscallContext::new(SYS_EPOLL_CREATE1, [flags as u64, 0, 0, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_epoll_ctl(frame: &SyscallFrame) -> Result<i64, i32> {
    let epfd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let op = u32::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    let fd = u32::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let (events, data) = read_epoll_event(frame.r10)?;
    let supervisor = &mut active_context().supervisor;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_epoll_ctl",
            SyscallContext::new(
                SYS_EPOLL_CTL,
                [epfd as u64, op as u64, fd as u64, events as u64, data, 0],
            ),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_epoll_wait(frame: &SyscallFrame) -> Result<i64, i32> {
    let epfd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let max_events = u32::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let timeout_ms = frame.r10 as i32 as i64;
    let supervisor = &mut active_context().supervisor;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_epoll_wait",
            SyscallContext::new(
                SYS_EPOLL_WAIT,
                [epfd as u64, max_events as u64, timeout_ms as u64, 0, 0, 0],
            ),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Bytes(bytes) => {
            let max_len = max_events as u64 * EPOLL_EVENT_SIZE;
            if bytes.len() as u64 > max_len {
                return Err(ERR_EFAULT);
            }
            let mut dest = user_lease(frame.rsi, bytes.len() as u64, true)?;
            dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&bytes);
            Ok((bytes.len() as u64 / EPOLL_EVENT_SIZE) as i64)
        }
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_socket(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_socket",
        SyscallContext::new(SYS_SOCKET, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_bind(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_bind",
        SyscallContext::new(SYS_BIND, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_connect(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_connect",
        SyscallContext::new(SYS_CONNECT, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_accept(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_accept",
        SyscallContext::new(SYS_ACCEPT, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_sendto(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let len = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let bytes = user_lease(frame.rsi, len as u64, false)?;
    let supervisor = &mut active_context().supervisor;
    let (ptr, copied_len) = supervisor
        .write_linux_arg_bytes(bytes.bytes().map_err(map_dmw_fault)?)
        .map_err(|_| ERR_EFAULT)?;
    dispatch_ret(
        "ring3_sendto",
        SyscallContext::new(
            SYS_SENDTO,
            [fd as u64, ptr as u64, copied_len as u64, frame.r10, frame.r8, frame.r9],
        ),
    )
}

fn sys_recvfrom(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let count = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let supervisor = &mut active_context().supervisor;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_recvfrom",
            SyscallContext::new(
                SYS_RECVFROM,
                [fd as u64, 0, count as u64, frame.r10, frame.r8, frame.r9],
            ),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Bytes(bytes) => {
            let mut dest = user_lease(frame.rsi, bytes.len() as u64, true)?;
            dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&bytes);
            Ok(bytes.len() as i64)
        }
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_setsockopt(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_setsockopt",
        SyscallContext::new(
            SYS_SETSOCKOPT,
            [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, 0],
        ),
    )
}

fn sys_getsockopt(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_getsockopt",
        SyscallContext::new(
            SYS_GETSOCKOPT,
            [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, 0],
        ),
    )
}

fn sys_fcntl(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_fcntl",
        SyscallContext::new(SYS_FCNTL, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_mmap(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_mmap",
        SyscallContext::new(
            SYS_MMAP,
            [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9],
        ),
    )
}

fn sys_munmap(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_munmap",
        SyscallContext::new(SYS_MUNMAP, [frame.rdi, frame.rsi, 0, 0, 0, 0]),
    )
}

fn dispatch_ret(label: &str, ctx: SyscallContext) -> Result<i64, i32> {
    let supervisor = &mut active_context().supervisor;
    match supervisor.dispatch_linux_syscall(label, ctx).map_err(|_| ERR_EINVAL)? {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_getdents64(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let count = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let supervisor = &mut active_context().supervisor;
    let packed = supervisor.getdents64_abi(fd, count as u32).map_err(|_| ERR_EINVAL)?;
    let mut dest = user_lease(frame.rsi, packed.len() as u64, true)?;
    dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&packed);
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
    let mut dest = user_lease(frame.rdi, (cwd.len() + 1) as u64, true)?;
    let dest_bytes = dest.bytes_mut().map_err(map_dmw_fault)?;
    dest_bytes[..cwd.len()].copy_from_slice(&cwd);
    dest_bytes[cwd.len()] = 0;
    Ok((cwd.len() + 1) as i64)
}

fn sys_readlinkat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(frame.rdi as i64, &path)?;
    let count = usize::try_from(frame.r10).map_err(|_| ERR_EINVAL)?;
    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor.write_linux_arg_bytes(&resolved).map_err(|_| ERR_EFAULT)?;
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
    let mut dest = user_lease(frame.rdx, written as u64, true)?;
    dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&link[..written]);
    Ok(written as i64)
}

fn sys_uname(frame: &SyscallFrame) -> Result<i64, i32> {
    let supervisor = &mut active_context().supervisor;
    let encoded = supervisor.uname_abi().map_err(|_| ERR_EINVAL)?;
    let mut dest = user_lease(frame.rdi, encoded.len() as u64, true)?;
    dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&encoded);
    Ok(0)
}

fn sys_nanosleep(frame: &SyscallFrame) -> Result<i64, i32> {
    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = {
        let req = user_lease(frame.rdi, LINUX_TIMESPEC_SIZE, false)?;
        supervisor
            .write_linux_arg_bytes(req.bytes().map_err(map_dmw_fault)?)
            .map_err(|_| ERR_EFAULT)?
    };
    match supervisor
        .dispatch_linux_syscall(
            "ring3_nanosleep",
            SyscallContext::new(SYS_NANOSLEEP, [ptr as u64, len as u64, 0, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_futex(frame: &SyscallFrame) -> Result<i64, i32> {
    let current_word = {
        let word = user_lease(frame.rdi, 4, false)?;
        let bytes = word.bytes().map_err(map_dmw_fault)?;
        u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ERR_EINVAL)?) as u64
    };

    let supervisor = &mut active_context().supervisor;
    let (timeout_ptr, timeout_len) = if frame.r10 == 0 {
        (0u64, 0u64)
    } else {
        let timeout = user_lease(frame.r10, LINUX_TIMESPEC_SIZE, false)?;
        let (ptr, len) = supervisor
            .write_linux_arg_bytes(timeout.bytes().map_err(map_dmw_fault)?)
            .map_err(|_| ERR_EFAULT)?;
        (ptr as u64, len as u64)
    };

    match supervisor
        .dispatch_linux_syscall(
            "ring3_futex",
            SyscallContext::new(
                SYS_FUTEX,
                [frame.rdi, frame.rsi, frame.rdx, timeout_ptr, timeout_len, current_word],
            ),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn handle_exit(status: i32) -> ! {
    serial_println!("== post-ring3 semantic object graph ==");
    for line in active_context().supervisor.semantic_debug_lines() {
        serial_println!("{}", line);
    }
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

struct ActivationGuard {
    activation_id: u64,
}

impl Drop for ActivationGuard {
    fn drop(&mut self) {
        crate::substrate::dmw::finish_activation(self.activation_id);
        active_context().finish_activation(self.activation_id);
    }
}

struct UserDmwLease {
    lease: crate::substrate::dmw::DmwLease,
    resource_handle: Option<ResourceHandle>,
    generation: u64,
}

impl UserDmwLease {
    fn bytes(&self) -> Result<&[u8], crate::substrate::dmw::DmwFault> {
        if let Some(handle) = self.resource_handle {
            active_context()
                .supervisor
                .validate_resource_handle(handle)
                .map_err(|_| crate::substrate::dmw::DmwFault::WindowViolation)?;
        }
        self.lease.bytes()
    }

    fn bytes_mut(&mut self) -> Result<&mut [u8], crate::substrate::dmw::DmwFault> {
        if let Some(handle) = self.resource_handle {
            active_context()
                .supervisor
                .validate_resource_handle(handle)
                .map_err(|_| crate::substrate::dmw::DmwFault::WindowViolation)?;
        }
        self.lease.bytes_mut()
    }
}

impl Drop for UserDmwLease {
    fn drop(&mut self) {
        let Some(resource_handle) = self.resource_handle.take() else {
            return;
        };
        active_context().supervisor.record_window_lease_destroyed(resource_handle, self.generation);
    }
}

fn user_lease(ptr: u64, len: u64, writable: bool) -> Result<UserDmwLease, i32> {
    active_context()
        .supervisor
        .require_capability("linux_elf_frontend", "dmw.window", "acquire")
        .map_err(|_| ERR_EPERM)?;
    validate_user_range(ptr, len, writable)?;
    let lease = crate::substrate::dmw::acquire(active_context().activation_id, ptr, len, writable)
        .map_err(map_dmw_fault)?;
    let generation = lease.generation();
    let resource_handle = active_context().supervisor.record_window_lease_created(
        lease.slot_index(),
        generation,
        lease.activation_id(),
        lease.ptr(),
        lease.len(),
        lease.writable(),
    );
    Ok(UserDmwLease { lease, resource_handle: Some(resource_handle), generation })
}

fn read_epoll_event(ptr: u64) -> Result<(u32, u64), i32> {
    let lease = user_lease(ptr, EPOLL_EVENT_SIZE, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    let events = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ERR_EINVAL)?);
    let data = u64::from_le_bytes(bytes[4..12].try_into().map_err(|_| ERR_EINVAL)?);
    Ok((events, data))
}

fn map_dmw_fault(fault: crate::substrate::dmw::DmwFault) -> i32 {
    match fault {
        crate::substrate::dmw::DmwFault::NoFreeSlots => ERR_EFAULT,
        crate::substrate::dmw::DmwFault::WindowViolation => {
            crate::kwarn!("WindowViolationTrap while touching guest memory");
            ERR_EFAULT
        }
    }
}

fn read_user_c_string(ptr: u64, max_len: usize) -> Result<Vec<u8>, i32> {
    let lease = user_lease(ptr, max_len as u64, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    let mut out = Vec::new();
    for byte in bytes.iter().copied() {
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
        active_context().supervisor.getcwd().map_err(|_| ERR_EBADF)?
    } else if dirfd >= 0 {
        active_context().supervisor.fd_path(dirfd as u32).map_err(|_| ERR_EBADF)?
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
