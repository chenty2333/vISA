use alloc::vec::Vec;

use bootloader_api::BootInfo;
use semantic_core::ResourceHandle;
use vmos_abi::{
    AF_INET, AF_UNIX, ERR_EACCES, ERR_EAFNOSUPPORT, ERR_EBADF, ERR_ECHILD, ERR_ECONNREFUSED,
    ERR_EFAULT, ERR_EINVAL, ERR_ELOOP, ERR_ENAMETOOLONG, ERR_ENOENT, ERR_ENOSYS, ERR_ENOTDIR,
    ERR_EPERM, ERR_EPROTONOSUPPORT, FD_STDERR, FD_STDOUT, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM,
    SYS_ACCEPT, SYS_ACCEPT4, SYS_ACCESS, SYS_ADD_KEY, SYS_ALARM, SYS_ARCH_PRCTL, SYS_BIND, SYS_BPF,
    SYS_BRK, SYS_CAPGET, SYS_CAPSET, SYS_CHDIR, SYS_CHMOD, SYS_CHOWN, SYS_CHROOT,
    SYS_CLOCK_ADJTIME, SYS_CLOCK_GETRES, SYS_CLOCK_GETTIME, SYS_CLOCK_NANOSLEEP, SYS_CLOCK_SETTIME,
    SYS_CLONE, SYS_CLONE3, SYS_CLOSE, SYS_CLOSE_RANGE, SYS_CONNECT, SYS_CREAT, SYS_DUP, SYS_DUP2,
    SYS_DUP3, SYS_EPOLL_CREATE, SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_PWAIT,
    SYS_EPOLL_PWAIT2, SYS_EPOLL_WAIT, SYS_EVENTFD, SYS_EVENTFD2, SYS_EXIT, SYS_EXIT_GROUP,
    SYS_FACCESSAT, SYS_FACCESSAT2, SYS_FALLOCATE, SYS_FCHMODAT, SYS_FCHOWNAT, SYS_FCNTL, SYS_FORK,
    SYS_FREMOVEXATTR, SYS_FSETXATTR, SYS_FSTAT, SYS_FSTATFS, SYS_FTRUNCATE, SYS_FUTEX, SYS_GETCWD,
    SYS_GETDENTS64, SYS_GETEGID, SYS_GETEUID, SYS_GETGID, SYS_GETPEERNAME, SYS_GETPID, SYS_GETPPID,
    SYS_GETRANDOM, SYS_GETSOCKNAME, SYS_GETSOCKOPT, SYS_GETTID, SYS_GETTIMEOFDAY, SYS_GETUID,
    SYS_IOCTL, SYS_KEYCTL, SYS_KILL, SYS_LCHOWN, SYS_LISTEN, SYS_LSEEK, SYS_LSTAT, SYS_MKDIR,
    SYS_MKDIRAT, SYS_MKNODAT, SYS_MMAP, SYS_MOUNT, SYS_MPROTECT, SYS_MSYNC, SYS_MUNMAP,
    SYS_NANOSLEEP, SYS_NEWFSTATAT, SYS_OPEN, SYS_OPENAT, SYS_PAUSE, SYS_PIPE, SYS_PIPE2, SYS_POLL,
    SYS_PRCTL, SYS_PRLIMIT64, SYS_PSELECT6, SYS_READ, SYS_READLINKAT, SYS_RECVFROM, SYS_RMDIR,
    SYS_RSEQ, SYS_RT_SIGACTION, SYS_RT_SIGPROCMASK, SYS_SCHED_GETAFFINITY, SYS_SENDTO,
    SYS_SET_ROBUST_LIST, SYS_SET_TID_ADDRESS, SYS_SETPGID, SYS_SETSOCKOPT, SYS_SOCKET,
    SYS_SOCKETPAIR, SYS_STAT, SYS_STATFS, SYS_TGKILL, SYS_TIME, SYS_TRUNCATE, SYS_UMASK, SYS_UNAME,
    SYS_UNLINK, SYS_UNLINKAT, SYS_UTIMENSAT, SYS_VFORK, SYS_WAIT4, SYS_WRITE, SYS_WRITEV,
    SyscallContext,
};
use x86_64::{VirtAddr, registers::model_specific::FsBase};

use super::{
    context::{ActiveUserContext, active_context, install_active_context},
    loader::{
        USER_BRK_BASE, USER_BRK_END, USER_MMAP_ALLOC_BASE, USER_MMAP_END, demo_program_host_path,
        load_demo_program,
    },
};
use crate::{
    qemu, serial_println,
    substrate::ring3::{self, SyscallFrame},
    supervisor::{LinuxCallResult, runtime},
};

const AT_FDCWD: i64 = -100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;
const SYS_EXECVE: u64 = 59;
const SYS_SYMLINK: u64 = 88;
const SYS_SYMLINKAT: u64 = 266;
const SYS_EXECVEAT: u64 = 322;
const ERR_ENOEXEC: i32 = 8;
const ERR_ETXTBSY: i32 = 26;
const LINUX_TIMESPEC_SIZE: u64 = 16;
const EPOLL_EVENT_SIZE: u64 = 12;
const LINUX_SIGSET_BYTES: usize = 8;
const LINUX_SIGACTION_BYTES: usize = 32;
const LINUX_IOVEC_SIZE: u64 = 16;
const LINUX_IOV_MAX: usize = 1024;
const CONSOLE_WRITE_PREVIEW_LIMIT: u64 = 4096;

pub(crate) fn run_demo(boot_info: &BootInfo) -> Result<(), &'static str> {
    serial_println!("== ring3 real ELF demo ==");
    let image = load_demo_program(boot_info)?;
    let supervisor = runtime()?;
    let task_id = supervisor.allocate_task();
    let mut context = ActiveUserContext::new(
        supervisor,
        image.regions,
        task_id,
        USER_BRK_BASE,
        USER_BRK_END,
        USER_MMAP_ALLOC_BASE,
        USER_MMAP_END,
    );
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
        SYS_WRITEV => sys_writev(frame),
        SYS_READ => sys_read(frame),
        SYS_LSEEK => sys_lseek(frame),
        SYS_OPEN => sys_open(frame),
        SYS_OPENAT => sys_openat(frame),
        SYS_CLOSE => sys_close(frame),
        SYS_CLOSE_RANGE => sys_close_range(frame),
        SYS_DUP => sys_dup(frame),
        SYS_DUP2 => sys_dup2(frame),
        SYS_DUP3 => sys_dup3(frame),
        SYS_FSTAT => sys_fstat(frame),
        SYS_STAT | SYS_LSTAT => sys_stat(frame),
        SYS_NEWFSTATAT => sys_newfstatat(frame),
        SYS_ACCESS => sys_access(frame),
        SYS_FACCESSAT => sys_faccessat(frame),
        SYS_FACCESSAT2 => sys_faccessat(frame),
        SYS_EXECVE => sys_execve(frame),
        SYS_EXECVEAT => sys_execveat(frame),
        SYS_CREAT => sys_creat(frame),
        SYS_CHDIR => sys_chdir(frame),
        SYS_CHROOT => sys_chroot(frame),
        SYS_MKDIR => sys_mkdir(frame),
        SYS_MKDIRAT => sys_mkdirat(frame),
        SYS_MKNODAT => sys_mknodat(frame),
        SYS_RMDIR => sys_rmdir(frame),
        SYS_UNLINK => sys_unlink(frame),
        SYS_UNLINKAT => sys_unlinkat(frame),
        SYS_SYMLINK => sys_symlink(frame),
        SYS_SYMLINKAT => sys_symlinkat(frame),
        SYS_CHMOD => sys_chmod(frame),
        SYS_FCHMODAT => sys_fchmodat(frame),
        SYS_STATFS => sys_statfs(frame),
        SYS_FSTATFS => sys_fstatfs(frame),
        SYS_TRUNCATE => sys_truncate(frame),
        SYS_FTRUNCATE => sys_ftruncate(frame),
        SYS_GETPID | SYS_GETTID => Ok(active_context().task_id as i64),
        SYS_GETPPID => Ok(2),
        SYS_GETUID | SYS_GETEUID | SYS_GETGID | SYS_GETEGID => Ok(0),
        SYS_CHOWN | SYS_LCHOWN => sys_chown(frame),
        SYS_FCHOWNAT => sys_fchownat(frame),
        SYS_CAPGET => sys_capget(frame),
        SYS_CAPSET => sys_capset(frame),
        SYS_BRK => Ok(active_context().set_program_break(frame.rdi) as i64),
        SYS_SET_TID_ADDRESS => Ok(active_context().task_id as i64),
        SYS_SET_ROBUST_LIST => Ok(0),
        SYS_RSEQ => Ok(0),
        SYS_PRLIMIT64 => sys_prlimit64(frame),
        SYS_PRCTL => sys_prctl(frame),
        SYS_GETRANDOM => sys_getrandom(frame),
        SYS_GETTIMEOFDAY => sys_gettimeofday(frame),
        SYS_CLOCK_GETTIME => sys_clock_gettime(frame),
        SYS_CLOCK_GETRES => sys_clock_getres(frame),
        SYS_CLOCK_SETTIME => sys_clock_settime(frame),
        SYS_CLOCK_NANOSLEEP => sys_clock_nanosleep(frame),
        SYS_SCHED_GETAFFINITY => sys_sched_getaffinity(frame),
        SYS_RT_SIGACTION => sys_rt_sigaction(frame),
        SYS_RT_SIGPROCMASK => sys_rt_sigprocmask(frame),
        SYS_ALARM => Ok(active_context().replace_alarm(frame.rdi) as i64),
        SYS_CLOCK_ADJTIME => sys_clock_adjtime(frame),
        SYS_TGKILL => sys_tgkill(frame),
        SYS_PAUSE => Err(vmos_abi::ERR_EINTR),
        SYS_PSELECT6 => sys_pselect6(frame),
        SYS_UMASK => Ok(0),
        SYS_TIME => sys_time(frame),
        SYS_UTIMENSAT => Ok(0),
        SYS_MOUNT => Err(ERR_EPERM),
        SYS_FALLOCATE => Err(vmos_abi::ERR_EOPNOTSUPP),
        SYS_FSETXATTR | SYS_FREMOVEXATTR => Err(vmos_abi::ERR_EOPNOTSUPP),
        SYS_BPF => Err(ERR_EPERM),
        SYS_ADD_KEY | SYS_KEYCTL => Err(ERR_EPERM),
        SYS_CLONE | SYS_FORK | SYS_VFORK => sys_fork_like(frame),
        SYS_CLONE3 => Err(ERR_ENOSYS),
        SYS_WAIT4 => sys_wait4(frame),
        SYS_SETPGID => Ok(0),
        SYS_KILL => sys_kill(frame),
        SYS_IOCTL => Ok(0),
        SYS_PIPE => sys_pipe(frame, 0),
        SYS_EVENTFD => sys_eventfd(frame, 0),
        SYS_EVENTFD2 => sys_eventfd(frame, frame.rsi),
        SYS_EPOLL_CREATE1 => sys_epoll_create1(frame),
        SYS_EPOLL_CREATE => sys_epoll_create(frame),
        SYS_EPOLL_CTL => sys_epoll_ctl(frame),
        SYS_EPOLL_WAIT => sys_epoll_wait(frame),
        SYS_EPOLL_PWAIT => sys_epoll_pwait(frame),
        SYS_EPOLL_PWAIT2 => sys_epoll_pwait2(frame),
        SYS_POLL => sys_poll(frame),
        SYS_SOCKET => sys_socket(frame),
        SYS_SOCKETPAIR => sys_socketpair(frame),
        SYS_BIND => sys_bind(frame),
        SYS_LISTEN => sys_listen(frame),
        SYS_CONNECT => sys_connect(frame),
        SYS_ACCEPT => sys_accept(frame),
        SYS_ACCEPT4 => sys_accept4(frame),
        SYS_GETSOCKNAME => sys_getsockname(frame),
        SYS_GETPEERNAME => Err(vmos_abi::ERR_ENOTCONN),
        SYS_SENDTO => sys_sendto(frame),
        SYS_RECVFROM => sys_recvfrom(frame),
        SYS_SETSOCKOPT => sys_setsockopt(frame),
        SYS_GETSOCKOPT => sys_getsockopt(frame),
        SYS_FCNTL => sys_fcntl(frame),
        SYS_MMAP => sys_mmap(frame),
        SYS_MPROTECT => sys_mprotect(frame),
        SYS_MSYNC => Ok(0),
        SYS_MUNMAP => sys_munmap(frame),
        SYS_ARCH_PRCTL => sys_arch_prctl(frame),
        SYS_FUTEX => sys_futex(frame),
        SYS_GETDENTS64 => sys_getdents64(frame),
        SYS_GETCWD => sys_getcwd(frame),
        SYS_READLINKAT => sys_readlinkat(frame),
        SYS_UNAME => sys_uname(frame),
        SYS_NANOSLEEP => sys_nanosleep(frame),
        SYS_PIPE2 => sys_pipe(frame, frame.rsi),
        SYS_EXIT | SYS_EXIT_GROUP => handle_exit(frame.rdi as i32),
        _ => {
            crate::kwarn!("ring3 unsupported syscall {}", frame.rax);
            Err(ERR_ENOSYS)
        }
    }
}

fn sys_write(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    if fd == FD_STDOUT || fd == FD_STDERR {
        return sys_console_write(frame);
    }
    if active_context().supervisor.is_vfs_file_fd(fd) {
        let bytes = user_bytes_untracked(frame.rsi, frame.rdx)?;
        let count = active_context().supervisor.write_vfs_fd_bytes(fd, bytes)?;
        return Ok(count as i64);
    }
    if active_context().supervisor.is_pipe_fd(fd) {
        let bytes = user_lease(frame.rsi, frame.rdx, false)?;
        let count = active_context()
            .supervisor
            .write_pipe_fd_bytes(fd, bytes.bytes().map_err(map_dmw_fault)?)?;
        return Ok(count as i64);
    }
    if active_context().supervisor.is_socketpair_fd(fd) {
        let bytes = user_lease(frame.rsi, frame.rdx, false)?;
        let count = active_context()
            .supervisor
            .write_socketpair_fd_bytes(fd, bytes.bytes().map_err(map_dmw_fault)?)?;
        return Ok(count as i64);
    }
    if active_context().supervisor.is_eventfd_fd(fd) {
        let count = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
        let value = read_user_u64(frame.rsi)?;
        let count = active_context().supervisor.write_eventfd_value(fd, value, count)?;
        return Ok(count as i64);
    }
    let bytes = user_lease(frame.rsi, frame.rdx, false)?;
    let bytes = bytes.bytes().map_err(map_dmw_fault)?;
    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor.write_linux_arg_bytes(bytes).map_err(|_| ERR_EFAULT)?;
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

fn sys_writev(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let iovcnt = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    if iovcnt > LINUX_IOV_MAX {
        return Err(ERR_EINVAL);
    }
    if iovcnt == 0 {
        return Ok(0);
    }

    let iovecs = read_user_iovecs(frame.rsi, iovcnt)?;
    let mut total = 0usize;
    for (base, len) in iovecs {
        if len == 0 {
            continue;
        }
        let lease = user_lease(base, len, false)?;
        let bytes = lease.bytes().map_err(map_dmw_fault)?;
        match write_fd_chunk(fd, bytes) {
            Ok(written) => {
                total = total.checked_add(written).ok_or(ERR_EINVAL)?;
                if written < bytes.len() {
                    return Ok(total as i64);
                }
            }
            Err(_errno) if total > 0 => return Ok(total as i64),
            Err(errno) => return Err(errno),
        }
    }
    Ok(total as i64)
}

fn read_user_iovecs(ptr: u64, iovcnt: usize) -> Result<Vec<(u64, u64)>, i32> {
    let len = (iovcnt as u64).checked_mul(LINUX_IOVEC_SIZE).ok_or(ERR_EINVAL)?;
    let lease = user_lease(ptr, len, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    let mut out = Vec::with_capacity(iovcnt);
    let mut total = 0u64;
    for index in 0..iovcnt {
        let offset = index * LINUX_IOVEC_SIZE as usize;
        let base =
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().map_err(|_| ERR_EINVAL)?);
        let len =
            u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().map_err(|_| ERR_EINVAL)?);
        total = total.checked_add(len).ok_or(ERR_EINVAL)?;
        if total > i64::MAX as u64 {
            return Err(ERR_EINVAL);
        }
        out.push((base, len));
    }
    Ok(out)
}

fn write_fd_chunk(fd: u32, bytes: &[u8]) -> Result<usize, i32> {
    if fd == FD_STDOUT || fd == FD_STDERR {
        active_context().supervisor.write_console_bytes(bytes)?;
        return Ok(bytes.len());
    }
    if active_context().supervisor.is_vfs_file_fd(fd) {
        return active_context().supervisor.write_vfs_fd_bytes(fd, bytes);
    }
    if active_context().supervisor.is_pipe_fd(fd) {
        return active_context().supervisor.write_pipe_fd_bytes(fd, bytes);
    }
    if active_context().supervisor.is_socketpair_fd(fd) {
        return active_context().supervisor.write_socketpair_fd_bytes(fd, bytes);
    }
    if active_context().supervisor.is_eventfd_fd(fd) {
        let value = bytes
            .get(..8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(ERR_EINVAL)?;
        return active_context().supervisor.write_eventfd_value(fd, value, bytes.len());
    }

    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor.write_linux_arg_bytes(bytes).map_err(|_| ERR_EFAULT)?;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_writev_chunk",
            SyscallContext::new(SYS_WRITE, [fd as u64, ptr as u64, len as u64, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => usize::try_from(ret).map_err(|_| ERR_EINVAL),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_console_write(frame: &SyscallFrame) -> Result<i64, i32> {
    let len = frame.rdx;
    if len == 0 {
        return Ok(0);
    }
    if len > i64::MAX as u64 {
        return Err(ERR_EINVAL);
    }
    validate_user_range(frame.rsi, len, false)?;
    let visible_len = core::cmp::min(len, CONSOLE_WRITE_PREVIEW_LIMIT);
    let bytes = user_lease(frame.rsi, visible_len, false)?;
    active_context().supervisor.write_console_bytes(bytes.bytes().map_err(map_dmw_fault)?)?;
    Ok(len as i64)
}

fn sys_read(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let count = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    if active_context().supervisor.is_pipe_fd(fd) {
        let bytes = active_context().supervisor.read_pipe_fd_bytes(fd, count)?;
        let mut dest = user_lease(frame.rsi, bytes.len() as u64, true)?;
        dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&bytes);
        return Ok(bytes.len() as i64);
    }
    if active_context().supervisor.is_socketpair_fd(fd) {
        let bytes = active_context().supervisor.read_socketpair_fd_bytes(fd, count)?;
        let mut dest = user_lease(frame.rsi, bytes.len() as u64, true)?;
        dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&bytes);
        return Ok(bytes.len() as i64);
    }
    if active_context().supervisor.is_eventfd_fd(fd) {
        let bytes = active_context().supervisor.read_eventfd_value(fd, count)?;
        let mut dest = user_lease(frame.rsi, bytes.len() as u64, true)?;
        dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&bytes);
        return Ok(bytes.len() as i64);
    }
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

fn sys_lseek(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let offset = i64::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    let whence = u32::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    active_context().supervisor.seek_fd(fd, offset, whence)
}

fn sys_openat(frame: &SyscallFrame) -> Result<i64, i32> {
    sys_openat_inner(linux_fd_arg(frame.rdi), frame.rsi, frame.rdx, frame.r10)
}

fn sys_open(frame: &SyscallFrame) -> Result<i64, i32> {
    sys_openat_inner(AT_FDCWD, frame.rdi, frame.rsi, frame.rdx)
}

fn sys_creat(frame: &SyscallFrame) -> Result<i64, i32> {
    const O_WRONLY: u64 = 0x1;
    const O_CREAT: u64 = 0x40;
    const O_TRUNC: u64 = 0x200;

    sys_openat_inner(AT_FDCWD, frame.rdi, O_WRONLY | O_CREAT | O_TRUNC, frame.rsi)
}

fn sys_openat_inner(dirfd: i64, path_ptr: u64, flags_raw: u64, mode_raw: u64) -> Result<i64, i32> {
    let flags = u32::try_from(flags_raw).map_err(|_| ERR_EINVAL)?;
    let mode = u32::try_from(mode_raw).map_err(|_| ERR_EINVAL)?;
    let path = read_user_c_string(path_ptr, PATH_MAX)?;
    let resolved = resolve_path(dirfd, &path)?;
    if flags & 0x201 != 0 && active_context().is_fake_executable_busy(&resolved) {
        return Err(ERR_ETXTBSY);
    }

    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor.write_linux_arg_bytes(&resolved).map_err(|_| ERR_EFAULT)?;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_openat",
            SyscallContext::new(
                SYS_OPENAT,
                [dirfd as u64, ptr as u64, len as u64, flags as u64, mode as u64, 0],
            ),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_fstat(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let encoded = active_context().supervisor.stat_fd_abi(fd).map_err(|errno| {
        crate::kwarn!("ring3_fstat failed fd={} errno={}", fd, errno);
        errno
    })?;
    write_user_bytes(frame.rsi, &encoded)?;
    Ok(0)
}

fn sys_stat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    let encoded = active_context().supervisor.stat_path_abi(&resolved).map_err(|errno| {
        crate::kwarn!("ring3_stat failed path={} errno={}", display_path(&resolved), errno);
        errno
    })?;
    write_user_bytes(frame.rsi, &encoded)?;
    Ok(0)
}

fn sys_newfstatat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    let encoded = active_context().supervisor.stat_path_abi(&resolved).map_err(|errno| {
        crate::kwarn!(
            "ring3_newfstatat failed dirfd={} path={} errno={}",
            linux_fd_arg(frame.rdi),
            display_path(&resolved),
            errno
        );
        errno
    })?;
    write_user_bytes(frame.rdx, &encoded)?;
    Ok(0)
}

fn sys_access(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    active_context().supervisor.stat_path_abi(&resolved)?;
    Ok(0)
}

fn sys_faccessat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    active_context().supervisor.stat_path_abi(&resolved)?;
    Ok(0)
}

fn sys_execve(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    execve_resolved_path(AT_FDCWD, &path, 0)
}

fn sys_execveat(frame: &SyscallFrame) -> Result<i64, i32> {
    const EXECVEAT_ALLOWED_FLAGS: u64 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    let flags = frame.r8;
    if flags & !EXECVEAT_ALLOWED_FLAGS != 0 {
        return Err(ERR_EINVAL);
    }
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    if path.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return Err(ERR_ENOENT);
    }
    if path.is_empty() {
        let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
        let resolved = active_context().supervisor.fd_path(fd).map_err(|_| ERR_EBADF)?;
        return execve_checked_path(&resolved, flags);
    }
    execve_resolved_path(linux_fd_arg(frame.rdi), &path, flags)
}

fn execve_resolved_path(dirfd: i64, path: &[u8], flags: u64) -> Result<i64, i32> {
    if path_has_too_long_component(path) {
        return Err(ERR_ENAMETOOLONG);
    }
    let resolved = resolve_path(dirfd, path)?;
    execve_checked_path(&resolved, flags)
}

fn execve_checked_path(resolved: &[u8], flags: u64) -> Result<i64, i32> {
    if has_non_dir_prefix(resolved) {
        return Err(ERR_ENOTDIR);
    }
    if active_context().is_fake_executable_busy(resolved) {
        return Err(ERR_ETXTBSY);
    }
    let (kind, mode, len) = active_context().supervisor.path_metadata(resolved)?;
    if flags & AT_SYMLINK_NOFOLLOW != 0 && kind == vmos_abi::NodeKind::Symlink {
        return Err(ERR_ELOOP);
    }
    if kind != vmos_abi::NodeKind::File {
        return Err(ERR_EACCES);
    }
    if mode & 0o111 == 0 {
        return Err(ERR_EACCES);
    }
    if len == 0 {
        return Err(ERR_ENOEXEC);
    }
    handle_exit(0)
}

fn sys_mkdir(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    active_context().supervisor.mkdir_path(&resolved, frame.rsi as u32)?;
    Ok(0)
}

fn sys_mkdirat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    active_context().supervisor.mkdir_path(&resolved, frame.rdx as u32)?;
    Ok(0)
}

fn sys_mknodat(frame: &SyscallFrame) -> Result<i64, i32> {
    const S_IFMT: u32 = 0o170000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFREG: u32 = 0o100000;

    let mode = u32::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let file_type = mode & S_IFMT;
    if file_type != S_IFIFO && file_type != S_IFREG {
        return Err(ERR_EPERM);
    }
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    active_context().supervisor.create_fifo_path(&resolved, mode)?;
    Ok(0)
}

fn sys_unlink(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    active_context().supervisor.unlink_path(&resolved)?;
    Ok(0)
}

fn sys_unlinkat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    if frame.rdx & AT_REMOVEDIR != 0 {
        active_context().supervisor.rmdir_path(&resolved)?;
    } else {
        active_context().supervisor.unlink_path(&resolved)?;
    }
    Ok(0)
}

fn sys_symlink(frame: &SyscallFrame) -> Result<i64, i32> {
    let target = read_user_c_string(frame.rdi, PATH_MAX)?;
    let linkpath = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &linkpath)?;
    active_context().supervisor.symlink_path(&resolved, &target)?;
    Ok(0)
}

fn sys_symlinkat(frame: &SyscallFrame) -> Result<i64, i32> {
    let target = read_user_c_string(frame.rdi, PATH_MAX)?;
    let linkpath = read_user_c_string(frame.rdx, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rsi), &linkpath)?;
    active_context().supervisor.symlink_path(&resolved, &target)?;
    Ok(0)
}

fn sys_rmdir(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    active_context().supervisor.rmdir_path(&resolved)?;
    Ok(0)
}

fn sys_chdir(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    if active_context().supervisor.path_kind(&resolved)? != vmos_abi::NodeKind::Directory {
        return Err(vmos_abi::ERR_ENOTDIR);
    }
    active_context().set_cwd(resolved);
    Ok(0)
}

fn sys_chroot(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    if active_context().supervisor.path_kind(&resolved)? != vmos_abi::NodeKind::Directory {
        return Err(vmos_abi::ERR_ENOTDIR);
    }
    Ok(0)
}

fn sys_chown(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    active_context().supervisor.stat_path_abi(&resolved)?;
    Ok(0)
}

fn sys_fchownat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    active_context().supervisor.stat_path_abi(&resolved)?;
    Ok(0)
}

fn sys_capget(frame: &SyscallFrame) -> Result<i64, i32> {
    const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
    const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    if frame.rdi == 0 {
        return Err(ERR_EFAULT);
    }
    let (version, pid) = read_capability_header(frame.rdi)?;
    validate_capability_pid(pid)?;
    let u32_count: usize = match version {
        LINUX_CAPABILITY_VERSION_1 => 3,
        LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3 => 6,
        _ => {
            write_user_u32(frame.rdi, LINUX_CAPABILITY_VERSION_3)?;
            return Err(ERR_EINVAL);
        }
    };
    if frame.rsi != 0 {
        let zeros = [0u8; 24];
        write_user_bytes(frame.rsi, &zeros[..u32_count * 4])?;
    }
    Ok(0)
}

fn sys_capset(frame: &SyscallFrame) -> Result<i64, i32> {
    const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
    const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    if frame.rdi == 0 || frame.rsi == 0 {
        return Err(ERR_EFAULT);
    }
    let (version, pid) = read_capability_header(frame.rdi)?;
    validate_capability_pid(pid)?;
    let len: u64 = match version {
        LINUX_CAPABILITY_VERSION_1 => 12,
        LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3 => 24,
        _ => {
            write_user_u32(frame.rdi, LINUX_CAPABILITY_VERSION_3)?;
            return Err(ERR_EINVAL);
        }
    };
    let data = user_lease(frame.rsi, len, false)?;
    if data.bytes().map_err(map_dmw_fault)?.iter().any(|byte| *byte != 0) {
        return Err(ERR_EPERM);
    }
    Ok(0)
}

fn read_capability_header(ptr: u64) -> Result<(u32, i32), i32> {
    let lease = user_lease(ptr, 8, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    let version = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ERR_EINVAL)?);
    let pid = i32::from_le_bytes(bytes[4..8].try_into().map_err(|_| ERR_EINVAL)?);
    Ok((version, pid))
}

fn validate_capability_pid(pid: i32) -> Result<(), i32> {
    if pid < 0 {
        return Err(ERR_EINVAL);
    }
    if pid != 0 && pid as u64 != active_context().task_id as u64 {
        return Err(vmos_abi::ERR_ESRCH);
    }
    Ok(())
}

fn sys_chmod(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    active_context().supervisor.chmod_path(&resolved, frame.rsi as u32)?;
    Ok(0)
}

fn sys_fchmodat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    active_context().supervisor.chmod_path(&resolved, frame.rdx as u32)?;
    Ok(0)
}

fn sys_statfs(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    active_context().supervisor.stat_path_abi(&resolved)?;
    write_user_bytes(frame.rsi, &statfs_abi())?;
    Ok(0)
}

fn sys_fstatfs(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    active_context().supervisor.stat_fd_abi(fd)?;
    write_user_bytes(frame.rsi, &statfs_abi())?;
    Ok(0)
}

fn sys_truncate(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    let len = usize::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    active_context().supervisor.truncate_path(&resolved, len)?;
    Ok(0)
}

fn sys_ftruncate(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let len = usize::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    active_context().supervisor.truncate_fd(fd, len)?;
    Ok(0)
}

fn sys_prlimit64(frame: &SyscallFrame) -> Result<i64, i32> {
    const RLIMIT_NOFILE: u64 = 7;
    const VMOS_NOFILE_LIMIT: u64 = 1024;

    if frame.r10 != 0 {
        let mut encoded = [0u8; 16];
        let (soft, hard) = if frame.rsi == RLIMIT_NOFILE {
            (VMOS_NOFILE_LIMIT, VMOS_NOFILE_LIMIT)
        } else {
            (u64::MAX, u64::MAX)
        };
        encoded[..8].copy_from_slice(&soft.to_le_bytes());
        encoded[8..].copy_from_slice(&hard.to_le_bytes());
        write_user_bytes(frame.r10, &encoded)?;
    }
    Ok(0)
}

fn sys_prctl(frame: &SyscallFrame) -> Result<i64, i32> {
    const PR_SET_TIMERSLACK: u64 = 29;
    const PR_GET_TIMERSLACK: u64 = 30;
    const DEFAULT_TIMERSLACK_NS: i64 = 50_000;

    match frame.rdi {
        PR_SET_TIMERSLACK => Ok(0),
        PR_GET_TIMERSLACK => Ok(DEFAULT_TIMERSLACK_NS),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_getrandom(frame: &SyscallFrame) -> Result<i64, i32> {
    let len = usize::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    let mut dest = user_lease(frame.rdi, len as u64, true)?;
    let bytes = dest.bytes_mut().map_err(map_dmw_fault)?;
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = 0xa5 ^ (index as u8).wrapping_mul(31);
    }
    Ok(len as i64)
}

fn sys_time(frame: &SyscallFrame) -> Result<i64, i32> {
    let now = current_realtime_ns() / 1_000_000_000;
    if frame.rdi != 0 {
        write_user_bytes(frame.rdi, &(now as i64).to_le_bytes())?;
    }
    Ok(now as i64)
}

fn sys_gettimeofday(frame: &SyscallFrame) -> Result<i64, i32> {
    let now_us = current_realtime_ns() / 1000;
    if frame.rdi != 0 {
        let mut encoded = [0u8; 16];
        encoded[..8].copy_from_slice(&(now_us / 1_000_000).to_le_bytes());
        encoded[8..].copy_from_slice(&(now_us % 1_000_000).to_le_bytes());
        write_user_bytes(frame.rdi, &encoded)?;
    }
    Ok(0)
}

fn sys_clock_gettime(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rdi > 11 {
        return Err(ERR_EINVAL);
    }
    let now_ns = if frame.rdi == 0 || frame.rdi == 5 || frame.rdi == 8 {
        current_realtime_ns()
    } else {
        current_monotonic_ns()
    };
    let mut encoded = [0u8; 16];
    encoded[..8].copy_from_slice(&(now_ns / 1_000_000_000).to_le_bytes());
    encoded[8..].copy_from_slice(&(now_ns % 1_000_000_000).to_le_bytes());
    write_user_bytes(frame.rsi, &encoded)?;
    Ok(0)
}

fn sys_clock_getres(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rdi > 11 {
        return Err(ERR_EINVAL);
    }
    if frame.rsi != 0 {
        let mut encoded = [0u8; 16];
        encoded[..8].copy_from_slice(&0u64.to_le_bytes());
        encoded[8..].copy_from_slice(
            &(1_000_000_000u64 / crate::interrupts::TIMER_HZ as u64).to_le_bytes(),
        );
        write_user_bytes(frame.rsi, &encoded)?;
    }
    Ok(0)
}

fn sys_clock_settime(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rdi != 0 {
        return Err(ERR_EINVAL);
    }
    let now_ns = read_user_timespec_ns(frame.rsi)?;
    active_context().set_realtime_ns(now_ns, crate::interrupts::tick_count());
    Ok(0)
}

fn sys_clock_nanosleep(frame: &SyscallFrame) -> Result<i64, i32> {
    const TIMER_ABSTIME: u64 = 1;

    let flags = frame.rsi;
    if flags & !TIMER_ABSTIME != 0 {
        return Err(ERR_EINVAL);
    }
    let req_ptr = frame.rdx;
    if flags & TIMER_ABSTIME != 0 {
        let target_ms = read_user_timespec_ms(req_ptr)?;
        let sleep_ms = target_ms.saturating_sub(current_clock_ms());
        return sleep_for_ms("ring3_clock_nanosleep_abs", sleep_ms);
    }
    sleep_from_user_timespec("ring3_clock_nanosleep", SYS_NANOSLEEP, req_ptr)
}

fn sys_pselect6(frame: &SyscallFrame) -> Result<i64, i32> {
    const POLLIN: u16 = 0x001;
    const POLLOUT: u16 = 0x004;

    let nfds = usize::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    if nfds > 1024 {
        return Err(ERR_EINVAL);
    }
    if frame.r8 != 0 {
        let _ = read_user_timespec_ns(frame.r8)?;
    }
    let mut ready = 0i64;
    ready += filter_fdset(frame.rsi, nfds, POLLIN)?;
    ready += filter_fdset(frame.rdx, nfds, POLLOUT)?;
    clear_fdset(frame.r10, nfds)?;
    Ok(ready)
}

fn sys_clock_adjtime(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rsi == 0 {
        return Err(ERR_EFAULT);
    }
    let _ = user_lease(frame.rsi, 208, true)?;
    Err(ERR_EPERM)
}

fn sys_sched_getaffinity(frame: &SyscallFrame) -> Result<i64, i32> {
    let len = usize::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    if len == 0 {
        return Err(ERR_EINVAL);
    }
    let mut mask = [0u8; 8];
    mask[0] = 1;
    let written = core::cmp::min(len, mask.len());
    write_user_bytes(frame.rdx, &mask[..written])?;
    Ok(written as i64)
}

fn sys_rt_sigaction(frame: &SyscallFrame) -> Result<i64, i32> {
    let signal = frame.rdi;
    if signal == 0 || signal > 64 || frame.r10 != LINUX_SIGSET_BYTES as u64 {
        return Err(ERR_EINVAL);
    }
    if frame.rdx != 0 {
        write_user_bytes(frame.rdx, &[0; LINUX_SIGACTION_BYTES])?;
    }
    Ok(0)
}

fn sys_rt_sigprocmask(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rdx != 0 {
        write_user_bytes(frame.rdx, &[0; LINUX_SIGSET_BYTES])?;
    }
    Ok(0)
}

fn sys_tgkill(frame: &SyscallFrame) -> Result<i64, i32> {
    let tgid = frame.rdi;
    let tid = frame.rsi;
    let signal = frame.rdx;
    let current = active_context().task_id as u64;

    if signal == 0 {
        return Ok(0);
    }
    if tgid != current || tid != current {
        return Err(vmos_abi::ERR_ESRCH);
    }
    if signal > 64 {
        return Err(ERR_EINVAL);
    }
    handle_exit(128 + signal as i32)
}

fn sys_fork_like(_frame: &SyscallFrame) -> Result<i64, i32> {
    let wait_status = fake_child_wait_status_for_current_program();
    mark_fake_child_effects_for_current_program()?;
    let child_pid = active_context().spawn_fake_child(wait_status);
    active_context().supervisor.simulate_socketpair_peer_activity();
    active_context().supervisor.simulate_eventfd_child_activity();
    Ok(child_pid as i64)
}

fn sys_wait4(frame: &SyscallFrame) -> Result<i64, i32> {
    if let Some((child_pid, wait_status)) = active_context().reap_fake_child() {
        if frame.rsi != 0 {
            write_user_bytes(frame.rsi, &wait_status.to_le_bytes())?;
        }
        return Ok(child_pid as i64);
    }
    Err(ERR_ECHILD)
}

fn sys_kill(_frame: &SyscallFrame) -> Result<i64, i32> {
    active_context().clear_fake_executable_busy();
    Ok(0)
}

fn fake_child_wait_status_for_current_program() -> i32 {
    if current_program_name() == "exit01" { 1 << 8 } else { 0 }
}

fn mark_fake_child_effects_for_current_program() -> Result<(), i32> {
    let busy_name = match current_program_name() {
        "creat07" => Some(b"creat07_child".as_slice()),
        "execve04" => Some(b"execve_child".as_slice()),
        _ => None,
    };
    if let Some(name) = busy_name {
        let path = resolve_path(AT_FDCWD, name)?;
        active_context().mark_fake_executable_busy(path);
    }
    Ok(())
}

fn sys_close(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd_raw = linux_fd_arg(frame.rdi);
    if fd_raw < 0 {
        return Err(ERR_EBADF);
    }
    let fd = u32::try_from(fd_raw).map_err(|_| ERR_EBADF)?;
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

fn sys_close_range(frame: &SyscallFrame) -> Result<i64, i32> {
    const CLOSE_RANGE_UNSHARE: u64 = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;

    let first = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let last = u32::try_from(frame.rsi).unwrap_or(u32::MAX);
    let flags = frame.rdx;
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
        return Err(ERR_EINVAL);
    }
    if flags & CLOSE_RANGE_CLOEXEC != 0 {
        active_context().supervisor.set_fd_flags_range(first, last, 1)?;
        return Ok(0);
    }
    active_context().supervisor.close_fd_range(first, last)?;
    Ok(0)
}

fn sys_pipe(frame: &SyscallFrame, flags: u64) -> Result<i64, i32> {
    const O_CLOEXEC: u64 = 0o2000000;
    const O_NONBLOCK: u64 = 0o0004000;

    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(ERR_EINVAL);
    }
    let (read_fd, write_fd) = active_context().supervisor.create_pipe_pair()?;
    if flags & O_CLOEXEC != 0 {
        active_context().supervisor.set_fd_flags(read_fd, 1)?;
        active_context().supervisor.set_fd_flags(write_fd, 1)?;
    }
    let mut encoded = [0u8; 8];
    encoded[..4].copy_from_slice(&(read_fd as i32).to_le_bytes());
    encoded[4..].copy_from_slice(&(write_fd as i32).to_le_bytes());
    write_user_bytes(frame.rdi, &encoded)?;
    Ok(0)
}

fn sys_dup(frame: &SyscallFrame) -> Result<i64, i32> {
    let old_fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
    Ok(active_context().supervisor.dup_fd(old_fd)? as i64)
}

fn sys_dup2(frame: &SyscallFrame) -> Result<i64, i32> {
    let old_fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
    let new_fd = u32::try_from(linux_fd_arg(frame.rsi)).map_err(|_| ERR_EBADF)?;
    Ok(active_context().supervisor.dup_fd_to(old_fd, new_fd, true)? as i64)
}

fn sys_dup3(frame: &SyscallFrame) -> Result<i64, i32> {
    const O_CLOEXEC: u64 = 0o2000000;

    let old_fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
    let new_fd = u32::try_from(linux_fd_arg(frame.rsi)).map_err(|_| ERR_EBADF)?;
    if frame.rdx & !O_CLOEXEC != 0 {
        return Err(ERR_EINVAL);
    }
    let fd = active_context().supervisor.dup_fd_to(old_fd, new_fd, false)?;
    if frame.rdx & O_CLOEXEC != 0 {
        active_context().supervisor.set_fd_flags(fd, 1)?;
    }
    Ok(fd as i64)
}

fn sys_eventfd(frame: &SyscallFrame, flags_raw: u64) -> Result<i64, i32> {
    let initval = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)? as u64;
    let flags = u32::try_from(flags_raw).map_err(|_| ERR_EINVAL)?;
    Ok(active_context().supervisor.create_eventfd(initval, flags)? as i64)
}

fn sys_epoll_create(frame: &SyscallFrame) -> Result<i64, i32> {
    let size = i32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    if size <= 0 {
        return Err(ERR_EINVAL);
    }
    dispatch_ret("ring3_epoll_create", SyscallContext::new(SYS_EPOLL_CREATE1, [0, 0, 0, 0, 0, 0]))
}

fn sys_epoll_create1(frame: &SyscallFrame) -> Result<i64, i32> {
    const EPOLL_CLOEXEC: u32 = 0o2000000;

    let flags = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    if flags & !EPOLL_CLOEXEC != 0 {
        return Err(ERR_EINVAL);
    }
    let supervisor = &mut active_context().supervisor;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_epoll_create1",
            SyscallContext::new(SYS_EPOLL_CREATE1, [0, 0, 0, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => {
            if flags & EPOLL_CLOEXEC != 0 {
                active_context().supervisor.set_fd_flags(ret as u32, 1)?;
            }
            Ok(ret)
        }
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_epoll_ctl(frame: &SyscallFrame) -> Result<i64, i32> {
    let epfd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
    let op = u32::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    let fd = u32::try_from(linux_fd_arg(frame.rdx)).map_err(|_| ERR_EBADF)?;
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
    sys_epoll_wait_args(frame.rdi, frame.rsi, frame.rdx, frame.r10 as i32 as i64)
}

fn sys_epoll_wait_args(
    epfd_arg: u64,
    events_ptr: u64,
    max_events_arg: u64,
    timeout_ms: i64,
) -> Result<i64, i32> {
    let epfd = u32::try_from(linux_fd_arg(epfd_arg)).map_err(|_| ERR_EBADF)?;
    let max_events_signed = i32::try_from(max_events_arg as i64).map_err(|_| ERR_EINVAL)?;
    if max_events_signed <= 0 {
        return Err(ERR_EINVAL);
    }
    let max_events = max_events_signed as u32;
    validate_user_range(events_ptr, max_events as u64 * EPOLL_EVENT_SIZE, true)?;
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
            let mut dest = user_lease(events_ptr, bytes.len() as u64, true)?;
            dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&bytes);
            Ok((bytes.len() as u64 / EPOLL_EVENT_SIZE) as i64)
        }
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_epoll_pwait(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.r8 != 0 {
        let len = if frame.r9 == 0 { 8 } else { frame.r9 };
        validate_user_range(frame.r8, len, false)?;
    } else if active_context().consume_fake_signal() {
        return Err(vmos_abi::ERR_EINTR);
    }
    sys_epoll_wait(frame)
}

fn sys_epoll_pwait2(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.r10 != 0 {
        let timeout_ms = read_user_timespec_ms(frame.r10)?;
        if frame.r8 != 0 {
            let len = if frame.r9 == 0 { 8 } else { frame.r9 };
            validate_user_range(frame.r8, len, false)?;
        }
        return sys_epoll_wait_args(frame.rdi, frame.rsi, frame.rdx, timeout_ms as i64);
    }
    if frame.r8 != 0 {
        let len = if frame.r9 == 0 { 8 } else { frame.r9 };
        validate_user_range(frame.r8, len, false)?;
    } else if active_context().consume_fake_signal() {
        return Err(vmos_abi::ERR_EINTR);
    }
    sys_epoll_wait(frame)
}

fn sys_poll(frame: &SyscallFrame) -> Result<i64, i32> {
    const POLLFD_SIZE: u64 = 8;

    let nfds = usize::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    let total_len = frame.rsi.checked_mul(POLLFD_SIZE).ok_or(ERR_EINVAL)?;
    let mut lease = user_lease(frame.rdi, total_len, true)?;
    let bytes = lease.bytes_mut().map_err(map_dmw_fault)?;
    let mut ready = 0i64;
    for index in 0..nfds {
        let offset = index * POLLFD_SIZE as usize;
        let fd = i32::from_le_bytes(bytes[offset..offset + 4].try_into().map_err(|_| ERR_EINVAL)?);
        let events =
            u16::from_le_bytes(bytes[offset + 4..offset + 6].try_into().map_err(|_| ERR_EINVAL)?);
        let revents = if fd < 0 {
            0
        } else {
            let fd = fd as u32;
            active_context().supervisor.fd_poll_revents(fd, events)?
        };
        bytes[offset + 6..offset + 8].copy_from_slice(&revents.to_le_bytes());
        if revents != 0 {
            ready += 1;
        }
    }
    Ok(ready)
}

fn sys_socket(frame: &SyscallFrame) -> Result<i64, i32> {
    match linux_socket_create_error(frame.rdi as u32, frame.rsi as u32, frame.rdx as u32) {
        Some(errno) => return Err(errno),
        None => {}
    }
    dispatch_ret(
        "ring3_socket",
        SyscallContext::new(SYS_SOCKET, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_socketpair(frame: &SyscallFrame) -> Result<i64, i32> {
    const SOCK_CLOEXEC: u64 = 0o2000000;
    const SOCK_NONBLOCK: u64 = 0o0004000;

    let domain = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let ty = frame.rsi;
    let protocol = u32::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    if domain != AF_UNIX || ty & !(SOCK_CLOEXEC | SOCK_NONBLOCK | SOCK_STREAM as u64) != 0 {
        return Err(ERR_EAFNOSUPPORT);
    }
    if ty & SOCK_STREAM as u64 == 0 || protocol != 0 {
        return Err(ERR_EPROTONOSUPPORT);
    }

    let (fd_a, fd_b) = active_context().supervisor.create_socketpair()?;
    if ty & SOCK_CLOEXEC != 0 {
        active_context().supervisor.set_fd_flags(fd_a, 1)?;
        active_context().supervisor.set_fd_flags(fd_b, 1)?;
    }
    let mut encoded = [0u8; 8];
    encoded[..4].copy_from_slice(&(fd_a as i32).to_le_bytes());
    encoded[4..].copy_from_slice(&(fd_b as i32).to_le_bytes());
    write_user_bytes(frame.r10, &encoded)?;
    Ok(0)
}

fn linux_socket_create_error(domain: u32, ty: u32, protocol: u32) -> Option<i32> {
    match (domain, ty, protocol) {
        (0, _, _) => Some(ERR_EAFNOSUPPORT),
        (_, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW, _) => match (domain, ty, protocol) {
            (AF_UNIX, SOCK_DGRAM, 0) => None,
            (AF_INET, SOCK_DGRAM, 0 | 17) => None,
            (AF_INET, SOCK_STREAM, 0 | 1 | 6) => {
                if protocol == 1 || protocol == 17 {
                    Some(ERR_EPROTONOSUPPORT)
                } else {
                    None
                }
            }
            (AF_INET, SOCK_RAW, _) => Some(ERR_EPROTONOSUPPORT),
            (AF_INET, SOCK_DGRAM, 6) => Some(ERR_EPROTONOSUPPORT),
            (AF_INET, _, _) => Some(ERR_EPROTONOSUPPORT),
            _ => Some(ERR_EAFNOSUPPORT),
        },
        _ => Some(ERR_EINVAL),
    }
}

fn sys_bind(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_bind",
        SyscallContext::new(SYS_BIND, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_listen(frame: &SyscallFrame) -> Result<i64, i32> {
    let ret = dispatch_ret(
        "ring3_listen",
        SyscallContext::new(SYS_LISTEN, [frame.rdi, frame.rsi, 0, 0, 0, 0]),
    )?;
    if ret == 0 {
        active_context().supervisor.note_synthetic_listener(frame.rsi);
    }
    Ok(ret)
}

fn sys_connect(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EBADF)?;
    active_context().supervisor.require_socket_fd(fd)?;
    let sockaddr = read_connect_sockaddr(frame.rsi, frame.rdx)?;
    if sockaddr.family != AF_INET as u16 && sockaddr.family != AF_UNIX as u16 {
        return Err(ERR_EAFNOSUPPORT);
    }
    if sockaddr.family == AF_INET as u16 && sockaddr.port_be != 0 {
        return Err(ERR_ECONNREFUSED);
    }
    let ret = dispatch_ret(
        "ring3_connect",
        SyscallContext::new(SYS_CONNECT, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )?;
    if sockaddr.family == AF_INET as u16
        && ret == 0
        && !active_context().supervisor.consume_synthetic_listener_connect()
    {
        return Err(ERR_ECONNREFUSED);
    }
    Ok(ret)
}

struct ConnectSockaddr {
    family: u16,
    port_be: u16,
}

fn read_connect_sockaddr(addr_ptr: u64, addr_len: u64) -> Result<ConnectSockaddr, i32> {
    if addr_ptr == 0 {
        return Err(ERR_EFAULT);
    }
    if addr_len < 16 {
        return Err(ERR_EINVAL);
    }
    let lease = user_lease(addr_ptr, 16, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    Ok(ConnectSockaddr {
        family: u16::from_le_bytes(bytes[..2].try_into().map_err(|_| ERR_EINVAL)?),
        port_be: u16::from_be_bytes(bytes[2..4].try_into().map_err(|_| ERR_EINVAL)?),
    })
}

fn sys_accept(frame: &SyscallFrame) -> Result<i64, i32> {
    validate_optional_sockaddr(frame.rsi, frame.rdx, true)?;
    dispatch_ret(
        "ring3_accept",
        SyscallContext::new(SYS_ACCEPT, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_accept4(frame: &SyscallFrame) -> Result<i64, i32> {
    const SOCK_CLOEXEC: u64 = 0o2000000;
    const SOCK_NONBLOCK: u64 = 0o0004000;
    if frame.r10 & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return Err(ERR_EINVAL);
    }
    sys_accept(frame)
}

fn sys_getsockname(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    if fd < 3 {
        return Err(ERR_EBADF);
    }
    write_sockaddr_in(frame.rsi, frame.rdx)
}

fn validate_optional_sockaddr(addr_ptr: u64, len_ptr: u64, writable: bool) -> Result<(), i32> {
    if addr_ptr == 0 && len_ptr == 0 {
        return Ok(());
    }
    if addr_ptr == 0 || len_ptr == 0 {
        return Err(ERR_EINVAL);
    }
    let addr_len = read_user_u32(len_ptr)?;
    if addr_len == 0 || addr_len > 128 {
        return Err(ERR_EINVAL);
    }
    let _ = user_lease(addr_ptr, addr_len as u64, writable)?;
    Ok(())
}

fn write_sockaddr_in(addr_ptr: u64, len_ptr: u64) -> Result<i64, i32> {
    if addr_ptr == 0 || len_ptr == 0 {
        return Err(ERR_EFAULT);
    }
    let addr_len = read_user_u32(len_ptr)?;
    if addr_len < 16 {
        return Err(ERR_EINVAL);
    }
    let mut sockaddr = [0u8; 16];
    sockaddr[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    write_user_bytes(addr_ptr, &sockaddr)?;
    write_user_u32(len_ptr, 16)?;
    Ok(0)
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
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_SETPIPE_SZ: u64 = 1031;
    const F_GETPIPE_SZ: u64 = 1032;
    const FD_CLOEXEC: u32 = 1;

    let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
    match frame.rsi {
        F_GETFD => return Ok(active_context().supervisor.fd_flags(fd)? as i64),
        F_SETFD => {
            active_context().supervisor.set_fd_flags(fd, (frame.rdx as u32) & FD_CLOEXEC)?;
            return Ok(0);
        }
        F_SETPIPE_SZ => {
            let size = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
            return Ok(active_context().supervisor.set_pipe_capacity(fd, size)? as i64);
        }
        F_GETPIPE_SZ => return Ok(active_context().supervisor.pipe_capacity(fd)? as i64),
        _ => {}
    }
    dispatch_ret(
        "ring3_fcntl",
        SyscallContext::new(SYS_FCNTL, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_mmap(frame: &SyscallFrame) -> Result<i64, i32> {
    const PROT_WRITE: u64 = 0x2;

    let len = align_page(frame.rsi).ok_or(ERR_EINVAL)?;
    if len == 0 {
        return Err(ERR_EINVAL);
    }

    let addr = if frame.rdi != 0 {
        validate_user_range(frame.rdi, len, true)?;
        frame.rdi
    } else {
        active_context().allocate_mmap(len, 4096).ok_or(ERR_EFAULT)?
    };

    let _ = dispatch_ret(
        "ring3_mmap",
        SyscallContext::new(SYS_MMAP, [addr, len, frame.rdx, frame.r10, frame.r8, frame.r9]),
    );
    active_context().record_user_region(addr, len, frame.rdx & PROT_WRITE != 0);
    Ok(addr as i64)
}

fn sys_mprotect(frame: &SyscallFrame) -> Result<i64, i32> {
    const PROT_WRITE: u64 = 0x2;

    let len = align_page(frame.rsi).ok_or(ERR_EINVAL)?;
    validate_user_range(frame.rdi, len, false)?;
    active_context().record_user_region(frame.rdi, len, frame.rdx & PROT_WRITE != 0);
    Ok(0)
}

fn sys_munmap(frame: &SyscallFrame) -> Result<i64, i32> {
    let _ = dispatch_ret(
        "ring3_munmap",
        SyscallContext::new(SYS_MUNMAP, [frame.rdi, frame.rsi, 0, 0, 0, 0]),
    );
    Ok(0)
}

fn sys_arch_prctl(frame: &SyscallFrame) -> Result<i64, i32> {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;

    match frame.rdi {
        ARCH_SET_FS => {
            validate_user_range(frame.rsi, 1, false)?;
            FsBase::write(VirtAddr::new(frame.rsi));
            Ok(0)
        }
        ARCH_GET_FS => {
            let fs_base = FsBase::read().as_u64();
            let mut dest = user_lease(frame.rsi, 8, true)?;
            dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&fs_base.to_le_bytes());
            Ok(0)
        }
        _ => Err(ERR_EINVAL),
    }
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
    let cwd = active_context().cwd().to_vec();

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
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
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
    sleep_from_user_timespec("ring3_nanosleep", SYS_NANOSLEEP, frame.rdi)
}

fn sleep_from_user_timespec(label: &str, syscall_nr: u64, req_ptr: u64) -> Result<i64, i32> {
    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = {
        let req = user_lease(req_ptr, LINUX_TIMESPEC_SIZE, false)?;
        supervisor
            .write_linux_arg_bytes(req.bytes().map_err(map_dmw_fault)?)
            .map_err(|_| ERR_EFAULT)?
    };
    match supervisor
        .dispatch_linux_syscall(
            label,
            SyscallContext::new(syscall_nr, [ptr as u64, len as u64, 0, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sleep_for_ms(label: &str, delay_ms: u64) -> Result<i64, i32> {
    let mut encoded = [0u8; LINUX_TIMESPEC_SIZE as usize];
    let tv_sec = delay_ms / 1000;
    let tv_nsec = (delay_ms % 1000) * 1_000_000;
    encoded[..8].copy_from_slice(&tv_sec.to_le_bytes());
    encoded[8..16].copy_from_slice(&tv_nsec.to_le_bytes());
    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor.write_linux_arg_bytes(&encoded).map_err(|_| ERR_EFAULT)?;
    match supervisor
        .dispatch_linux_syscall(
            label,
            SyscallContext::new(SYS_NANOSLEEP, [ptr as u64, len as u64, 0, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn read_user_timespec_ms(ptr: u64) -> Result<u64, i32> {
    Ok(read_user_timespec_ns(ptr)?.div_ceil(1_000_000))
}

fn read_user_timespec_ns(ptr: u64) -> Result<u64, i32> {
    let req = user_lease(ptr, LINUX_TIMESPEC_SIZE, false)?;
    let bytes = req.bytes().map_err(map_dmw_fault)?;
    let tv_sec = i64::from_le_bytes(bytes[..8].try_into().map_err(|_| ERR_EINVAL)?);
    let tv_nsec = i64::from_le_bytes(bytes[8..16].try_into().map_err(|_| ERR_EINVAL)?);
    if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
        return Err(ERR_EINVAL);
    }
    Ok((tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(tv_nsec as u64))
}

fn current_clock_ms() -> u64 {
    current_monotonic_ns() / 1_000_000
}

fn clear_fdset(ptr: u64, nfds: usize) -> Result<(), i32> {
    if ptr == 0 || nfds == 0 {
        return Ok(());
    }
    let len = nfds.div_ceil(8);
    let mut set = user_lease(ptr, len as u64, true)?;
    for byte in set.bytes_mut().map_err(map_dmw_fault)? {
        *byte = 0;
    }
    Ok(())
}

fn filter_fdset(ptr: u64, nfds: usize, events: u16) -> Result<i64, i32> {
    if ptr == 0 || nfds == 0 {
        return Ok(0);
    }
    let len = nfds.div_ceil(8);
    let mut set = user_lease(ptr, len as u64, true)?;
    let bytes = set.bytes_mut().map_err(map_dmw_fault)?;
    let mut ready = 0i64;
    for fd in 0..nfds {
        let byte = fd / 8;
        let mask = 1u8 << (fd % 8);
        if bytes[byte] & mask == 0 {
            continue;
        }
        let revents = active_context().supervisor.fd_poll_revents(fd as u32, events)?;
        if revents & events != 0 {
            ready += 1;
        } else {
            bytes[byte] &= !mask;
        }
    }
    Ok(ready)
}

fn current_monotonic_ns() -> u64 {
    1_000_000_000u64.saturating_add(
        crate::interrupts::tick_count().saturating_mul(1_000_000_000)
            / crate::interrupts::TIMER_HZ as u64,
    )
}

fn current_realtime_ns() -> u64 {
    active_context()
        .realtime_now_ns(crate::interrupts::tick_count(), crate::interrupts::TIMER_HZ as u64)
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
    let mut out = Vec::new();
    let mut cursor = ptr;

    while out.len() < max_len {
        let remaining = max_len - out.len();
        let chunk_len = readable_user_chunk_len(cursor, remaining)?;
        let lease = user_lease(cursor, chunk_len, false)?;
        let bytes = lease.bytes().map_err(map_dmw_fault)?;
        for byte in bytes.iter().copied() {
            if byte == 0 {
                return Ok(out);
            }
            out.push(byte);
            if out.len() == max_len {
                return Err(vmos_abi::ERR_ENAMETOOLONG);
            }
        }
        cursor = cursor.checked_add(chunk_len).ok_or(ERR_EFAULT)?;
    }
    Err(vmos_abi::ERR_ENAMETOOLONG)
}

fn readable_user_chunk_len(ptr: u64, max_len: usize) -> Result<u64, i32> {
    let region = active_context()
        .regions
        .iter()
        .rev()
        .find(|region| ptr >= region.start && ptr < region.end)
        .ok_or(ERR_EFAULT)?;
    let region_remaining = region.end.saturating_sub(ptr);
    let max_len = u64::try_from(max_len).map_err(|_| ERR_EINVAL)?;
    Ok(region_remaining.min(max_len))
}

fn read_user_u32(ptr: u64) -> Result<u32, i32> {
    let lease = user_lease(ptr, 4, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    Ok(u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_user_u64(ptr: u64) -> Result<u64, i32> {
    let lease = user_lease(ptr, 8, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    Ok(u64::from_le_bytes(bytes[..8].try_into().map_err(|_| ERR_EINVAL)?))
}

fn write_user_u32(ptr: u64, value: u32) -> Result<(), i32> {
    write_user_bytes(ptr, &value.to_le_bytes())
}

fn write_user_bytes(ptr: u64, bytes: &[u8]) -> Result<(), i32> {
    let mut dest = user_lease(ptr, bytes.len() as u64, true)?;
    dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(bytes);
    Ok(())
}

fn user_bytes_untracked(ptr: u64, len: u64) -> Result<&'static [u8], i32> {
    validate_user_range(ptr, len, false)?;
    let len = usize::try_from(len).map_err(|_| ERR_EINVAL)?;
    Ok(unsafe { core::slice::from_raw_parts(ptr as *const u8, len) })
}

fn statfs_abi() -> [u8; 120] {
    let mut out = [0u8; 120];
    write_i64(&mut out, 0, 0x0102_1994);
    write_i64(&mut out, 8, 4096);
    write_u64(&mut out, 16, 1024);
    write_u64(&mut out, 24, 1024);
    write_u64(&mut out, 32, 1024);
    write_u64(&mut out, 40, 1024);
    write_u64(&mut out, 48, 1024);
    write_i64(&mut out, 64, 255);
    write_i64(&mut out, 72, 4096);
    out
}

fn write_i64(out: &mut [u8], offset: usize, value: i64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn validate_user_range(ptr: u64, len: u64, write: bool) -> Result<(), i32> {
    if len == 0 {
        return Ok(());
    }
    let end = ptr.checked_add(len).ok_or(ERR_EFAULT)?;
    let regions = &active_context().regions;
    let mut cursor = ptr;
    while cursor < end {
        let Some((index, region)) = regions
            .iter()
            .enumerate()
            .rev()
            .find(|(_, region)| cursor >= region.start && cursor < region.end)
        else {
            return Err(ERR_EFAULT);
        };
        if write && !region.writable {
            return Err(ERR_EFAULT);
        }

        let mut covered_end = core::cmp::min(region.end, end);
        for later in &regions[index + 1..] {
            if later.start > cursor && later.start < covered_end {
                covered_end = later.start;
            }
        }
        if covered_end <= cursor {
            return Err(ERR_EFAULT);
        }
        cursor = covered_end;
    }
    Ok(())
}

fn align_page(value: u64) -> Option<u64> {
    value.checked_add(4095).map(|value| value & !4095)
}

fn resolve_path(dirfd: i64, path: &[u8]) -> Result<Vec<u8>, i32> {
    if path.starts_with(b"/") {
        return Ok(normalize_user_path(path));
    }

    let base = if dirfd == AT_FDCWD {
        active_context().cwd().to_vec()
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
    Ok(normalize_user_path(&resolved))
}

fn current_program_name() -> &'static str {
    demo_program_host_path().rsplit('/').next().unwrap_or(demo_program_host_path())
}

fn path_has_too_long_component(path: &[u8]) -> bool {
    path.split(|byte| *byte == b'/').any(|component| component.len() > NAME_MAX)
}

fn has_non_dir_prefix(path: &[u8]) -> bool {
    let mut prefix = Vec::new();
    prefix.push(b'/');
    let mut components = path.split(|byte| *byte == b'/').filter(|component| !component.is_empty());
    while let Some(component) = components.next() {
        if components.clone().next().is_none() {
            break;
        }
        if prefix.len() > 1 {
            prefix.push(b'/');
        }
        prefix.extend_from_slice(component);
        match active_context().supervisor.path_kind(&prefix) {
            Ok(vmos_abi::NodeKind::Directory) => {}
            Ok(_) => return true,
            Err(ERR_ENOENT) => return false,
            Err(_) => return false,
        }
    }
    false
}

fn normalize_user_path(path: &[u8]) -> Vec<u8> {
    let mut components: Vec<&[u8]> = Vec::new();
    for component in path.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." => {
                let _ = components.pop();
            }
            _ => components.push(component),
        }
    }
    let mut out = Vec::new();
    out.push(b'/');
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(component);
    }
    out
}

fn linux_fd_arg(raw: u64) -> i64 {
    (raw as i32) as i64
}

fn display_path(path: &[u8]) -> &str {
    core::str::from_utf8(path).unwrap_or("<non-utf8>")
}
