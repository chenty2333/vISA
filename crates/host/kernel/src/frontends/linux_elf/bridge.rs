use alloc::vec::Vec;

use bootloader_api::BootInfo;
use semantic_core::ResourceHandle;
use vmos_abi::{
    AF_INET, AF_UNIX, ERR_EAFNOSUPPORT, ERR_EBADF, ERR_ECHILD, ERR_EFAULT, ERR_EINVAL, ERR_ENOSYS,
    ERR_EPERM, ERR_EPROTONOSUPPORT, FD_STDERR, FD_STDOUT, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM,
    SYS_ACCEPT, SYS_ACCESS, SYS_ADD_KEY, SYS_ALARM, SYS_ARCH_PRCTL, SYS_BIND, SYS_BRK, SYS_CHDIR,
    SYS_CHMOD, SYS_CHOWN, SYS_CLOCK_ADJTIME, SYS_CLOCK_GETRES, SYS_CLOCK_GETTIME,
    SYS_CLOCK_NANOSLEEP, SYS_CLONE, SYS_CLOSE, SYS_CONNECT, SYS_CREAT, SYS_EPOLL_CREATE1,
    SYS_EPOLL_CTL, SYS_EPOLL_WAIT, SYS_EXIT, SYS_EXIT_GROUP, SYS_FALLOCATE, SYS_FCHMODAT,
    SYS_FCHOWNAT, SYS_FCNTL, SYS_FORK, SYS_FSTAT, SYS_FSTATFS, SYS_FTRUNCATE, SYS_FUTEX,
    SYS_GETCWD, SYS_GETDENTS64, SYS_GETEGID, SYS_GETEUID, SYS_GETGID, SYS_GETPEERNAME, SYS_GETPID,
    SYS_GETPPID, SYS_GETRANDOM, SYS_GETSOCKNAME, SYS_GETSOCKOPT, SYS_GETTID, SYS_GETUID, SYS_IOCTL,
    SYS_KEYCTL, SYS_KILL, SYS_LCHOWN, SYS_LISTEN, SYS_LSEEK, SYS_LSTAT, SYS_MKDIR, SYS_MKDIRAT,
    SYS_MMAP, SYS_MOUNT, SYS_MPROTECT, SYS_MSYNC, SYS_MUNMAP, SYS_NANOSLEEP, SYS_NEWFSTATAT,
    SYS_OPEN, SYS_OPENAT, SYS_PIPE2, SYS_PRCTL, SYS_PRLIMIT64, SYS_READ, SYS_READLINKAT,
    SYS_RECVFROM, SYS_RMDIR, SYS_RSEQ, SYS_RT_SIGACTION, SYS_RT_SIGPROCMASK, SYS_SCHED_GETAFFINITY,
    SYS_SENDTO, SYS_SET_ROBUST_LIST, SYS_SET_TID_ADDRESS, SYS_SETPGID, SYS_SETSOCKOPT, SYS_SOCKET,
    SYS_STAT, SYS_STATFS, SYS_TGKILL, SYS_TRUNCATE, SYS_UMASK, SYS_UNAME, SYS_UNLINK, SYS_UNLINKAT,
    SYS_VFORK, SYS_WAIT4, SYS_WRITE, SyscallContext,
};
use x86_64::{VirtAddr, registers::model_specific::FsBase};

use super::{
    context::{ActiveUserContext, active_context, install_active_context},
    loader::{USER_BRK_BASE, USER_BRK_END, USER_MMAP_ALLOC_BASE, USER_MMAP_END, load_demo_program},
};
use crate::{
    qemu, serial_println,
    substrate::ring3::{self, SyscallFrame},
    supervisor::{LinuxCallResult, runtime},
};

const AT_FDCWD: i64 = -100;
const AT_REMOVEDIR: u64 = 0x200;
const PATH_MAX: usize = 256;
const LINUX_TIMESPEC_SIZE: u64 = 16;
const EPOLL_EVENT_SIZE: u64 = 12;
const LINUX_SIGSET_BYTES: usize = 8;
const LINUX_SIGACTION_BYTES: usize = 32;
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
        SYS_READ => sys_read(frame),
        SYS_LSEEK => sys_lseek(frame),
        SYS_OPEN => sys_open(frame),
        SYS_OPENAT => sys_openat(frame),
        SYS_CLOSE => sys_close(frame),
        SYS_FSTAT => sys_fstat(frame),
        SYS_STAT | SYS_LSTAT => sys_stat(frame),
        SYS_NEWFSTATAT => sys_newfstatat(frame),
        SYS_ACCESS => sys_access(frame),
        SYS_CREAT => sys_creat(frame),
        SYS_CHDIR => sys_chdir(frame),
        SYS_MKDIR => sys_mkdir(frame),
        SYS_MKDIRAT => sys_mkdirat(frame),
        SYS_RMDIR => sys_rmdir(frame),
        SYS_UNLINK => sys_unlink(frame),
        SYS_UNLINKAT => sys_unlinkat(frame),
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
        SYS_BRK => Ok(active_context().set_program_break(frame.rdi) as i64),
        SYS_SET_TID_ADDRESS => Ok(active_context().task_id as i64),
        SYS_SET_ROBUST_LIST => Ok(0),
        SYS_RSEQ => Ok(0),
        SYS_PRLIMIT64 => sys_prlimit64(frame),
        SYS_PRCTL => sys_prctl(frame),
        SYS_GETRANDOM => sys_getrandom(frame),
        SYS_CLOCK_GETTIME => sys_clock_gettime(frame),
        SYS_CLOCK_GETRES => sys_clock_getres(frame),
        SYS_CLOCK_NANOSLEEP => sys_clock_nanosleep(frame),
        SYS_SCHED_GETAFFINITY => sys_sched_getaffinity(frame),
        SYS_RT_SIGACTION => sys_rt_sigaction(frame),
        SYS_RT_SIGPROCMASK => sys_rt_sigprocmask(frame),
        SYS_ALARM => Ok(active_context().replace_alarm(frame.rdi) as i64),
        SYS_CLOCK_ADJTIME => sys_clock_adjtime(frame),
        SYS_TGKILL => sys_tgkill(frame),
        SYS_UMASK => Ok(0),
        SYS_MOUNT => Err(ERR_EPERM),
        SYS_FALLOCATE => Err(vmos_abi::ERR_EOPNOTSUPP),
        SYS_ADD_KEY | SYS_KEYCTL => Err(ERR_EPERM),
        SYS_CLONE | SYS_FORK | SYS_VFORK => sys_fork_like(frame),
        SYS_WAIT4 => sys_wait4(frame),
        SYS_SETPGID => Ok(0),
        SYS_KILL => Ok(0),
        SYS_IOCTL => Ok(0),
        SYS_EPOLL_CREATE1 => sys_epoll_create1(frame),
        SYS_EPOLL_CTL => sys_epoll_ctl(frame),
        SYS_EPOLL_WAIT => sys_epoll_wait(frame),
        SYS_SOCKET => sys_socket(frame),
        SYS_BIND => sys_bind(frame),
        SYS_LISTEN => sys_listen(frame),
        SYS_CONNECT => sys_connect(frame),
        SYS_ACCEPT => sys_accept(frame),
        SYS_GETSOCKNAME => sys_getsockname(frame),
        SYS_GETPEERNAME => Err(vmos_abi::ERR_ENOTCONN),
        SYS_SENDTO => sys_sendto(frame),
        SYS_RECVFROM => sys_recvfrom(frame),
        SYS_SETSOCKOPT => sys_setsockopt(frame),
        SYS_GETSOCKOPT => sys_getsockopt(frame),
        SYS_FCNTL => sys_fcntl(frame),
        SYS_MMAP => sys_mmap(frame),
        SYS_MPROTECT => Ok(0),
        SYS_MSYNC => Ok(0),
        SYS_MUNMAP => sys_munmap(frame),
        SYS_ARCH_PRCTL => sys_arch_prctl(frame),
        SYS_FUTEX => sys_futex(frame),
        SYS_GETDENTS64 => sys_getdents64(frame),
        SYS_GETCWD => sys_getcwd(frame),
        SYS_READLINKAT => sys_readlinkat(frame),
        SYS_UNAME => sys_uname(frame),
        SYS_NANOSLEEP => sys_nanosleep(frame),
        SYS_PIPE2 => Err(ERR_ENOSYS),
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
    if frame.r10 != 0 {
        let mut encoded = [0u8; 16];
        let soft = u64::MAX;
        let hard = u64::MAX;
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

fn sys_clock_gettime(frame: &SyscallFrame) -> Result<i64, i32> {
    let mut encoded = [0u8; 16];
    let tick_ns = 1_000_000_000u64 / crate::interrupts::TIMER_HZ as u64;
    let now_ns =
        1_000_000_000u64.saturating_add(crate::interrupts::tick_count().saturating_mul(tick_ns));
    encoded[..8].copy_from_slice(&(now_ns / 1_000_000_000).to_le_bytes());
    encoded[8..].copy_from_slice(&(now_ns % 1_000_000_000).to_le_bytes());
    write_user_bytes(frame.rsi, &encoded)?;
    Ok(0)
}

fn sys_clock_getres(frame: &SyscallFrame) -> Result<i64, i32> {
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
    Ok(0)
}

fn sys_wait4(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rsi != 0 {
        write_user_bytes(frame.rsi, &0i32.to_le_bytes())?;
    }
    Err(ERR_ECHILD)
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
    match linux_socket_create_error(frame.rdi as u32, frame.rsi as u32, frame.rdx as u32) {
        Some(errno) => return Err(errno),
        None => {}
    }
    dispatch_ret(
        "ring3_socket",
        SyscallContext::new(SYS_SOCKET, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
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
    dispatch_ret(
        "ring3_listen",
        SyscallContext::new(SYS_LISTEN, [frame.rdi, frame.rsi, 0, 0, 0, 0]),
    )
}

fn sys_connect(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_connect",
        SyscallContext::new(SYS_CONNECT, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_accept(frame: &SyscallFrame) -> Result<i64, i32> {
    validate_optional_sockaddr(frame.rsi, frame.rdx, true)?;
    dispatch_ret(
        "ring3_accept",
        SyscallContext::new(SYS_ACCEPT, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
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
    dispatch_ret(
        "ring3_fcntl",
        SyscallContext::new(SYS_FCNTL, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

fn sys_mmap(frame: &SyscallFrame) -> Result<i64, i32> {
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
    Ok(addr as i64)
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
    let req = user_lease(ptr, LINUX_TIMESPEC_SIZE, false)?;
    let bytes = req.bytes().map_err(map_dmw_fault)?;
    let tv_sec = i64::from_le_bytes(bytes[..8].try_into().map_err(|_| ERR_EINVAL)?);
    let tv_nsec = i64::from_le_bytes(bytes[8..16].try_into().map_err(|_| ERR_EINVAL)?);
    if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
        return Err(ERR_EINVAL);
    }
    Ok((tv_sec as u64).saturating_mul(1000).saturating_add((tv_nsec as u64).div_ceil(1_000_000)))
}

fn current_clock_ms() -> u64 {
    1000u64.saturating_add(
        crate::interrupts::tick_count().saturating_mul(1000) / crate::interrupts::TIMER_HZ as u64,
    )
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

fn read_user_u32(ptr: u64) -> Result<u32, i32> {
    let lease = user_lease(ptr, 4, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    Ok(u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ERR_EINVAL)?))
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

fn align_page(value: u64) -> Option<u64> {
    value.checked_add(4095).map(|value| value & !4095)
}

fn resolve_path(dirfd: i64, path: &[u8]) -> Result<Vec<u8>, i32> {
    if path.starts_with(b"/") {
        return Ok(path.to_vec());
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
    Ok(resolved)
}

fn linux_fd_arg(raw: u64) -> i64 {
    (raw as i32) as i64
}

fn display_path(path: &[u8]) -> &str {
    core::str::from_utf8(path).unwrap_or("<non-utf8>")
}
