use alloc::{vec, vec::Vec};

use bootloader_api::BootInfo;
use semantic_core::{CredentialTransitionKind, LinuxCapSets, ResourceHandle};
use service_core::seccomp::{
    AUDIT_ARCH_X86_64, SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_TSYNC, SeccompDecision,
    SeccompFilterProgram, SeccompInstruction, linux_seccomp_notif_sizes_bytes,
    seccomp_action_available_without_listener,
};
use vmos_abi::{
    AF_INET, AF_UNIX, ERR_E2BIG, ERR_EACCES, ERR_EAFNOSUPPORT, ERR_EAGAIN, ERR_EBADF, ERR_EBUSY,
    ERR_ECANCELED, ERR_EDEADLK, ERR_EFAULT, ERR_EINTR, ERR_EINVAL, ERR_ELOOP, ERR_ENAMETOOLONG,
    ERR_ENOENT, ERR_ENOMEM, ERR_ENOSYS, ERR_ENOTDIR, ERR_EOPNOTSUPP, ERR_EPERM,
    ERR_EPROTONOSUPPORT, ERR_ESRCH, FD_STDERR, FD_STDOUT, FUTEX_CLOCK_REALTIME, FUTEX_CMD_MASK,
    FUTEX_CMP_REQUEUE, FUTEX_CMP_REQUEUE_PI, FUTEX_LOCK_PI, FUTEX_LOCK_PI2, FUTEX_OWNER_DIED,
    FUTEX_REQUEUE, FUTEX_TID_MASK, FUTEX_TRYLOCK_PI, FUTEX_UNLOCK_PI, FUTEX_WAIT,
    FUTEX_WAIT_BITSET, FUTEX_WAIT_REQUEUE_PI, FUTEX_WAITERS, FUTEX_WAKE, FUTEX_WAKE_BITSET,
    SO_ERROR, SO_REUSEADDR, SO_REUSEPORT, SO_TYPE, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM, SOL_SOCKET,
    SYS_ACCEPT, SYS_ACCEPT4, SYS_ACCESS, SYS_ADD_KEY, SYS_ALARM, SYS_ARCH_PRCTL, SYS_BIND, SYS_BPF,
    SYS_BRK, SYS_CAPGET, SYS_CAPSET, SYS_CHDIR, SYS_CHMOD, SYS_CHOWN, SYS_CHROOT,
    SYS_CLOCK_ADJTIME, SYS_CLOCK_GETRES, SYS_CLOCK_GETTIME, SYS_CLOCK_NANOSLEEP, SYS_CLOCK_SETTIME,
    SYS_CLONE, SYS_CLONE3, SYS_CLOSE, SYS_CLOSE_RANGE, SYS_CONNECT, SYS_CREAT, SYS_DUP, SYS_DUP2,
    SYS_DUP3, SYS_EPOLL_CREATE, SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_PWAIT,
    SYS_EPOLL_PWAIT2, SYS_EPOLL_WAIT, SYS_EVENTFD, SYS_EVENTFD2, SYS_EXIT, SYS_EXIT_GROUP,
    SYS_FACCESSAT, SYS_FACCESSAT2, SYS_FALLOCATE, SYS_FCHMODAT, SYS_FCHOWNAT, SYS_FCNTL,
    SYS_FGETXATTR, SYS_FLISTXATTR, SYS_FLOCK, SYS_FORK, SYS_FREMOVEXATTR, SYS_FSETXATTR, SYS_FSTAT,
    SYS_FSTATFS, SYS_FTRUNCATE, SYS_FUTEX, SYS_GET_ROBUST_LIST, SYS_GETCWD, SYS_GETDENTS64,
    SYS_GETEGID, SYS_GETEUID, SYS_GETGID, SYS_GETPEERNAME, SYS_GETPGID, SYS_GETPGRP, SYS_GETPID,
    SYS_GETPPID, SYS_GETRANDOM, SYS_GETRLIMIT, SYS_GETSID, SYS_GETSOCKNAME, SYS_GETSOCKOPT,
    SYS_GETTID, SYS_GETTIMEOFDAY, SYS_GETUID, SYS_IOCTL, SYS_KEYCTL, SYS_KILL, SYS_LCHOWN,
    SYS_LINK, SYS_LINKAT, SYS_LISTEN, SYS_LSEEK, SYS_LSTAT, SYS_MADVISE, SYS_MKDIR, SYS_MKDIRAT,
    SYS_MKNODAT, SYS_MMAP, SYS_MOUNT, SYS_MPROTECT, SYS_MREMAP, SYS_MSYNC, SYS_MUNMAP,
    SYS_NANOSLEEP, SYS_NEWFSTATAT, SYS_OPEN, SYS_OPENAT, SYS_PAUSE, SYS_PIPE, SYS_PIPE2, SYS_POLL,
    SYS_PPOLL, SYS_PRCTL, SYS_PREADV, SYS_PREADV2, SYS_PRLIMIT64, SYS_PSELECT6, SYS_PWRITEV,
    SYS_PWRITEV2, SYS_READ, SYS_READLINK, SYS_READLINKAT, SYS_READV, SYS_RECVFROM, SYS_RENAME,
    SYS_RENAMEAT, SYS_RENAMEAT2, SYS_RMDIR, SYS_RSEQ, SYS_RT_SIGACTION, SYS_RT_SIGPENDING,
    SYS_RT_SIGPROCMASK, SYS_RT_SIGRETURN, SYS_RT_SIGSUSPEND, SYS_RT_SIGTIMEDWAIT,
    SYS_SCHED_GETAFFINITY, SYS_SECCOMP, SYS_SELECT, SYS_SENDTO, SYS_SET_ROBUST_LIST,
    SYS_SET_TID_ADDRESS, SYS_SETPGID, SYS_SETRLIMIT, SYS_SETSID, SYS_SETSOCKOPT, SYS_SIGALTSTACK,
    SYS_SOCKET, SYS_SOCKETPAIR, SYS_STAT, SYS_STATFS, SYS_TGKILL, SYS_TIME, SYS_TIMERFD_CREATE,
    SYS_TIMERFD_GETTIME, SYS_TIMERFD_SETTIME, SYS_TRUNCATE, SYS_UMASK, SYS_UNAME, SYS_UNLINK,
    SYS_UNLINKAT, SYS_UTIMENSAT, SYS_VFORK, SYS_WAIT4, SYS_WRITE, SYS_WRITEV, SyscallContext,
};
use x86_64::{
    PhysAddr, VirtAddr, registers::model_specific::FsBase, structures::paging::PhysFrame,
};

use super::{
    context::{
        ActiveUserContext, ClockAdjustmentState, CredentialState, ExecFileCapabilities,
        UserAddressSpaceState, UserPageBacking, UserPageMapping, UserRegion, active_context,
        install_active_context, try_active_context,
    },
    loader::{
        ExecStackCredentials, USER_BRK_BASE, USER_BRK_END, USER_MMAP_ALLOC_BASE, USER_MMAP_END,
        clone_user_page_mappings, copy_user_page_bytes, cow_break_user_page,
        demo_program_host_path, discard_user_page_range, discard_zero_user_page_range,
        fill_user_page_frame, load_demo_program, populate_user_page_range,
        prefault_user_page_range, prepare_user_program, protect_user_page_range,
        switch_user_page_mappings, unmap_user_page_range, user_elf_interpreter_path,
    },
};
use crate::{
    qemu, serial_println,
    substrate::ring3::{self, SyscallFrame, UserReturnContext},
    supervisor::{
        LinuxCallResult, runtime,
        types::{
            AccessIds, CAP_SETGID, CAP_SETPCAP, CAP_SYS_ADMIN, CAP_SYS_CHROOT, CAP_SYS_RESOURCE,
            LINUX_KNOWN_CAPS, LINUX_SUPPORTED_SECUREBITS, PendingSignal, RLIMIT_AS, RLIMIT_NOFILE,
            Rlimit, RobustListRegistration, RseqRegistration, SIGALTSTACK_SS_AUTODISARM,
            SIGALTSTACK_SS_DISABLE, SIGALTSTACK_SS_ONSTACK, ServiceCallError, SigAction,
            SignalAltStack, UserSignalDelivery,
        },
    },
};

const AT_FDCWD: i64 = -100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_EACCESS: u64 = 0x200;
const UTIME_NOW: i64 = 1_073_741_823;
const UTIME_OMIT: i64 = 1_073_741_822;
const RENAME_NOREPLACE: u64 = 1;
const RENAME_EXCHANGE: u64 = 2;
const RENAME_WHITEOUT: u64 = 4;
const RENAME_SUPPORTED_FLAGS: u64 = RENAME_NOREPLACE | RENAME_EXCHANGE;
const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;
const SECURITY_CAPABILITY_XATTR: &[u8] = b"security.capability";
const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_ATTR_MAX_SIZE: usize = 256;
const BPF_ATTR_MAP_CREATE_SIZE: usize = 20;
const BPF_ATTR_MAP_LOOKUP_SIZE: usize = 24;
const BPF_ATTR_MAP_UPDATE_SIZE: usize = 32;
const BPF_ATTR_MAP_DELETE_SIZE: usize = 16;
const SYS_EXECVE: u64 = 59;
const SYS_PREAD64: u64 = 17;
const SYS_PWRITE64: u64 = 18;
const SYS_SYMLINK: u64 = 88;
const SYS_SETUID: u64 = 105;
const SYS_SETGID: u64 = 106;
const SYS_SETREUID: u64 = 113;
const SYS_SETREGID: u64 = 114;
const SYS_GETGROUPS: u64 = 115;
const SYS_SETGROUPS: u64 = 116;
const SYS_SETRESUID: u64 = 117;
const SYS_GETRESUID: u64 = 118;
const SYS_SETRESGID: u64 = 119;
const SYS_GETRESGID: u64 = 120;
const SYS_SETFSUID: u64 = 122;
const SYS_SETFSGID: u64 = 123;
const SYS_UMOUNT2: u64 = 166;
const SYS_SYMLINKAT: u64 = 266;
const SYS_EXECVEAT: u64 = 322;
const ERR_ENOEXEC: i32 = 8;
const ERR_ENODEV: i32 = 19;
const ERR_ENOTTY: i32 = 25;
const LINUX_TIMESPEC_SIZE: u64 = 16;
const LINUX_TIMEVAL_SIZE: u64 = 16;
const LINUX_ITIMERSPEC_SIZE: usize = 32;
const LINUX_RUSAGE_SIZE: usize = 144;
const EPOLL_EVENT_SIZE: u64 = 12;
const LINUX_SIGSET_BYTES: usize = 8;
const LINUX_SIGACTION_BYTES: usize = 32;
const LINUX_STACK_T_BYTES: usize = 24;
const MINSIGSTKSZ: u64 = 2048;
const PSELECT6_SIGMASK_ARG_BYTES: usize = 16;
const PSELECT6_MAX_FDS: usize = 1024;
const PSELECT6_FDSET_WORDS: usize = PSELECT6_MAX_FDS / 64;
const LINUX_IOVEC_SIZE: u64 = 16;
const LINUX_IOV_MAX: usize = 1024;
const RWF_NOWAIT: u64 = 0x0000_0008;
const RWF_APPEND: u64 = 0x0000_0010;
const O_NONBLOCK: u32 = 0o4000;
const EXEC_ARG_MAX_BYTES: usize = 131_072;
const EXEC_ARG_MAX_STRINGS: usize = 4096;
const CONSOLE_WRITE_PREVIEW_LIMIT: u64 = 4096;
const X86_64_USER_CANONICAL_LIMIT: u64 = 0x0000_8000_0000_0000;
const ROBUST_LIST_HEAD_SIZE: u64 = 24;
const ROBUST_LIST_LIMIT: usize = 2048;
const SIGSYS: u8 = 31;
const SI_CODE_SYS_SECCOMP: i32 = 1;
const SA_SIGINFO: u64 = 0x4;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_RESTART: u64 = 0x1000_0000;
const FCNTL_F_SETLKW: u64 = 7;
const VMOS_SIGNAL_FRAME_MAGIC: u64 = 0x564d_4f53_5349_4746; // "VMOSSIGF"
const VMOS_SIGNAL_FRAME_SIZE: usize = 160;
const VMOS_SIGNAL_FRAME_ALTSTACK_RESTORE_OFFSET: usize = 136;
const LINUX_SIGINFO_SIZE: usize = 128;
const LINUX_UCONTEXT_MIN_SIZE: usize = 968;
const LINUX_UCONTEXT_STACK_OFFSET: usize = 16;
const LINUX_UCONTEXT_MCONTEXT_OFFSET: usize = 40;
const LINUX_UCONTEXT_SIGMASK_OFFSET: usize = 296;
const LINUX_UCONTEXT_FPREGS_MEM_OFFSET: usize = 424;
const LINUX_MCONTEXT_FPREGS_OFFSET: usize = 184;
const LINUX_GREG_R8: usize = 0;
const LINUX_GREG_R9: usize = 1;
const LINUX_GREG_R10: usize = 2;
const LINUX_GREG_R11: usize = 3;
const LINUX_GREG_RDI: usize = 8;
const LINUX_GREG_RSI: usize = 9;
const LINUX_GREG_RDX: usize = 12;
const LINUX_GREG_RAX: usize = 13;
const LINUX_GREG_RCX: usize = 14;
const LINUX_GREG_RSP: usize = 15;
const LINUX_GREG_RIP: usize = 16;
const LINUX_GREG_EFL: usize = 17;
const LINUX_GREG_OLDMASK: usize = 21;
const RFLAGS_FORCED_USER_BITS: u64 = 0x202;
const RFLAGS_RESTORABLE_USER_MASK: u64 = 0x0024_0cd5;
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x100000;

#[derive(Clone, Copy)]
struct PselectFdSetSnapshot {
    read_ptr: u64,
    write_ptr: u64,
    except_ptr: u64,
    nfds: usize,
    read_bits: [u64; PSELECT6_FDSET_WORDS],
    write_bits: [u64; PSELECT6_FDSET_WORDS],
    except_bits: [u64; PSELECT6_FDSET_WORDS],
}

struct PselectReadySet {
    ready: i64,
    read_bits: [u64; PSELECT6_FDSET_WORDS],
    write_bits: [u64; PSELECT6_FDSET_WORDS],
}

#[derive(Clone, Copy)]
struct PollFdEntry {
    fd: i32,
    events: u16,
    revents: u16,
}

pub(crate) fn run_demo(boot_info: &'static BootInfo) -> Result<(), &'static str> {
    serial_println!("== ring3 real ELF demo ==");
    let image = load_demo_program(boot_info)?;
    let physical_memory_offset = boot_info
        .physical_memory_offset
        .as_ref()
        .copied()
        .ok_or("bootloader did not provide physical_memory_offset")?;
    let supervisor = runtime()?;
    let task_id = supervisor.bind_bootstrap_linux_task();
    let mut context = ActiveUserContext::new(
        supervisor,
        image.regions,
        image.page_mappings,
        image.frame_allocator,
        task_id,
        1, // pid: bootstrap init process
        1, // tid: bootstrap thread
        USER_BRK_BASE,
        USER_BRK_END,
        USER_MMAP_ALLOC_BASE,
        USER_MMAP_END,
        physical_memory_offset,
        b"/bin/vmos-ltp".to_vec(),
    );
    install_active_context(&mut context);

    crate::kinfo!("entering ring3 ELF demo");
    ring3::enter_user_mode(image.entry, image.stack_top);
}

pub(crate) extern "C" fn syscall_dispatch_from_asm(frame: *mut SyscallFrame) {
    let frame = unsafe { &mut *frame };
    let syscall_nr = frame.rax;
    match dispatch_syscall(frame) {
        Ok(ret) => frame.rax = ret as u64,
        Err(errno) => frame.rax = (-(errno as i64)) as u64,
    }
    if syscall_nr != SYS_RT_SIGRETURN {
        deliver_pending_signal_to_user(frame, syscall_nr);
    }
}

fn dispatch_syscall(frame: &mut SyscallFrame) -> Result<i64, i32> {
    let syscall_nr = frame.rax;
    let (task_id, activation_id) = {
        let context = active_context();
        (context.task_id, context.begin_activation())
    };
    let _activation = ActivationGuard { activation_id };
    active_context().supervisor.set_current_task(task_id);
    let seccomp_call_addr = seccomp_syscall_instruction_addr(frame);
    match active_context().supervisor.check_seccomp_syscall(
        active_context().tid,
        syscall_nr,
        seccomp_call_addr,
        [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9],
    ) {
        SeccompDecision::Allow => {}
        SeccompDecision::Log { data } => {
            crate::kinfo!(
                "seccomp log syscall={} tid={} data={}",
                syscall_nr,
                active_context().tid,
                data
            );
        }
        SeccompDecision::Errno(errno) => return Ok(-(errno as i64)),
        SeccompDecision::Trap { errno } => {
            let syscall = syscall_nr.min(u32::MAX as u64) as u32;
            active_context().supervisor.queue_seccomp_trap_to_thread(
                active_context().tid,
                seccomp_call_addr,
                syscall,
                AUDIT_ARCH_X86_64,
                errno,
            );
            return Ok(syscall_nr as i64);
        }
        SeccompDecision::Trace | SeccompDecision::UserNotif => return Err(ERR_ENOSYS),
        SeccompDecision::Kill { signal } => {
            crate::kwarn!("seccomp killed syscall {}", syscall_nr);
            return handle_exit_syscall(frame, 128 + signal as i32);
        }
    }
    let result = match syscall_nr {
        SYS_WRITE => sys_write(frame),
        SYS_WRITEV => sys_writev(frame),
        SYS_READ => sys_read(frame),
        SYS_READV => sys_readv(frame),
        SYS_PREADV => sys_preadv(frame),
        SYS_PWRITEV => sys_pwritev(frame),
        SYS_PREADV2 => sys_preadv2(frame),
        SYS_PWRITEV2 => sys_pwritev2(frame),
        SYS_PREAD64 => sys_pread64(frame),
        SYS_PWRITE64 => sys_pwrite64(frame),
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
        SYS_LINK => sys_link(frame),
        SYS_LINKAT => sys_linkat(frame),
        SYS_UNLINK => sys_unlink(frame),
        SYS_UNLINKAT => sys_unlinkat(frame),
        SYS_RENAME => sys_rename(frame),
        SYS_RENAMEAT => sys_renameat(frame),
        SYS_RENAMEAT2 => sys_renameat2(frame),
        SYS_SYMLINK => sys_symlink(frame),
        SYS_SYMLINKAT => sys_symlinkat(frame),
        SYS_CHMOD => sys_chmod(frame),
        SYS_FCHMODAT => sys_fchmodat(frame),
        SYS_STATFS => sys_statfs(frame),
        SYS_FSTATFS => sys_fstatfs(frame),
        SYS_TRUNCATE => sys_truncate(frame),
        SYS_FTRUNCATE => sys_ftruncate(frame),
        SYS_GETPID => Ok(active_context().pid as i64),
        SYS_GETTID => Ok(active_context().tid as i64),
        SYS_GETPGID => sys_getpgid(frame),
        SYS_GETPGRP => sys_getpgrp(),
        SYS_GETPPID => Ok(current_parent_pid() as i64),
        SYS_GETSID => sys_getsid(frame),
        SYS_GETUID => Ok(active_context().uid() as i64),
        SYS_GETEUID => Ok(active_context().euid() as i64),
        SYS_GETGID => Ok(active_context().gid() as i64),
        SYS_GETEGID => Ok(active_context().egid() as i64),
        SYS_SETUID => sys_setuid(frame),
        SYS_SETGID => sys_setgid(frame),
        SYS_SETREUID => sys_setreuid(frame),
        SYS_SETREGID => sys_setregid(frame),
        SYS_GETGROUPS => sys_getgroups(frame),
        SYS_SETGROUPS => sys_setgroups(frame),
        SYS_SETRESUID => sys_setresuid(frame),
        SYS_GETRESUID => sys_getresuid(frame),
        SYS_SETRESGID => sys_setresgid(frame),
        SYS_GETRESGID => sys_getresgid(frame),
        SYS_SETFSUID => sys_setfsuid(frame),
        SYS_SETFSGID => sys_setfsgid(frame),
        SYS_CHOWN | SYS_LCHOWN => sys_chown(frame),
        SYS_FCHOWNAT => sys_fchownat(frame),
        SYS_CAPGET => sys_capget(frame),
        SYS_CAPSET => sys_capset(frame),
        SYS_BRK => sys_brk(frame),
        SYS_SET_TID_ADDRESS => sys_set_tid_address(frame),
        SYS_SET_ROBUST_LIST => sys_set_robust_list(frame),
        SYS_GET_ROBUST_LIST => sys_get_robust_list(frame),
        SYS_RSEQ => sys_rseq(frame),
        SYS_GETRLIMIT => sys_getrlimit(frame),
        SYS_SETRLIMIT => sys_setrlimit(frame),
        SYS_PRLIMIT64 => sys_prlimit64(frame),
        SYS_PRCTL => sys_prctl(frame),
        SYS_SECCOMP => sys_seccomp(frame),
        SYS_GETRANDOM => sys_getrandom(frame),
        SYS_GETTIMEOFDAY => sys_gettimeofday(frame),
        SYS_CLOCK_GETTIME => sys_clock_gettime(frame),
        SYS_CLOCK_GETRES => sys_clock_getres(frame),
        SYS_CLOCK_SETTIME => sys_clock_settime(frame),
        SYS_CLOCK_NANOSLEEP => sys_clock_nanosleep(frame),
        SYS_SCHED_GETAFFINITY => sys_sched_getaffinity(frame),
        SYS_RT_SIGACTION => sys_rt_sigaction(frame),
        SYS_RT_SIGPROCMASK => sys_rt_sigprocmask(frame),
        SYS_RT_SIGRETURN => sys_rt_sigreturn(frame),
        SYS_RT_SIGPENDING => sys_rt_sigpending(frame),
        SYS_RT_SIGTIMEDWAIT => sys_rt_sigtimedwait(frame),
        SYS_RT_SIGSUSPEND => sys_rt_sigsuspend(frame),
        SYS_SIGALTSTACK => sys_sigaltstack(frame),
        SYS_ALARM => Ok(active_context().replace_alarm(frame.rdi) as i64),
        SYS_CLOCK_ADJTIME => sys_clock_adjtime(frame),
        SYS_TGKILL => sys_tgkill(frame),
        SYS_PAUSE => sys_pause(frame),
        SYS_SELECT => sys_select(frame),
        SYS_PSELECT6 => sys_pselect6(frame),
        SYS_UMASK => sys_umask(frame),
        SYS_TIME => sys_time(frame),
        SYS_UTIMENSAT => sys_utimensat(frame),
        SYS_MOUNT => sys_mount(frame),
        SYS_UMOUNT2 => sys_umount2(frame),
        SYS_FALLOCATE => sys_fallocate(frame),
        SYS_FSETXATTR => sys_fsetxattr(frame),
        SYS_FGETXATTR => sys_fgetxattr(frame),
        SYS_FLISTXATTR => sys_flistxattr(frame),
        SYS_FREMOVEXATTR => sys_fremovexattr(frame),
        SYS_BPF => sys_bpf(frame),
        SYS_ADD_KEY | SYS_KEYCTL => Err(ERR_EPERM),
        SYS_CLONE | SYS_FORK | SYS_VFORK => sys_fork_like(frame),
        SYS_CLONE3 => sys_clone3(frame),
        SYS_WAIT4 => sys_wait4(frame),
        SYS_SETPGID => sys_setpgid(frame),
        SYS_SETSID => sys_setsid(),
        SYS_KILL => sys_kill(frame),
        SYS_IOCTL => sys_ioctl(frame),
        SYS_PIPE => sys_pipe(frame, 0),
        SYS_EVENTFD => sys_eventfd(frame, 0),
        SYS_EVENTFD2 => sys_eventfd(frame, frame.rsi),
        SYS_TIMERFD_CREATE => sys_timerfd_create(frame),
        SYS_TIMERFD_SETTIME => sys_timerfd_settime(frame),
        SYS_TIMERFD_GETTIME => sys_timerfd_gettime(frame),
        SYS_EPOLL_CREATE1 => sys_epoll_create1(frame),
        SYS_EPOLL_CREATE => sys_epoll_create(frame),
        SYS_EPOLL_CTL => sys_epoll_ctl(frame),
        SYS_EPOLL_WAIT => sys_epoll_wait(frame),
        SYS_EPOLL_PWAIT => sys_epoll_pwait(frame),
        SYS_EPOLL_PWAIT2 => sys_epoll_pwait2(frame),
        SYS_POLL => sys_poll(frame),
        SYS_PPOLL => sys_ppoll(frame),
        SYS_SOCKET => sys_socket(frame),
        SYS_SOCKETPAIR => sys_socketpair(frame),
        SYS_BIND => sys_bind(frame),
        SYS_LISTEN => sys_listen(frame),
        SYS_CONNECT => sys_connect(frame),
        SYS_ACCEPT => sys_accept(frame),
        SYS_ACCEPT4 => sys_accept4(frame),
        SYS_GETSOCKNAME => sys_getsockname(frame),
        SYS_GETPEERNAME => sys_getpeername(frame),
        SYS_SENDTO => sys_sendto(frame),
        SYS_RECVFROM => sys_recvfrom(frame),
        SYS_SETSOCKOPT => sys_setsockopt(frame),
        SYS_GETSOCKOPT => sys_getsockopt(frame),
        SYS_FLOCK => sys_flock(frame),
        SYS_FCNTL => sys_fcntl(frame),
        SYS_MMAP => sys_mmap(frame),
        SYS_MREMAP => sys_mremap(frame),
        SYS_MPROTECT => sys_mprotect(frame),
        SYS_MSYNC => sys_msync(frame),
        SYS_MADVISE => sys_madvise(frame),
        SYS_MUNMAP => sys_munmap(frame),
        SYS_ARCH_PRCTL => sys_arch_prctl(frame),
        SYS_FUTEX => sys_futex(frame),
        SYS_GETDENTS64 => sys_getdents64(frame),
        SYS_GETCWD => sys_getcwd(frame),
        SYS_READLINK => sys_readlink(frame),
        SYS_READLINKAT => sys_readlinkat(frame),
        SYS_UNAME => sys_uname(frame),
        SYS_NANOSLEEP => sys_nanosleep(frame),
        SYS_PIPE2 => sys_pipe(frame, frame.rsi),
        SYS_EXIT | SYS_EXIT_GROUP => return handle_exit_syscall(frame, frame.rdi as i32),
        _ => {
            crate::kwarn!("ring3 unsupported syscall {}", frame.rax);
            Err(ERR_ENOSYS)
        }
    };
    result
}

fn seccomp_syscall_instruction_addr(frame: &SyscallFrame) -> u64 {
    frame.rcx.checked_sub(2).unwrap_or(frame.rcx)
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
        if count != 0 {
            active_context().queue_io_signal();
        }
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
    if active_context().supervisor.is_timerfd_fd(fd) {
        return Err(ERR_EINVAL);
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
    let iovcnt = validate_iovcnt(frame.rdx)?;
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

fn sys_readv(frame: &SyscallFrame) -> Result<i64, i32> {
    sys_readv_with_blocking(frame, true)
}

fn sys_readv_with_blocking(frame: &SyscallFrame, allow_blocking: bool) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let iovcnt = validate_iovcnt(frame.rdx)?;
    if iovcnt == 0 {
        return Ok(0);
    }

    let iovecs = read_user_iovecs(frame.rsi, iovcnt)?;
    for (base, len) in &iovecs {
        validate_user_range(*base, *len, true)?;
    }

    let mut total = 0usize;
    for (base, len) in iovecs {
        if len == 0 {
            continue;
        }
        let count = usize::try_from(len).map_err(|_| ERR_EINVAL)?;
        match read_fd_chunk(fd, count, allow_blocking) {
            Ok(bytes) => {
                let read_len = bytes.len();
                if read_len != 0 {
                    let mut dest = user_lease(base, read_len as u64, true)?;
                    dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&bytes);
                }
                total = total.checked_add(read_len).ok_or(ERR_EINVAL)?;
                if read_len < count {
                    return Ok(total as i64);
                }
            }
            Err(_errno) if total > 0 => return Ok(total as i64),
            Err(errno) => return Err(errno),
        }
    }
    Ok(total as i64)
}

fn sys_preadv(frame: &SyscallFrame) -> Result<i64, i32> {
    let offset = preadv_offset_from_split(frame.r10, frame.r8)?;
    sys_preadv_at(frame, offset)
}

fn sys_preadv2(frame: &SyscallFrame) -> Result<i64, i32> {
    let nowait = preadv2_flags_nowait(frame.r9)?;
    match preadv2_offset_from_split(frame.r10, frame.r8)? {
        VectoredIoOffset::Current => sys_readv_with_blocking(frame, !nowait),
        VectoredIoOffset::Explicit(offset) => sys_preadv_at(frame, offset),
    }
}

fn sys_preadv_at(frame: &SyscallFrame, mut offset: usize) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let iovcnt = validate_iovcnt(frame.rdx)?;
    if iovcnt == 0 {
        return Ok(0);
    }

    let iovecs = read_user_iovecs(frame.rsi, iovcnt)?;
    for (base, len) in &iovecs {
        validate_user_range(*base, *len, true)?;
    }

    let mut total = 0usize;
    for (base, len) in iovecs {
        if len == 0 {
            continue;
        }
        let count = usize::try_from(len).map_err(|_| ERR_EINVAL)?;
        match active_context().supervisor.read_vfs_fd_range(fd, offset, count) {
            Ok(bytes) => {
                let read_len = bytes.len();
                if read_len != 0 {
                    let mut dest = user_lease(base, read_len as u64, true)?;
                    dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&bytes);
                }
                total = total.checked_add(read_len).ok_or(ERR_EINVAL)?;
                offset = offset.checked_add(read_len).ok_or(ERR_EINVAL)?;
                if read_len < count {
                    return Ok(total as i64);
                }
            }
            Err(_errno) if total > 0 => return Ok(total as i64),
            Err(errno) => return Err(errno),
        }
    }
    Ok(total as i64)
}

fn sys_pwritev(frame: &SyscallFrame) -> Result<i64, i32> {
    let offset = preadv_offset_from_split(frame.r10, frame.r8)?;
    sys_pwritev_at(frame, offset)
}

fn sys_pwritev2(frame: &SyscallFrame) -> Result<i64, i32> {
    let append = pwritev2_flags_append(frame.r9)?;
    match preadv2_offset_from_split(frame.r10, frame.r8)? {
        VectoredIoOffset::Current if append => sys_pwritev_append(frame, true),
        VectoredIoOffset::Current => sys_writev(frame),
        VectoredIoOffset::Explicit(_) if append => sys_pwritev_append(frame, false),
        VectoredIoOffset::Explicit(offset) => sys_pwritev_at(frame, offset),
    }
}

fn sys_pwritev_at(frame: &SyscallFrame, mut offset: usize) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let iovcnt = validate_iovcnt(frame.rdx)?;
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
        match active_context().supervisor.write_vfs_fd_range(fd, offset, bytes) {
            Ok(written) => {
                total = total.checked_add(written).ok_or(ERR_EINVAL)?;
                offset = offset.checked_add(written).ok_or(ERR_EINVAL)?;
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

fn sys_pwritev_append(frame: &SyscallFrame, update_cursor: bool) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let iovcnt = validate_iovcnt(frame.rdx)?;
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
        match active_context().supervisor.write_vfs_fd_append(fd, bytes, update_cursor) {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VectoredIoOffset {
    Current,
    Explicit(usize),
}

fn validate_iovcnt(iovcnt_arg: u64) -> Result<usize, i32> {
    let iovcnt = usize::try_from(iovcnt_arg).map_err(|_| ERR_EINVAL)?;
    if iovcnt > LINUX_IOV_MAX {
        return Err(ERR_EINVAL);
    }
    Ok(iovcnt)
}

fn preadv_offset_from_split(pos_l: u64, pos_h: u64) -> Result<usize, i32> {
    let raw = ((pos_h & u32::MAX as u64) << 32) | (pos_l & u32::MAX as u64);
    if raw > i64::MAX as u64 {
        return Err(ERR_EINVAL);
    }
    usize::try_from(raw).map_err(|_| ERR_EINVAL)
}

fn preadv2_offset_from_split(pos_l: u64, pos_h: u64) -> Result<VectoredIoOffset, i32> {
    let raw = ((pos_h & u32::MAX as u64) << 32) | (pos_l & u32::MAX as u64);
    if raw == u64::MAX {
        return Ok(VectoredIoOffset::Current);
    }
    preadv_offset_from_split(pos_l, pos_h).map(VectoredIoOffset::Explicit)
}

fn validate_preadv2_flags(flags: u64) -> Result<(), i32> {
    if flags & !RWF_NOWAIT == 0 { Ok(()) } else { Err(ERR_EOPNOTSUPP) }
}

fn preadv2_flags_nowait(flags: u64) -> Result<bool, i32> {
    validate_preadv2_flags(flags)?;
    Ok(flags & RWF_NOWAIT != 0)
}

fn validate_pwritev2_flags(flags: u64) -> Result<(), i32> {
    if flags & !(RWF_NOWAIT | RWF_APPEND) == 0 { Ok(()) } else { Err(ERR_EOPNOTSUPP) }
}

fn pwritev2_flags_append(flags: u64) -> Result<bool, i32> {
    validate_pwritev2_flags(flags)?;
    Ok(flags & RWF_APPEND != 0)
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

fn read_fd_chunk(fd: u32, count: usize, allow_blocking: bool) -> Result<Vec<u8>, i32> {
    if active_context().supervisor.is_pipe_fd(fd) {
        return active_context().supervisor.read_pipe_fd_bytes(fd, count);
    }
    if active_context().supervisor.is_socketpair_fd(fd) {
        return active_context().supervisor.read_socketpair_fd_bytes(fd, count);
    }
    if active_context().supervisor.is_eventfd_fd(fd) {
        return active_context().supervisor.read_eventfd_value(fd, count);
    }
    if active_context().supervisor.is_timerfd_fd(fd) {
        return match active_context().supervisor.read_timerfd_value(fd, count) {
            Ok(bytes) => Ok(bytes),
            Err(ERR_EAGAIN)
                if allow_blocking
                    && active_context().supervisor.file_status_flags(fd)? & O_NONBLOCK == 0 =>
            {
                block_on_readable_fd(fd)?;
                active_context().supervisor.read_timerfd_value(fd, count)
            }
            Err(errno) => Err(errno),
        };
    }

    let supervisor = &mut active_context().supervisor;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_readv_chunk",
            SyscallContext::new(SYS_READ, [fd as u64, 0, count as u64, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Bytes(bytes) => Ok(bytes),
        LinuxCallResult::Ret(0) => Ok(Vec::new()),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
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
        let written = active_context().supervisor.write_pipe_fd_bytes(fd, bytes)?;
        if written != 0 {
            active_context().queue_io_signal();
        }
        return Ok(written);
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
    if active_context().supervisor.is_timerfd_fd(fd) {
        return Err(ERR_EINVAL);
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
    if active_context().supervisor.is_timerfd_fd(fd) {
        let bytes = match active_context().supervisor.read_timerfd_value(fd, count) {
            Ok(bytes) => bytes,
            Err(ERR_EAGAIN)
                if active_context().supervisor.file_status_flags(fd)? & O_NONBLOCK == 0 =>
            {
                block_on_readable_fd(fd)?;
                active_context().supervisor.read_timerfd_value(fd, count)?
            }
            Err(errno) => return Err(errno),
        };
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

fn block_on_readable_fd(fd: u32) -> Result<(), i32> {
    let fd = usize::try_from(fd).map_err(|_| ERR_EINVAL)?;
    if fd >= PSELECT6_MAX_FDS {
        return Err(ERR_EINVAL);
    }
    let mut read_bits = [0u64; PSELECT6_FDSET_WORDS];
    set_fd_bit(&mut read_bits, fd);
    active_context().supervisor.block_on_fdset_wait(
        read_bits,
        [0; PSELECT6_FDSET_WORDS],
        [0; PSELECT6_FDSET_WORDS],
        u16::try_from(fd + 1).map_err(|_| ERR_EINVAL)?,
        None,
    )
}

fn sys_pread64(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let count = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let offset = positioned_io_offset(frame.r10)?;
    let bytes = active_context().supervisor.read_vfs_fd_range(fd, offset, count)?;
    let mut dest = user_lease(frame.rsi, bytes.len() as u64, true)?;
    dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&bytes);
    Ok(bytes.len() as i64)
}

fn sys_pwrite64(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let count = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let offset = positioned_io_offset(frame.r10)?;
    if count == 0 {
        return Ok(0);
    }
    let lease = user_lease(frame.rsi, count as u64, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    let written = active_context().supervisor.write_vfs_fd_range(fd, offset, bytes)?;
    Ok(written as i64)
}

fn positioned_io_offset(offset: u64) -> Result<usize, i32> {
    if offset > i64::MAX as u64 {
        return Err(ERR_EINVAL);
    }
    usize::try_from(offset).map_err(|_| ERR_EINVAL)
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
    const O_CREAT: u32 = 0x40;

    let flags = u32::try_from(flags_raw).map_err(|_| ERR_EINVAL)?;
    let mut mode = u32::try_from(mode_raw).map_err(|_| ERR_EINVAL)?;
    if flags & O_CREAT != 0 {
        mode = apply_umask(mode);
    }
    let path = read_user_c_string(path_ptr, PATH_MAX)?;
    let resolved = resolve_path(dirfd, &path)?;
    // ETXTBSY enforcement not yet implemented (no real fork model)

    let owner_ids = active_context().open_owner_ids();
    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor.write_linux_arg_bytes(&resolved).map_err(|_| ERR_EFAULT)?;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_openat",
            SyscallContext::new(
                SYS_OPENAT,
                [dirfd as u64, ptr as u64, len as u64, flags as u64, mode as u64, owner_ids],
            ),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_umask(frame: &SyscallFrame) -> Result<i64, i32> {
    Ok(active_context().replace_umask(frame.rdi as u32) as i64)
}

fn apply_umask(mode: u32) -> u32 {
    mode & !(active_context().umask() & 0o777)
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
    let resolved = resolve_final_symlink_for_stat(resolved, frame.rax != SYS_LSTAT)?;
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
    let follow_symlink = frame.r10 & AT_SYMLINK_NOFOLLOW == 0;
    let resolved = resolve_final_symlink_for_stat(resolved, follow_symlink)?;
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
    let mode = u32::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    if mode & !0x7 != 0 {
        return Err(ERR_EINVAL);
    }
    let access = real_access_snapshot();
    active_context().supervisor.check_path_access(&resolved, mode, access.ids())?;
    Ok(0)
}

fn sys_faccessat(frame: &SyscallFrame) -> Result<i64, i32> {
    const FACCESSAT_ALLOWED_FLAGS: u64 = AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    let flags = if frame.rax == SYS_FACCESSAT { 0 } else { frame.r10 };
    if flags & !FACCESSAT_ALLOWED_FLAGS != 0 {
        return Err(ERR_EINVAL);
    }
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    if path.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return Err(ERR_ENOENT);
    }
    let resolved = if path.is_empty() {
        let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
        active_context().supervisor.fd_path(fd).map_err(|_| ERR_EBADF)?
    } else {
        resolve_path(linux_fd_arg(frame.rdi), &path)?
    };
    let mode = u32::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    if mode & !0x7 != 0 {
        return Err(ERR_EINVAL);
    }
    let access =
        if flags & AT_EACCESS != 0 { effective_access_snapshot() } else { real_access_snapshot() };
    active_context().supervisor.check_path_access(&resolved, mode, access.ids())?;
    Ok(0)
}

fn sys_execve(frame: &mut SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let argv = read_exec_string_array(frame.rsi)?;
    let envp = read_exec_string_array(frame.rdx)?;
    execve_resolved_path(frame, AT_FDCWD, &path, 0, argv, envp)
}

fn sys_execveat(frame: &mut SyscallFrame) -> Result<i64, i32> {
    const EXECVEAT_ALLOWED_FLAGS: u64 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    let flags = frame.r8;
    if flags & !EXECVEAT_ALLOWED_FLAGS != 0 {
        return Err(ERR_EINVAL);
    }
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let argv = read_exec_string_array(frame.rdx)?;
    let envp = read_exec_string_array(frame.r10)?;
    if path.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return Err(ERR_ENOENT);
    }
    if path.is_empty() {
        let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
        let resolved = active_context().supervisor.fd_path(fd).map_err(|_| ERR_EBADF)?;
        return execve_checked_path(frame, &resolved, flags, argv, envp);
    }
    execve_resolved_path(frame, linux_fd_arg(frame.rdi), &path, flags, argv, envp)
}

fn execve_resolved_path(
    frame: &mut SyscallFrame,
    dirfd: i64,
    path: &[u8],
    flags: u64,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
) -> Result<i64, i32> {
    if path_has_too_long_component(path) {
        return Err(ERR_ENAMETOOLONG);
    }
    let resolved = resolve_path(dirfd, path)?;
    execve_checked_path(frame, &resolved, flags, argv, envp)
}

fn execve_checked_path(
    frame: &mut SyscallFrame,
    resolved: &[u8],
    flags: u64,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
) -> Result<i64, i32> {
    if active_context().has_suspended_vfork_parent()
        || active_context().has_suspended_clone_parent()
    {
        return Err(ERR_ENOSYS);
    }
    if has_non_dir_prefix(resolved) {
        return Err(ERR_ENOTDIR);
    }
    let (kind, mode, len, owner_uid, owner_gid) =
        active_context().supervisor.path_metadata(resolved)?;
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
    let access = effective_access_snapshot();
    let bytes = active_context().supervisor.read_vfs_file_path(resolved, access.ids())?;
    let interpreter_path = user_elf_interpreter_path(&bytes).map_err(exec_load_errno)?;
    let interpreter_bytes = if let Some(path) = interpreter_path {
        Some(active_context().supervisor.read_vfs_file_path(&path, access.ids())?)
    } else {
        None
    };
    let file_capabilities = read_exec_file_capabilities(resolved)?;
    execve_replace_image(
        frame,
        resolved,
        bytes,
        interpreter_bytes,
        argv,
        envp,
        mode,
        owner_uid,
        owner_gid,
        file_capabilities,
    )
}

fn execve_replace_image(
    frame: &mut SyscallFrame,
    resolved: &[u8],
    bytes: Vec<u8>,
    interpreter_bytes: Option<Vec<u8>>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    file_capabilities: Option<ExecFileCapabilities>,
) -> Result<i64, i32> {
    let stack_credentials =
        exec_stack_credentials_for_file(mode, owner_uid, owner_gid, file_capabilities.is_some());
    let envp = sanitize_secure_exec_envp(envp, stack_credentials.secure);
    let image = {
        let context = active_context();
        prepare_user_program(
            context.physical_memory_offset(),
            &mut context.frame_allocator,
            &bytes,
            interpreter_bytes.as_deref(),
            &argv,
            &envp,
            resolved,
            stack_credentials,
        )
        .map_err(exec_load_errno)?
    };
    let entry = image.entry;
    let stack_top = image.stack_top;
    let current_regions = active_context().regions.clone();
    let current_mappings = active_context().page_mappings.clone();
    let next_regions = image.regions.clone();
    let next_mappings = image.page_mappings.clone();
    sync_file_shared_page_mappings(&current_mappings)?;

    let switch_result = {
        let context = active_context();
        switch_user_page_mappings(
            context.physical_memory_offset(),
            &current_mappings,
            &current_regions,
            &next_mappings,
            &next_regions,
            &mut context.frame_allocator,
            true,
        )
    };
    if let Err(err) = switch_result {
        let context = active_context();
        if err.next_mappings_cleaned() {
            image.release_frames(&mut context.frame_allocator);
        } else {
            crate::kwarn!("execve prepared frames leaked after incomplete page-table cleanup");
        }
        crate::kwarn!("execve page-table switch failed: {}", err.message());
        return Err(ERR_EFAULT);
    }
    release_file_shared_page_refs(&current_mappings);

    {
        let context = active_context();
        context.replace_user_image(
            image.regions,
            image.page_mappings,
            USER_BRK_BASE,
            USER_BRK_END,
            USER_MMAP_ALLOC_BASE,
            USER_MMAP_END,
        );
        context.set_exec_path(resolved.to_vec());
        context.supervisor.close_cloexec_fds_for_exec();
        if !context.supervisor.reset_signal_state_for_exec(context.pid, context.tid) {
            return Err(ERR_ESRCH);
        }
    }
    apply_exec_credential_fixup(mode, owner_uid, owner_gid, file_capabilities)?;
    {
        let context = active_context();
        if !context.supervisor.mark_process_execed(context.pid) {
            crate::kwarn!("execve could not mark pid {} execed", context.pid);
        }
    }

    let mut next = ring3::capture_user_return(frame);
    next.frame.rax = 0;
    next.frame.rcx = entry;
    next.rsp = stack_top;
    next.fs_base = 0;
    ring3::install_user_return(frame, next);
    Ok(0)
}

fn exec_stack_credentials_for_file(
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    has_file_capabilities: bool,
) -> ExecStackCredentials {
    const S_ISUID: u32 = 0o4000;
    const S_ISGID: u32 = 0o2000;

    let context = active_context();
    let uid = context.uid();
    let gid = context.gid();
    let euid = if mode & S_ISUID != 0 { owner_uid } else { context.euid() };
    let egid = if mode & S_ISGID != 0 { owner_gid } else { context.egid() };
    ExecStackCredentials {
        uid,
        euid,
        gid,
        egid,
        secure: has_file_capabilities || euid != uid || egid != gid,
    }
}

fn sanitize_secure_exec_envp(envp: Vec<Vec<u8>>, secure: bool) -> Vec<Vec<u8>> {
    if !secure {
        return envp;
    }
    envp.into_iter().filter(|entry| !is_secure_exec_unsafe_env(entry)).collect()
}

fn is_secure_exec_unsafe_env(entry: &[u8]) -> bool {
    const UNSAFE_PREFIXES: &[&[u8]] = &[
        b"LD_",
        b"GLIBC_TUNABLES=",
        b"GCONV_PATH=",
        b"GETCONF_DIR=",
        b"HOSTALIASES=",
        b"LOCALDOMAIN=",
        b"LOCPATH=",
        b"MALLOC_",
        b"NLSPATH=",
        b"RESOLV_HOST_CONF=",
        b"RES_OPTIONS=",
        b"TMPDIR=",
        b"TZDIR=",
    ];

    UNSAFE_PREFIXES.iter().any(|prefix| entry.starts_with(prefix))
}

fn apply_exec_credential_fixup(
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    file_capabilities: Option<ExecFileCapabilities>,
) -> Result<(), i32> {
    let before = active_context().credential_state();
    active_context().apply_exec_file_credentials(owner_uid, owner_gid, mode, file_capabilities);
    let after = active_context().credential_state();
    if before == after {
        return Ok(());
    }
    let kind = if before.uid != after.uid || before.euid != after.euid || before.suid != after.suid
    {
        CredentialTransitionKind::SetResUid { ruid: after.uid, euid: after.euid, suid: after.suid }
    } else if before.gid != after.gid || before.egid != after.egid || before.sgid != after.sgid {
        CredentialTransitionKind::SetResGid { rgid: after.gid, egid: after.egid, sgid: after.sgid }
    } else {
        CredentialTransitionKind::CapSet {
            bounding: before.cap_bounding != after.cap_bounding,
            inheritable: before.cap_inheritable != after.cap_inheritable,
            permitted: before.cap_permitted != after.cap_permitted,
            effective: before.cap_effective != after.cap_effective,
            ambient: before.cap_ambient != after.cap_ambient,
            securebits: before.securebits != after.securebits,
        }
    };
    if let Err(errno) = record_credential_transition(kind) {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(())
}

fn read_exec_file_capabilities(path: &[u8]) -> Result<Option<ExecFileCapabilities>, i32> {
    let Some(value) =
        active_context().supervisor.path_xattr_value(path, SECURITY_CAPABILITY_XATTR)?
    else {
        return Ok(None);
    };
    parse_exec_file_capabilities(&value)
}

fn parse_exec_file_capabilities(value: &[u8]) -> Result<Option<ExecFileCapabilities>, i32> {
    const VFS_CAP_REVISION_MASK: u32 = 0xff00_0000;
    const VFS_CAP_REVISION_1: u32 = 0x0100_0000;
    const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
    const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
    const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;
    const VFS_CAP_KNOWN_FLAGS: u32 = VFS_CAP_FLAGS_EFFECTIVE;

    let expected_len = match value.len() {
        12 | 20 | 24 => value.len(),
        _ => return Err(ERR_EINVAL),
    };
    let magic_etc = read_u32_from(value, 0)?;
    let flags = magic_etc & !VFS_CAP_REVISION_MASK;
    if flags & !VFS_CAP_KNOWN_FLAGS != 0 {
        return Err(ERR_EINVAL);
    }
    let revision = magic_etc & VFS_CAP_REVISION_MASK;
    let words = match (revision, expected_len) {
        (VFS_CAP_REVISION_1, 12) => 1usize,
        (VFS_CAP_REVISION_2, 20) => 2usize,
        (VFS_CAP_REVISION_3, 24) => {
            let rootid = read_u32_from(value, 20)?;
            if rootid != 0 {
                return Ok(None);
            }
            2usize
        }
        _ => return Err(ERR_EINVAL),
    };

    let mut permitted = read_u32_from(value, 4)? as u64;
    let mut inheritable = read_u32_from(value, 8)? as u64;
    if words == 2 {
        permitted |= (read_u32_from(value, 12)? as u64) << 32;
        inheritable |= (read_u32_from(value, 16)? as u64) << 32;
    }
    Ok(Some(ExecFileCapabilities {
        permitted: permitted & LINUX_KNOWN_CAPS,
        inheritable: inheritable & LINUX_KNOWN_CAPS,
        effective: flags & VFS_CAP_FLAGS_EFFECTIVE != 0,
    }))
}

fn exec_load_errno(err: &'static str) -> i32 {
    match err {
        "user ELF was invalid"
        | "user ELF type unsupported"
        | "user ELF address overflowed"
        | "user ELF segment overflowed"
        | "user ELF offset overflowed"
        | "user ELF file size overflowed"
        | "user ELF file range overflowed"
        | "user ELF referenced bytes outside the image"
        | "user ELF program header table is not mapped"
        | "user ELF program header table overflowed"
        | "user ELF segment file exceeds memory size"
        | "user ELF interpreter invalid"
        | "user ELF interpreter type unsupported"
        | "user ELF interpreter nested"
        | "user ELF interpreter provided for static image"
        | "user ELF has multiple interpreters"
        | "user ELF interpreter path invalid"
        | "user ELF interpreter offset overflowed"
        | "user ELF interpreter size overflowed"
        | "user ELF interpreter range overflowed"
        | "user ELF interpreter outside image" => ERR_ENOEXEC,
        "user ELF interpreter missing" => ERR_ENOENT,
        "out of usable frames for user image" | "out of usable frames for user stack" => ERR_ENOMEM,
        "initial stack underflowed"
        | "initial stack overflowed"
        | "initial stack exceeded one page"
        | "initial stack string contains nul" => ERR_E2BIG,
        _ => ERR_EFAULT,
    }
}

fn sys_mkdir(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    let mode = apply_umask(frame.rsi as u32);
    let access = effective_access_snapshot();
    active_context().supervisor.mkdir_path(&resolved, mode, access.ids())?;
    Ok(0)
}

fn sys_mkdirat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    let mode = apply_umask(frame.rdx as u32);
    let access = effective_access_snapshot();
    active_context().supervisor.mkdir_path(&resolved, mode, access.ids())?;
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
    let mode = apply_umask(mode);
    let access = effective_access_snapshot();
    active_context().supervisor.create_fifo_path(&resolved, mode, access.ids())?;
    Ok(0)
}

fn sys_unlink(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    let access = effective_access_snapshot();
    active_context().supervisor.unlink_path(&resolved, access.ids())?;
    Ok(0)
}

fn sys_unlinkat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    let access = effective_access_snapshot();
    if frame.rdx & AT_REMOVEDIR != 0 {
        active_context().supervisor.rmdir_path(&resolved, access.ids())?;
    } else {
        active_context().supervisor.unlink_path(&resolved, access.ids())?;
    }
    Ok(0)
}

fn sys_link(frame: &SyscallFrame) -> Result<i64, i32> {
    let old_path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let new_path = read_user_c_string(frame.rsi, PATH_MAX)?;
    link_resolved_paths(AT_FDCWD, &old_path, AT_FDCWD, &new_path, 0)
}

fn sys_linkat(frame: &SyscallFrame) -> Result<i64, i32> {
    const LINKAT_ALLOWED_FLAGS: u64 = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH;

    let flags = frame.r8;
    if flags & !LINKAT_ALLOWED_FLAGS != 0 {
        return Err(ERR_EINVAL);
    }
    let old_path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let new_path = read_user_c_string(frame.r10, PATH_MAX)?;
    link_resolved_paths(
        linux_fd_arg(frame.rdi),
        &old_path,
        linux_fd_arg(frame.rdx),
        &new_path,
        flags,
    )
}

fn link_resolved_paths(
    old_dirfd: i64,
    old_path: &[u8],
    new_dirfd: i64,
    new_path: &[u8],
    flags: u64,
) -> Result<i64, i32> {
    if old_path.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return Err(ERR_ENOENT);
    }
    if new_path.is_empty() {
        return Err(ERR_ENOENT);
    }
    let mut old_resolved = resolve_path(old_dirfd, old_path)?;
    if flags & AT_SYMLINK_FOLLOW != 0 {
        old_resolved = resolve_final_symlink_for_stat(old_resolved, true)?;
    }
    let new_resolved = resolve_path(new_dirfd, new_path)?;
    let access = effective_access_snapshot();
    active_context().supervisor.link_path(&old_resolved, &new_resolved, access.ids())?;
    Ok(0)
}

fn sys_rename(frame: &SyscallFrame) -> Result<i64, i32> {
    let old_path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let new_path = read_user_c_string(frame.rsi, PATH_MAX)?;
    rename_resolved_paths(AT_FDCWD, &old_path, AT_FDCWD, &new_path, 0)
}

fn sys_renameat(frame: &SyscallFrame) -> Result<i64, i32> {
    let old_path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let new_path = read_user_c_string(frame.r10, PATH_MAX)?;
    rename_resolved_paths(linux_fd_arg(frame.rdi), &old_path, linux_fd_arg(frame.rdx), &new_path, 0)
}

fn sys_renameat2(frame: &SyscallFrame) -> Result<i64, i32> {
    let flags = frame.r8;
    if flags & !RENAME_SUPPORTED_FLAGS != 0
        || flags & RENAME_WHITEOUT != 0
        || flags & (RENAME_NOREPLACE | RENAME_EXCHANGE) == RENAME_NOREPLACE | RENAME_EXCHANGE
    {
        return Err(ERR_EINVAL);
    }
    let old_path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let new_path = read_user_c_string(frame.r10, PATH_MAX)?;
    rename_resolved_paths(
        linux_fd_arg(frame.rdi),
        &old_path,
        linux_fd_arg(frame.rdx),
        &new_path,
        flags,
    )
}

fn rename_resolved_paths(
    old_dirfd: i64,
    old_path: &[u8],
    new_dirfd: i64,
    new_path: &[u8],
    flags: u64,
) -> Result<i64, i32> {
    if old_path.is_empty() || new_path.is_empty() {
        return Err(ERR_ENOENT);
    }
    let old_resolved = resolve_path(old_dirfd, old_path)?;
    let new_resolved = resolve_path(new_dirfd, new_path)?;
    let access = effective_access_snapshot();
    active_context().supervisor.rename_path(
        &old_resolved,
        &new_resolved,
        u32::try_from(flags).map_err(|_| ERR_EINVAL)?,
        access.ids(),
    )?;
    Ok(0)
}

fn sys_symlink(frame: &SyscallFrame) -> Result<i64, i32> {
    let target = read_user_c_string(frame.rdi, PATH_MAX)?;
    let linkpath = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &linkpath)?;
    let access = effective_access_snapshot();
    active_context().supervisor.symlink_path(&resolved, &target, access.ids())?;
    Ok(0)
}

fn sys_symlinkat(frame: &SyscallFrame) -> Result<i64, i32> {
    let target = read_user_c_string(frame.rdi, PATH_MAX)?;
    let linkpath = read_user_c_string(frame.rdx, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rsi), &linkpath)?;
    let access = effective_access_snapshot();
    active_context().supervisor.symlink_path(&resolved, &target, access.ids())?;
    Ok(0)
}

fn sys_rmdir(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    let access = effective_access_snapshot();
    active_context().supervisor.rmdir_path(&resolved, access.ids())?;
    Ok(0)
}

fn sys_chdir(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    let access = effective_access_snapshot();
    active_context().supervisor.check_path_access(&resolved, 0x1, access.ids())?;
    if active_context().supervisor.path_kind(&resolved)? != vmos_abi::NodeKind::Directory {
        return Err(vmos_abi::ERR_ENOTDIR);
    }
    active_context().set_cwd(resolved);
    Ok(0)
}

fn sys_chroot(frame: &SyscallFrame) -> Result<i64, i32> {
    if !active_context().has_effective_capability(CAP_SYS_CHROOT) {
        return Err(ERR_EPERM);
    }
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    let access = effective_access_snapshot();
    active_context().supervisor.check_path_access(&resolved, 0x1, access.ids())?;
    if active_context().supervisor.path_kind(&resolved)? != vmos_abi::NodeKind::Directory {
        return Err(vmos_abi::ERR_ENOTDIR);
    }
    active_context().set_root(resolved);
    Ok(0)
}

fn sys_chown(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    let uid = linux_owner_arg(frame.rsi)?;
    let gid = linux_owner_arg(frame.rdx)?;
    let access = effective_access_snapshot();
    active_context().supervisor.chown_path(&resolved, uid, gid, access.ids())?;
    Ok(0)
}

fn sys_fchownat(frame: &SyscallFrame) -> Result<i64, i32> {
    const FCHOWNAT_ALLOWED_FLAGS: u64 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    if frame.r8 & !FCHOWNAT_ALLOWED_FLAGS != 0 {
        return Err(ERR_EINVAL);
    }
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    if path.is_empty() && frame.r8 & AT_EMPTY_PATH == 0 {
        return Err(ERR_ENOENT);
    }
    let resolved = if path.is_empty() {
        let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
        active_context().supervisor.fd_path(fd).map_err(|_| ERR_EBADF)?
    } else {
        resolve_path(linux_fd_arg(frame.rdi), &path)?
    };
    let uid = linux_owner_arg(frame.rdx)?;
    let gid = linux_owner_arg(frame.r10)?;
    let access = effective_access_snapshot();
    active_context().supervisor.chown_path(&resolved, uid, gid, access.ids())?;
    Ok(0)
}

fn sys_setuid(frame: &SyscallFrame) -> Result<i64, i32> {
    let uid = linux_id_arg(frame.rdi)?;
    let before = active_context().credential_state();
    let old = before.uid;
    if !active_context().set_uid(uid) {
        return Err(ERR_EPERM);
    }
    if let Err(errno) = record_credential_transition(CredentialTransitionKind::SetUid {
        old,
        new: active_context().uid(),
    }) {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(0)
}

fn sys_setgid(frame: &SyscallFrame) -> Result<i64, i32> {
    let gid = linux_id_arg(frame.rdi)?;
    let before = active_context().credential_state();
    let old = before.gid;
    if !active_context().set_gid(gid) {
        return Err(ERR_EPERM);
    }
    if let Err(errno) = record_credential_transition(CredentialTransitionKind::SetGid {
        old,
        new: active_context().gid(),
    }) {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(0)
}

fn sys_setreuid(frame: &SyscallFrame) -> Result<i64, i32> {
    let ruid = optional_linux_id_arg(frame.rdi)?;
    let euid = optional_linux_id_arg(frame.rsi)?;
    let before = active_context().credential_state();
    if !active_context().set_reuid(ruid, euid) {
        return Err(ERR_EPERM);
    }
    let after = active_context().credential_state();
    if let Err(errno) = record_credential_transition(CredentialTransitionKind::SetReUid {
        ruid: after.uid,
        euid: after.euid,
    }) {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(0)
}

fn sys_setregid(frame: &SyscallFrame) -> Result<i64, i32> {
    let rgid = optional_linux_id_arg(frame.rdi)?;
    let egid = optional_linux_id_arg(frame.rsi)?;
    let before = active_context().credential_state();
    if !active_context().set_regid(rgid, egid) {
        return Err(ERR_EPERM);
    }
    let after = active_context().credential_state();
    if let Err(errno) = record_credential_transition(CredentialTransitionKind::SetReGid {
        rgid: after.gid,
        egid: after.egid,
    }) {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(0)
}

fn sys_setresuid(frame: &SyscallFrame) -> Result<i64, i32> {
    let ruid = optional_linux_id_arg(frame.rdi)?;
    let euid = optional_linux_id_arg(frame.rsi)?;
    let suid = optional_linux_id_arg(frame.rdx)?;
    let before = active_context().credential_state();
    if !active_context().set_resuid(ruid, euid, suid) {
        return Err(ERR_EPERM);
    }
    let after = active_context().credential_state();
    if before == after {
        return Ok(0);
    }
    if let Err(errno) = record_credential_transition(CredentialTransitionKind::SetResUid {
        ruid: after.uid,
        euid: after.euid,
        suid: after.suid,
    }) {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(0)
}

fn sys_setresgid(frame: &SyscallFrame) -> Result<i64, i32> {
    let rgid = optional_linux_id_arg(frame.rdi)?;
    let egid = optional_linux_id_arg(frame.rsi)?;
    let sgid = optional_linux_id_arg(frame.rdx)?;
    let before = active_context().credential_state();
    if !active_context().set_resgid(rgid, egid, sgid) {
        return Err(ERR_EPERM);
    }
    let after = active_context().credential_state();
    if before == after {
        return Ok(0);
    }
    if let Err(errno) = record_credential_transition(CredentialTransitionKind::SetResGid {
        rgid: after.gid,
        egid: after.egid,
        sgid: after.sgid,
    }) {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(0)
}

fn sys_getgroups(frame: &SyscallFrame) -> Result<i64, i32> {
    let size = usize::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let groups = active_context().supplementary_groups().to_vec();
    if size == 0 {
        return Ok(groups.len() as i64);
    }
    if frame.rsi == 0 {
        return Err(ERR_EFAULT);
    }
    if size < groups.len() {
        return Err(ERR_EINVAL);
    }
    let mut encoded = Vec::with_capacity(groups.len() * 4);
    for group in &groups {
        encoded.extend_from_slice(&group.to_le_bytes());
    }
    write_user_bytes(frame.rsi, &encoded)?;
    Ok(groups.len() as i64)
}

fn sys_setgroups(frame: &SyscallFrame) -> Result<i64, i32> {
    const NGROUPS_MAX: usize = 65_536;

    let size = usize::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    if size > NGROUPS_MAX {
        return Err(ERR_EINVAL);
    }
    if !active_context().has_effective_capability(CAP_SETGID) {
        return Err(ERR_EPERM);
    }
    if size != 0 && frame.rsi == 0 {
        return Err(ERR_EFAULT);
    }
    let bytes = read_user_bytes(frame.rsi, size.checked_mul(4).ok_or(ERR_EINVAL)?)?;
    let mut groups = Vec::with_capacity(size);
    for chunk in bytes.chunks_exact(4) {
        groups.push(u32::from_le_bytes(chunk.try_into().map_err(|_| ERR_EINVAL)?));
    }
    let before = active_context().credential_state();
    let old_len = before.supplementary_groups.len();
    if !active_context().set_groups(groups) {
        return Err(ERR_EPERM);
    }
    let new_len = active_context().supplementary_groups().len();
    if let Err(errno) =
        record_credential_transition(CredentialTransitionKind::SetGroups { old_len, new_len })
    {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(0)
}

fn sys_getresuid(frame: &SyscallFrame) -> Result<i64, i32> {
    let uid = active_context().uid();
    let euid = active_context().euid();
    write_user_u32(frame.rdi, uid)?;
    write_user_u32(frame.rsi, euid)?;
    write_user_u32(frame.rdx, active_context().suid())?;
    Ok(0)
}

fn sys_getresgid(frame: &SyscallFrame) -> Result<i64, i32> {
    let gid = active_context().gid();
    let egid = active_context().egid();
    write_user_u32(frame.rdi, gid)?;
    write_user_u32(frame.rsi, egid)?;
    write_user_u32(frame.rdx, active_context().sgid())?;
    Ok(0)
}

fn sys_setfsuid(frame: &SyscallFrame) -> Result<i64, i32> {
    let uid = frame.rdi as u32;
    let before = active_context().credential_state();
    let old = active_context().set_fsuid(uid);
    if before.fsuid != active_context().fsuid()
        && let Err(errno) = record_credential_transition(CredentialTransitionKind::SetFsuid {
            old,
            new: active_context().fsuid(),
        })
    {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(old as i64)
}

fn sys_setfsgid(frame: &SyscallFrame) -> Result<i64, i32> {
    let gid = frame.rdi as u32;
    let before = active_context().credential_state();
    let old = active_context().set_fsgid(gid);
    if before.fsgid != active_context().fsgid()
        && let Err(errno) = record_credential_transition(CredentialTransitionKind::SetFsgid {
            old,
            new: active_context().fsgid(),
        })
    {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(old as i64)
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
        let context = active_context();
        let encoded = encode_capability_data(
            context.cap_effective(),
            context.cap_permitted(),
            context.cap_inheritable(),
        );
        write_user_bytes(frame.rsi, &encoded[..u32_count * 4])?;
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
    let len: usize = match version {
        LINUX_CAPABILITY_VERSION_1 => 12,
        LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3 => 24,
        _ => {
            write_user_u32(frame.rdi, LINUX_CAPABILITY_VERSION_3)?;
            return Err(ERR_EINVAL);
        }
    };
    let bytes = read_user_bytes(frame.rsi, len)?;
    let (effective, permitted, inheritable) = decode_capability_data(&bytes)?;
    let before = active_context().credential_state();
    if !active_context().set_capability_sets_from_capset(permitted, effective, inheritable) {
        return Err(ERR_EPERM);
    }
    if let Err(errno) = record_credential_transition(CredentialTransitionKind::CapSet {
        bounding: false,
        inheritable: before.cap_inheritable != active_context().cap_inheritable(),
        permitted: before.cap_permitted != active_context().cap_permitted(),
        effective: before.cap_effective != active_context().cap_effective(),
        ambient: before.cap_ambient != active_context().cap_ambient(),
        securebits: false,
    }) {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(0)
}

fn encode_capability_data(effective: u64, permitted: u64, inheritable: u64) -> [u8; 24] {
    let words = [
        effective as u32,
        permitted as u32,
        inheritable as u32,
        (effective >> 32) as u32,
        (permitted >> 32) as u32,
        (inheritable >> 32) as u32,
    ];
    let mut out = [0u8; 24];
    for (index, word) in words.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn decode_capability_data(bytes: &[u8]) -> Result<(u64, u64, u64), i32> {
    if bytes.len() != 12 && bytes.len() != 24 {
        return Err(ERR_EINVAL);
    }
    let read = |index: usize| -> Result<u32, i32> {
        Ok(u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().map_err(|_| ERR_EINVAL)?))
    };
    let effective = read(0)? as u64 | if bytes.len() == 24 { (read(3)? as u64) << 32 } else { 0 };
    let permitted = read(1)? as u64 | if bytes.len() == 24 { (read(4)? as u64) << 32 } else { 0 };
    let inheritable = read(2)? as u64 | if bytes.len() == 24 { (read(5)? as u64) << 32 } else { 0 };
    Ok((effective, permitted, inheritable))
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
    if pid != 0 && pid as u32 != active_context().pid {
        return Err(vmos_abi::ERR_ESRCH);
    }
    Ok(())
}

fn sys_chmod(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rdi, PATH_MAX)?;
    let resolved = resolve_path(AT_FDCWD, &path)?;
    let access = effective_access_snapshot();
    active_context().supervisor.chmod_path(&resolved, frame.rsi as u32, access.ids())?;
    Ok(0)
}

fn sys_fchmodat(frame: &SyscallFrame) -> Result<i64, i32> {
    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    let access = effective_access_snapshot();
    active_context().supervisor.chmod_path(&resolved, frame.rdx as u32, access.ids())?;
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
    let access = effective_access_snapshot();
    active_context().supervisor.truncate_path(&resolved, len, access.ids())?;
    Ok(0)
}

fn sys_ftruncate(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let len = usize::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    active_context().supervisor.truncate_fd(fd, len)?;
    Ok(0)
}

fn sys_fallocate(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let mode = u32::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    let offset = frame.rdx as i64;
    let len = frame.r10 as i64;
    if offset < 0 || len <= 0 {
        return Err(ERR_EINVAL);
    }
    let offset = usize::try_from(offset).map_err(|_| ERR_EINVAL)?;
    let len = usize::try_from(len).map_err(|_| ERR_EINVAL)?;
    active_context().supervisor.fallocate_fd(fd, mode, offset, len)?;
    Ok(0)
}

fn sys_fsetxattr(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EBADF)?;
    let name = read_xattr_name(frame.rsi)?;
    let size = usize::try_from(frame.r10).map_err(|_| ERR_EINVAL)?;
    let value = read_user_bytes(frame.rdx, size)?;
    let flags = u32::try_from(frame.r8).map_err(|_| ERR_EINVAL)?;
    let access = effective_access_snapshot();
    active_context().supervisor.fsetxattr_fd(fd, &name, &value, flags, access.ids())?;
    Ok(0)
}

fn sys_fgetxattr(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EBADF)?;
    let name = read_xattr_name(frame.rsi)?;
    let size = usize::try_from(frame.r10).map_err(|_| ERR_EINVAL)?;
    let access = effective_access_snapshot();
    let value = active_context().supervisor.fgetxattr_fd(fd, &name, size, access.ids())?;
    if size != 0 {
        write_user_bytes(frame.rdx, &value)?;
    }
    Ok(value.len() as i64)
}

fn sys_flistxattr(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EBADF)?;
    let size = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
    let access = effective_access_snapshot();
    let names = active_context().supervisor.flistxattr_fd(fd, size, access.ids())?;
    if size != 0 {
        write_user_bytes(frame.rsi, &names)?;
    }
    Ok(names.len() as i64)
}

fn sys_fremovexattr(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EBADF)?;
    let name = read_xattr_name(frame.rsi)?;
    let access = effective_access_snapshot();
    active_context().supervisor.fremovexattr_fd(fd, &name, access.ids())?;
    Ok(0)
}

fn sys_bpf(frame: &SyscallFrame) -> Result<i64, i32> {
    let cmd = u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    let attr_size = usize::try_from(frame.rdx).map_err(|_| ERR_E2BIG)?;
    match cmd {
        BPF_MAP_CREATE => {
            if !active_context().has_effective_capability(CAP_SYS_ADMIN) {
                return Err(ERR_EPERM);
            }
            let attr = read_bpf_attr(frame.rsi, attr_size, BPF_ATTR_MAP_CREATE_SIZE)?;
            let map_type = read_u32_from(&attr, 0)?;
            let key_size = read_u32_from(&attr, 4)?;
            let value_size = read_u32_from(&attr, 8)?;
            let max_entries = read_u32_from(&attr, 12)?;
            let map_flags = read_u32_from(&attr, 16)?;
            active_context()
                .supervisor
                .bpf_map_create(map_type, key_size, value_size, max_entries, map_flags)
                .map(|fd| fd as i64)
        }
        BPF_MAP_LOOKUP_ELEM => {
            let attr = read_bpf_attr(frame.rsi, attr_size, BPF_ATTR_MAP_LOOKUP_SIZE)?;
            let map_fd = read_u32_from(&attr, 0)?;
            let key_ptr = read_u64_from(&attr, 8)?;
            let value_ptr = read_u64_from(&attr, 16)?;
            let (key_size, _) = active_context().supervisor.bpf_map_shape_for_fd(map_fd)?;
            let key = read_user_bytes(key_ptr, key_size)?;
            let value = active_context().supervisor.bpf_map_lookup_elem(map_fd, &key)?;
            write_user_bytes(value_ptr, &value)?;
            Ok(0)
        }
        BPF_MAP_UPDATE_ELEM => {
            let attr = read_bpf_attr(frame.rsi, attr_size, BPF_ATTR_MAP_UPDATE_SIZE)?;
            let map_fd = read_u32_from(&attr, 0)?;
            let key_ptr = read_u64_from(&attr, 8)?;
            let value_ptr = read_u64_from(&attr, 16)?;
            let flags = read_u64_from(&attr, 24)?;
            let (key_size, value_size) =
                active_context().supervisor.bpf_map_shape_for_fd(map_fd)?;
            let key = read_user_bytes(key_ptr, key_size)?;
            let value = read_user_bytes(value_ptr, value_size)?;
            active_context().supervisor.bpf_map_update_elem(map_fd, &key, &value, flags)?;
            Ok(0)
        }
        BPF_MAP_DELETE_ELEM => {
            let attr = read_bpf_attr(frame.rsi, attr_size, BPF_ATTR_MAP_DELETE_SIZE)?;
            let map_fd = read_u32_from(&attr, 0)?;
            let key_ptr = read_u64_from(&attr, 8)?;
            let (key_size, _) = active_context().supervisor.bpf_map_shape_for_fd(map_fd)?;
            let key = read_user_bytes(key_ptr, key_size)?;
            active_context().supervisor.bpf_map_delete_elem(map_fd, &key)?;
            Ok(0)
        }
        _ => Err(ERR_EOPNOTSUPP),
    }
}

fn read_bpf_attr(ptr: u64, size: usize, min_size: usize) -> Result<Vec<u8>, i32> {
    if ptr == 0 {
        return Err(ERR_EFAULT);
    }
    if size < min_size {
        return Err(ERR_EINVAL);
    }
    if size > BPF_ATTR_MAX_SIZE {
        return Err(ERR_E2BIG);
    }
    read_user_bytes(ptr, size)
}

fn sys_getrlimit(frame: &SyscallFrame) -> Result<i64, i32> {
    sys_rlimit(active_context().pid, frame.rdi, 0, frame.rsi)
}

fn sys_setrlimit(frame: &SyscallFrame) -> Result<i64, i32> {
    sys_rlimit(active_context().pid, frame.rdi, frame.rsi, 0)
}

fn sys_prlimit64(frame: &SyscallFrame) -> Result<i64, i32> {
    let pid = if frame.rdi == 0 {
        active_context().pid
    } else {
        u32::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?
    };
    sys_rlimit(pid, frame.rsi, frame.rdx, frame.r10)
}

fn sys_rlimit(
    pid: u32,
    resource_raw: u64,
    new_limit_ptr: u64,
    old_limit_ptr: u64,
) -> Result<i64, i32> {
    if active_context().supervisor.query_process(pid).is_none() {
        return Err(ERR_ESRCH);
    }
    let resource = usize::try_from(resource_raw).map_err(|_| ERR_EINVAL)?;
    if resource >= 16 {
        return Err(ERR_EINVAL);
    }

    let old_limit = active_context().supervisor.get_rlimit(pid, resource);
    let new_limit = if new_limit_ptr != 0 {
        let bytes = read_user_bytes(new_limit_ptr, 16)?;
        let new_limit = Rlimit {
            cur: u64::from_le_bytes(bytes[..8].try_into().map_err(|_| ERR_EINVAL)?),
            max: u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| ERR_EINVAL)?),
        };
        if new_limit.cur > new_limit.max {
            return Err(ERR_EINVAL);
        }
        if new_limit.max > old_limit.max
            && !active_context().has_effective_capability(CAP_SYS_RESOURCE)
        {
            return Err(ERR_EPERM);
        }
        Some(new_limit)
    } else {
        None
    };
    if old_limit_ptr != 0 {
        let mut encoded = [0u8; 16];
        encoded[..8].copy_from_slice(&old_limit.cur.to_le_bytes());
        encoded[8..].copy_from_slice(&old_limit.max.to_le_bytes());
        write_user_bytes(old_limit_ptr, &encoded)?;
    }
    if let Some(new_limit) = new_limit {
        if !active_context().supervisor.set_rlimit(pid, resource, new_limit) {
            return Err(ERR_ESRCH);
        }
    }
    Ok(0)
}

fn sys_prctl(frame: &SyscallFrame) -> Result<i64, i32> {
    const PR_GET_DUMPABLE: u64 = 3;
    const PR_SET_DUMPABLE: u64 = 4;
    const PR_GET_KEEPCAPS: u64 = 7;
    const PR_SET_KEEPCAPS: u64 = 8;
    const PR_SET_NO_NEW_PRIVS: u64 = 38;
    const PR_GET_NO_NEW_PRIVS: u64 = 39;
    const PR_GET_SECCOMP: u64 = 21;
    const PR_SET_SECCOMP: u64 = 22;
    const PR_CAPBSET_READ: u64 = 23;
    const PR_CAPBSET_DROP: u64 = 24;
    const PR_GET_SECUREBITS: u64 = 27;
    const PR_SET_SECUREBITS: u64 = 28;
    const PR_SET_TIMERSLACK: u64 = 29;
    const PR_GET_TIMERSLACK: u64 = 30;
    const PR_CAP_AMBIENT: u64 = 47;

    match frame.rdi {
        PR_GET_DUMPABLE => {
            if frame.rsi != 0 || frame.rdx != 0 || frame.r10 != 0 || frame.r8 != 0 {
                return Err(ERR_EINVAL);
            }
            active_context()
                .supervisor
                .process_dumpable(active_context().pid)
                .map(|dumpable| dumpable as i64)
        }
        PR_SET_DUMPABLE => sys_prctl_set_dumpable(frame.rsi, frame.rdx, frame.r10, frame.r8),
        PR_GET_KEEPCAPS => {
            if frame.rsi != 0 || frame.rdx != 0 || frame.r10 != 0 || frame.r8 != 0 {
                return Err(ERR_EINVAL);
            }
            Ok(active_context().keepcaps() as i64)
        }
        PR_SET_KEEPCAPS => sys_prctl_set_keepcaps(frame.rsi, frame.rdx, frame.r10, frame.r8),
        PR_SET_NO_NEW_PRIVS => {
            if frame.rsi != 1 || frame.rdx != 0 || frame.r10 != 0 || frame.r8 != 0 {
                return Err(ERR_EINVAL);
            }
            if active_context().supervisor.set_no_new_privs(active_context().tid, true) {
                Ok(0)
            } else {
                Err(ERR_ESRCH)
            }
        }
        PR_GET_NO_NEW_PRIVS => {
            if frame.rsi != 0 || frame.rdx != 0 || frame.r10 != 0 || frame.r8 != 0 {
                return Err(ERR_EINVAL);
            }
            Ok(active_context().supervisor.no_new_privs(active_context().tid) as i64)
        }
        PR_GET_SECCOMP => {
            if frame.rsi != 0 || frame.rdx != 0 || frame.r10 != 0 || frame.r8 != 0 {
                return Err(ERR_EINVAL);
            }
            active_context()
                .supervisor
                .seccomp_mode(active_context().tid)
                .ok_or(ERR_ESRCH)
                .map(|mode| mode as i64)
        }
        PR_SET_SECCOMP => {
            if frame.r10 != 0 || frame.r8 != 0 {
                return Err(ERR_EINVAL);
            }
            install_seccomp_mode(frame.rsi, frame.rdx, 0)
        }
        PR_CAPBSET_READ => sys_prctl_capbset_read(frame.rsi, frame.rdx, frame.r10, frame.r8),
        PR_CAPBSET_DROP => sys_prctl_capbset_drop(frame.rsi, frame.rdx, frame.r10, frame.r8),
        PR_GET_SECUREBITS => {
            if frame.rsi != 0 || frame.rdx != 0 || frame.r10 != 0 || frame.r8 != 0 {
                return Err(ERR_EINVAL);
            }
            Ok(active_context().securebits() as i64)
        }
        PR_SET_SECUREBITS => sys_prctl_set_securebits(frame.rsi, frame.rdx, frame.r10, frame.r8),
        PR_SET_TIMERSLACK => sys_prctl_set_timerslack(frame.rsi, frame.rdx, frame.r10, frame.r8),
        PR_GET_TIMERSLACK => {
            if frame.rsi != 0 || frame.rdx != 0 || frame.r10 != 0 || frame.r8 != 0 {
                return Err(ERR_EINVAL);
            }
            Ok(active_context().timer_slack_ns().min(i64::MAX as u64) as i64)
        }
        PR_CAP_AMBIENT => sys_prctl_cap_ambient(frame.rsi, frame.rdx, frame.r10, frame.r8),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_prctl_set_timerslack(value: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64, i32> {
    if arg3 != 0 || arg4 != 0 || arg5 != 0 || value > i64::MAX as u64 {
        return Err(ERR_EINVAL);
    }
    active_context().set_timer_slack_ns(value);
    Ok(0)
}

fn sys_prctl_set_dumpable(value: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64, i32> {
    if value > 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
        return Err(ERR_EINVAL);
    }
    active_context().supervisor.set_process_dumpable(active_context().pid, value != 0)?;
    Ok(0)
}

fn sys_prctl_set_keepcaps(value: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64, i32> {
    if value > 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
        return Err(ERR_EINVAL);
    }
    let before = active_context().credential_state();
    if !active_context().set_keepcaps(value != 0) {
        return Err(ERR_EPERM);
    }
    record_securebits_transition_if_changed(before)
}

fn sys_prctl_set_securebits(bits: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64, i32> {
    if bits > u32::MAX as u64 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
        return Err(ERR_EINVAL);
    }
    let bits = bits as u32;
    if bits & !LINUX_SUPPORTED_SECUREBITS != 0 {
        return Err(ERR_EINVAL);
    }
    if !active_context().has_effective_capability(CAP_SETPCAP) {
        return Err(ERR_EPERM);
    }
    let before = active_context().credential_state();
    if !active_context().set_securebits(bits) {
        return Err(ERR_EPERM);
    }
    record_securebits_transition_if_changed(before)
}

fn record_securebits_transition_if_changed(before: CredentialState) -> Result<i64, i32> {
    if before.securebits == active_context().securebits() {
        return Ok(0);
    }
    if let Err(errno) = record_credential_transition(CredentialTransitionKind::CapSet {
        bounding: false,
        inheritable: false,
        permitted: false,
        effective: false,
        ambient: false,
        securebits: true,
    }) {
        restore_credential_state(before);
        return Err(errno);
    }
    Ok(0)
}

fn sys_prctl_capbset_read(cap: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64, i32> {
    if arg3 != 0 || arg4 != 0 || arg5 != 0 {
        return Err(ERR_EINVAL);
    }
    let capability = capability_bit_from_prctl_arg(cap)?;
    Ok(active_context().cap_bounding_is_set(capability) as i64)
}

fn sys_prctl_capbset_drop(cap: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64, i32> {
    if arg3 != 0 || arg4 != 0 || arg5 != 0 {
        return Err(ERR_EINVAL);
    }
    let capability = capability_bit_from_prctl_arg(cap)?;
    let before = active_context().credential_state();
    if !active_context().drop_bounding_capability(capability) {
        return Err(ERR_EPERM);
    }
    if before.cap_bounding != active_context().credential_state().cap_bounding {
        if let Err(errno) = record_credential_transition(CredentialTransitionKind::CapSet {
            bounding: true,
            inheritable: false,
            permitted: false,
            effective: false,
            ambient: false,
            securebits: false,
        }) {
            restore_credential_state(before);
            return Err(errno);
        }
    }
    Ok(0)
}

fn sys_prctl_cap_ambient(op: u64, cap: u64, arg4: u64, arg5: u64) -> Result<i64, i32> {
    const PR_CAP_AMBIENT_IS_SET: u64 = 1;
    const PR_CAP_AMBIENT_RAISE: u64 = 2;
    const PR_CAP_AMBIENT_LOWER: u64 = 3;
    const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;

    match op {
        PR_CAP_AMBIENT_IS_SET => {
            if arg4 != 0 || arg5 != 0 {
                return Err(ERR_EINVAL);
            }
            let capability = capability_bit_from_prctl_arg(cap)?;
            Ok(active_context().cap_ambient_is_set(capability) as i64)
        }
        PR_CAP_AMBIENT_RAISE => {
            if arg4 != 0 || arg5 != 0 {
                return Err(ERR_EINVAL);
            }
            let capability = capability_bit_from_prctl_arg(cap)?;
            let before = active_context().credential_state();
            if !active_context().raise_ambient_capability(capability) {
                return Err(ERR_EPERM);
            }
            if before.cap_ambient != active_context().cap_ambient() {
                if let Err(errno) = record_credential_transition(CredentialTransitionKind::CapSet {
                    bounding: false,
                    inheritable: false,
                    permitted: false,
                    effective: false,
                    ambient: true,
                    securebits: false,
                }) {
                    restore_credential_state(before);
                    return Err(errno);
                }
            }
            Ok(0)
        }
        PR_CAP_AMBIENT_LOWER => {
            if arg4 != 0 || arg5 != 0 {
                return Err(ERR_EINVAL);
            }
            let capability = capability_bit_from_prctl_arg(cap)?;
            let before = active_context().credential_state();
            active_context().lower_ambient_capability(capability);
            if before.cap_ambient != active_context().cap_ambient() {
                if let Err(errno) = record_credential_transition(CredentialTransitionKind::CapSet {
                    bounding: false,
                    inheritable: false,
                    permitted: false,
                    effective: false,
                    ambient: true,
                    securebits: false,
                }) {
                    restore_credential_state(before);
                    return Err(errno);
                }
            }
            Ok(0)
        }
        PR_CAP_AMBIENT_CLEAR_ALL => {
            if cap != 0 || arg4 != 0 || arg5 != 0 {
                return Err(ERR_EINVAL);
            }
            let before = active_context().credential_state();
            active_context().clear_ambient_capabilities();
            if before.cap_ambient != active_context().cap_ambient() {
                if let Err(errno) = record_credential_transition(CredentialTransitionKind::CapSet {
                    bounding: false,
                    inheritable: false,
                    permitted: false,
                    effective: false,
                    ambient: true,
                    securebits: false,
                }) {
                    restore_credential_state(before);
                    return Err(errno);
                }
            }
            Ok(0)
        }
        _ => Err(ERR_EINVAL),
    }
}

fn capability_bit_from_prctl_arg(cap: u64) -> Result<u64, i32> {
    if cap >= u64::BITS as u64 {
        return Err(ERR_EINVAL);
    }
    let capability = 1u64 << cap;
    if capability & LINUX_KNOWN_CAPS == 0 {
        return Err(ERR_EINVAL);
    }
    Ok(capability)
}

fn sys_seccomp(frame: &SyscallFrame) -> Result<i64, i32> {
    const SECCOMP_SET_MODE_STRICT: u64 = 0;
    const SECCOMP_SET_MODE_FILTER: u64 = 1;
    const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
    const SECCOMP_GET_NOTIF_SIZES: u64 = 3;

    match frame.rdi {
        SECCOMP_SET_MODE_STRICT => {
            if frame.rsi != 0 {
                return Err(ERR_EINVAL);
            }
            install_seccomp_mode(1, 0, 0)
        }
        SECCOMP_SET_MODE_FILTER => install_seccomp_mode(2, frame.rdx, frame.rsi),
        SECCOMP_GET_ACTION_AVAIL => {
            if frame.rsi != 0 {
                return Err(ERR_EINVAL);
            }
            seccomp_get_action_avail(frame.rdx)
        }
        SECCOMP_GET_NOTIF_SIZES => {
            if frame.rsi != 0 {
                return Err(ERR_EINVAL);
            }
            seccomp_get_notif_sizes(frame.rdx)
        }
        _ => Err(ERR_EINVAL),
    }
}

fn seccomp_get_action_avail(ptr: u64) -> Result<i64, i32> {
    let action = read_user_u32(ptr)?;
    if seccomp_action_available_without_listener(action) {
        Ok(0)
    } else {
        Err(vmos_abi::ERR_EOPNOTSUPP)
    }
}

fn seccomp_get_notif_sizes(ptr: u64) -> Result<i64, i32> {
    write_user_bytes(ptr, &linux_seccomp_notif_sizes_bytes())?;
    Ok(0)
}

fn install_seccomp_mode(mode: u64, arg: u64, flags: u64) -> Result<i64, i32> {
    const SECCOMP_MODE_STRICT: u64 = 1;
    const SECCOMP_MODE_FILTER: u64 = 2;

    match mode {
        SECCOMP_MODE_STRICT => {
            if flags != 0 || arg != 0 {
                return Err(ERR_EINVAL);
            }
            active_context().supervisor.set_seccomp_strict(active_context().tid).map(|()| 0)
        }
        SECCOMP_MODE_FILTER => {
            let supported_flags = SECCOMP_FILTER_FLAG_LOG | SECCOMP_FILTER_FLAG_TSYNC;
            if flags & !supported_flags != 0 {
                return Err(ERR_EINVAL);
            }
            let privileged = active_context().has_effective_capability(CAP_SYS_ADMIN);
            if !privileged && !active_context().supervisor.no_new_privs(active_context().tid) {
                return Err(ERR_EACCES);
            }
            let program = read_seccomp_filter_program(arg)?;
            active_context()
                .supervisor
                .set_seccomp_filter(
                    active_context().tid,
                    program,
                    privileged,
                    flags & SECCOMP_FILTER_FLAG_TSYNC != 0,
                    flags & SECCOMP_FILTER_FLAG_LOG != 0,
                )
                .map(|()| 0)
        }
        _ => Err(ERR_EINVAL),
    }
}

fn read_seccomp_filter_program(ptr: u64) -> Result<SeccompFilterProgram, i32> {
    const SOCK_FPROG_SIZE: usize = 16;
    const SOCK_FILTER_SIZE: usize = 8;
    const MAX_FILTER_INSTRUCTIONS: usize = 4096;

    let fprog = read_user_bytes(ptr, SOCK_FPROG_SIZE)?;
    let len = u16::from_le_bytes(fprog[0..2].try_into().map_err(|_| ERR_EINVAL)?) as usize;
    let filter_ptr = u64::from_le_bytes(fprog[8..16].try_into().map_err(|_| ERR_EINVAL)?);
    if len == 0 || len > MAX_FILTER_INSTRUCTIONS {
        return Err(ERR_EINVAL);
    }
    if filter_ptr == 0 {
        return Err(ERR_EFAULT);
    }
    let byte_len = len.checked_mul(SOCK_FILTER_SIZE).ok_or(ERR_EINVAL)?;
    let raw_filter = read_user_bytes(filter_ptr, byte_len)?;
    let mut instructions = Vec::with_capacity(len);
    for chunk in raw_filter.chunks_exact(SOCK_FILTER_SIZE) {
        instructions.push(SeccompInstruction::new(
            u16::from_le_bytes(chunk[0..2].try_into().map_err(|_| ERR_EINVAL)?),
            chunk[2],
            chunk[3],
            u32::from_le_bytes(chunk[4..8].try_into().map_err(|_| ERR_EINVAL)?),
        ));
    }
    SeccompFilterProgram::new(instructions).map_err(|_| ERR_EINVAL)
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum UtimensatPermission {
    None,
    WriteOrOwner,
    OwnerOnly,
}

fn sys_utimensat(frame: &SyscallFrame) -> Result<i64, i32> {
    const UTIMENSAT_ALLOWED_FLAGS: u64 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    let flags = frame.r10;
    if flags & !UTIMENSAT_ALLOWED_FLAGS != 0 {
        return Err(ERR_EINVAL);
    }

    let path = read_user_c_string(frame.rsi, PATH_MAX)?;
    if path.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return Err(ERR_ENOENT);
    }
    let now_ns = current_realtime_ns();
    let (atime_ns, mtime_ns, permission) = read_utimensat_times(frame.rdx, now_ns)?;
    let access = effective_access_snapshot();
    let check_permissions = permission != UtimensatPermission::None;
    let allow_write_access = permission == UtimensatPermission::WriteOrOwner;

    if path.is_empty() {
        let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
        active_context().supervisor.update_timestamps_fd(
            fd,
            atime_ns,
            mtime_ns,
            now_ns,
            check_permissions,
            allow_write_access,
            access.ids(),
        )?;
        return Ok(0);
    }

    let resolved = resolve_path(linux_fd_arg(frame.rdi), &path)?;
    let follow_symlink = flags & AT_SYMLINK_NOFOLLOW == 0;
    let resolved = resolve_final_symlink_for_stat(resolved, follow_symlink)?;
    active_context().supervisor.update_timestamps_path(
        &resolved,
        atime_ns,
        mtime_ns,
        now_ns,
        check_permissions,
        allow_write_access,
        access.ids(),
    )?;
    Ok(0)
}

fn read_utimensat_times(
    ptr: u64,
    now_ns: u64,
) -> Result<(Option<u64>, Option<u64>, UtimensatPermission), i32> {
    if ptr == 0 {
        return Ok((Some(now_ns), Some(now_ns), UtimensatPermission::WriteOrOwner));
    }
    let bytes = read_user_bytes(ptr, (LINUX_TIMESPEC_SIZE * 2) as usize)?;
    let atime = decode_utimensat_timespec(&bytes[0..16], now_ns)?;
    let mtime = decode_utimensat_timespec(&bytes[16..32], now_ns)?;
    let permission = match (atime, mtime) {
        (None, None) => UtimensatPermission::None,
        (Some(atime), Some(mtime)) if atime == now_ns && mtime == now_ns => {
            let atime_nsec = read_i64_from(&bytes, 8)?;
            let mtime_nsec = read_i64_from(&bytes, 24)?;
            if atime_nsec == UTIME_NOW && mtime_nsec == UTIME_NOW {
                UtimensatPermission::WriteOrOwner
            } else {
                UtimensatPermission::OwnerOnly
            }
        }
        _ => UtimensatPermission::OwnerOnly,
    };
    Ok((atime, mtime, permission))
}

fn decode_utimensat_timespec(bytes: &[u8], now_ns: u64) -> Result<Option<u64>, i32> {
    let tv_sec = i64::from_le_bytes(bytes[..8].try_into().map_err(|_| ERR_EINVAL)?);
    let tv_nsec = i64::from_le_bytes(bytes[8..16].try_into().map_err(|_| ERR_EINVAL)?);
    match tv_nsec {
        UTIME_NOW => Ok(Some(now_ns)),
        UTIME_OMIT => Ok(None),
        0..=999_999_999 if tv_sec >= 0 => {
            Ok(Some((tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(tv_nsec as u64)))
        }
        _ => Err(ERR_EINVAL),
    }
}

fn sys_mount(frame: &SyscallFrame) -> Result<i64, i32> {
    let target = read_user_c_string(frame.rsi, PATH_MAX)?;
    let target = resolve_path(AT_FDCWD, &target)?;
    if active_context().supervisor.path_kind(&target)? != vmos_abi::NodeKind::Directory {
        return Err(ERR_ENOTDIR);
    }
    let fs_type =
        if frame.rdx == 0 { Vec::new() } else { read_user_c_string(frame.rdx, PATH_MAX)? };
    if fs_type.as_slice() != b"tmpfs" {
        return Err(ERR_ENODEV);
    }
    Ok(0)
}

fn sys_umount2(frame: &SyscallFrame) -> Result<i64, i32> {
    let target = read_user_c_string(frame.rdi, PATH_MAX)?;
    let target = resolve_path(AT_FDCWD, &target)?;
    active_context().supervisor.stat_path_abi(&target)?;
    Ok(0)
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
    const CLOCK_REALTIME: u64 = 0;
    const CLOCK_REALTIME_COARSE: u64 = 5;
    const CLOCK_REALTIME_ALARM: u64 = 8;
    const CLOCK_TAI: u64 = 11;

    if frame.rdi > 11 {
        return Err(ERR_EINVAL);
    }
    let now_ns = match frame.rdi {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE | CLOCK_REALTIME_ALARM => current_realtime_ns(),
        CLOCK_TAI => current_tai_ns(),
        _ => current_monotonic_ns(),
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
    active_context().supervisor.cancel_realtime_timerfds_on_clock_set();
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
    let nofile = active_context().supervisor.get_rlimit(active_context().pid, RLIMIT_NOFILE).cur;
    let nfds = validate_pselect6_nfds(frame.rdi, nofile)?;
    let temporary_sigmask = read_pselect_sigmask(frame.r9)?;
    let timeout_ms = if frame.r8 != 0 {
        let ms = read_user_timespec_ms(frame.r8)?;
        Some(core::cmp::min(ms, u32::MAX as u64) as u32)
    } else {
        None
    };
    let snapshot = read_pselect_fdsets(frame.rsi, frame.rdx, frame.r10, nfds)?;
    let ready = collect_pselect_ready(&snapshot)?;
    if ready.ready != 0 || timeout_ms == Some(0) {
        return write_pselect_result(&snapshot, &ready);
    }

    let tid = active_context().tid;
    let old_sigmask = if let Some(sigmask) = temporary_sigmask {
        Some(active_context().supervisor.set_sigmask(tid, 2, sigmask).ok_or(ERR_EINVAL)?)
    } else {
        None
    };
    let wait_result = active_context().supervisor.block_on_fdset_wait(
        snapshot.read_bits,
        snapshot.write_bits,
        [0; PSELECT6_FDSET_WORDS],
        u16::try_from(nfds).map_err(|_| ERR_EINVAL)?,
        timeout_ms,
    );
    if let Some(old_sigmask) = old_sigmask {
        active_context().supervisor.set_sigmask(tid, 2, old_sigmask).ok_or(ERR_EINVAL)?;
    }
    wait_result?;

    let ready = collect_pselect_ready(&snapshot)?;
    write_pselect_result(&snapshot, &ready)
}

fn sys_select(frame: &SyscallFrame) -> Result<i64, i32> {
    let nofile = active_context().supervisor.get_rlimit(active_context().pid, RLIMIT_NOFILE).cur;
    let nfds = validate_pselect6_nfds(frame.rdi, nofile)?;
    let timeout_ms = if frame.r8 != 0 { Some(read_user_timeval_ms(frame.r8)?) } else { None };
    let wait_timeout_ms = timeout_ms.map(|ms| core::cmp::min(ms, u32::MAX as u64) as u32);
    let start_ns = current_monotonic_ns();
    let snapshot = read_pselect_fdsets(frame.rsi, frame.rdx, frame.r10, nfds)?;
    let ready = collect_pselect_ready(&snapshot)?;
    if ready.ready != 0 || wait_timeout_ms == Some(0) {
        let ret = write_pselect_result(&snapshot, &ready)?;
        write_select_timeout_remaining(frame.r8, timeout_ms, start_ns)?;
        return Ok(ret);
    }

    let wait_result = active_context().supervisor.block_on_fdset_wait(
        snapshot.read_bits,
        snapshot.write_bits,
        [0; PSELECT6_FDSET_WORDS],
        u16::try_from(nfds).map_err(|_| ERR_EINVAL)?,
        wait_timeout_ms,
    );
    if let Err(errno) = wait_result {
        if errno == ERR_EINTR {
            write_select_timeout_remaining(frame.r8, timeout_ms, start_ns)?;
        }
        return Err(errno);
    }

    let ready = collect_pselect_ready(&snapshot)?;
    let ret = write_pselect_result(&snapshot, &ready)?;
    write_select_timeout_remaining(frame.r8, timeout_ms, start_ns)?;
    Ok(ret)
}

fn validate_pselect6_nfds(nfds_arg: u64, nofile: u64) -> Result<usize, i32> {
    let nfds = usize::try_from(nfds_arg).map_err(|_| ERR_EINVAL)?;
    if !wait_nfds_within_rlimit(nfds, nofile) {
        return Err(ERR_EINVAL);
    }
    if nfds > PSELECT6_MAX_FDS {
        return Err(ERR_EINVAL);
    }
    Ok(nfds)
}

fn sys_clock_adjtime(frame: &SyscallFrame) -> Result<i64, i32> {
    const CLOCK_REALTIME: u64 = 0;
    const TIMEX_SIZE: usize = 208;
    const ADJ_OFFSET: u32 = 0x0001;
    const ADJ_FREQUENCY: u32 = 0x0002;
    const ADJ_MAXERROR: u32 = 0x0004;
    const ADJ_ESTERROR: u32 = 0x0008;
    const ADJ_STATUS: u32 = 0x0010;
    const ADJ_TIMECONST: u32 = 0x0020;
    const ADJ_TAI: u32 = 0x0080;
    const ADJ_SETOFFSET: u32 = 0x0100;
    const ADJ_MICRO: u32 = 0x1000;
    const ADJ_NANO: u32 = 0x2000;
    const ADJ_TICK: u32 = 0x4000;
    const SUPPORTED_MODES: u32 = ADJ_OFFSET
        | ADJ_FREQUENCY
        | ADJ_MAXERROR
        | ADJ_ESTERROR
        | ADJ_STATUS
        | ADJ_TIMECONST
        | ADJ_TAI
        | ADJ_SETOFFSET
        | ADJ_MICRO
        | ADJ_NANO
        | ADJ_TICK;
    const STA_UNSYNC: i32 = 0x0040;
    const STA_RONLY: i32 = 0x0100 | 0x0200 | 0x0400 | 0x0800 | 0x1000 | 0x2000 | 0x4000 | 0x8000;
    const TIME_OK: i64 = 0;
    const TIME_ERROR: i64 = 5;

    if frame.rsi == 0 {
        return Err(ERR_EFAULT);
    }
    if frame.rdi != CLOCK_REALTIME {
        return Err(ERR_EINVAL);
    }

    let mut tx_lease = user_lease(frame.rsi, TIMEX_SIZE as u64, true)?;
    let mut tx = tx_lease.bytes_mut().map_err(map_dmw_fault)?.to_vec();
    let modes = read_u32_from(&tx, 0)?;
    if modes & !SUPPORTED_MODES != 0 || modes & ADJ_MICRO != 0 && modes & ADJ_NANO != 0 {
        return Err(ERR_EINVAL);
    }

    let tick = crate::interrupts::tick_count();
    let timer_hz = crate::interrupts::TIMER_HZ as u64;
    let current_ns = current_realtime_ns();
    active_context().set_realtime_ns(current_ns, tick);

    let mut state = active_context().clock_adj_state();
    if modes & ADJ_MICRO != 0 {
        state.nano = false;
    }
    if modes & ADJ_NANO != 0 {
        state.nano = true;
    }
    let unit_ns = if state.nano { 1i128 } else { 1_000i128 };

    let mut delta_ns = 0i128;
    if modes & ADJ_OFFSET != 0 {
        delta_ns =
            delta_ns.saturating_add((read_i64_from(&tx, 8)? as i128).saturating_mul(unit_ns));
    }
    if modes & ADJ_SETOFFSET != 0 {
        let sec = read_i64_from(&tx, 72)? as i128;
        let frac = read_i64_from(&tx, 80)? as i128;
        delta_ns = delta_ns
            .saturating_add(sec.saturating_mul(1_000_000_000))
            .saturating_add(frac.saturating_mul(unit_ns));
    }
    if delta_ns != 0 {
        active_context().adjust_realtime_ns(delta_ns, tick, timer_hz);
        active_context().supervisor.cancel_realtime_timerfds_on_clock_set();
    }

    let current_ns = current_realtime_ns();
    active_context().set_realtime_ns(current_ns, tick);
    if modes & ADJ_FREQUENCY != 0 {
        state.freq_scaled_ppm = read_i64_from(&tx, 16)?;
    }
    if modes & ADJ_MAXERROR != 0 {
        state.maxerror_us = read_i64_from(&tx, 24)?;
    }
    if modes & ADJ_ESTERROR != 0 {
        state.esterror_us = read_i64_from(&tx, 32)?;
    }
    if modes & ADJ_STATUS != 0 {
        state.status = read_i32_from(&tx, 40)? & !STA_RONLY;
    }
    if modes & ADJ_TIMECONST != 0 {
        state.constant = read_i64_from(&tx, 48)?;
    }
    if modes & ADJ_TICK != 0 {
        state.tick_us = read_i64_from(&tx, 88)?;
    }
    if modes & ADJ_TAI != 0 {
        state.tai = read_i32_from(&tx, 160)?;
    }
    active_context().set_clock_adj_state(state);

    write_timex_snapshot(
        &mut tx,
        modes,
        active_context().clock_adj_state(),
        current_realtime_ns(),
    )?;
    tx_lease.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&tx);

    if state.status & STA_UNSYNC != 0 { Ok(TIME_ERROR) } else { Ok(TIME_OK) }
}

fn write_timex_snapshot(
    tx: &mut [u8],
    modes: u32,
    state: ClockAdjustmentState,
    now_ns: u64,
) -> Result<(), i32> {
    const STA_NANO: i32 = 0x2000;
    write_u32(tx, 0, modes);
    write_i64(tx, 8, 0);
    write_i64(tx, 16, state.freq_scaled_ppm);
    write_i64(tx, 24, state.maxerror_us);
    write_i64(tx, 32, state.esterror_us);
    let status = if state.nano { state.status | STA_NANO } else { state.status & !STA_NANO };
    write_i32(tx, 40, status);
    write_i64(tx, 48, state.constant);
    write_i64(tx, 56, 1_000_000 / crate::interrupts::TIMER_HZ as i64);
    write_i64(tx, 64, 500);
    write_i64(tx, 72, (now_ns / 1_000_000_000) as i64);
    let subsec = now_ns % 1_000_000_000;
    write_i64(tx, 80, if state.nano { subsec as i64 } else { (subsec / 1_000) as i64 });
    write_i64(tx, 88, state.tick_us);
    write_i64(tx, 96, 0);
    write_i64(tx, 104, 0);
    write_i32(tx, 112, 0);
    write_i64(tx, 120, 0);
    write_i64(tx, 128, 0);
    write_i64(tx, 136, 0);
    write_i64(tx, 144, 0);
    write_i64(tx, 152, 0);
    write_i32(tx, 160, state.tai);
    Ok(())
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
    let signo = u8::try_from(frame.rdi).map_err(|_| ERR_EINVAL)?;
    if signo == 0 || signo >= 64 || frame.r10 != LINUX_SIGSET_BYTES as u64 {
        return Err(ERR_EINVAL);
    }
    // Read new action from userspace (if provided)
    let new_act = if frame.rsi != 0 {
        let bytes = read_user_bytes(frame.rsi, LINUX_SIGACTION_BYTES)?;
        SigAction {
            handler: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            flags: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            restorer: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            mask: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        }
    } else {
        SigAction::default()
    };
    if frame.rsi != 0 && matches!(signo, 9 | 19) {
        return Err(ERR_EINVAL);
    }
    let pid = active_context().pid;
    let supervisor = &mut active_context().supervisor;
    // Return old action
    let old = supervisor.get_sigaction(pid, signo).unwrap_or_default();
    if frame.rdx != 0 {
        let mut buf = [0u8; LINUX_SIGACTION_BYTES];
        buf[0..8].copy_from_slice(&old.handler.to_le_bytes());
        buf[8..16].copy_from_slice(&old.flags.to_le_bytes());
        buf[16..24].copy_from_slice(&old.restorer.to_le_bytes());
        buf[24..32].copy_from_slice(&old.mask.to_le_bytes());
        write_user_bytes(frame.rdx, &buf)?;
    }
    if frame.rsi != 0 && !supervisor.set_sigaction(pid, signo, new_act) {
        return Err(ERR_EINVAL);
    }
    Ok(0)
}

fn sys_rt_sigprocmask(frame: &SyscallFrame) -> Result<i64, i32> {
    let how = frame.rdi as u32;
    let set_ptr = frame.rsi;
    let oldset_ptr = frame.rdx;
    let sigsetsize = frame.r10;
    if sigsetsize != LINUX_SIGSET_BYTES as u64 {
        return Err(ERR_EINVAL);
    }
    let tid = active_context().tid;
    let supervisor = &mut active_context().supervisor;
    let old_mask = supervisor.get_sigmask(tid).unwrap_or(0);
    if oldset_ptr != 0 {
        write_user_bytes(oldset_ptr, &old_mask.to_le_bytes())?;
    }
    if set_ptr != 0 {
        let bytes = read_user_bytes(set_ptr, LINUX_SIGSET_BYTES)?;
        let set = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        if supervisor.set_sigmask(tid, how, set).is_none() {
            return Err(ERR_EINVAL);
        }
    }
    Ok(0)
}

fn sys_rt_sigpending(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rsi != LINUX_SIGSET_BYTES as u64 {
        return Err(ERR_EINVAL);
    }
    let pending = active_context()
        .supervisor
        .blocked_pending_signal_set(active_context().tid)
        .ok_or(ERR_ESRCH)?;
    write_user_bytes(frame.rdi, &pending.to_le_bytes())?;
    Ok(0)
}

fn sys_rt_sigreturn(frame: &mut SyscallFrame) -> Result<i64, i32> {
    match restore_from_signal_frame(frame) {
        Ok(restored) => ring3::resume_user_return(restored),
        Err(errno) => {
            crate::kwarn!("rt_sigreturn failed errno={}", errno);
            let pid = active_context().pid;
            active_context().supervisor.process_exit(pid, 128 + 11);
            handle_user_fault(11);
        }
    }
}

fn sys_pause(_frame: &SyscallFrame) -> Result<i64, i32> {
    active_context().supervisor.block_on_signal_wait()?;
    Err(vmos_abi::ERR_EINTR)
}

fn sys_rt_sigsuspend(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rsi != LINUX_SIGSET_BYTES as u64 {
        return Err(ERR_EINVAL);
    }
    if frame.rdi == 0 {
        return Err(ERR_EFAULT);
    }
    let temporary_sigmask = read_user_u64(frame.rdi)?;
    let tid = active_context().tid;
    active_context().supervisor.begin_sigsuspend(tid, temporary_sigmask).ok_or(ERR_EINVAL)?;

    let wait_result = active_context().supervisor.block_on_signal_wait();
    match wait_result {
        Err(vmos_abi::ERR_EINTR) => Err(vmos_abi::ERR_EINTR),
        Ok(()) => {
            active_context().supervisor.cancel_sigsuspend(tid);
            Err(vmos_abi::ERR_EINTR)
        }
        Err(errno) => {
            active_context().supervisor.cancel_sigsuspend(tid);
            Err(errno)
        }
    }
}

fn sys_sigaltstack(frame: &SyscallFrame) -> Result<i64, i32> {
    let new_stack = if frame.rdi == 0 { None } else { Some(read_linux_stack_t(frame.rdi)?) };
    let saved = ring3::capture_user_return(frame);
    let tid = active_context().tid;
    let current_stack = active_context().supervisor.signal_alt_stack(tid).ok_or(ERR_ESRCH)?;
    let on_stack = current_stack.contains(saved.rsp);

    if new_stack.is_some() && on_stack {
        return Err(ERR_EPERM);
    }
    if frame.rsi != 0 {
        write_linux_stack_t(frame.rsi, current_stack, on_stack)?;
    }
    if let Some(stack) = new_stack {
        active_context().supervisor.set_signal_alt_stack(tid, stack).ok_or(ERR_ESRCH)?;
    }
    Ok(0)
}

fn read_linux_stack_t(ptr: u64) -> Result<SignalAltStack, i32> {
    let bytes = read_user_bytes(ptr, LINUX_STACK_T_BYTES)?;
    let sp = read_u64_from(&bytes, 0)?;
    let flags = read_u32_from(&bytes, 8)?;
    let size = read_u64_from(&bytes, 16)?;
    match flags {
        0 | SIGALTSTACK_SS_AUTODISARM => {
            if size < MINSIGSTKSZ {
                return Err(ERR_ENOMEM);
            }
            validate_lower_user_address_range(sp, size)?;
            Ok(SignalAltStack { sp, size, flags })
        }
        SIGALTSTACK_SS_DISABLE => Ok(SignalAltStack::disabled()),
        _ => Err(ERR_EINVAL),
    }
}

fn write_linux_stack_t(ptr: u64, stack: SignalAltStack, on_stack: bool) -> Result<(), i32> {
    let mut out = [0u8; LINUX_STACK_T_BYTES];
    encode_linux_stack_t(&mut out, 0, stack, on_stack);
    write_user_bytes(ptr, &out)
}

fn encode_linux_stack_t(out: &mut [u8], offset: usize, stack: SignalAltStack, on_stack: bool) {
    let flags = if on_stack {
        SIGALTSTACK_SS_ONSTACK
    } else if stack.is_disabled() {
        SIGALTSTACK_SS_DISABLE
    } else {
        stack.flags & SIGALTSTACK_SS_AUTODISARM
    };
    write_u64(out, offset, stack.sp);
    write_u32(out, offset + 8, flags);
    write_u64(out, offset + 16, stack.size);
}

fn restore_from_signal_frame(frame: &mut SyscallFrame) -> Result<UserReturnContext, i32> {
    let current = ring3::capture_user_return(frame);
    let bytes = read_user_bytes(current.rsp, VMOS_SIGNAL_FRAME_SIZE)?;
    if read_u64_from(&bytes, 0)? != VMOS_SIGNAL_FRAME_MAGIC {
        return Err(ERR_EINVAL);
    }

    let saved_fs_base = read_u64_from(&bytes, 32)?;
    let ucontext_sp = current
        .rsp
        .checked_add(VMOS_SIGNAL_FRAME_SIZE as u64)
        .and_then(|addr| addr.checked_add(LINUX_SIGINFO_SIZE as u64))
        .ok_or(ERR_EFAULT)?;
    let ucontext = read_user_bytes(ucontext_sp, LINUX_UCONTEXT_MIN_SIZE)?;
    let restored = decode_linux_ucontext_return(&ucontext, saved_fs_base)?;
    let restored_sigmask = read_u64_from(&ucontext, LINUX_UCONTEXT_SIGMASK_OFFSET)?;
    let tid = active_context().tid;
    if active_context().supervisor.set_sigmask(tid, 2, restored_sigmask).is_none() {
        crate::kwarn!("rt_sigreturn could not restore sigmask for tid {}", tid);
    }
    if read_u64_from(&bytes, VMOS_SIGNAL_FRAME_ALTSTACK_RESTORE_OFFSET)? != 0 {
        let stack = SignalAltStack {
            sp: read_u64_from(&bytes, 112)?,
            size: read_u64_from(&bytes, 120)?,
            flags: read_u32_from(&bytes, 128)?,
        };
        if active_context().supervisor.set_signal_alt_stack(tid, stack).is_none() {
            crate::kwarn!("rt_sigreturn could not restore altstack for tid {}", tid);
        }
    }
    Ok(restored)
}

fn deliver_pending_signal_to_user(frame: &mut SyscallFrame, syscall_nr: u64) {
    let tid = active_context().tid;
    if let Some(delivery) = active_context().supervisor.take_pending_user_handler_signal(tid) {
        let restart_syscall = signal_restart_syscall(frame, syscall_nr, delivery.action.flags);
        if let Err(errno) = install_user_signal_frame(frame, delivery, restart_syscall) {
            crate::kwarn!("signal frame install failed errno={}", errno);
            let pid = active_context().pid;
            active_context().supervisor.process_exit(pid, 128 + 11);
            handle_user_fault(11);
        }
    } else {
        active_context().supervisor.deliver_pending_signals(tid);
    }
}

fn install_user_signal_frame(
    frame: &mut SyscallFrame,
    delivery: UserSignalDelivery,
    restart_syscall: Option<u64>,
) -> Result<(), i32> {
    if delivery.action.restorer == 0 {
        return Err(ERR_ENOSYS);
    }
    validate_user_range(delivery.action.handler, 1, false)?;
    validate_user_range(delivery.action.restorer, 1, false)?;

    let mut saved = ring3::capture_user_return(frame);
    if let Some(syscall_nr) = restart_syscall {
        saved.frame.rax = syscall_nr;
        saved.frame.rcx = saved.frame.rcx.checked_sub(2).ok_or(ERR_EFAULT)?;
    }
    let alt_stack = if delivery.action.flags & SA_ONSTACK != 0 {
        active_context().supervisor.signal_alt_stack_for_delivery(active_context().tid, saved.rsp)
    } else {
        None
    };
    let stack_top = match alt_stack {
        Some(stack) => stack.top().ok_or(ERR_EFAULT)?,
        None => saved.rsp,
    };
    let total_len = 8 + VMOS_SIGNAL_FRAME_SIZE + LINUX_SIGINFO_SIZE + LINUX_UCONTEXT_MIN_SIZE;
    let base = stack_top.checked_sub(total_len as u64 + 16).ok_or(ERR_EFAULT)?;
    let frame_sp = (base & !15).checked_add(8).ok_or(ERR_EFAULT)?;
    if let Some(stack) = alt_stack {
        if frame_sp < stack.sp {
            return Err(ERR_EFAULT);
        }
    }
    let record_sp = frame_sp.checked_add(8).ok_or(ERR_EFAULT)?;
    let siginfo_sp = record_sp.checked_add(VMOS_SIGNAL_FRAME_SIZE as u64).ok_or(ERR_EFAULT)?;
    let ucontext_sp = siginfo_sp.checked_add(LINUX_SIGINFO_SIZE as u64).ok_or(ERR_EFAULT)?;
    let signal_stack =
        active_context().supervisor.signal_alt_stack(active_context().tid).unwrap_or_default();
    let restore_alt_stack = alt_stack.filter(|stack| stack.autodisarm());

    write_user_u64(frame_sp, delivery.action.restorer)?;
    write_user_bytes(
        record_sp,
        &encode_vmos_signal_frame(
            &saved,
            delivery.old_sigmask,
            delivery.signal.signo,
            restore_alt_stack,
        ),
    )?;
    write_user_bytes(siginfo_sp, &encode_linux_siginfo(&delivery.signal))?;
    write_user_bytes(
        ucontext_sp,
        &encode_linux_ucontext(&saved, delivery.old_sigmask, signal_stack, ucontext_sp),
    )?;
    if restore_alt_stack.is_some() {
        active_context()
            .supervisor
            .set_signal_alt_stack(active_context().tid, SignalAltStack::disabled())
            .ok_or(ERR_ESRCH)?;
    }

    let mut next = saved;
    next.rsp = frame_sp;
    next.frame.rcx = delivery.action.handler;
    next.frame.rdi = delivery.signal.signo as u64;
    if delivery.action.flags & SA_SIGINFO != 0 {
        next.frame.rsi = siginfo_sp;
        next.frame.rdx = ucontext_sp;
    } else {
        next.frame.rsi = 0;
        next.frame.rdx = 0;
    }
    next.frame.rax = 0;
    ring3::install_user_return(frame, next);
    Ok(())
}

fn signal_restart_syscall(frame: &SyscallFrame, syscall_nr: u64, action_flags: u64) -> Option<u64> {
    if action_flags & SA_RESTART == 0 || linux_error_return(frame) != Some(ERR_EINTR) {
        return None;
    }
    restartable_interrupted_syscall(frame, syscall_nr).then_some(syscall_nr)
}

fn linux_error_return(frame: &SyscallFrame) -> Option<i32> {
    let ret = frame.rax as i64;
    (ret < 0 && ret >= -4095).then_some((-ret) as i32)
}

fn restartable_interrupted_syscall(frame: &SyscallFrame, syscall_nr: u64) -> bool {
    match syscall_nr {
        SYS_READ | SYS_READV | SYS_WRITE | SYS_WRITEV | SYS_WAIT4 | SYS_ACCEPT | SYS_ACCEPT4
        | SYS_CONNECT | SYS_SENDTO | SYS_RECVFROM | SYS_FLOCK => true,
        SYS_FCNTL => frame.rsi == FCNTL_F_SETLKW,
        SYS_FUTEX => {
            let op = (frame.rsi as u32) & FUTEX_CMD_MASK;
            op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET
        }
        _ => false,
    }
}

fn encode_vmos_signal_frame(
    saved: &UserReturnContext,
    old_sigmask: u64,
    signo: u8,
    restore_alt_stack: Option<SignalAltStack>,
) -> [u8; VMOS_SIGNAL_FRAME_SIZE] {
    let mut out = [0u8; VMOS_SIGNAL_FRAME_SIZE];
    write_u64(&mut out, 0, VMOS_SIGNAL_FRAME_MAGIC);
    write_u64(&mut out, 8, signo as u64);
    write_u64(&mut out, 16, old_sigmask);
    write_u64(&mut out, 24, saved.rsp);
    write_u64(&mut out, 32, saved.fs_base);
    write_u64(&mut out, 40, saved.frame.r9);
    write_u64(&mut out, 48, saved.frame.r8);
    write_u64(&mut out, 56, saved.frame.r10);
    write_u64(&mut out, 64, saved.frame.rdx);
    write_u64(&mut out, 72, saved.frame.rsi);
    write_u64(&mut out, 80, saved.frame.rdi);
    write_u64(&mut out, 88, saved.frame.rax);
    write_u64(&mut out, 96, saved.frame.rcx);
    write_u64(&mut out, 104, saved.frame.r11);
    if let Some(stack) = restore_alt_stack {
        write_u64(&mut out, 112, stack.sp);
        write_u64(&mut out, 120, stack.size);
        write_u32(&mut out, 128, stack.flags);
        write_u64(&mut out, VMOS_SIGNAL_FRAME_ALTSTACK_RESTORE_OFFSET, 1);
    }
    out
}

fn encode_linux_siginfo(
    signal: &crate::supervisor::types::PendingSignal,
) -> [u8; LINUX_SIGINFO_SIZE] {
    let mut out = [0u8; LINUX_SIGINFO_SIZE];
    write_i32(&mut out, 0, signal.signo as i32);
    write_i32(&mut out, 4, signal.si_errno);
    write_i32(&mut out, 8, signal.si_code);
    if signal.signo == SIGSYS && signal.si_code == SI_CODE_SYS_SECCOMP {
        write_u64(&mut out, 16, signal.si_call_addr);
        write_u32(&mut out, 24, signal.si_syscall);
        write_u32(&mut out, 28, signal.si_arch);
    } else {
        write_u32(&mut out, 16, signal.si_pid);
        write_u32(&mut out, 20, signal.si_uid);
    }
    out
}

fn linux_signal_mask_bit(signo: u8) -> u64 {
    if signo == 0 || signo >= 64 { 0 } else { 1u64 << (signo - 1) }
}

fn signal_wait_set_contains(wait_set: u64, signal: u32) -> bool {
    let Ok(signo) = u8::try_from(signal) else {
        return false;
    };
    signo != 9 && signo != 19 && wait_set & linux_signal_mask_bit(signo) != 0
}

fn write_sigtimedwait_result(info_ptr: u64, signal: &PendingSignal) -> Result<i64, i32> {
    if info_ptr != 0 {
        write_user_bytes(info_ptr, &encode_linux_siginfo(signal))?;
    }
    Ok(signal.signo as i64)
}

fn encode_linux_ucontext(
    saved: &UserReturnContext,
    old_sigmask: u64,
    signal_stack: SignalAltStack,
    ucontext_sp: u64,
) -> [u8; LINUX_UCONTEXT_MIN_SIZE] {
    let mut out = [0u8; LINUX_UCONTEXT_MIN_SIZE];
    encode_linux_stack_t(
        &mut out,
        LINUX_UCONTEXT_STACK_OFFSET,
        signal_stack,
        signal_stack.contains(saved.rsp),
    );
    let mcontext = LINUX_UCONTEXT_MCONTEXT_OFFSET;
    write_linux_greg(&mut out, LINUX_GREG_R8, saved.frame.r8);
    write_linux_greg(&mut out, LINUX_GREG_R9, saved.frame.r9);
    write_linux_greg(&mut out, LINUX_GREG_R10, saved.frame.r10);
    write_linux_greg(&mut out, LINUX_GREG_R11, saved.user_r11);
    write_linux_greg(&mut out, LINUX_GREG_RDI, saved.frame.rdi);
    write_linux_greg(&mut out, LINUX_GREG_RSI, saved.frame.rsi);
    write_linux_greg(&mut out, LINUX_GREG_RDX, saved.frame.rdx);
    write_linux_greg(&mut out, LINUX_GREG_RAX, saved.frame.rax);
    write_linux_greg(&mut out, LINUX_GREG_RCX, saved.user_rcx);
    write_linux_greg(&mut out, LINUX_GREG_RSP, saved.rsp);
    write_linux_greg(&mut out, LINUX_GREG_RIP, saved.frame.rcx);
    write_linux_greg(&mut out, LINUX_GREG_EFL, saved.frame.r11);
    write_linux_greg(&mut out, LINUX_GREG_OLDMASK, old_sigmask);
    write_u64(
        &mut out,
        mcontext + LINUX_MCONTEXT_FPREGS_OFFSET,
        ucontext_sp.saturating_add(LINUX_UCONTEXT_FPREGS_MEM_OFFSET as u64),
    );
    write_u64(&mut out, LINUX_UCONTEXT_SIGMASK_OFFSET, old_sigmask);
    out
}

fn decode_linux_ucontext_return(
    bytes: &[u8],
    saved_fs_base: u64,
) -> Result<UserReturnContext, i32> {
    let rip = read_linux_greg(bytes, LINUX_GREG_RIP)?;
    let rsp = read_linux_greg(bytes, LINUX_GREG_RSP)?;
    let rcx = read_linux_greg(bytes, LINUX_GREG_RCX)?;
    let r11 = read_linux_greg(bytes, LINUX_GREG_R11)?;
    validate_lower_user_address_range(rip, 1)?;
    validate_lower_user_address_range(rsp, 1)?;
    Ok(UserReturnContext {
        frame: SyscallFrame {
            r9: read_linux_greg(bytes, LINUX_GREG_R9)?,
            r8: read_linux_greg(bytes, LINUX_GREG_R8)?,
            r10: read_linux_greg(bytes, LINUX_GREG_R10)?,
            rdx: read_linux_greg(bytes, LINUX_GREG_RDX)?,
            rsi: read_linux_greg(bytes, LINUX_GREG_RSI)?,
            rdi: read_linux_greg(bytes, LINUX_GREG_RDI)?,
            rax: read_linux_greg(bytes, LINUX_GREG_RAX)?,
            rcx: rip,
            r11: sanitize_restored_rflags(read_linux_greg(bytes, LINUX_GREG_EFL)?),
        },
        rsp,
        fs_base: saved_fs_base,
        user_rcx: rcx,
        user_r11: r11,
    })
}

fn write_linux_greg(out: &mut [u8], index: usize, value: u64) {
    write_u64(out, LINUX_UCONTEXT_MCONTEXT_OFFSET + index * 8, value);
}

fn read_linux_greg(bytes: &[u8], index: usize) -> Result<u64, i32> {
    read_u64_from(bytes, LINUX_UCONTEXT_MCONTEXT_OFFSET + index * 8)
}

fn sanitize_restored_rflags(flags: u64) -> u64 {
    (flags & RFLAGS_RESTORABLE_USER_MASK) | RFLAGS_FORCED_USER_BITS
}

fn sys_rt_sigtimedwait(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.r10 != LINUX_SIGSET_BYTES as u64 {
        return Err(ERR_EINVAL);
    }
    if frame.rdi == 0 {
        return Err(ERR_EFAULT);
    }
    let wait_set = read_user_u64(frame.rdi)?;
    let timeout_ms = if frame.rdx != 0 {
        let ms = read_user_timespec_ms(frame.rdx)?;
        Some(core::cmp::min(ms, u32::MAX as u64) as u32)
    } else {
        None
    };
    let tid = active_context().tid;

    if let Some(signal) =
        active_context().supervisor.take_pending_signal_matching_set(tid, wait_set)
    {
        return write_sigtimedwait_result(frame.rsi, &signal);
    }

    if let Some(signo) =
        active_context().consume_io_signal_if(|signal| signal_wait_set_contains(wait_set, signal))
    {
        let signal = PendingSignal::basic(
            u8::try_from(signo).map_err(|_| ERR_EINVAL)?,
            0,
            active_context().pid,
            active_context().uid(),
        );
        return write_sigtimedwait_result(frame.rsi, &signal);
    }

    if timeout_ms == Some(0) {
        return Err(ERR_EAGAIN);
    }
    active_context().supervisor.block_on_signal_set_wait(wait_set, timeout_ms)?;
    if let Some(signal) =
        active_context().supervisor.take_pending_signal_matching_set(tid, wait_set)
    {
        return write_sigtimedwait_result(frame.rsi, &signal);
    }
    Err(ERR_EAGAIN)
}

fn sys_tgkill(frame: &SyscallFrame) -> Result<i64, i32> {
    let tgid = linux_pid_arg(frame.rdi)?;
    let tid = linux_pid_arg(frame.rsi)?;
    let signal = frame.rdx;

    if tgid <= 0 || tid <= 0 {
        return Err(ERR_EINVAL);
    }
    if signal >= 64 {
        return Err(ERR_EINVAL);
    }
    let sender_pid = active_context().pid;
    active_context().supervisor.queue_signal_by_tgkill(
        sender_pid,
        tgid as u32,
        tid as u32,
        signal as u8,
    )?;
    Ok(0)
}

fn sys_getpgid(frame: &SyscallFrame) -> Result<i64, i32> {
    let pid_arg = linux_pid_arg(frame.rdi)?;
    let context = active_context();
    let current_pid = context.pid;
    context.supervisor.get_process_group_id(current_pid, pid_arg).map(|pgid| pgid as i64)
}

fn sys_getpgrp() -> Result<i64, i32> {
    let context = active_context();
    let current_pid = context.pid;
    context.supervisor.get_process_group_id(current_pid, 0).map(|pgid| pgid as i64)
}

fn sys_getsid(frame: &SyscallFrame) -> Result<i64, i32> {
    let pid_arg = linux_pid_arg(frame.rdi)?;
    let context = active_context();
    let current_pid = context.pid;
    context.supervisor.get_session_id(current_pid, pid_arg).map(|sid| sid as i64)
}

fn sys_setpgid(frame: &SyscallFrame) -> Result<i64, i32> {
    let pid_arg = linux_pid_arg(frame.rdi)?;
    let pgid_arg = linux_pid_arg(frame.rsi)?;
    let context = active_context();
    let current_pid = context.pid;
    context.supervisor.set_process_group_id(current_pid, pid_arg, pgid_arg)?;
    Ok(0)
}

fn sys_setsid() -> Result<i64, i32> {
    let context = active_context();
    let current_pid = context.pid;
    context.supervisor.create_session_for_process(current_pid).map(|sid| sid as i64)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CloneRequest {
    flags: u64,
    stack: u64,
    parent_tid_ptr: u64,
    child_tid_ptr: u64,
    tls_base: u64,
}

fn sys_fork_like(frame: &mut SyscallFrame) -> Result<i64, i32> {
    const SIGCHLD_FLAG: u64 = 17;

    if frame.rax == SYS_VFORK {
        return sys_vfork(frame);
    }
    let request = if frame.rax == SYS_CLONE {
        CloneRequest {
            flags: frame.rdi,
            stack: frame.rsi,
            parent_tid_ptr: frame.rdx,
            child_tid_ptr: frame.r10,
            tls_base: frame.r8,
        }
    } else {
        CloneRequest {
            flags: SIGCHLD_FLAG,
            stack: 0,
            parent_tid_ptr: 0,
            child_tid_ptr: 0,
            tls_base: 0,
        }
    };
    sys_clone_request(frame, request)
}

fn sys_clone3(frame: &mut SyscallFrame) -> Result<i64, i32> {
    let size = usize::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    let request = read_clone3_request(frame.rdi, size)?;
    sys_clone_request(frame, request)
}

fn sys_clone_request(frame: &mut SyscallFrame, request: CloneRequest) -> Result<i64, i32> {
    const CLONE_EXIT_SIGNAL_MASK: u64 = 0xff;
    const CLONE_VM: u64 = 0x100;
    const CLONE_FS: u64 = 0x200;
    const CLONE_FILES: u64 = 0x400;
    const CLONE_SIGHAND: u64 = 0x800;
    const CLONE_THREAD: u64 = 0x10000;
    const CLONE_SETTLS: u64 = 0x80000;
    const CLONE_PARENT_SETTID: u64 = 0x100000;
    const CLONE_CHILD_CLEARTID: u64 = 0x200000;
    const CLONE_CHILD_SETTID: u64 = 0x1000000;
    const SUPPORTED_SHARED_VM_CLONE_MASK: u64 = CLONE_EXIT_SIGNAL_MASK
        | CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_CHILD_SETTID;
    const SUPPORTED_INDEPENDENT_VM_CLONE_MASK: u64 = CLONE_EXIT_SIGNAL_MASK
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_CHILD_SETTID;

    if active_context().has_suspended_clone_parent() {
        return Err(ERR_ENOSYS);
    }
    let flags = request.flags;
    let stack = request.stack;
    let parent_tid_ptr = request.parent_tid_ptr;
    let child_tid_ptr = request.child_tid_ptr;
    let tls_base = request.tls_base;
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
        return Err(ERR_EINVAL);
    }
    if flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0 {
        return Err(ERR_EINVAL);
    }
    let shared_vm_flags_supported = flags & CLONE_VM != 0;
    let shared_vm_preflight_ok = flags & !SUPPORTED_SHARED_VM_CLONE_MASK == 0
        && shared_vm_flags_supported
        && stack != 0
        && flags & CLONE_EXIT_SIGNAL_MASK < 64;
    let independent_vm_preflight_ok = flags & CLONE_VM == 0
        && flags & !SUPPORTED_INDEPENDENT_VM_CLONE_MASK == 0
        && flags & CLONE_EXIT_SIGNAL_MASK < 64;
    if flags & CLONE_VM == 0 && !independent_vm_preflight_ok {
        if flags & CLONE_EXIT_SIGNAL_MASK >= 64 {
            return Err(ERR_EINVAL);
        }
        return Err(ERR_ENOSYS);
    }
    let child_fs_base = if shared_vm_preflight_ok && flags & CLONE_SETTLS != 0 {
        Some(user_fs_base(tls_base)?)
    } else if independent_vm_preflight_ok && flags & CLONE_SETTLS != 0 {
        Some(user_fs_base(tls_base)?)
    } else {
        None
    };
    let mut parent_tid_lease = if shared_vm_preflight_ok && flags & CLONE_PARENT_SETTID != 0 {
        Some(user_lease(parent_tid_ptr, 4, true)?)
    } else if independent_vm_preflight_ok && flags & CLONE_PARENT_SETTID != 0 {
        Some(user_lease(parent_tid_ptr, 4, true)?)
    } else {
        None
    };
    let mut child_tid_lease = if shared_vm_preflight_ok && flags & CLONE_CHILD_SETTID != 0 {
        Some(user_lease(child_tid_ptr, 4, true)?)
    } else {
        None
    };
    let child_tid_preflight_lease =
        if independent_vm_preflight_ok && flags & CLONE_CHILD_SETTID != 0 {
            Some(user_lease(child_tid_ptr, 4, true)?)
        } else {
            None
        };
    let clear_child_tid = if flags & CLONE_CHILD_CLEARTID != 0 && child_tid_ptr != 0 {
        Some(child_tid_ptr)
    } else {
        None
    };

    let (parent_pid, parent_tid_runtime, credential) = {
        let context = active_context();
        (context.pid, context.tid, context.credential_state())
    };
    let caps = LinuxCapSets {
        bounding: credential.cap_bounding,
        inheritable: credential.cap_inheritable,
        permitted: credential.cap_permitted,
        effective: credential.cap_effective,
        ambient: credential.cap_ambient,
        securebits: credential.securebits,
    };

    if shared_vm_flags_supported {
        let (child_task_id, child_pid, child_tid_runtime) =
            active_context().supervisor.create_shared_vm_clone_child(
                flags,
                stack,
                parent_pid,
                parent_tid_runtime,
                credential.uid,
                credential.euid,
                credential.suid,
                credential.fsuid,
                credential.gid,
                credential.egid,
                credential.sgid,
                credential.fsgid,
                credential.supplementary_groups,
                caps,
                clear_child_tid,
            )?;
        if let Some(parent_tid_lease) = parent_tid_lease.as_mut() {
            parent_tid_lease
                .bytes_mut()
                .map_err(map_dmw_fault)?
                .copy_from_slice(&child_tid_runtime.to_le_bytes());
        }
        if let Some(child_tid_lease) = child_tid_lease.as_mut() {
            child_tid_lease
                .bytes_mut()
                .map_err(map_dmw_fault)?
                .copy_from_slice(&child_tid_runtime.to_le_bytes());
        }
        drop(parent_tid_lease);
        drop(child_tid_lease);

        let files_shared = flags & CLONE_FILES != 0;
        let fd_snapshot = if files_shared {
            None
        } else {
            Some(active_context().supervisor.fork_fd_table_for_owner(child_task_id))
        };
        let mut parent_return = ring3::capture_user_return(frame);
        parent_return.frame.rax = child_pid as u64;
        let mut child_return = parent_return;
        child_return.frame.rax = 0;
        child_return.rsp = stack;
        if let Some(fs_base) = child_fs_base {
            child_return.fs_base = fs_base.as_u64();
        }
        let parent_task_id = active_context().task_id;
        active_context().supervisor.mark_task_blocked(parent_task_id);
        active_context().suspend_for_clone_child(
            child_task_id,
            child_pid,
            child_tid_runtime,
            parent_return,
            flags & CLONE_FS != 0,
            files_shared,
            fd_snapshot,
            None,
        );
        active_context().supervisor.set_current_task(child_task_id);
        ring3::install_user_return(frame, child_return);
        return Ok(0);
    }

    // The current ring3 runner is child-runs-first. This gives fork/clone an
    // independent VM by sharing tracked user frames read-only and breaking COW
    // when the child writes, but it is still not a general runnable scheduler.
    let mut child_address_space = clone_active_user_address_space()?;
    let (child_task_id, child_pid, child_tid_runtime) =
        active_context().supervisor.create_independent_vm_clone_child(
            flags,
            parent_pid,
            parent_tid_runtime,
            credential.uid,
            credential.euid,
            credential.suid,
            credential.fsuid,
            credential.gid,
            credential.egid,
            credential.sgid,
            credential.fsgid,
            credential.supplementary_groups,
            caps,
            clear_child_tid,
        )?;
    if let Some(parent_tid_lease) = parent_tid_lease.as_mut() {
        parent_tid_lease
            .bytes_mut()
            .map_err(map_dmw_fault)?
            .copy_from_slice(&child_tid_runtime.to_le_bytes());
    }
    drop(parent_tid_lease);
    drop(child_tid_preflight_lease);

    let files_shared = flags & CLONE_FILES != 0;
    let fd_snapshot = if files_shared {
        None
    } else {
        Some(active_context().supervisor.fork_fd_table_for_owner(child_task_id))
    };
    let mut parent_return = ring3::capture_user_return(frame);
    parent_return.frame.rax = child_pid as u64;
    let mut child_return = parent_return;
    child_return.frame.rax = 0;
    if stack != 0 {
        child_return.rsp = stack;
    }
    if let Some(fs_base) = child_fs_base {
        child_return.fs_base = fs_base.as_u64();
    }
    switch_active_user_address_space_to_child(&mut child_address_space)?;
    let parent_task_id = active_context().task_id;
    active_context().supervisor.mark_task_blocked(parent_task_id);
    active_context().suspend_for_clone_child(
        child_task_id,
        child_pid,
        child_tid_runtime,
        parent_return,
        flags & CLONE_FS != 0,
        files_shared,
        fd_snapshot,
        Some(child_address_space),
    );
    if flags & CLONE_CHILD_SETTID != 0 {
        write_user_u32(child_tid_ptr, child_tid_runtime)?;
    }
    active_context().supervisor.set_current_task(child_task_id);
    ring3::install_user_return(frame, child_return);
    Ok(0)
}

fn read_clone3_request(ptr: u64, size: usize) -> Result<CloneRequest, i32> {
    const CLONE3_ARGS_SIZE_V0: usize = 64;
    const CLONE3_ARGS_SIZE_V1: usize = 80;
    const CLONE3_ARGS_SIZE_V2: usize = 88;

    match size {
        CLONE3_ARGS_SIZE_V0 | CLONE3_ARGS_SIZE_V1 | CLONE3_ARGS_SIZE_V2 => {}
        _ if size > CLONE3_ARGS_SIZE_V2 => return Err(ERR_E2BIG),
        _ => return Err(ERR_EINVAL),
    }
    let bytes = read_user_bytes(ptr, size)?;
    parse_clone3_request_bytes(&bytes, size)
}

fn parse_clone3_request_bytes(bytes: &[u8], size: usize) -> Result<CloneRequest, i32> {
    const CLONE_EXIT_SIGNAL_MASK: u64 = 0xff;
    const CLONE3_ARGS_SIZE_V0: usize = 64;
    const CLONE3_ARGS_SIZE_V1: usize = 80;
    const CLONE3_ARGS_SIZE_V2: usize = 88;
    const CLONE3_FLAGS: usize = 0;
    const CLONE3_PIDFD: usize = 8;
    const CLONE3_CHILD_TID: usize = 16;
    const CLONE3_PARENT_TID: usize = 24;
    const CLONE3_EXIT_SIGNAL: usize = 32;
    const CLONE3_STACK: usize = 40;
    const CLONE3_STACK_SIZE: usize = 48;
    const CLONE3_TLS: usize = 56;
    const CLONE3_SET_TID: usize = 64;
    const CLONE3_SET_TID_SIZE: usize = 72;
    const CLONE3_CGROUP: usize = 80;

    match size {
        CLONE3_ARGS_SIZE_V0 | CLONE3_ARGS_SIZE_V1 | CLONE3_ARGS_SIZE_V2 => {}
        _ if size > CLONE3_ARGS_SIZE_V2 => return Err(ERR_E2BIG),
        _ => return Err(ERR_EINVAL),
    }
    if bytes.len() != size {
        return Err(ERR_EINVAL);
    }

    let flags = read_u64_from(bytes, CLONE3_FLAGS)?;
    let pidfd = read_u64_from(bytes, CLONE3_PIDFD)?;
    let child_tid = read_u64_from(bytes, CLONE3_CHILD_TID)?;
    let parent_tid = read_u64_from(bytes, CLONE3_PARENT_TID)?;
    let exit_signal = read_u64_from(bytes, CLONE3_EXIT_SIGNAL)?;
    let stack = read_u64_from(bytes, CLONE3_STACK)?;
    let stack_size = read_u64_from(bytes, CLONE3_STACK_SIZE)?;
    let tls = read_u64_from(bytes, CLONE3_TLS)?;
    let set_tid =
        if size >= CLONE3_ARGS_SIZE_V1 { read_u64_from(bytes, CLONE3_SET_TID)? } else { 0 };
    let set_tid_size =
        if size >= CLONE3_ARGS_SIZE_V1 { read_u64_from(bytes, CLONE3_SET_TID_SIZE)? } else { 0 };
    let cgroup = if size >= CLONE3_ARGS_SIZE_V2 { read_u64_from(bytes, CLONE3_CGROUP)? } else { 0 };

    if flags & CLONE_EXIT_SIGNAL_MASK != 0 || exit_signal >= 64 {
        return Err(ERR_EINVAL);
    }
    if stack == 0 && stack_size != 0 {
        return Err(ERR_EINVAL);
    }
    if stack != 0 && stack_size == 0 {
        return Err(ERR_EINVAL);
    }
    if pidfd != 0 || set_tid != 0 || set_tid_size != 0 || cgroup != 0 {
        return Err(ERR_ENOSYS);
    }

    let stack = if stack == 0 { 0 } else { stack.checked_add(stack_size).ok_or(ERR_EINVAL)? };
    Ok(CloneRequest {
        flags: flags | exit_signal,
        stack,
        parent_tid_ptr: parent_tid,
        child_tid_ptr: child_tid,
        tls_base: tls,
    })
}

fn sys_vfork(frame: &SyscallFrame) -> Result<i64, i32> {
    if active_context().has_suspended_vfork_parent() {
        return Err(ERR_ENOSYS);
    }
    let (parent_pid, parent_tid, credential) = {
        let context = active_context();
        (context.pid, context.tid, context.credential_state())
    };
    let caps = LinuxCapSets {
        bounding: credential.cap_bounding,
        inheritable: credential.cap_inheritable,
        permitted: credential.cap_permitted,
        effective: credential.cap_effective,
        ambient: credential.cap_ambient,
        securebits: credential.securebits,
    };
    let (child_task_id, child_pid, child_tid) = active_context().supervisor.create_vfork_child(
        parent_pid,
        parent_tid,
        credential.uid,
        credential.euid,
        credential.suid,
        credential.fsuid,
        credential.gid,
        credential.egid,
        credential.sgid,
        credential.fsgid,
        credential.supplementary_groups,
        caps,
    )?;
    let mut parent_return = ring3::capture_user_return(frame);
    parent_return.frame.rax = child_pid as u64;
    let parent_task_id = active_context().task_id;
    active_context().supervisor.mark_task_blocked(parent_task_id);
    active_context().suspend_for_vfork_child(child_task_id, child_pid, child_tid, parent_return);
    active_context().supervisor.set_current_task(child_task_id);
    Ok(0)
}

fn sys_set_tid_address(frame: &SyscallFrame) -> Result<i64, i32> {
    let tid = active_context().tid;
    let clear_child_tid = if frame.rdi == 0 { None } else { Some(frame.rdi) };
    active_context().supervisor.set_thread_clear_child_tid(tid, clear_child_tid)?;
    Ok(tid as i64)
}

fn sys_set_robust_list(frame: &SyscallFrame) -> Result<i64, i32> {
    let head = frame.rdi;
    let len = frame.rsi;
    if len != ROBUST_LIST_HEAD_SIZE {
        return Err(ERR_EINVAL);
    }
    if head != 0 {
        validate_user_range(head, ROBUST_LIST_HEAD_SIZE, false)?;
    }
    let registration = if head == 0 { None } else { Some(RobustListRegistration { head, len }) };
    let tid = active_context().tid;
    active_context().supervisor.set_thread_robust_list(tid, registration)?;
    Ok(0)
}

fn sys_get_robust_list(frame: &SyscallFrame) -> Result<i64, i32> {
    validate_user_range(frame.rsi, 8, true)?;
    validate_user_range(frame.rdx, 8, true)?;
    let target_tid = get_robust_list_target_tid(frame.rdi)?;
    let (caller_pid, caller_tid) = (active_context().pid, active_context().tid);
    let registration = active_context()
        .supervisor
        .get_thread_robust_list_for_caller(caller_pid, caller_tid, target_tid)?;
    let (head, len) = registration
        .map(|registration| (registration.head, registration.len))
        .unwrap_or((0, ROBUST_LIST_HEAD_SIZE));
    write_user_u64(frame.rsi, head)?;
    write_user_u64(frame.rdx, len)?;
    Ok(0)
}

fn get_robust_list_target_tid(raw_pid: u64) -> Result<u32, i32> {
    if raw_pid == 0 {
        return Ok(active_context().tid);
    }
    let signed_pid = raw_pid as i64;
    if signed_pid < 0 {
        return Err(ERR_ESRCH);
    }
    if raw_pid > i32::MAX as u64 {
        return Err(ERR_ESRCH);
    }
    u32::try_from(raw_pid).map_err(|_| ERR_ESRCH)
}

fn sys_rseq(frame: &SyscallFrame) -> Result<i64, i32> {
    const RSEQ_ABI_SIZE: u64 = 32;
    const RSEQ_ABI_ALIGN: u64 = 32;
    const RSEQ_FLAG_UNREGISTER: u64 = 1;
    const RSEQ_CPU_ID_UNINITIALIZED: u32 = u32::MAX;
    const RSEQ_CPU_ID_START_OFFSET: usize = 0;
    const RSEQ_CPU_ID_OFFSET: usize = 4;
    const RSEQ_NODE_ID_OFFSET: usize = 24;
    const RSEQ_MM_CID_OFFSET: usize = 28;

    let ptr = frame.rdi;
    let len = frame.rsi;
    let flags = frame.rdx;
    let signature = u32::try_from(frame.r10).map_err(|_| ERR_EINVAL)?;
    if ptr == 0 || ptr & (RSEQ_ABI_ALIGN - 1) != 0 || len != RSEQ_ABI_SIZE {
        return Err(ERR_EINVAL);
    }
    if flags & !RSEQ_FLAG_UNREGISTER != 0 {
        return Err(ERR_EINVAL);
    }

    let len_u32 = u32::try_from(len).map_err(|_| ERR_EINVAL)?;
    let registration = RseqRegistration { ptr, len: len_u32, signature };
    let tid = active_context().tid;
    if flags & RSEQ_FLAG_UNREGISTER != 0 {
        let current =
            active_context().supervisor.thread_rseq_registration(tid).ok_or(ERR_EINVAL)?;
        if current != registration {
            return Err(ERR_EINVAL);
        }
        write_user_u32(ptr + RSEQ_CPU_ID_START_OFFSET as u64, RSEQ_CPU_ID_UNINITIALIZED)?;
        write_user_u32(ptr + RSEQ_CPU_ID_OFFSET as u64, RSEQ_CPU_ID_UNINITIALIZED)?;
        active_context().supervisor.unregister_thread_rseq(tid, registration)?;
        return Ok(0);
    }

    if active_context().supervisor.thread_rseq_registration(tid).is_some() {
        return Err(ERR_EBUSY);
    }
    let mut lease = user_lease(ptr, len, true)?;
    let bytes = lease.bytes_mut().map_err(map_dmw_fault)?;
    bytes[RSEQ_CPU_ID_START_OFFSET..RSEQ_CPU_ID_START_OFFSET + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    bytes[RSEQ_CPU_ID_OFFSET..RSEQ_CPU_ID_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
    bytes[RSEQ_NODE_ID_OFFSET..RSEQ_NODE_ID_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
    bytes[RSEQ_MM_CID_OFFSET..RSEQ_MM_CID_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
    drop(lease);

    active_context().supervisor.register_thread_rseq(tid, registration)?;
    Ok(0)
}

fn sys_wait4(frame: &SyscallFrame) -> Result<i64, i32> {
    let selector = frame.rdi as i64;
    let status_ptr = frame.rsi;
    let options = frame.rdx;
    let rusage_ptr = frame.r10;
    let caller_pid = active_context().pid;

    loop {
        match active_context().supervisor.query_wait4(caller_pid, selector, options) {
            Ok(Some((pid, status))) => {
                if status_ptr != 0 {
                    write_user_u32(status_ptr, status)?;
                }
                if rusage_ptr != 0 {
                    write_user_bytes(rusage_ptr, &[0u8; LINUX_RUSAGE_SIZE])?;
                }
                active_context().supervisor.reap_wait4_child(caller_pid, pid)?;
                return Ok(pid as i64);
            }
            Ok(None) => return Ok(0),
            Err(ERR_ENOSYS) => {
                active_context().supervisor.block_on_wait4_child_exit(caller_pid, selector)?;
            }
            Err(errno) => return Err(errno),
        };
    }
}

fn sys_kill(frame: &SyscallFrame) -> Result<i64, i32> {
    let pid = linux_pid_arg(frame.rdi)?;
    let sig = frame.rsi;
    if sig >= 64 {
        return Err(ERR_EINVAL);
    }
    let current_pid = active_context().pid;
    active_context().supervisor.queue_signal_by_kill_selector(current_pid, pid, sig as u8)?;
    Ok(0)
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
    let flags = u32::try_from(flags).map_err(|_| ERR_EINVAL)?;
    let (read_fd, write_fd) = active_context().supervisor.create_pipe_pair_with_flags(flags)?;
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

fn sys_timerfd_create(frame: &SyscallFrame) -> Result<i64, i32> {
    let flags = u32::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    Ok(active_context().supervisor.create_timerfd(frame.rdi, flags)? as i64)
}

fn sys_timerfd_settime(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rdx == 0 {
        return Err(ERR_EFAULT);
    }
    let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
    let flags = u32::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    let (value_ns, interval_ns) = read_user_itimerspec_ns(frame.rdx)?;
    let (old_value_ns, old_interval_ns, was_canceled) =
        active_context().supervisor.timerfd_settime(fd, flags, value_ns, interval_ns)?;
    if frame.r10 != 0 {
        write_user_itimerspec_ns(frame.r10, old_value_ns, old_interval_ns)?;
    }
    if was_canceled {
        return Err(ERR_ECANCELED);
    }
    Ok(0)
}

fn sys_timerfd_gettime(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rsi == 0 {
        return Err(ERR_EFAULT);
    }
    let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
    let (value_ns, interval_ns) = active_context().supervisor.timerfd_gettime(fd)?;
    write_user_itimerspec_ns(frame.rsi, value_ns, interval_ns)?;
    Ok(0)
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

fn sys_epoll_wait_args_with_sigmask(
    epfd_arg: u64,
    events_ptr: u64,
    max_events_arg: u64,
    timeout_ms: i64,
    sigmask_ptr: u64,
    sigsetsize_arg: u64,
) -> Result<i64, i32> {
    let temporary_sigmask = read_epoll_sigmask(sigmask_ptr, sigsetsize_arg)?;
    let tid = active_context().tid;
    let old_sigmask = if let Some(sigmask) = temporary_sigmask {
        Some(active_context().supervisor.set_sigmask(tid, 2, sigmask).ok_or(ERR_EINVAL)?)
    } else {
        None
    };
    let result = sys_epoll_wait_args(epfd_arg, events_ptr, max_events_arg, timeout_ms);
    if let Some(old_sigmask) = old_sigmask {
        active_context().supervisor.set_sigmask(tid, 2, old_sigmask).ok_or(ERR_EINVAL)?;
    }
    result
}

fn read_epoll_sigmask(sigmask_ptr: u64, sigsetsize_arg: u64) -> Result<Option<u64>, i32> {
    if sigmask_ptr == 0 {
        return Ok(None);
    }
    let sigsetsize = if sigsetsize_arg == 0 { LINUX_SIGSET_BYTES as u64 } else { sigsetsize_arg };
    if sigsetsize != LINUX_SIGSET_BYTES as u64 {
        return Err(ERR_EINVAL);
    }
    Ok(Some(read_user_u64(sigmask_ptr)?))
}

fn sys_epoll_pwait(frame: &SyscallFrame) -> Result<i64, i32> {
    sys_epoll_wait_args_with_sigmask(
        frame.rdi,
        frame.rsi,
        frame.rdx,
        frame.r10 as i32 as i64,
        frame.r8,
        frame.r9,
    )
}

fn sys_epoll_pwait2(frame: &SyscallFrame) -> Result<i64, i32> {
    let timeout_ms = if frame.r10 != 0 { read_user_timespec_ms(frame.r10)? as i64 } else { -1 };
    sys_epoll_wait_args_with_sigmask(
        frame.rdi, frame.rsi, frame.rdx, timeout_ms, frame.r8, frame.r9,
    )
}

fn sys_poll(frame: &SyscallFrame) -> Result<i64, i32> {
    let timeout_ms = poll_timeout_ms(frame.rdx);
    sys_poll_args(frame.rdi, frame.rsi, timeout_ms, None)
}

fn sys_ppoll(frame: &SyscallFrame) -> Result<i64, i32> {
    let timeout_ms = read_ppoll_timeout_ms(frame.rdx)?;
    let temporary_sigmask = read_ppoll_sigmask(frame.r10, frame.r8)?;
    sys_poll_args(frame.rdi, frame.rsi, timeout_ms, temporary_sigmask)
}

fn sys_poll_args(
    fds_ptr: u64,
    nfds_arg: u64,
    timeout_ms: Option<u32>,
    temporary_sigmask: Option<u64>,
) -> Result<i64, i32> {
    let nfds = usize::try_from(nfds_arg).map_err(|_| ERR_EINVAL)?;
    let nofile = active_context().supervisor.get_rlimit(active_context().pid, RLIMIT_NOFILE).cur;
    if !wait_nfds_within_rlimit(nfds, nofile) {
        return Err(ERR_EINVAL);
    }
    let mut entries = read_pollfds(fds_ptr, nfds)?;
    let ready = collect_poll_revents(&mut entries)?;
    if ready != 0 || timeout_ms == Some(0) {
        return write_pollfds(fds_ptr, &entries, ready);
    }
    let (read_bits, write_bits, error_bits, wait_nfds) = poll_wait_bits(&entries)?;
    let tid = active_context().tid;
    let old_sigmask = if let Some(sigmask) = temporary_sigmask {
        Some(active_context().supervisor.set_sigmask(tid, 2, sigmask).ok_or(ERR_EINVAL)?)
    } else {
        None
    };
    let wait_result = active_context()
        .supervisor
        .block_on_fdset_wait(read_bits, write_bits, error_bits, wait_nfds, timeout_ms);
    if let Some(old_sigmask) = old_sigmask {
        active_context().supervisor.set_sigmask(tid, 2, old_sigmask).ok_or(ERR_EINVAL)?;
    }
    wait_result?;
    let ready = collect_poll_revents(&mut entries)?;
    write_pollfds(fds_ptr, &entries, ready)
}

fn poll_timeout_ms(timeout_arg: u64) -> Option<u32> {
    let timeout = timeout_arg as i32;
    if timeout < 0 { None } else { Some(timeout as u32) }
}

fn wait_nfds_within_rlimit(nfds: usize, nofile: u64) -> bool {
    u64::try_from(nfds).is_ok_and(|nfds| nfds <= nofile)
}

fn read_ppoll_timeout_ms(timeout_ptr: u64) -> Result<Option<u32>, i32> {
    if timeout_ptr == 0 {
        return Ok(None);
    }
    let ms = read_user_timespec_ms(timeout_ptr)?;
    Ok(Some(core::cmp::min(ms, u32::MAX as u64) as u32))
}

fn read_ppoll_sigmask(sigmask_ptr: u64, sigsetsize_arg: u64) -> Result<Option<u64>, i32> {
    if sigmask_ptr == 0 {
        return Ok(None);
    }
    if sigsetsize_arg != LINUX_SIGSET_BYTES as u64 {
        return Err(ERR_EINVAL);
    }
    Ok(Some(read_user_u64(sigmask_ptr)?))
}

fn read_pollfds(ptr: u64, nfds: usize) -> Result<Vec<PollFdEntry>, i32> {
    const POLLFD_SIZE: usize = 8;

    let len = nfds.checked_mul(POLLFD_SIZE).ok_or(ERR_EINVAL)?;
    let bytes = read_user_bytes(ptr, len)?;
    let mut entries = Vec::new();
    for index in 0..nfds {
        let offset = index * POLLFD_SIZE;
        let fd = i32::from_le_bytes(bytes[offset..offset + 4].try_into().map_err(|_| ERR_EINVAL)?);
        let events =
            u16::from_le_bytes(bytes[offset + 4..offset + 6].try_into().map_err(|_| ERR_EINVAL)?);
        entries.push(PollFdEntry { fd, events, revents: 0 });
    }
    Ok(entries)
}

fn collect_poll_revents(entries: &mut [PollFdEntry]) -> Result<i64, i32> {
    const POLLNVAL: u16 = 0x020;

    let supervisor = &mut active_context().supervisor;
    let mut ready = 0i64;
    for entry in entries {
        entry.revents = if entry.fd < 0 {
            0
        } else {
            match supervisor.fd_poll_revents(entry.fd as u32, entry.events) {
                Ok(revents) => revents,
                Err(ERR_EBADF) => POLLNVAL,
                Err(errno) => return Err(errno),
            }
        };
        if entry.revents != 0 {
            ready += 1;
        }
    }
    Ok(ready)
}

fn poll_wait_bits(
    entries: &[PollFdEntry],
) -> Result<
    ([u64; PSELECT6_FDSET_WORDS], [u64; PSELECT6_FDSET_WORDS], [u64; PSELECT6_FDSET_WORDS], u16),
    i32,
> {
    const POLLIN: u16 = 0x001;
    const POLLOUT: u16 = 0x004;
    const POLLRDNORM: u16 = 0x040;
    const POLLWRNORM: u16 = 0x100;
    const POLLRDHUP: u16 = 0x2000;
    const POLL_READ_EVENTS: u16 = POLLIN | POLLRDNORM;
    const POLL_WRITE_EVENTS: u16 = POLLOUT | POLLWRNORM;

    let mut read_bits = [0u64; PSELECT6_FDSET_WORDS];
    let mut write_bits = [0u64; PSELECT6_FDSET_WORDS];
    let mut error_bits = [0u64; PSELECT6_FDSET_WORDS];
    let mut wait_nfds = 0usize;
    for entry in entries {
        if entry.fd < 0 {
            continue;
        }
        let fd = usize::try_from(entry.fd).map_err(|_| ERR_EINVAL)?;
        if fd >= PSELECT6_MAX_FDS {
            return Err(ERR_ENOSYS);
        }
        set_fd_bit(&mut error_bits, fd);
        if entry.events & (POLL_READ_EVENTS | POLLRDHUP) != 0 {
            set_fd_bit(&mut read_bits, fd);
        }
        if entry.events & POLL_WRITE_EVENTS != 0 {
            set_fd_bit(&mut write_bits, fd);
        }
        wait_nfds = core::cmp::max(wait_nfds, fd + 1);
    }
    Ok((read_bits, write_bits, error_bits, u16::try_from(wait_nfds).map_err(|_| ERR_EINVAL)?))
}

fn write_pollfds(ptr: u64, entries: &[PollFdEntry], ready: i64) -> Result<i64, i32> {
    const POLLFD_SIZE: usize = 8;

    if entries.is_empty() {
        return Ok(ready);
    }
    let len = entries.len().checked_mul(POLLFD_SIZE).ok_or(ERR_EINVAL)?;
    let mut lease = user_lease(ptr, len as u64, true)?;
    let bytes = lease.bytes_mut().map_err(map_dmw_fault)?;
    for (index, entry) in entries.iter().enumerate() {
        let offset = index * POLLFD_SIZE;
        bytes[offset + 6..offset + 8].copy_from_slice(&entry.revents.to_le_bytes());
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

    let flags = u32::try_from(ty & (SOCK_CLOEXEC | SOCK_NONBLOCK)).map_err(|_| ERR_EINVAL)?;
    let (fd_a, fd_b) = active_context().supervisor.create_socketpair_with_flags(flags)?;
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
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EBADF)?;
    active_context().supervisor.require_socket_fd(fd)?;
    let sockaddr = read_socket_sockaddr(frame.rsi, frame.rdx)?;
    if sockaddr.family != AF_INET as u16 && sockaddr.family != AF_UNIX as u16 {
        return Err(ERR_EAFNOSUPPORT);
    }
    if sockaddr.family == AF_INET as u16 && frame.rdx < 16 {
        return Err(ERR_EINVAL);
    }
    dispatch_ret(
        "ring3_bind",
        SyscallContext::new(
            SYS_BIND,
            [
                frame.rdi,
                frame.rsi,
                frame.rdx,
                sockaddr.family as u64,
                sockaddr.ipv4_be as u64,
                sockaddr.port as u64,
            ],
        ),
    )
}

fn sys_listen(frame: &SyscallFrame) -> Result<i64, i32> {
    dispatch_ret(
        "ring3_listen",
        SyscallContext::new(SYS_LISTEN, [frame.rdi, frame.rsi, 0, 0, 0, 0]),
    )
}

fn sys_connect(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EBADF)?;
    active_context().supervisor.require_socket_fd(fd)?;
    let sockaddr = read_connect_sockaddr(frame.rsi, frame.rdx)?;
    if sockaddr.family != AF_INET as u16 && sockaddr.family != AF_UNIX as u16 {
        return Err(ERR_EAFNOSUPPORT);
    }
    let ret = dispatch_ret(
        "ring3_connect",
        SyscallContext::new(
            SYS_CONNECT,
            [
                frame.rdi,
                frame.rsi,
                frame.rdx,
                sockaddr.family as u64,
                sockaddr.ipv4_be as u64,
                sockaddr.port as u64,
            ],
        ),
    )?;
    Ok(ret)
}

struct ConnectSockaddr {
    family: u16,
    ipv4_be: u32,
    port: u16,
}

fn read_connect_sockaddr(addr_ptr: u64, addr_len: u64) -> Result<ConnectSockaddr, i32> {
    let sockaddr = read_socket_sockaddr(addr_ptr, addr_len)?;
    if sockaddr.family == AF_INET as u16 && addr_len < 16 {
        return Err(ERR_EINVAL);
    }
    Ok(sockaddr)
}

fn read_socket_sockaddr(addr_ptr: u64, addr_len: u64) -> Result<ConnectSockaddr, i32> {
    if addr_ptr == 0 {
        return Err(ERR_EFAULT);
    }
    if addr_len < 2 {
        return Err(ERR_EINVAL);
    }
    let family = {
        let header = user_lease(addr_ptr, 2, false)?;
        let header_bytes = header.bytes().map_err(map_dmw_fault)?;
        u16::from_le_bytes(header_bytes[..2].try_into().map_err(|_| ERR_EINVAL)?)
    };
    if family != AF_INET as u16 {
        return Ok(ConnectSockaddr { family, ipv4_be: 0, port: 0 });
    }
    if addr_len < 16 {
        return Err(ERR_EINVAL);
    }
    let lease = user_lease(addr_ptr, 16, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    Ok(ConnectSockaddr {
        family,
        port: u16::from_be_bytes(bytes[2..4].try_into().map_err(|_| ERR_EINVAL)?),
        ipv4_be: u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| ERR_EINVAL)?),
    })
}

fn sys_accept(frame: &SyscallFrame) -> Result<i64, i32> {
    sys_accept_with_flags(frame, 0)
}

fn sys_accept_with_flags(frame: &SyscallFrame, flags: u64) -> Result<i64, i32> {
    validate_optional_sockaddr(frame.rsi, frame.rdx, true)?;
    let fd = dispatch_ret(
        "ring3_accept",
        SyscallContext::new(SYS_ACCEPT, [frame.rdi, frame.rsi, frame.rdx, flags, 0, 0]),
    )?;
    if fd >= 0 {
        let endpoint = u32::try_from(fd).ok().and_then(|fd| {
            active_context().supervisor.socket_ipv4_endpoint(fd, true).ok().flatten()
        });
        let (addr, port) =
            endpoint.map(|endpoint| (endpoint.addr, endpoint.port)).unwrap_or(([0; 4], 0));
        write_optional_sockaddr_in_endpoint(frame.rsi, frame.rdx, addr, port)?;
    }
    Ok(fd)
}

fn sys_accept4(frame: &SyscallFrame) -> Result<i64, i32> {
    const SOCK_CLOEXEC: u64 = 0o2000000;
    const SOCK_NONBLOCK: u64 = 0o0004000;
    if frame.r10 & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return Err(ERR_EINVAL);
    }
    sys_accept_with_flags(frame, frame.r10)
}

fn sys_getsockname(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EBADF)?;
    let endpoint = active_context()
        .supervisor
        .socket_ipv4_endpoint(fd, false)?
        .map(|endpoint| (endpoint.addr, endpoint.port))
        .unwrap_or(([0; 4], 0));
    write_sockaddr_in_endpoint(frame.rsi, frame.rdx, endpoint.0, endpoint.1)
}

fn sys_getpeername(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(frame.rdi).map_err(|_| ERR_EBADF)?;
    let endpoint = active_context()
        .supervisor
        .socket_ipv4_endpoint(fd, true)?
        .ok_or(vmos_abi::ERR_ENOTCONN)?;
    write_sockaddr_in_endpoint(frame.rsi, frame.rdx, endpoint.addr, endpoint.port)
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

fn write_sockaddr_in_endpoint(
    addr_ptr: u64,
    len_ptr: u64,
    ipv4_addr: [u8; 4],
    port: u16,
) -> Result<i64, i32> {
    if addr_ptr == 0 || len_ptr == 0 {
        return Err(ERR_EFAULT);
    }
    let addr_len = read_user_u32(len_ptr)?;
    if addr_len < 16 {
        return Err(ERR_EINVAL);
    }
    let mut sockaddr = [0u8; 16];
    sockaddr[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    sockaddr[2..4].copy_from_slice(&port.to_be_bytes());
    sockaddr[4..8].copy_from_slice(&ipv4_addr);
    write_user_bytes(addr_ptr, &sockaddr)?;
    write_user_u32(len_ptr, 16)?;
    Ok(0)
}

fn write_optional_sockaddr_in_endpoint(
    addr_ptr: u64,
    len_ptr: u64,
    ipv4_addr: [u8; 4],
    port: u16,
) -> Result<(), i32> {
    if addr_ptr == 0 && len_ptr == 0 {
        return Ok(());
    }
    write_sockaddr_in_endpoint(addr_ptr, len_ptr, ipv4_addr, port).map(|_| ())
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
            let endpoint = supervisor
                .socket_ipv4_endpoint(fd, true)
                .ok()
                .flatten()
                .map(|endpoint| (endpoint.addr, endpoint.port));
            write_recvfrom_sockaddr_if_requested(frame.r8, frame.r9, endpoint)?;
            Ok(bytes.len() as i64)
        }
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn write_recvfrom_sockaddr_if_requested(
    addr_ptr: u64,
    len_ptr: u64,
    endpoint: Option<([u8; 4], u16)>,
) -> Result<(), i32> {
    if addr_ptr == 0 {
        return Ok(());
    }
    if len_ptr == 0 {
        return Err(ERR_EFAULT);
    }
    let (addr, port) = endpoint.unwrap_or(([0; 4], 0));
    write_sockaddr_in_endpoint(addr_ptr, len_ptr, addr, port).map(|_| ())
}

fn sys_setsockopt(frame: &SyscallFrame) -> Result<i64, i32> {
    let value = read_setsockopt_u32(frame.rsi, frame.rdx, frame.r10, frame.r8)?;
    dispatch_ret(
        "ring3_setsockopt",
        SyscallContext::new(
            SYS_SETSOCKOPT,
            [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, value],
        ),
    )
}

fn read_setsockopt_u32(level: u64, optname: u64, optval_ptr: u64, optlen: u64) -> Result<u64, i32> {
    let (Ok(level), Ok(optname)) = (u32::try_from(level), u32::try_from(optname)) else {
        return Ok(0);
    };
    if level != SOL_SOCKET || !matches!(optname, SO_REUSEADDR | SO_REUSEPORT) {
        return Ok(0);
    }
    if optval_ptr == 0 {
        return Err(ERR_EFAULT);
    }
    if optlen < 4 {
        return Err(ERR_EINVAL);
    }
    read_user_u32(optval_ptr).map(u64::from)
}

fn sys_getsockopt(frame: &SyscallFrame) -> Result<i64, i32> {
    let supervisor = &mut active_context().supervisor;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_getsockopt",
            SyscallContext::new(
                SYS_GETSOCKOPT,
                [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, 0],
            ),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => {
            write_getsockopt_u32(frame.rsi, frame.rdx, frame.r10, frame.r8, ret as u32)?;
            Ok(0)
        }
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn write_getsockopt_u32(
    level: u64,
    optname: u64,
    optval_ptr: u64,
    optlen_ptr: u64,
    value: u32,
) -> Result<(), i32> {
    const SOCKOPT_U32_LEN: u32 = 4;

    if optval_ptr == 0 || optlen_ptr == 0 {
        return Err(ERR_EFAULT);
    }
    let (Ok(level), Ok(optname)) = (u32::try_from(level), u32::try_from(optname)) else {
        return Err(ERR_EOPNOTSUPP);
    };
    if level != SOL_SOCKET || !matches!(optname, SO_ERROR | SO_TYPE | SO_REUSEADDR | SO_REUSEPORT) {
        return Err(ERR_EOPNOTSUPP);
    }
    let optlen = read_user_u32(optlen_ptr)?;
    if optlen < SOCKOPT_U32_LEN {
        return Err(ERR_EINVAL);
    }
    write_user_u32(optval_ptr, value)?;
    write_user_u32(optlen_ptr, SOCKOPT_U32_LEN)
}

fn sys_ioctl(frame: &SyscallFrame) -> Result<i64, i32> {
    const LOOP_CTL_GET_FREE: u64 = 0x4c82;
    const BLKGETSIZE64: u64 = 0x8008_1272;
    const VMOS_LTP_LOOP_BYTES: u64 = 300 * 1024 * 1024;

    let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
    active_context().supervisor.fd_flags(fd)?;
    match frame.rsi {
        LOOP_CTL_GET_FREE => {
            let path = active_context().supervisor.fd_path(fd).map_err(|_| ERR_ENOTTY)?;
            if path == b"/dev/loop-control" { Ok(0) } else { Err(ERR_ENOTTY) }
        }
        BLKGETSIZE64 => {
            let path = active_context().supervisor.fd_path(fd).map_err(|_| ERR_ENOTTY)?;
            if path != b"/dev/loop0" {
                return Err(ERR_ENOTTY);
            }
            write_user_u64(frame.rdx, VMOS_LTP_LOOP_BYTES)?;
            Ok(0)
        }
        _ => Err(ERR_ENOTTY),
    }
}

fn sys_flock(frame: &SyscallFrame) -> Result<i64, i32> {
    let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
    let operation = u32::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    active_context().supervisor.flock_fd(fd, operation)?;
    Ok(0)
}

fn sys_fcntl(frame: &SyscallFrame) -> Result<i64, i32> {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_GETLK: u64 = 5;
    const F_SETLK: u64 = 6;
    const F_SETLKW: u64 = 7;
    const F_SETOWN: u64 = 8;
    const F_GETOWN: u64 = 9;
    const F_SETSIG: u64 = 10;
    const F_GETSIG: u64 = 11;
    const F_SETOWN_EX: u64 = 15;
    const F_GETOWN_EX: u64 = 16;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_SETPIPE_SZ: u64 = 1031;
    const F_GETPIPE_SZ: u64 = 1032;
    const F_OWNER_TID: u32 = 0;
    const F_OWNER_PID: u32 = 1;
    const F_OWNER_PGRP: u32 = 2;
    const FD_CLOEXEC: u32 = 1;
    const F_OWNER_EX_SIZE: u64 = 8;
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;

    let fd = u32::try_from(linux_fd_arg(frame.rdi)).map_err(|_| ERR_EBADF)?;
    let _cmd = i32::try_from(frame.rsi).map_err(|_| ERR_EINVAL)?;
    active_context().supervisor.fd_flags(fd)?;
    match frame.rsi {
        F_DUPFD => {
            let min_fd = u32::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
            return Ok(active_context().supervisor.dup_fd_from(fd, min_fd)? as i64);
        }
        F_DUPFD_CLOEXEC => {
            let min_fd = u32::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
            let new_fd = active_context().supervisor.dup_fd_from(fd, min_fd)?;
            active_context().supervisor.set_fd_flags(new_fd, FD_CLOEXEC)?;
            return Ok(new_fd as i64);
        }
        F_GETFD => return Ok(active_context().supervisor.fd_flags(fd)? as i64),
        F_SETFD => {
            active_context().supervisor.set_fd_flags(fd, (frame.rdx as u32) & FD_CLOEXEC)?;
            return Ok(0);
        }
        F_GETFL => return Ok(active_context().supervisor.file_status_flags(fd)? as i64),
        F_SETFL => {
            active_context().supervisor.set_file_status_flags(fd, frame.rdx as u32)?;
            return Ok(0);
        }
        F_SETPIPE_SZ => {
            let size = usize::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
            return Ok(active_context().supervisor.set_pipe_capacity(fd, size)? as i64);
        }
        F_GETPIPE_SZ => return Ok(active_context().supervisor.pipe_capacity(fd)? as i64),
        F_GETLK => {
            let (lock_type, whence, start, len) = read_flock(frame.rdx)?;
            let owner = active_context().pid;
            let conflict = active_context()
                .supervisor
                .fcntl_getlk_fd(fd, owner, lock_type, whence, start, len)?;
            match conflict {
                Some((write, pid, lock_start, lock_len)) => {
                    write_flock(
                        frame.rdx,
                        if write { F_WRLCK } else { F_RDLCK },
                        0,
                        lock_start,
                        lock_len,
                        pid,
                    )?;
                }
                None => {
                    write_flock_type(frame.rdx, F_UNLCK)?;
                }
            }
            return Ok(0);
        }
        F_SETLK => {
            let (lock_type, whence, start, len) = read_flock(frame.rdx)?;
            active_context().supervisor.fcntl_setlk_fd(
                fd,
                active_context().pid,
                lock_type,
                whence,
                start,
                len,
            )?;
            return Ok(0);
        }
        F_SETLKW => {
            let (lock_type, whence, start, len) = read_flock(frame.rdx)?;
            active_context().supervisor.fcntl_setlkw_fd(
                fd,
                active_context().pid,
                lock_type,
                whence,
                start,
                len,
            )?;
            return Ok(0);
        }
        F_GETOWN => return Ok(active_context().io_owner()),
        F_SETOWN => {
            active_context().set_io_owner(frame.rdx as i64);
            return Ok(0);
        }
        F_GETOWN_EX => {
            let _ = user_lease(frame.rdx, F_OWNER_EX_SIZE, true)?;
            let (owner_type, owner_pid) = active_context().io_owner_ex();
            write_user_u32(frame.rdx, owner_type)?;
            write_user_u32(frame.rdx + 4, owner_pid as u32)?;
            return Ok(0);
        }
        F_SETOWN_EX => {
            let lease = user_lease(frame.rdx, F_OWNER_EX_SIZE, false)?;
            let bytes = lease.bytes().map_err(map_dmw_fault)?;
            let owner_type = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ERR_EINVAL)?);
            let owner_pid = i32::from_le_bytes(bytes[4..8].try_into().map_err(|_| ERR_EINVAL)?);
            match owner_type {
                F_OWNER_TID | F_OWNER_PID | F_OWNER_PGRP => {}
                _ => return Err(ERR_EINVAL),
            }
            active_context().set_io_owner_ex(owner_type, owner_pid);
            return Ok(0);
        }
        F_GETSIG => return Ok(active_context().io_signal() as i64),
        F_SETSIG => {
            let signal = u32::try_from(frame.rdx).map_err(|_| ERR_EINVAL)?;
            active_context().set_io_signal(signal);
            return Ok(0);
        }
        _ => {}
    }
    dispatch_ret(
        "ring3_fcntl",
        SyscallContext::new(SYS_FCNTL, [frame.rdi, frame.rsi, frame.rdx, 0, 0, 0]),
    )
}

enum MmapFileBacking {
    Private(Vec<u8>),
    Shared { vfs_node_id: u64, path: Vec<u8>, offset: usize, bytes: Vec<u8> },
}

impl MmapFileBacking {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Private(bytes) | Self::Shared { bytes, .. } => bytes,
        }
    }
}

fn sys_mmap(frame: &SyscallFrame) -> Result<i64, i32> {
    let len = align_page(frame.rsi).ok_or(ERR_EINVAL)?;
    if len == 0 {
        return Err(ERR_EINVAL);
    }
    let flags = frame.r10;
    let shared = flags & MAP_SHARED != 0;
    let private = flags & MAP_PRIVATE != 0;
    if shared == private {
        return Err(ERR_EINVAL);
    }
    let anonymous = flags & MAP_ANONYMOUS != 0;
    let fixed = flags & MAP_FIXED != 0;
    let fixed_noreplace = flags & MAP_FIXED_NOREPLACE != 0;
    let fixed_address = fixed || fixed_noreplace;
    let file_backing = if anonymous {
        None
    } else {
        if frame.r9 & 4095 != 0 {
            return Err(ERR_EINVAL);
        }
        let fd = u32::try_from(frame.r8).map_err(|_| ERR_EBADF)?;
        let offset = usize::try_from(frame.r9).map_err(|_| ERR_EINVAL)?;
        let count = usize::try_from(len).map_err(|_| ERR_ENOMEM)?;
        if private {
            Some(MmapFileBacking::Private(
                active_context().supervisor.read_vfs_fd_range(fd, offset, count)?,
            ))
        } else {
            let (vfs_node_id, path, bytes) = active_context()
                .supervisor
                .read_shared_mmap_vfs_fd_range(fd, offset, count, frame.rdx & PROT_WRITE != 0)?;
            Some(MmapFileBacking::Shared { vfs_node_id, path, offset, bytes })
        }
    };
    let as_limit = active_context().supervisor.get_rlimit(active_context().pid, RLIMIT_AS).cur;
    if as_limit != u64::MAX && active_context().mapped_user_bytes().saturating_add(len) > as_limit {
        return Err(ERR_ENOMEM);
    }

    let addr = if fixed_address || frame.rdi != 0 {
        if frame.rdi & 4095 != 0 {
            return Err(ERR_EINVAL);
        }
        validate_reserved_user_page_range(frame.rdi, len)?;
        frame.rdi
    } else {
        active_context().allocate_mmap(len, 4096).ok_or(ERR_EFAULT)?
    };

    let existing_ranges = active_context().mapped_user_subranges(addr, len);
    if fixed_noreplace && !existing_ranges.is_empty() {
        return Err(vmos_abi::ERR_EEXIST);
    }
    if fixed || file_backing.is_some() {
        for (start, end) in existing_ranges {
            unmap_active_user_page_range(start, end - start)?;
            active_context().unmap_user_region(start, end - start);
            active_context().supervisor.record_guest_memory_unmap(start, end - start);
        }
    } else {
        for (start, end) in existing_ranges {
            protect_active_user_page_range(start, end - start, frame.rdx)?;
        }
    }
    let _ = dispatch_ret(
        "ring3_mmap",
        SyscallContext::new(SYS_MMAP, [addr, len, frame.rdx, frame.r10, frame.r8, frame.r9]),
    );
    let (readable, writable, executable) = prot_user_region_permissions(frame.rdx);
    active_context().record_user_region(addr, len, readable, writable, executable);
    active_context()
        .supervisor
        .record_guest_memory_region(addr, len, readable, writable, executable);
    if let Some(file_backing) = file_backing {
        let map_prot = if frame.rdx == 0 { PROT_READ } else { frame.rdx };
        if map_prot != 0 {
            protect_active_user_page_range(addr, len, map_prot)?;
        }
        let bytes = file_backing.bytes();
        populate_active_user_page_range(addr, bytes)?;
        let retain_shared_refs = match file_backing {
            MmapFileBacking::Private(bytes) => {
                mark_active_user_page_range_file_private(addr, len, &bytes);
                false
            }
            MmapFileBacking::Shared { vfs_node_id, path, offset, bytes } => {
                mark_active_user_page_range_file_shared(
                    addr,
                    len,
                    &bytes,
                    vfs_node_id,
                    &path,
                    offset,
                );
                true
            }
        };
        if map_prot != frame.rdx {
            protect_active_user_page_range(addr, len, frame.rdx)?;
        }
        if retain_shared_refs {
            retain_active_file_shared_page_refs(addr, len);
        }
    }
    Ok(addr as i64)
}

fn sys_mremap(frame: &SyscallFrame) -> Result<i64, i32> {
    const MREMAP_MAYMOVE: u64 = 0x1;
    const MREMAP_FIXED: u64 = 0x2;
    const MREMAP_DONTUNMAP: u64 = 0x4;
    const MREMAP_KNOWN_FLAGS: u64 = MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP;

    let old_addr = frame.rdi;
    let old_size = frame.rsi;
    let new_size = frame.rdx;
    let flags = frame.r10;

    if old_addr & 4095 != 0 || flags & !MREMAP_KNOWN_FLAGS != 0 {
        return Err(ERR_EINVAL);
    }
    if new_size == 0 {
        return Err(ERR_EINVAL);
    }
    let fixed = flags & MREMAP_FIXED != 0;
    let dontunmap = flags & MREMAP_DONTUNMAP != 0;
    if (fixed || dontunmap) && flags & MREMAP_MAYMOVE == 0 {
        return Err(ERR_EINVAL);
    }
    let new_len = align_page(new_size).ok_or(ERR_EINVAL)?;
    if old_size == 0 {
        if flags & MREMAP_MAYMOVE == 0 || dontunmap {
            return Err(ERR_EINVAL);
        }
        return clone_active_shared_mapping_for_mremap(old_addr, new_len, fixed, frame.r8);
    }
    let old_len = align_page(old_size).ok_or(ERR_EINVAL)?;
    if dontunmap && old_len != new_len {
        return Err(ERR_EINVAL);
    }
    validate_lower_user_address_range(old_addr, old_len)?;
    validate_mapped_user_range(old_addr, old_len)?;
    let old_end = old_addr.checked_add(old_len).ok_or(ERR_EINVAL)?;
    let (readable, writable, executable, dont_fork, wipe_on_fork) =
        single_user_region_attributes(old_addr, old_len).ok_or(ERR_ENOSYS)?;

    if dontunmap {
        validate_active_user_page_range_dontunmap_backing(old_addr, old_len)?;
        let new_addr = if fixed {
            let new_addr = frame.r8;
            if new_addr & 4095 != 0 {
                return Err(ERR_EINVAL);
            }
            validate_reserved_user_page_range(new_addr, new_len).map_err(|_| ERR_EINVAL)?;
            let target_end = new_addr.checked_add(new_len).ok_or(ERR_EINVAL)?;
            if ranges_overlap_for_mremap(old_addr, old_end, new_addr, target_end) {
                return Err(ERR_EINVAL);
            }
            new_addr
        } else {
            active_context().find_mmap_gap(new_len, 4096).ok_or(ERR_ENOMEM)?
        };
        let target_unmap_ranges = active_context().mapped_user_subranges(new_addr, new_len);
        let target_unmap_len = subranges_total_len(&target_unmap_ranges);
        let as_limit = active_context().supervisor.get_rlimit(active_context().pid, RLIMIT_AS).cur;
        if as_limit != u64::MAX
            && active_context()
                .mapped_user_bytes()
                .saturating_sub(target_unmap_len)
                .saturating_add(new_len)
                > as_limit
        {
            return Err(ERR_ENOMEM);
        }
        move_active_user_mapping_range(old_addr, old_len, new_addr, new_len, fixed, true)?;
        return Ok(new_addr as i64);
    }

    if fixed {
        let new_addr = frame.r8;
        if new_addr & 4095 != 0 {
            return Err(ERR_EINVAL);
        }
        validate_reserved_user_page_range(new_addr, new_len).map_err(|_| ERR_EINVAL)?;
        let target_end = new_addr.checked_add(new_len).ok_or(ERR_EINVAL)?;
        if ranges_overlap_for_mremap(old_addr, old_end, new_addr, target_end) {
            return Err(ERR_EINVAL);
        }
        move_active_user_mapping_range(old_addr, old_len, new_addr, new_len, true, false)?;
        return Ok(new_addr as i64);
    }

    if new_len == old_len {
        return Ok(old_addr as i64);
    }

    if new_len < old_len {
        let shrink_start = old_addr.checked_add(new_len).ok_or(ERR_EINVAL)?;
        let shrink_len = old_len - new_len;
        unmap_active_user_page_range(shrink_start, shrink_len)?;
        active_context().unmap_user_region(shrink_start, shrink_len);
        active_context().supervisor.record_guest_memory_unmap(shrink_start, shrink_len);
        return Ok(old_addr as i64);
    }

    validate_reserved_user_page_range(old_addr, new_len)?;
    let new_end = old_addr.checked_add(new_len).ok_or(ERR_EINVAL)?;
    if !active_context().mapped_user_subranges(old_end, new_end - old_end).is_empty() {
        if flags & MREMAP_MAYMOVE == 0 {
            return Err(ERR_ENOMEM);
        }
        let new_addr = active_context().find_mmap_gap(new_len, 4096).ok_or(ERR_ENOMEM)?;
        move_active_user_mapping_range(old_addr, old_len, new_addr, new_len, false, false)?;
        return Ok(new_addr as i64);
    }

    let grow_len = new_len - old_len;
    let as_limit = active_context().supervisor.get_rlimit(active_context().pid, RLIMIT_AS).cur;
    if as_limit != u64::MAX
        && active_context().mapped_user_bytes().saturating_add(grow_len) > as_limit
    {
        return Err(ERR_ENOMEM);
    }

    active_context().record_user_region_with_fork_advice(
        old_end,
        grow_len,
        readable,
        writable,
        executable,
        dont_fork,
        wipe_on_fork,
    );
    active_context()
        .supervisor
        .record_guest_memory_region(old_end, grow_len, readable, writable, executable);
    Ok(old_addr as i64)
}

fn clone_active_shared_mapping_for_mremap(
    old_addr: u64,
    new_len: u64,
    fixed: bool,
    fixed_target: u64,
) -> Result<i64, i32> {
    validate_lower_user_address_range(old_addr, new_len)?;
    validate_mapped_user_range(old_addr, new_len)?;
    let old_end = old_addr.checked_add(new_len).ok_or(ERR_EINVAL)?;
    let region_attrs = single_user_region_attributes(old_addr, new_len).ok_or(ERR_ENOSYS)?;
    validate_active_user_page_range_file_shared(old_addr, new_len)?;
    sync_active_file_shared_page_range(old_addr, new_len)?;

    let new_addr = if fixed {
        if fixed_target & 4095 != 0 {
            return Err(ERR_EINVAL);
        }
        validate_reserved_user_page_range(fixed_target, new_len).map_err(|_| ERR_EINVAL)?;
        let target_end = fixed_target.checked_add(new_len).ok_or(ERR_EINVAL)?;
        if ranges_overlap_for_mremap(old_addr, old_end, fixed_target, target_end) {
            return Err(ERR_EINVAL);
        }
        fixed_target
    } else {
        active_context().find_mmap_gap(new_len, 4096).ok_or(ERR_ENOMEM)?
    };
    let target_end = new_addr.checked_add(new_len).ok_or(ERR_EINVAL)?;
    let target_unmap_ranges = active_context().mapped_user_subranges(new_addr, new_len);
    let target_unmap_len = subranges_total_len(&target_unmap_ranges);
    let as_limit = active_context().supervisor.get_rlimit(active_context().pid, RLIMIT_AS).cur;
    if as_limit != u64::MAX
        && active_context()
            .mapped_user_bytes()
            .saturating_sub(target_unmap_len)
            .saturating_add(new_len)
            > as_limit
    {
        return Err(ERR_ENOMEM);
    }

    let current_regions = active_context().regions.clone();
    let current_mappings = active_context().page_mappings.clone();
    let mut next_regions = current_regions.clone();
    if fixed {
        replace_user_region_range_for_mremap(&mut next_regions, new_addr, target_end, None);
    }
    replace_user_region_range_for_mremap(
        &mut next_regions,
        new_addr,
        target_end,
        Some(region_attrs),
    );

    let mut next_mappings = Vec::with_capacity(
        current_mappings
            .len()
            .saturating_add(usize::try_from(new_len / 4096).map_err(|_| ERR_ENOMEM)?),
    );
    let mut cloned_mappings = Vec::new();
    let mut dropped_mappings = Vec::new();
    for mapping in &current_mappings {
        if fixed && mapping.va >= new_addr && mapping.va < target_end {
            dropped_mappings.push(mapping.clone());
            continue;
        }
        next_mappings.push(mapping.clone());
        if mapping.va >= old_addr && mapping.va < old_end {
            let mut cloned = mapping.clone();
            cloned.va = new_addr.checked_add(mapping.va - old_addr).ok_or(ERR_EINVAL)?;
            cloned.frame_start = 0;
            cloned.present = false;
            cloned.owned = false;
            cloned.cow = false;
            cloned_mappings.push(cloned.clone());
            next_mappings.push(cloned);
        }
    }
    if has_duplicate_user_page_mapping(&next_mappings) {
        return Err(ERR_ENOMEM);
    }
    sync_file_shared_page_mappings(&dropped_mappings)?;

    let switch_result = {
        let context = active_context();
        switch_user_page_mappings(
            context.physical_memory_offset(),
            &current_mappings,
            &current_regions,
            &next_mappings,
            &next_regions,
            &mut context.frame_allocator,
            false,
        )
    };
    if let Err(err) = switch_result {
        crate::kwarn!("mremap shared clone page-table switch failed: {}", err.message());
        return Err(ERR_EFAULT);
    }

    release_file_shared_page_refs(&dropped_mappings);
    retain_file_shared_page_refs(&cloned_mappings);
    let context = active_context();
    for mapping in dropped_mappings {
        if mapping.owned && mapping.frame_start != 0 {
            context.frame_allocator.deallocate_frame(PhysFrame::containing_address(PhysAddr::new(
                mapping.frame_start,
            )));
        }
    }
    context.page_mappings = next_mappings;
    context.regions = next_regions;
    context.commit_mmap_allocation(new_addr, new_len).ok_or(ERR_EINVAL)?;
    for (start, end) in target_unmap_ranges {
        context.supervisor.record_guest_memory_unmap(start, end - start);
    }
    let (readable, writable, executable, _, _) = region_attrs;
    context
        .supervisor
        .record_guest_memory_region(new_addr, new_len, readable, writable, executable);
    Ok(new_addr as i64)
}

fn move_active_user_mapping_range(
    old_addr: u64,
    old_len: u64,
    new_addr: u64,
    new_len: u64,
    replace_target: bool,
    preserve_source_region: bool,
) -> Result<(), i32> {
    let old_end = old_addr.checked_add(old_len).ok_or(ERR_EINVAL)?;
    let moved_end = old_addr.checked_add(old_len.min(new_len)).ok_or(ERR_EINVAL)?;
    let target_end = new_addr.checked_add(new_len).ok_or(ERR_EINVAL)?;
    validate_reserved_user_page_range(new_addr, new_len)?;
    let target_unmap_ranges = active_context().mapped_user_subranges(new_addr, new_len);
    if !replace_target && !target_unmap_ranges.is_empty() {
        return Err(ERR_ENOMEM);
    }
    let region_attrs = single_user_region_attributes(old_addr, old_len).ok_or(ERR_ENOSYS)?;

    let current_regions = active_context().regions.clone();
    let current_mappings = active_context().page_mappings.clone();
    let mut next_regions = current_regions.clone();
    if !preserve_source_region {
        replace_user_region_range_for_mremap(&mut next_regions, old_addr, old_end, None);
    }
    if replace_target {
        replace_user_region_range_for_mremap(&mut next_regions, new_addr, target_end, None);
    }
    replace_user_region_range_for_mremap(
        &mut next_regions,
        new_addr,
        new_addr.checked_add(new_len).ok_or(ERR_EINVAL)?,
        Some(region_attrs),
    );

    let mut next_mappings = Vec::with_capacity(current_mappings.len());
    let mut dropped_mappings = Vec::new();
    for mapping in &current_mappings {
        if mapping.va >= old_addr && mapping.va < old_end {
            if mapping.va < moved_end {
                let mut moved = mapping.clone();
                moved.va = new_addr.checked_add(mapping.va - old_addr).ok_or(ERR_EINVAL)?;
                next_mappings.push(moved);
                if preserve_source_region {
                    let mut source = mapping.clone();
                    source.frame_start = 0;
                    source.present = false;
                    source.owned = false;
                    source.cow = false;
                    next_mappings.push(source);
                }
            } else {
                dropped_mappings.push(mapping.clone());
            }
        } else if replace_target && mapping.va >= new_addr && mapping.va < target_end {
            dropped_mappings.push(mapping.clone());
        } else {
            next_mappings.push(mapping.clone());
        }
    }
    if has_duplicate_user_page_mapping(&next_mappings) {
        return Err(ERR_ENOMEM);
    }
    sync_file_shared_page_mappings(&dropped_mappings)?;

    let switch_result = {
        let context = active_context();
        switch_user_page_mappings(
            context.physical_memory_offset(),
            &current_mappings,
            &current_regions,
            &next_mappings,
            &next_regions,
            &mut context.frame_allocator,
            false,
        )
    };
    if let Err(err) = switch_result {
        crate::kwarn!("mremap page-table move failed: {}", err.message());
        return Err(ERR_EFAULT);
    }

    release_file_shared_page_refs(&dropped_mappings);
    let context = active_context();
    for mapping in dropped_mappings {
        if mapping.owned && mapping.frame_start != 0 {
            context.frame_allocator.deallocate_frame(PhysFrame::containing_address(PhysAddr::new(
                mapping.frame_start,
            )));
        }
    }
    context.page_mappings = next_mappings;
    context.regions = next_regions;
    context.commit_mmap_allocation(new_addr, new_len).ok_or(ERR_EINVAL)?;
    if !preserve_source_region {
        context.supervisor.record_guest_memory_unmap(old_addr, old_len);
    }
    for (start, end) in target_unmap_ranges {
        context.supervisor.record_guest_memory_unmap(start, end - start);
    }
    let (readable, writable, executable, _, _) = region_attrs;
    context
        .supervisor
        .record_guest_memory_region(new_addr, new_len, readable, writable, executable);
    Ok(())
}

fn sys_brk(frame: &SyscallFrame) -> Result<i64, i32> {
    let requested = frame.rdi;
    let current = active_context().program_break();
    if requested == 0 {
        return Ok(current as i64);
    }

    let (brk_base, brk_end) = active_context().program_break_bounds();
    if requested < brk_base || requested > brk_end {
        return Ok(current as i64);
    }

    if requested > current {
        let start = align_page(current).ok_or(ERR_EINVAL)?;
        let end = align_page(requested).ok_or(ERR_EINVAL)?;
        if end > start {
            active_context().record_user_region(start, end - start, true, true, false);
            active_context().supervisor.record_guest_memory_region(
                start,
                end - start,
                true,
                true,
                false,
            );
        }
    } else if requested < current {
        let start = align_page(requested).ok_or(ERR_EINVAL)?;
        let end = align_page(current).ok_or(ERR_EINVAL)?;
        if end > start {
            unmap_active_user_page_range(start, end - start)?;
            active_context().unmap_user_region(start, end - start);
            active_context().supervisor.record_guest_memory_unmap(start, end - start);
        }
    }

    active_context().commit_program_break(requested);
    Ok(requested as i64)
}

fn sys_mprotect(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rdi & 4095 != 0 {
        return Err(ERR_EINVAL);
    }
    let len = align_page(frame.rsi).ok_or(ERR_EINVAL)?;
    validate_mapped_user_range(frame.rdi, len)?;
    protect_active_user_page_range(frame.rdi, len, frame.rdx)?;
    let (readable, writable, executable) = prot_user_region_permissions(frame.rdx);
    active_context().protect_user_region(frame.rdi, len, readable, writable, executable);
    active_context()
        .supervisor
        .record_guest_memory_region(frame.rdi, len, readable, writable, executable);
    Ok(0)
}

fn sys_msync(frame: &SyscallFrame) -> Result<i64, i32> {
    const MS_ASYNC: u64 = 0x1;
    const MS_INVALIDATE: u64 = 0x2;
    const MS_SYNC: u64 = 0x4;
    const MS_SUPPORTED: u64 = MS_ASYNC | MS_INVALIDATE | MS_SYNC;

    if frame.rdi & 4095 != 0 {
        return Err(ERR_EINVAL);
    }
    if frame.rdx & !MS_SUPPORTED != 0 || frame.rdx & (MS_ASYNC | MS_SYNC) == MS_ASYNC | MS_SYNC {
        return Err(ERR_EINVAL);
    }
    let len = align_page(frame.rsi).ok_or(ERR_EINVAL)?;
    if len == 0 {
        return Ok(0);
    }
    validate_mapped_user_range(frame.rdi, len)
        .map_err(|errno| if errno == ERR_EFAULT { ERR_ENOMEM } else { errno })?;
    sync_active_file_shared_page_range(frame.rdi, len)?;
    Ok(0)
}

fn sys_madvise(frame: &SyscallFrame) -> Result<i64, i32> {
    const MADV_NORMAL: u64 = 0;
    const MADV_RANDOM: u64 = 1;
    const MADV_SEQUENTIAL: u64 = 2;
    const MADV_WILLNEED: u64 = 3;
    const MADV_DONTNEED: u64 = 4;
    const MADV_FREE: u64 = 8;
    const MADV_REMOVE: u64 = 9;
    const MADV_DONTFORK: u64 = 10;
    const MADV_DOFORK: u64 = 11;
    const MADV_MERGEABLE: u64 = 12;
    const MADV_UNMERGEABLE: u64 = 13;
    const MADV_HUGEPAGE: u64 = 14;
    const MADV_NOHUGEPAGE: u64 = 15;
    const MADV_DONTDUMP: u64 = 16;
    const MADV_DODUMP: u64 = 17;
    const MADV_WIPEONFORK: u64 = 18;
    const MADV_KEEPONFORK: u64 = 19;
    const MADV_COLD: u64 = 20;
    const MADV_PAGEOUT: u64 = 21;
    const MADV_POPULATE_READ: u64 = 22;
    const MADV_POPULATE_WRITE: u64 = 23;

    match frame.rdx {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED | MADV_DONTNEED | MADV_FREE
        | MADV_REMOVE | MADV_DONTFORK | MADV_DOFORK | MADV_MERGEABLE | MADV_UNMERGEABLE
        | MADV_HUGEPAGE | MADV_NOHUGEPAGE | MADV_DONTDUMP | MADV_DODUMP | MADV_WIPEONFORK
        | MADV_KEEPONFORK | MADV_COLD | MADV_PAGEOUT | MADV_POPULATE_READ | MADV_POPULATE_WRITE => {
        }
        _ => return Err(ERR_EINVAL),
    }

    if frame.rdi & 4095 != 0 {
        return Err(ERR_EINVAL);
    }
    let len = align_page(frame.rsi).ok_or(ERR_EINVAL)?;
    if len == 0 {
        return Ok(0);
    }
    validate_lower_user_address_range(frame.rdi, len)?;
    validate_mapped_user_range(frame.rdi, len)
        .map_err(|errno| if errno == ERR_EFAULT { ERR_ENOMEM } else { errno })?;
    match frame.rdx {
        MADV_DONTNEED => discard_active_user_page_range(frame.rdi, len)?,
        MADV_FREE => discard_active_zero_user_page_range(frame.rdi, len)?,
        MADV_REMOVE => remove_active_file_shared_page_range(frame.rdi, len)?,
        MADV_DONTFORK => active_context().set_user_region_fork_advice(frame.rdi, len, true, false),
        MADV_DOFORK => set_active_user_region_dofork(frame.rdi, len),
        MADV_WIPEONFORK => {
            validate_active_user_page_range_zero_backing(frame.rdi, len)?;
            active_context().set_user_region_fork_advice(frame.rdi, len, false, true);
        }
        MADV_KEEPONFORK => set_active_user_region_keeponfork(frame.rdi, len),
        MADV_POPULATE_READ => {
            validate_user_range_access(frame.rdi, len, UserRangeAccess::Read)?;
            prefault_active_user_page_range(frame.rdi, len, false)?;
        }
        MADV_POPULATE_WRITE => {
            validate_user_range_access(frame.rdi, len, UserRangeAccess::Write)?;
            prefault_active_user_page_range(frame.rdi, len, true)?;
        }
        _ => {}
    }
    Ok(0)
}

fn sys_munmap(frame: &SyscallFrame) -> Result<i64, i32> {
    if frame.rdi & 4095 != 0 {
        return Err(ERR_EINVAL);
    }
    let len = align_page(frame.rsi).ok_or(ERR_EINVAL)?;
    if len == 0 {
        return Err(ERR_EINVAL);
    }
    validate_lower_user_address_range(frame.rdi, len)?;
    let mapped_ranges = active_context().mapped_user_subranges(frame.rdi, len);
    for (start, end) in mapped_ranges {
        unmap_active_user_page_range(start, end - start)?;
    }
    let _ =
        dispatch_ret("ring3_munmap", SyscallContext::new(SYS_MUNMAP, [frame.rdi, len, 0, 0, 0, 0]));
    active_context().unmap_user_region(frame.rdi, len);
    active_context().supervisor.record_guest_memory_unmap(frame.rdi, len);
    Ok(0)
}

fn sys_arch_prctl(frame: &SyscallFrame) -> Result<i64, i32> {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;

    match frame.rdi {
        ARCH_SET_FS => {
            FsBase::write(user_fs_base(frame.rsi)?);
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

fn user_fs_base(base: u64) -> Result<VirtAddr, i32> {
    if base >= X86_64_USER_CANONICAL_LIMIT {
        return Err(ERR_EPERM);
    }
    VirtAddr::try_new(base).map_err(|_| ERR_EPERM)
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
    let cwd = active_context().visible_cwd();

    if cwd.len() + 1 > size {
        return Err(ERR_EINVAL);
    }
    let mut dest = user_lease(frame.rdi, (cwd.len() + 1) as u64, true)?;
    let dest_bytes = dest.bytes_mut().map_err(map_dmw_fault)?;
    dest_bytes[..cwd.len()].copy_from_slice(&cwd);
    dest_bytes[cwd.len()] = 0;
    Ok((cwd.len() + 1) as i64)
}

fn sys_readlink(frame: &SyscallFrame) -> Result<i64, i32> {
    sys_readlink_impl(AT_FDCWD, frame.rdi, frame.rsi, frame.rdx)
}

fn sys_readlinkat(frame: &SyscallFrame) -> Result<i64, i32> {
    sys_readlink_impl(linux_fd_arg(frame.rdi), frame.rsi, frame.rdx, frame.r10)
}

fn sys_readlink_impl(dirfd: i64, path_ptr: u64, buf_ptr: u64, count_arg: u64) -> Result<i64, i32> {
    let path = read_user_c_string(path_ptr, PATH_MAX)?;
    let resolved = resolve_path(dirfd, &path)?;
    let count = usize::try_from(count_arg).map_err(|_| ERR_EINVAL)?;
    if count == 0 {
        return Err(ERR_EINVAL);
    }
    let link = if resolved == b"/proc/self/exe" {
        active_context().exec_path().to_vec()
    } else {
        readlink_via_supervisor(dirfd, &resolved)?
    };
    let written = core::cmp::min(link.len(), count);
    let mut dest = user_lease(buf_ptr, written as u64, true)?;
    dest.bytes_mut().map_err(map_dmw_fault)?.copy_from_slice(&link[..written]);
    Ok(written as i64)
}

fn readlink_via_supervisor(dirfd: i64, resolved: &[u8]) -> Result<Vec<u8>, i32> {
    let supervisor = &mut active_context().supervisor;
    let (ptr, len) = supervisor.write_linux_arg_bytes(&resolved).map_err(|_| ERR_EFAULT)?;
    match supervisor
        .dispatch_linux_syscall(
            "ring3_readlinkat",
            SyscallContext::new(SYS_READLINKAT, [dirfd as u64, ptr as u64, len as u64, 0, 0, 0]),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Bytes(bytes) => Ok(bytes),
        LinuxCallResult::Ret(ret) if ret <= 0 => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
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

fn read_user_timeval_ms(ptr: u64) -> Result<u64, i32> {
    let req = user_lease(ptr, LINUX_TIMEVAL_SIZE, false)?;
    let bytes = req.bytes().map_err(map_dmw_fault)?;
    select_timeval_ms(
        i64::from_le_bytes(bytes[..8].try_into().map_err(|_| ERR_EINVAL)?),
        i64::from_le_bytes(bytes[8..16].try_into().map_err(|_| ERR_EINVAL)?),
    )
}

fn select_timeval_ms(tv_sec: i64, tv_usec: i64) -> Result<u64, i32> {
    if tv_sec < 0 || !(0..1_000_000).contains(&tv_usec) {
        return Err(ERR_EINVAL);
    }
    Ok((tv_sec as u64).saturating_mul(1000).saturating_add((tv_usec as u64).div_ceil(1000)))
}

fn write_select_timeout_remaining(
    ptr: u64,
    timeout_ms: Option<u64>,
    start_ns: u64,
) -> Result<(), i32> {
    let Some(timeout_ms) = timeout_ms else {
        return Ok(());
    };
    let remaining_ms = select_remaining_timeout_ms(timeout_ms, start_ns, current_monotonic_ns());
    write_user_bytes(ptr, &select_timeval_bytes(remaining_ms))
}

fn select_remaining_timeout_ms(timeout_ms: u64, start_ns: u64, now_ns: u64) -> u64 {
    timeout_ms.saturating_sub(now_ns.saturating_sub(start_ns).div_ceil(1_000_000))
}

fn select_timeval_bytes(timeout_ms: u64) -> [u8; LINUX_TIMEVAL_SIZE as usize] {
    let mut bytes = [0u8; LINUX_TIMEVAL_SIZE as usize];
    let tv_sec = (timeout_ms / 1000) as i64;
    let tv_usec = ((timeout_ms % 1000) * 1000) as i64;
    bytes[..8].copy_from_slice(&tv_sec.to_le_bytes());
    bytes[8..16].copy_from_slice(&tv_usec.to_le_bytes());
    bytes
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

fn read_user_itimerspec_ns(ptr: u64) -> Result<(u64, u64), i32> {
    let req = user_lease(ptr, LINUX_ITIMERSPEC_SIZE as u64, false)?;
    let bytes = req.bytes().map_err(map_dmw_fault)?;
    let interval_ns = decode_timespec_ns_from(bytes, 0)?;
    let value_ns = decode_timespec_ns_from(bytes, 16)?;
    Ok((value_ns, interval_ns))
}

fn write_user_itimerspec_ns(ptr: u64, value_ns: u64, interval_ns: u64) -> Result<(), i32> {
    let mut encoded = [0u8; LINUX_ITIMERSPEC_SIZE];
    encode_timespec_ns_into(&mut encoded, 0, interval_ns);
    encode_timespec_ns_into(&mut encoded, 16, value_ns);
    write_user_bytes(ptr, &encoded)
}

fn decode_timespec_ns_from(bytes: &[u8], offset: usize) -> Result<u64, i32> {
    let tv_sec = read_i64_from(bytes, offset)?;
    let tv_nsec = read_i64_from(bytes, offset + 8)?;
    if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
        return Err(ERR_EINVAL);
    }
    Ok((tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(tv_nsec as u64))
}

fn encode_timespec_ns_into(out: &mut [u8], offset: usize, ns: u64) {
    write_i64(out, offset, (ns / 1_000_000_000) as i64);
    write_i64(out, offset + 8, (ns % 1_000_000_000) as i64);
}

fn current_clock_ms() -> u64 {
    current_monotonic_ns() / 1_000_000
}

fn read_pselect_sigmask(arg_ptr: u64) -> Result<Option<u64>, i32> {
    if arg_ptr == 0 {
        return Ok(None);
    }
    let bytes = read_user_bytes(arg_ptr, PSELECT6_SIGMASK_ARG_BYTES)?;
    let mask_ptr = read_u64_from(&bytes, 0)?;
    let mask_len = read_u64_from(&bytes, 8)?;
    if mask_ptr == 0 {
        return Ok(None);
    }
    if mask_len != LINUX_SIGSET_BYTES as u64 {
        return Err(ERR_EINVAL);
    }
    Ok(Some(read_user_u64(mask_ptr)?))
}

fn read_pselect_fdsets(
    read_ptr: u64,
    write_ptr: u64,
    except_ptr: u64,
    nfds: usize,
) -> Result<PselectFdSetSnapshot, i32> {
    Ok(PselectFdSetSnapshot {
        read_ptr,
        write_ptr,
        except_ptr,
        nfds,
        read_bits: read_fdset_bits(read_ptr, nfds)?,
        write_bits: read_fdset_bits(write_ptr, nfds)?,
        except_bits: read_fdset_bits(except_ptr, nfds)?,
    })
}

fn read_fdset_bits(ptr: u64, nfds: usize) -> Result<[u64; PSELECT6_FDSET_WORDS], i32> {
    let mut bits = [0u64; PSELECT6_FDSET_WORDS];
    if ptr == 0 || nfds == 0 {
        return Ok(bits);
    }
    let len = nfds.div_ceil(8);
    let bytes = read_user_bytes(ptr, len)?;
    for fd in 0..nfds {
        let byte = fd / 8;
        let mask = 1u8 << (fd % 8);
        if bytes[byte] & mask != 0 {
            set_fd_bit(&mut bits, fd);
        }
    }
    Ok(bits)
}

fn collect_pselect_ready(snapshot: &PselectFdSetSnapshot) -> Result<PselectReadySet, i32> {
    const POLLIN: u16 = 0x001;
    const POLLOUT: u16 = 0x004;

    let mut ready = PselectReadySet {
        ready: 0,
        read_bits: [0; PSELECT6_FDSET_WORDS],
        write_bits: [0; PSELECT6_FDSET_WORDS],
    };
    let supervisor = &mut active_context().supervisor;
    for fd in 0..snapshot.nfds {
        if fdset_bit(snapshot.read_bits, fd) {
            let revents = supervisor.fd_poll_revents(fd as u32, POLLIN)?;
            if pselect_read_revents_ready(revents) {
                set_fd_bit(&mut ready.read_bits, fd);
                ready.ready += 1;
            }
        }
        if fdset_bit(snapshot.write_bits, fd) {
            let revents = supervisor.fd_poll_revents(fd as u32, POLLOUT)?;
            if pselect_write_revents_ready(revents) {
                set_fd_bit(&mut ready.write_bits, fd);
                ready.ready += 1;
            }
        }
        if fdset_bit(snapshot.except_bits, fd) {
            let _ = supervisor.fd_poll_revents(fd as u32, 0)?;
        }
    }
    Ok(ready)
}

fn pselect_read_revents_ready(revents: u16) -> bool {
    const POLLIN: u16 = 0x001;
    const POLLERR: u16 = 0x008;
    const POLLHUP: u16 = 0x010;

    revents & (POLLIN | POLLERR | POLLHUP) != 0
}

fn pselect_write_revents_ready(revents: u16) -> bool {
    const POLLOUT: u16 = 0x004;
    const POLLERR: u16 = 0x008;
    const POLLHUP: u16 = 0x010;

    revents & (POLLOUT | POLLERR | POLLHUP) != 0
}

fn write_pselect_result(
    snapshot: &PselectFdSetSnapshot,
    ready: &PselectReadySet,
) -> Result<i64, i32> {
    write_fdset_bits(snapshot.read_ptr, snapshot.nfds, ready.read_bits)?;
    write_fdset_bits(snapshot.write_ptr, snapshot.nfds, ready.write_bits)?;
    write_fdset_bits(snapshot.except_ptr, snapshot.nfds, [0; PSELECT6_FDSET_WORDS])?;
    Ok(ready.ready)
}

fn write_fdset_bits(ptr: u64, nfds: usize, bits: [u64; PSELECT6_FDSET_WORDS]) -> Result<(), i32> {
    if ptr == 0 || nfds == 0 {
        return Ok(());
    }
    let len = nfds.div_ceil(8);
    let mut set = user_lease(ptr, len as u64, true)?;
    let bytes = set.bytes_mut().map_err(map_dmw_fault)?;
    for byte in bytes.iter_mut() {
        *byte = 0;
    }
    for fd in 0..nfds {
        if fdset_bit(bits, fd) {
            bytes[fd / 8] |= 1u8 << (fd % 8);
        }
    }
    Ok(())
}

fn fdset_bit(bits: [u64; PSELECT6_FDSET_WORDS], fd: usize) -> bool {
    bits[fd / 64] & (1u64 << (fd % 64)) != 0
}

fn set_fd_bit(bits: &mut [u64; PSELECT6_FDSET_WORDS], fd: usize) {
    bits[fd / 64] |= 1u64 << (fd % 64);
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

fn current_tai_ns() -> u64 {
    let realtime_ns = current_realtime_ns();
    let tai_offset_ns = active_context().clock_adj_state().tai as i128 * 1_000_000_000i128;
    if tai_offset_ns >= 0 {
        realtime_ns.saturating_add(tai_offset_ns as u64)
    } else {
        realtime_ns.saturating_sub((-tai_offset_ns) as u64)
    }
}

fn sys_futex(frame: &SyscallFrame) -> Result<i64, i32> {
    validate_futex_uaddr(frame.rdi)?;
    let raw_op = frame.rsi as u32;
    let op = raw_op & FUTEX_CMD_MASK;
    match op {
        FUTEX_LOCK_PI => {
            return sys_futex_lock_pi(frame, false, futex_pi_lock_timeout_clock(raw_op, false));
        }
        FUTEX_LOCK_PI2 => {
            return sys_futex_lock_pi(frame, false, futex_pi_lock_timeout_clock(raw_op, true));
        }
        FUTEX_TRYLOCK_PI => {
            if !futex_pi_non_timeout_flags_valid(raw_op) {
                return Err(ERR_EINVAL);
            }
            return sys_futex_lock_pi(frame, true, FutexPiTimeoutClock::Realtime);
        }
        FUTEX_UNLOCK_PI => {
            if !futex_pi_non_timeout_flags_valid(raw_op) {
                return Err(ERR_EINVAL);
            }
            return sys_futex_unlock_pi(frame);
        }
        _ => {}
    }

    let current_word = {
        let word = user_lease(frame.rdi, 4, false)?;
        let bytes = word.bytes().map_err(map_dmw_fault)?;
        u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ERR_EINVAL)?) as u64
    };
    if op == FUTEX_WAIT_REQUEUE_PI {
        return sys_futex_wait_requeue_pi(frame, current_word);
    }
    if op == FUTEX_CMP_REQUEUE_PI {
        return sys_futex_cmp_requeue_pi(frame, current_word);
    }
    if op == FUTEX_WAIT_BITSET && current_word != frame.rdx {
        return Err(vmos_abi::ERR_EAGAIN);
    }
    if op == FUTEX_REQUEUE || op == FUTEX_CMP_REQUEUE {
        return sys_futex_requeue(frame, op, current_word);
    }
    let futex_arg5 =
        if op == FUTEX_WAIT_BITSET || op == FUTEX_WAKE_BITSET { frame.r9 } else { current_word };

    let supervisor = &mut active_context().supervisor;
    let needs_timeout = op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET;
    let (timeout_ptr, timeout_len) = if !needs_timeout || frame.r10 == 0 {
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
                [frame.rdi, op as u64, frame.rdx, timeout_ptr, timeout_len, futex_arg5],
            ),
        )
        .map_err(|_| ERR_EINVAL)?
    {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_futex_requeue(frame: &SyscallFrame, op: u32, current_word: u64) -> Result<i64, i32> {
    validate_futex_uaddr(frame.r8)?;
    if frame.r8 == frame.rdi {
        return Err(ERR_EINVAL);
    }
    if op == FUTEX_CMP_REQUEUE && current_word != frame.r9 {
        return Err(vmos_abi::ERR_EAGAIN);
    }
    let requeue_count = frame.r10;
    let result = active_context()
        .supervisor
        .dispatch_linux_syscall(
            "ring3_futex_requeue",
            SyscallContext::new(
                SYS_FUTEX,
                [frame.rdi, op as u64, frame.rdx, requeue_count, frame.r8, 0],
            ),
        )
        .map_err(|_| ERR_EINVAL)?;
    match result {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

fn sys_futex_wait_requeue_pi(frame: &SyscallFrame, current_word: u64) -> Result<i64, i32> {
    validate_futex_uaddr(frame.r8)?;
    if frame.r8 == frame.rdi {
        return Err(ERR_EINVAL);
    }
    if current_word != frame.rdx {
        return Err(ERR_EAGAIN);
    }

    let (timeout_ptr, timeout_len) = futex_timeout_arg(frame.r10)?;
    let result = active_context()
        .supervisor
        .dispatch_linux_syscall(
            "ring3_futex_wait_requeue_pi",
            SyscallContext::new(
                SYS_FUTEX,
                [
                    frame.rdi,
                    FUTEX_WAIT_REQUEUE_PI as u64,
                    frame.rdx,
                    timeout_ptr,
                    timeout_len,
                    current_word,
                ],
            ),
        )
        .map_err(|_| ERR_EINVAL)?;
    linux_call_result(result)
}

fn sys_futex_cmp_requeue_pi(frame: &SyscallFrame, current_word: u64) -> Result<i64, i32> {
    validate_futex_uaddr(frame.r8)?;
    if frame.r8 == frame.rdi {
        return Err(ERR_EINVAL);
    }
    if frame.rdx != 1 {
        return Err(ERR_EINVAL);
    }
    if current_word != frame.r9 {
        return Err(ERR_EAGAIN);
    }
    let requeue_count = u32::try_from(frame.r10).map_err(|_| ERR_EINVAL)?;
    let total_to_move = 1u32.checked_add(requeue_count).ok_or(ERR_EINVAL)?;
    let dst_word = read_writable_futex_word(frame.r8)?;
    if active_context()
        .supervisor
        .require_capability("futex_service", "futex.waitset", "requeue")
        .is_err()
    {
        return Err(ERR_EPERM);
    }

    let moved = active_context()
        .supervisor
        .requeue_futex_pi_waiters(frame.rdi, frame.r8, total_to_move)
        .map_err(service_error_to_errno)?;
    if moved == 0 {
        return Ok(0);
    }

    let owner = dst_word & FUTEX_TID_MASK;
    if owner == 0 {
        let Some(handoff) = active_context()
            .supervisor
            .prepare_futex_pi_handoff(frame.r8)
            .map_err(service_error_to_errno)?
        else {
            return Err(ERR_EINVAL);
        };
        write_user_u32(
            frame.r8,
            futex_pi_handoff_word(
                dst_word,
                handoff.next_owner_tid & FUTEX_TID_MASK,
                handoff.has_more_waiters,
            ),
        )?;
        active_context()
            .supervisor
            .complete_futex_pi_ownerless_handoff(frame.r8, handoff)
            .map_err(service_error_to_errno)?;
    } else {
        let wait_word = futex_pi_wait_word(dst_word);
        if wait_word != dst_word {
            write_user_u32(frame.r8, wait_word)?;
        }
        if let Some(owner_task) = active_context().supervisor.task_id_for_tid(owner) {
            active_context().supervisor.refresh_futex_pi_boost(owner_task, frame.r8);
        }
    }

    Ok(moved as i64)
}

fn futex_timeout_arg(timeout_user_ptr: u64) -> Result<(u64, u64), i32> {
    if timeout_user_ptr == 0 {
        return Ok((0, 0));
    }
    let timeout = read_user_bytes(timeout_user_ptr, LINUX_TIMESPEC_SIZE as usize)?;
    let (ptr, len) =
        active_context().supervisor.write_linux_arg_bytes(&timeout).map_err(|_| ERR_EFAULT)?;
    Ok((ptr as u64, len as u64))
}

fn read_writable_futex_word(ptr: u64) -> Result<u32, i32> {
    let mut lease = user_lease(ptr, 4, true)?;
    let bytes = lease.bytes_mut().map_err(map_dmw_fault)?;
    Ok(u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ERR_EINVAL)?))
}

fn validate_futex_uaddr(uaddr: u64) -> Result<(), i32> {
    if uaddr & 0x3 != 0 {
        return Err(ERR_EINVAL);
    }
    validate_user_range(uaddr, 4, false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FutexPiTimeoutClock {
    Realtime,
    Monotonic,
}

fn futex_pi_non_timeout_flags_valid(raw_op: u32) -> bool {
    raw_op & FUTEX_CLOCK_REALTIME == 0
}

fn futex_pi_lock_timeout_clock(raw_op: u32, pi2: bool) -> FutexPiTimeoutClock {
    if pi2 && raw_op & FUTEX_CLOCK_REALTIME == 0 {
        FutexPiTimeoutClock::Monotonic
    } else {
        FutexPiTimeoutClock::Realtime
    }
}

fn sys_futex_lock_pi(
    frame: &SyscallFrame,
    try_only: bool,
    timeout_clock: FutexPiTimeoutClock,
) -> Result<i64, i32> {
    let uaddr = frame.rdi;
    let tid = active_context().tid & FUTEX_TID_MASK;
    let word = read_user_u32(uaddr)?;
    let owner = word & FUTEX_TID_MASK;

    if owner == 0 {
        write_user_u32(uaddr, futex_pi_owner_word(word, tid))?;
        return Ok(0);
    }
    if owner == tid {
        return Err(ERR_EDEADLK);
    }
    if try_only {
        return Err(vmos_abi::ERR_EAGAIN);
    }

    if active_context()
        .supervisor
        .require_capability("futex_service", "futex.waitset", "wait")
        .is_err()
    {
        return Err(ERR_EPERM);
    }
    let (timeout_ptr, timeout_len) = futex_pi_lock_timeout_arg(frame.r10, timeout_clock)?;
    // Reuse the existing futex wait queue here; this is bounded blocking handoff,
    // not a full PI scheduler transfer.
    let wait_word = futex_pi_wait_word(word);
    if wait_word != word {
        write_user_u32(uaddr, wait_word)?;
    }
    let owner_task = active_context().supervisor.task_id_for_tid(owner);
    let wait_priority = active_context().supervisor.current_task_priority();
    if let Some(owner_task) = owner_task {
        active_context().supervisor.register_futex_pi_boost(owner_task, uaddr, wait_priority);
    }
    let result = match active_context().supervisor.dispatch_linux_syscall(
        "ring3_futex_lock_pi",
        SyscallContext::new(
            SYS_FUTEX,
            [
                uaddr,
                FUTEX_WAIT as u64,
                wait_word as u64,
                timeout_ptr,
                timeout_len,
                wait_word as u64,
            ],
        ),
    ) {
        Ok(result) => result,
        Err(_) => {
            if let Some(owner_task) = owner_task {
                active_context().supervisor.refresh_futex_pi_boost(owner_task, uaddr);
            }
            if let Ok(current_word) = read_user_u32(uaddr)
                && let Some(restore_word) = futex_pi_restore_wait_word(word, current_word)
            {
                log_ignored_user_write(
                    "futex pi dispatch restore",
                    write_user_u32(uaddr, restore_word),
                );
            }
            return Err(ERR_EINVAL);
        }
    };
    match result {
        LinuxCallResult::Ret(ret) if ret >= 0 => {
            let current_word = read_user_u32(uaddr)?;
            write_user_u32(uaddr, futex_pi_owner_word(current_word, tid))?;
            active_context().supervisor.adopt_futex_pi_after_wait(uaddr, owner_task);
            Ok(0)
        }
        LinuxCallResult::Ret(ret) => {
            if let Some(owner_task) = owner_task {
                active_context().supervisor.refresh_futex_pi_boost(owner_task, uaddr);
            }
            if ret == -(ERR_EAGAIN as i64)
                && let Ok(current_word) = read_user_u32(uaddr)
                && let Some(restore_word) = futex_pi_restore_wait_word(word, current_word)
            {
                log_ignored_user_write(
                    "futex pi eagain restore",
                    write_user_u32(uaddr, restore_word),
                );
            }
            Err((-ret) as i32)
        }
        _ => {
            if let Some(owner_task) = owner_task {
                active_context().supervisor.refresh_futex_pi_boost(owner_task, uaddr);
            }
            if let Ok(current_word) = read_user_u32(uaddr)
                && let Some(restore_word) = futex_pi_restore_wait_word(word, current_word)
            {
                log_ignored_user_write(
                    "futex pi non-ret restore",
                    write_user_u32(uaddr, restore_word),
                );
            }
            Err(ERR_EINVAL)
        }
    }
}

fn futex_pi_lock_timeout_arg(
    timeout_user_ptr: u64,
    clock: FutexPiTimeoutClock,
) -> Result<(u64, u64), i32> {
    if timeout_user_ptr == 0 {
        return Ok((0, 0));
    }
    let target_ns = read_user_timespec_ns(timeout_user_ptr)?;
    let now_ns = match clock {
        FutexPiTimeoutClock::Realtime => current_realtime_ns(),
        FutexPiTimeoutClock::Monotonic => current_monotonic_ns(),
    };
    let timeout_ms = target_ns.saturating_sub(now_ns).div_ceil(1_000_000);
    write_timespec_ms_arg(timeout_ms)
}

fn write_timespec_ms_arg(delay_ms: u64) -> Result<(u64, u64), i32> {
    let mut encoded = [0u8; LINUX_TIMESPEC_SIZE as usize];
    let clamped_ms = delay_ms.min(u32::MAX as u64);
    let tv_sec = clamped_ms / 1000;
    let tv_nsec = (clamped_ms % 1000) * 1_000_000;
    encoded[..8].copy_from_slice(&tv_sec.to_le_bytes());
    encoded[8..16].copy_from_slice(&tv_nsec.to_le_bytes());
    let (ptr, len) =
        active_context().supervisor.write_linux_arg_bytes(&encoded).map_err(|_| ERR_EFAULT)?;
    Ok((ptr as u64, len as u64))
}

fn sys_futex_unlock_pi(frame: &SyscallFrame) -> Result<i64, i32> {
    let uaddr = frame.rdi;
    let tid = active_context().tid & FUTEX_TID_MASK;
    let word = read_user_u32(uaddr)?;
    let owner = word & FUTEX_TID_MASK;
    if owner != tid {
        return Err(ERR_EPERM);
    }
    let owner_task = active_context().supervisor.current_task_id();
    if word & FUTEX_WAITERS != 0 {
        let handoff = active_context()
            .supervisor
            .prepare_futex_pi_handoff(uaddr)
            .map_err(service_error_to_errno)?;
        if let Some(handoff) = handoff {
            write_user_u32(
                uaddr,
                futex_pi_handoff_word(
                    word,
                    handoff.next_owner_tid & FUTEX_TID_MASK,
                    handoff.has_more_waiters,
                ),
            )?;
            active_context()
                .supervisor
                .complete_futex_pi_handoff(uaddr, owner_task, handoff)
                .map_err(service_error_to_errno)?;
            return Ok(0);
        }
        write_user_u32(uaddr, futex_pi_unlock_empty_word(word))?;
        active_context().supervisor.release_futex_pi_boost(owner_task, uaddr);
        return Ok(0);
    }
    write_user_u32(uaddr, 0)?;
    active_context().supervisor.release_futex_pi_boost(owner_task, uaddr);
    Ok(0)
}

fn futex_pi_owner_word(word: u32, tid: u32) -> u32 {
    (word & (FUTEX_OWNER_DIED | FUTEX_WAITERS)) | tid
}

fn futex_pi_wait_word(word: u32) -> u32 {
    word | FUTEX_WAITERS
}

fn futex_pi_restore_wait_word(original: u32, current: u32) -> Option<u32> {
    (current == futex_pi_wait_word(original)).then_some(original)
}

fn futex_pi_handoff_word(word: u32, tid: u32, has_more_waiters: bool) -> u32 {
    let mut next = (word & FUTEX_OWNER_DIED) | (tid & FUTEX_TID_MASK);
    if has_more_waiters {
        next |= FUTEX_WAITERS;
    }
    next
}

fn futex_pi_unlock_empty_word(word: u32) -> u32 {
    word & FUTEX_OWNER_DIED
}

fn service_error_to_errno(err: ServiceCallError) -> i32 {
    match err {
        ServiceCallError::Errno(errno) => errno,
        ServiceCallError::Trap(reason) => {
            crate::kwarn!("futex pi service trap: {}", reason);
            ERR_EINVAL
        }
        ServiceCallError::Invalid(err) => {
            crate::kwarn!("futex pi service invalid response: {}", err);
            ERR_EINVAL
        }
    }
}

fn linux_call_result(result: LinuxCallResult) -> Result<i64, i32> {
    match result {
        LinuxCallResult::Ret(ret) if ret >= 0 => Ok(ret),
        LinuxCallResult::Ret(ret) => Err((-ret) as i32),
        _ => Err(ERR_EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use vmos_abi::{
        ERR_EINTR, FUTEX_CLOCK_REALTIME, FUTEX_LOCK_PI, FUTEX_LOCK_PI2, FUTEX_OWNER_DIED,
        FUTEX_TID_MASK, FUTEX_TRYLOCK_PI, FUTEX_UNLOCK_PI, FUTEX_WAIT, FUTEX_WAIT_BITSET,
        FUTEX_WAITERS, SYS_ACCEPT, SYS_ACCEPT4, SYS_CONNECT, SYS_FCNTL, SYS_FLOCK, SYS_FUTEX,
        SYS_READ, SYS_READV, SYS_RECVFROM, SYS_SENDTO, SYS_WAIT4, SYS_WRITE, SYS_WRITEV,
    };

    use super::{
        CloneRequest, FCNTL_F_SETLKW, FutexPiTimeoutClock, LINUX_GREG_EFL, LINUX_GREG_R11,
        LINUX_GREG_RCX, LINUX_GREG_RIP, LINUX_GREG_RSP, PSELECT6_MAX_FDS, SA_RESTART,
        SignalAltStack, SyscallFrame, UserReturnContext, VectoredIoOffset,
        decode_linux_ucontext_return, encode_linux_ucontext, futex_pi_handoff_word,
        futex_pi_lock_timeout_clock, futex_pi_non_timeout_flags_valid, futex_pi_owner_word,
        futex_pi_restore_wait_word, futex_pi_unlock_empty_word, futex_pi_wait_word,
        parse_clone3_request_bytes, positioned_io_offset, preadv_offset_from_split,
        preadv2_flags_nowait, preadv2_offset_from_split, pselect_read_revents_ready,
        pselect_write_revents_ready, pwritev2_flags_append, read_linux_greg,
        restartable_interrupted_syscall, sanitize_restored_rflags, select_remaining_timeout_ms,
        select_timeval_bytes, select_timeval_ms, signal_restart_syscall, validate_iovcnt,
        validate_preadv2_flags, validate_pselect6_nfds, validate_pwritev2_flags,
        wait_nfds_within_rlimit, write_linux_greg,
    };

    fn write_u64_at(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn syscall_frame_with_ret(ret: i64) -> SyscallFrame {
        SyscallFrame {
            r9: 0,
            r8: 0,
            r10: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rax: ret as u64,
            rcx: 0x4000,
            r11: 0x202,
        }
    }

    #[test]
    fn sa_restart_covers_current_blocking_syscall_set() {
        let mut frame = syscall_frame_with_ret(-(ERR_EINTR as i64));
        for syscall in [
            SYS_READ,
            SYS_READV,
            SYS_WRITE,
            SYS_WRITEV,
            SYS_WAIT4,
            SYS_ACCEPT,
            SYS_ACCEPT4,
            SYS_CONNECT,
            SYS_SENDTO,
            SYS_RECVFROM,
            SYS_FLOCK,
        ] {
            assert!(restartable_interrupted_syscall(&frame, syscall));
            assert_eq!(signal_restart_syscall(&frame, syscall, SA_RESTART), Some(syscall));
        }

        frame.rsi = FCNTL_F_SETLKW;
        assert!(restartable_interrupted_syscall(&frame, SYS_FCNTL));
        assert_eq!(signal_restart_syscall(&frame, SYS_FCNTL, SA_RESTART), Some(SYS_FCNTL));

        frame.rsi = FUTEX_WAIT as u64;
        assert!(restartable_interrupted_syscall(&frame, SYS_FUTEX));
        frame.rsi = FUTEX_WAIT_BITSET as u64;
        assert!(restartable_interrupted_syscall(&frame, SYS_FUTEX));
    }

    #[test]
    fn sa_restart_rejects_non_restartable_or_non_eintr_results() {
        let mut frame = syscall_frame_with_ret(-(ERR_EINTR as i64));
        assert_eq!(signal_restart_syscall(&frame, SYS_READ, 0), None);
        assert_eq!(signal_restart_syscall(&frame, vmos_abi::SYS_GETPID, SA_RESTART), None);

        frame.rax = 0;
        assert_eq!(signal_restart_syscall(&frame, SYS_READ, SA_RESTART), None);

        frame.rax = (-(ERR_EINTR as i64)) as u64;
        frame.rsi = 0;
        assert!(!restartable_interrupted_syscall(&frame, SYS_FCNTL));
        frame.rsi = vmos_abi::FUTEX_WAKE as u64;
        assert!(!restartable_interrupted_syscall(&frame, SYS_FUTEX));
    }

    #[test]
    fn futex_pi_owner_word_preserves_state_bits() {
        let word = FUTEX_OWNER_DIED | FUTEX_WAITERS | 0x1234;
        let owned = futex_pi_owner_word(word, 0x55aa);
        assert_eq!(owned & FUTEX_OWNER_DIED, FUTEX_OWNER_DIED);
        assert_eq!(owned & FUTEX_WAITERS, FUTEX_WAITERS);
        assert_eq!(owned & 0xffff, 0x55aa);
    }

    #[test]
    fn futex_pi_unlock_word_preserves_state_bits() {
        let word = FUTEX_OWNER_DIED | FUTEX_WAITERS | 0x1234;
        let unlocked = futex_pi_unlock_empty_word(word);
        assert_eq!(unlocked, FUTEX_OWNER_DIED);
    }

    #[test]
    fn futex_pi_handoff_word_installs_next_owner_and_waiters_state() {
        let word = FUTEX_OWNER_DIED | FUTEX_WAITERS | 0x1234;
        let handoff = futex_pi_handoff_word(word, 0x55aa, true);
        assert_eq!(handoff & FUTEX_OWNER_DIED, FUTEX_OWNER_DIED);
        assert_eq!(handoff & FUTEX_WAITERS, FUTEX_WAITERS);
        assert_eq!(handoff & FUTEX_TID_MASK, 0x55aa);

        let final_handoff = futex_pi_handoff_word(word, 0x33cc, false);
        assert_eq!(final_handoff & FUTEX_OWNER_DIED, FUTEX_OWNER_DIED);
        assert_eq!(final_handoff & FUTEX_WAITERS, 0);
        assert_eq!(final_handoff & FUTEX_TID_MASK, 0x33cc);
    }

    #[test]
    fn futex_pi_wait_word_sets_waiters_bit_only() {
        assert_eq!(futex_pi_wait_word(0x1234), 0x1234 | FUTEX_WAITERS);
    }

    #[test]
    fn futex_pi_restore_wait_word_only_rewinds_matching_wait_state() {
        let original = FUTEX_OWNER_DIED | 0x1234;
        assert_eq!(
            futex_pi_restore_wait_word(original, futex_pi_wait_word(original)),
            Some(original)
        );
        assert_eq!(futex_pi_restore_wait_word(original, original), None);
        assert_eq!(
            futex_pi_restore_wait_word(original, FUTEX_OWNER_DIED | FUTEX_WAITERS | 0x5678),
            None
        );
    }

    #[test]
    fn futex_lock_pi_clock_flag_uses_realtime_without_rejecting_flag() {
        assert_eq!(
            futex_pi_lock_timeout_clock(FUTEX_LOCK_PI, false),
            FutexPiTimeoutClock::Realtime
        );
        assert_eq!(
            futex_pi_lock_timeout_clock(FUTEX_LOCK_PI | FUTEX_CLOCK_REALTIME, false),
            FutexPiTimeoutClock::Realtime
        );
        assert_eq!(
            futex_pi_lock_timeout_clock(FUTEX_LOCK_PI2, true),
            FutexPiTimeoutClock::Monotonic
        );
        assert_eq!(
            futex_pi_lock_timeout_clock(FUTEX_LOCK_PI2 | FUTEX_CLOCK_REALTIME, true),
            FutexPiTimeoutClock::Realtime
        );
    }

    #[test]
    fn futex_pi_non_timeout_ops_reject_realtime_clock_flag() {
        assert!(futex_pi_non_timeout_flags_valid(FUTEX_TRYLOCK_PI));
        assert!(futex_pi_non_timeout_flags_valid(FUTEX_UNLOCK_PI));
        assert!(!futex_pi_non_timeout_flags_valid(FUTEX_TRYLOCK_PI | FUTEX_CLOCK_REALTIME));
        assert!(!futex_pi_non_timeout_flags_valid(FUTEX_UNLOCK_PI | FUTEX_CLOCK_REALTIME));
    }

    #[test]
    fn wait_nfds_honors_rlimit_nofile_boundary() {
        assert!(wait_nfds_within_rlimit(0, 0));
        assert!(wait_nfds_within_rlimit(1024, 1024));
        assert!(!wait_nfds_within_rlimit(1025, 1024));
    }

    #[test]
    fn pselect6_nfds_honors_rlimit_before_user_fdsets() {
        assert_eq!(validate_pselect6_nfds(16, 16), Ok(16));
        assert_eq!(validate_pselect6_nfds(17, 16), Err(vmos_abi::ERR_EINVAL));
        assert_eq!(
            validate_pselect6_nfds((PSELECT6_MAX_FDS + 1) as u64, u64::MAX),
            Err(vmos_abi::ERR_EINVAL)
        );
    }

    #[test]
    fn iovcnt_validation_matches_linux_iov_max() {
        assert_eq!(validate_iovcnt(0), Ok(0));
        assert_eq!(validate_iovcnt(super::LINUX_IOV_MAX as u64), Ok(super::LINUX_IOV_MAX));
        assert_eq!(validate_iovcnt(super::LINUX_IOV_MAX as u64 + 1), Err(vmos_abi::ERR_EINVAL));
        assert_eq!(validate_iovcnt(u64::MAX), Err(vmos_abi::ERR_EINVAL));
    }

    #[test]
    fn preadv_offset_reconstructs_split_linux_offset() {
        assert_eq!(preadv_offset_from_split(0x89ab_cdef, 0x0123_4567), Ok(0x0123_4567_89ab_cdef));
        assert_eq!(preadv_offset_from_split(0xffff_ffff, 0x7fff_ffff), Ok(i64::MAX as usize));
        assert_eq!(preadv_offset_from_split(0, 0x8000_0000), Err(vmos_abi::ERR_EINVAL));
    }

    #[test]
    fn positioned_io_offset_rejects_negative_linux_offsets() {
        assert_eq!(positioned_io_offset(0), Ok(0));
        assert_eq!(positioned_io_offset(i64::MAX as u64), Ok(i64::MAX as usize));
        assert_eq!(positioned_io_offset(i64::MAX as u64 + 1), Err(vmos_abi::ERR_EINVAL));
        assert_eq!(positioned_io_offset(u64::MAX), Err(vmos_abi::ERR_EINVAL));
    }

    #[test]
    fn preadv2_offset_accepts_minus_one_as_current_offset() {
        assert_eq!(
            preadv2_offset_from_split(0xffff_ffff, 0xffff_ffff),
            Ok(VectoredIoOffset::Current)
        );
        assert_eq!(
            preadv2_offset_from_split(0x89ab_cdef, 0x0123_4567),
            Ok(VectoredIoOffset::Explicit(0x0123_4567_89ab_cdef))
        );
        assert_eq!(preadv2_offset_from_split(0, 0x8000_0000), Err(vmos_abi::ERR_EINVAL));
    }

    #[test]
    fn preadv2_flags_support_nowait_only() {
        assert_eq!(validate_preadv2_flags(0), Ok(()));
        assert_eq!(validate_preadv2_flags(0x0000_0008), Ok(()));
        assert_eq!(preadv2_flags_nowait(0), Ok(false));
        assert_eq!(preadv2_flags_nowait(0x0000_0008), Ok(true));
        assert_eq!(validate_preadv2_flags(0x0000_0001), Err(vmos_abi::ERR_EOPNOTSUPP));
        assert_eq!(validate_preadv2_flags(0x0000_0010), Err(vmos_abi::ERR_EOPNOTSUPP));
    }

    #[test]
    fn pwritev2_flags_support_nowait_and_append_only() {
        assert_eq!(validate_pwritev2_flags(0), Ok(()));
        assert_eq!(validate_pwritev2_flags(0x0000_0008), Ok(()));
        assert_eq!(validate_pwritev2_flags(0x0000_0010), Ok(()));
        assert_eq!(validate_pwritev2_flags(0x0000_0018), Ok(()));
        assert_eq!(pwritev2_flags_append(0), Ok(false));
        assert_eq!(pwritev2_flags_append(0x0000_0018), Ok(true));
        assert_eq!(validate_pwritev2_flags(0x0000_0001), Err(vmos_abi::ERR_EOPNOTSUPP));
        assert_eq!(validate_pwritev2_flags(0x0000_0040), Err(vmos_abi::ERR_EOPNOTSUPP));
    }

    #[test]
    fn select_timeval_ms_validates_and_rounds_up() {
        assert_eq!(select_timeval_ms(0, 0), Ok(0));
        assert_eq!(select_timeval_ms(0, 1), Ok(1));
        assert_eq!(select_timeval_ms(1, 999_001), Ok(2000));
        assert_eq!(select_timeval_ms(-1, 0), Err(vmos_abi::ERR_EINVAL));
        assert_eq!(select_timeval_ms(0, -1), Err(vmos_abi::ERR_EINVAL));
        assert_eq!(select_timeval_ms(0, 1_000_000), Err(vmos_abi::ERR_EINVAL));
    }

    #[test]
    fn select_remaining_timeout_tracks_elapsed_ms() {
        assert_eq!(select_remaining_timeout_ms(100, 1_000_000, 1_000_000), 100);
        assert_eq!(select_remaining_timeout_ms(100, 1_000_000, 1_000_001), 99);
        assert_eq!(select_remaining_timeout_ms(100, 1_000_000, 51_000_000), 50);
        assert_eq!(select_remaining_timeout_ms(100, 1_000_000, 102_000_000), 0);
    }

    #[test]
    fn select_timeval_bytes_uses_linux_x86_64_layout() {
        let bytes = select_timeval_bytes(12_345);
        assert_eq!(i64::from_le_bytes(bytes[..8].try_into().unwrap()), 12);
        assert_eq!(i64::from_le_bytes(bytes[8..16].try_into().unwrap()), 345_000);
    }

    #[test]
    fn pselect_ready_sets_treat_hup_and_err_as_read_write_ready() {
        const POLLIN: u16 = 0x001;
        const POLLOUT: u16 = 0x004;
        const POLLERR: u16 = 0x008;
        const POLLHUP: u16 = 0x010;

        assert!(pselect_read_revents_ready(POLLIN));
        assert!(pselect_read_revents_ready(POLLHUP));
        assert!(pselect_read_revents_ready(POLLERR));
        assert!(!pselect_read_revents_ready(POLLOUT));

        assert!(pselect_write_revents_ready(POLLOUT));
        assert!(pselect_write_revents_ready(POLLHUP));
        assert!(pselect_write_revents_ready(POLLERR));
        assert!(!pselect_write_revents_ready(POLLIN));
    }

    #[test]
    fn signal_return_rflags_clears_control_bits() {
        let tf = 1 << 8;
        let iopl = 0x3000;
        let nt = 1 << 14;
        let rf = 1 << 16;
        let vm = 1 << 17;
        let high_reserved = 1 << 63;

        let restored = sanitize_restored_rflags(tf | iopl | nt | rf | vm | high_reserved);

        assert_eq!(restored & 0x202, 0x202);
        assert_eq!(restored & (tf | iopl | nt | rf | vm | high_reserved), 0);
    }

    #[test]
    fn signal_return_rflags_preserves_bounded_user_flags() {
        let user_flags = 0x0024_0cd5;
        let restored = sanitize_restored_rflags(user_flags);

        assert_eq!(restored & user_flags, user_flags);
        assert_eq!(restored & 0x202, 0x202);
    }

    #[test]
    fn signal_ucontext_keeps_syscall_clobbered_regs_separate_from_rip_and_rflags() {
        let saved = UserReturnContext {
            frame: SyscallFrame {
                r9: 0x91,
                r8: 0x81,
                r10: 0x10,
                rdx: 0x22,
                rsi: 0x33,
                rdi: 0x44,
                rax: 0x55,
                rcx: 0x4000_1234,
                r11: 0x202,
            },
            rsp: 0x7fff_0000,
            fs_base: 0x7000_0000,
            user_rcx: 0xaaaa_bbbb_cccc_dddd,
            user_r11: 0x1111_2222_3333_4444,
        };

        let mut encoded = encode_linux_ucontext(&saved, 0x55, SignalAltStack::disabled(), 0x8000);

        assert_eq!(read_linux_greg(&encoded, LINUX_GREG_RIP), Ok(saved.frame.rcx));
        assert_eq!(read_linux_greg(&encoded, LINUX_GREG_RCX), Ok(saved.user_rcx));
        assert_eq!(read_linux_greg(&encoded, LINUX_GREG_EFL), Ok(saved.frame.r11));
        assert_eq!(read_linux_greg(&encoded, LINUX_GREG_R11), Ok(saved.user_r11));

        write_linux_greg(&mut encoded, LINUX_GREG_RIP, 0x4000_5678);
        write_linux_greg(&mut encoded, LINUX_GREG_RSP, 0x7fff_1000);
        write_linux_greg(&mut encoded, LINUX_GREG_RCX, 0x1234_5678_9abc_def0);
        write_linux_greg(&mut encoded, LINUX_GREG_R11, 0xfedc_ba98_7654_3210);
        write_linux_greg(&mut encoded, LINUX_GREG_EFL, 0x8000_0000_0003_ffff);

        let restored = decode_linux_ucontext_return(&encoded, saved.fs_base).unwrap();
        assert_eq!(restored.frame.rcx, 0x4000_5678);
        assert_eq!(restored.rsp, 0x7fff_1000);
        assert_eq!(restored.user_rcx, 0x1234_5678_9abc_def0);
        assert_eq!(restored.user_r11, 0xfedc_ba98_7654_3210);
        assert_eq!(restored.frame.r11, sanitize_restored_rflags(0x8000_0000_0003_ffff));
    }

    #[test]
    fn clone3_parser_maps_v0_args_to_legacy_clone_request() {
        let mut bytes = [0u8; 64];
        write_u64_at(&mut bytes, 16, 0x1000);
        write_u64_at(&mut bytes, 24, 0x2000);
        write_u64_at(&mut bytes, 32, 17);
        write_u64_at(&mut bytes, 40, 0x7000_0000);
        write_u64_at(&mut bytes, 48, 0x4000);
        write_u64_at(&mut bytes, 56, 0x1234_5000);

        assert_eq!(
            parse_clone3_request_bytes(&bytes, 64),
            Ok(CloneRequest {
                flags: 17,
                stack: 0x7000_4000,
                parent_tid_ptr: 0x2000,
                child_tid_ptr: 0x1000,
                tls_base: 0x1234_5000,
            })
        );
    }

    #[test]
    fn clone3_parser_rejects_signal_bits_in_flags() {
        let mut bytes = [0u8; 64];
        write_u64_at(&mut bytes, 0, 17);

        assert_eq!(parse_clone3_request_bytes(&bytes, 64), Err(vmos_abi::ERR_EINVAL));
    }

    #[test]
    fn clone3_parser_rejects_unsupported_extension_fields() {
        let mut bytes = [0u8; 80];
        write_u64_at(&mut bytes, 72, 1);

        assert_eq!(parse_clone3_request_bytes(&bytes, 80), Err(vmos_abi::ERR_ENOSYS));
    }
}

fn handle_exit_syscall(frame: &mut SyscallFrame, status: i32) -> Result<i64, i32> {
    let pid = complete_current_process_exit(status);
    if let Some(return_context) = restore_suspended_parent_after_child_exit(pid) {
        ring3::install_user_return(frame, return_context);
        return Ok(return_context.frame.rax as i64);
    }
    finish_active_activation();
    finish_exited_runtime(status)
}

fn handle_exit(status: i32) -> ! {
    let pid = complete_current_process_exit(status);
    finish_active_activation();
    if let Some(return_context) = restore_suspended_parent_after_child_exit(pid) {
        ring3::resume_user_return(return_context);
    }
    finish_exited_runtime(status)
}

fn complete_current_process_exit(status: i32) -> u32 {
    let pid = active_context().pid;
    handle_robust_list_on_exit();
    clear_child_tid_on_exit();
    active_context().supervisor.process_exit(pid, status);
    pid
}

fn restore_suspended_parent_after_child_exit(child_pid: u32) -> Option<UserReturnContext> {
    if let Some(parent) = active_context().take_vfork_parent_for_child(child_pid) {
        let return_context = parent.return_context;
        active_context().restore_vfork_parent(parent);
        let parent_task_id = active_context().task_id;
        active_context().supervisor.mark_task_runnable(parent_task_id);
        active_context().supervisor.set_current_task(parent_task_id);
        return Some(return_context);
    }
    if let Some(mut parent) = active_context().take_clone_parent_for_child(child_pid) {
        let return_context = parent.return_context;
        if parent.address_space.is_some() {
            restore_independent_clone_parent_address_space(&mut parent).ok()?;
        }
        active_context().restore_clone_parent(parent);
        let parent_task_id = active_context().task_id;
        active_context().supervisor.mark_task_runnable(parent_task_id);
        active_context().supervisor.set_current_task(parent_task_id);
        return Some(return_context);
    }
    None
}

fn handle_robust_list_on_exit() {
    let tid = active_context().tid;
    let Some(registration) = active_context().supervisor.take_thread_robust_list(tid) else {
        return;
    };
    if registration.head == 0 {
        return;
    }
    if registration.len != ROBUST_LIST_HEAD_SIZE {
        crate::kwarn!("robust_list ignored unexpected len {}", registration.len);
        return;
    }
    let futex_offset = match robust_head_field(registration.head, 8).and_then(read_user_i64) {
        Ok(offset) => offset,
        Err(errno) => {
            crate::kwarn!("robust_list futex_offset read failed: errno {}", errno);
            return;
        }
    };
    let pending = match robust_head_field(registration.head, 16).and_then(read_user_u64) {
        Ok(ptr) => ptr,
        Err(errno) => {
            crate::kwarn!("robust_list pending read failed: errno {}", errno);
            return;
        }
    };
    let mut entry = match read_user_u64(registration.head) {
        Ok(ptr) => ptr,
        Err(errno) => {
            crate::kwarn!("robust_list head read failed: errno {}", errno);
            return;
        }
    };

    let mut visited = 0usize;
    while entry != 0 && entry != registration.head && visited < ROBUST_LIST_LIMIT {
        let next = match read_user_u64(entry) {
            Ok(ptr) => ptr,
            Err(errno) => {
                crate::kwarn!("robust_list entry read failed: errno {}", errno);
                break;
            }
        };
        process_robust_list_entry(entry, futex_offset, tid);
        entry = next;
        visited += 1;
    }
    if visited == ROBUST_LIST_LIMIT {
        crate::kwarn!("robust_list traversal hit entry limit");
    }
    if pending != 0 && pending != registration.head {
        process_robust_list_entry(pending, futex_offset, tid);
    }
}

fn robust_head_field(head: u64, offset: u64) -> Result<u64, i32> {
    head.checked_add(offset).ok_or(ERR_EFAULT)
}

fn process_robust_list_entry(entry: u64, futex_offset: i64, tid: u32) {
    let Some(futex_addr) = robust_futex_addr(entry, futex_offset) else {
        crate::kwarn!("robust_list futex address overflow");
        return;
    };
    mark_robust_futex_dead(futex_addr, tid);
}

fn robust_futex_addr(entry: u64, futex_offset: i64) -> Option<u64> {
    if futex_offset >= 0 {
        entry.checked_add(futex_offset as u64)
    } else {
        entry.checked_sub(futex_offset.wrapping_neg() as u64)
    }
}

fn mark_robust_futex_dead(futex_addr: u64, tid: u32) {
    let word = match read_user_u32(futex_addr) {
        Ok(word) => word,
        Err(errno) => {
            crate::kwarn!("robust_list futex read failed: errno {}", errno);
            return;
        }
    };
    if (word & FUTEX_TID_MASK) != (tid & FUTEX_TID_MASK) {
        return;
    }
    let new_word = (word & !FUTEX_TID_MASK) | FUTEX_OWNER_DIED;
    if let Err(errno) = write_user_u32(futex_addr, new_word) {
        crate::kwarn!("robust_list futex write failed: errno {}", errno);
        return;
    }
    if word & FUTEX_WAITERS == 0 {
        return;
    }
    let wake_result = active_context().supervisor.dispatch_linux_syscall(
        "ring3_robust_list_futex_wake",
        SyscallContext::new(SYS_FUTEX, [futex_addr, FUTEX_WAKE as u64, 1, 0, 0, 0]),
    );
    if wake_result.is_err() {
        crate::kwarn!("robust_list futex wake failed");
    }
}

fn clear_child_tid_on_exit() {
    let tid = active_context().tid;
    let Some(clear_child_tid) = active_context().supervisor.take_thread_clear_child_tid(tid) else {
        return;
    };
    if clear_child_tid == 0 {
        return;
    }
    if let Err(errno) = write_user_u32(clear_child_tid, 0) {
        crate::kwarn!("clear_child_tid write failed: errno {}", errno);
        return;
    }
    let wake_result = active_context().supervisor.dispatch_linux_syscall(
        "ring3_clear_child_tid",
        SyscallContext::new(SYS_FUTEX, [clear_child_tid, FUTEX_WAKE as u64, 1, 0, 0, 0]),
    );
    if wake_result.is_err() {
        crate::kwarn!("clear_child_tid futex wake failed");
    }
}

fn finish_active_activation() {
    let activation_id = active_context().activation_id;
    if activation_id != 0 {
        crate::substrate::dmw::finish_activation(activation_id);
        active_context().finish_activation(activation_id);
    }
}

fn finish_exited_runtime(status: i32) -> ! {
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

fn current_parent_pid() -> u32 {
    let pid = active_context().pid;
    active_context().supervisor.query_process(pid).map(|process| process.ppid).unwrap_or(pid)
}

struct AccessSnapshot {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    cap_effective: u64,
}

impl AccessSnapshot {
    fn ids(&self) -> AccessIds<'_> {
        AccessIds::with_caps(self.uid, self.gid, &self.groups, self.cap_effective)
    }
}

fn real_access_snapshot() -> AccessSnapshot {
    let context = active_context();
    AccessSnapshot {
        uid: context.uid(),
        gid: context.gid(),
        groups: context.supplementary_groups().to_vec(),
        cap_effective: if context.uid() == 0 { context.cap_permitted() } else { 0 },
    }
}

fn effective_access_snapshot() -> AccessSnapshot {
    let context = active_context();
    AccessSnapshot {
        uid: context.fsuid(),
        gid: context.fsgid(),
        groups: context.supplementary_groups().to_vec(),
        cap_effective: context.cap_effective(),
    }
}

fn record_credential_transition(kind: CredentialTransitionKind) -> Result<(), i32> {
    let (pid, state) = {
        let context = active_context();
        (context.pid, context.credential_state())
    };
    if active_context().supervisor.record_credential_transition(
        pid,
        state.uid,
        state.euid,
        state.suid,
        state.fsuid,
        state.gid,
        state.egid,
        state.sgid,
        state.fsgid,
        state.supplementary_groups,
        LinuxCapSets {
            bounding: state.cap_bounding,
            inheritable: state.cap_inheritable,
            permitted: state.cap_permitted,
            effective: state.cap_effective,
            ambient: state.cap_ambient,
            securebits: state.securebits,
        },
        kind,
    ) {
        Ok(())
    } else {
        Err(ERR_EINVAL)
    }
}

fn restore_credential_state(state: CredentialState) {
    active_context().restore_credential_state(state);
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
    ensure_active_user_pages_present(ptr, len)?;
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

fn read_flock(ptr: u64) -> Result<(i16, i16, i64, i64), i32> {
    let bytes = read_user_bytes(ptr, 32)?;
    let lock_type = i16::from_le_bytes(bytes[0..2].try_into().map_err(|_| ERR_EINVAL)?);
    let whence = i16::from_le_bytes(bytes[2..4].try_into().map_err(|_| ERR_EINVAL)?);
    let start = i64::from_le_bytes(bytes[8..16].try_into().map_err(|_| ERR_EINVAL)?);
    let len = i64::from_le_bytes(bytes[16..24].try_into().map_err(|_| ERR_EINVAL)?);
    Ok((lock_type, whence, start, len))
}

fn write_flock(
    ptr: u64,
    lock_type: i16,
    whence: i16,
    start: i64,
    len: i64,
    pid: u32,
) -> Result<(), i32> {
    let mut encoded = [0u8; 32];
    encoded[0..2].copy_from_slice(&lock_type.to_le_bytes());
    encoded[2..4].copy_from_slice(&whence.to_le_bytes());
    encoded[8..16].copy_from_slice(&start.to_le_bytes());
    encoded[16..24].copy_from_slice(&len.to_le_bytes());
    encoded[24..28].copy_from_slice(&(pid as i32).to_le_bytes());
    write_user_bytes(ptr, &encoded)
}

fn write_flock_type(ptr: u64, lock_type: i16) -> Result<(), i32> {
    let mut bytes = read_user_bytes(ptr, 32)?;
    bytes[0..2].copy_from_slice(&lock_type.to_le_bytes());
    write_user_bytes(ptr, &bytes)
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

fn read_user_bytes(ptr: u64, len: usize) -> Result<Vec<u8>, i32> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let lease = user_lease(ptr, len as u64, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    Ok(bytes.to_vec())
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

fn read_exec_string_array(ptr: u64) -> Result<Vec<Vec<u8>>, i32> {
    if ptr == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut total_bytes = 0usize;
    for index in 0..EXEC_ARG_MAX_STRINGS {
        let offset = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(8))
            .and_then(|offset| ptr.checked_add(offset))
            .ok_or(ERR_EFAULT)?;
        let string_ptr = read_user_u64(offset)?;
        if string_ptr == 0 {
            return Ok(out);
        }
        let remaining = EXEC_ARG_MAX_BYTES.checked_sub(total_bytes).ok_or(ERR_E2BIG)?;
        if remaining == 0 {
            return Err(ERR_E2BIG);
        }
        let value = read_user_c_string(string_ptr, remaining)
            .map_err(|errno| if errno == ERR_ENAMETOOLONG { ERR_E2BIG } else { errno })?;
        total_bytes = total_bytes
            .checked_add(value.len())
            .and_then(|len| len.checked_add(1))
            .ok_or(ERR_E2BIG)?;
        if total_bytes > EXEC_ARG_MAX_BYTES {
            return Err(ERR_E2BIG);
        }
        out.push(value);
    }
    Err(ERR_E2BIG)
}

fn read_xattr_name(ptr: u64) -> Result<Vec<u8>, i32> {
    const XATTR_NAME_MAX: usize = 255;

    let name = read_user_c_string(ptr, XATTR_NAME_MAX + 1)?;
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(ERR_EINVAL);
    }
    Ok(name)
}

fn readable_user_chunk_len(ptr: u64, max_len: usize) -> Result<u64, i32> {
    let region = active_context()
        .regions
        .iter()
        .rev()
        .find(|region| ptr >= region.start && ptr < region.end)
        .ok_or(ERR_EFAULT)?;
    if !region.readable {
        return Err(ERR_EFAULT);
    }
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

fn read_user_i64(ptr: u64) -> Result<i64, i32> {
    let lease = user_lease(ptr, 8, false)?;
    let bytes = lease.bytes().map_err(map_dmw_fault)?;
    Ok(i64::from_le_bytes(bytes[..8].try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_u32_from(bytes: &[u8], offset: usize) -> Result<u32, i32> {
    Ok(u32::from_le_bytes(bytes[offset..offset + 4].try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_i32_from(bytes: &[u8], offset: usize) -> Result<i32, i32> {
    Ok(i32::from_le_bytes(bytes[offset..offset + 4].try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_i64_from(bytes: &[u8], offset: usize) -> Result<i64, i32> {
    Ok(i64::from_le_bytes(bytes[offset..offset + 8].try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_u64_from(bytes: &[u8], offset: usize) -> Result<u64, i32> {
    Ok(u64::from_le_bytes(bytes[offset..offset + 8].try_into().map_err(|_| ERR_EINVAL)?))
}

fn write_user_u32(ptr: u64, value: u32) -> Result<(), i32> {
    write_user_bytes(ptr, &value.to_le_bytes())
}

fn log_ignored_user_write(context: &'static str, result: Result<(), i32>) {
    if let Err(errno) = result {
        crate::kwarn!("{} failed with errno {}", context, errno);
    }
}

fn write_user_u64(ptr: u64, value: u64) -> Result<(), i32> {
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

fn write_i32(out: &mut [u8], offset: usize, value: i32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[derive(Clone, Copy)]
enum UserRangeAccess {
    Mapped,
    Read,
    Write,
}

fn validate_user_range(ptr: u64, len: u64, write: bool) -> Result<(), i32> {
    let access = if write { UserRangeAccess::Write } else { UserRangeAccess::Read };
    validate_user_range_access(ptr, len, access)
}

fn validate_mapped_user_range(ptr: u64, len: u64) -> Result<(), i32> {
    validate_user_range_access(ptr, len, UserRangeAccess::Mapped)
}

fn single_user_region_attributes(ptr: u64, len: u64) -> Option<(bool, bool, bool, bool, bool)> {
    let end = ptr.checked_add(len)?;
    let region = active_context()
        .regions
        .iter()
        .rev()
        .find(|region| ptr >= region.start && end <= region.end)?;
    Some((
        region.readable,
        region.writable,
        region.executable,
        region.dont_fork,
        region.wipe_on_fork,
    ))
}

fn replace_user_region_range_for_mremap(
    regions: &mut Vec<UserRegion>,
    start: u64,
    end: u64,
    replacement: Option<(bool, bool, bool, bool, bool)>,
) {
    if start >= end {
        return;
    }
    let mut updated = Vec::with_capacity(regions.len().saturating_add(1));
    for region in regions.drain(..) {
        if region.end <= start || region.start >= end {
            updated.push(region);
            continue;
        }
        if region.start < start {
            updated.push(UserRegion {
                start: region.start,
                end: start,
                readable: region.readable,
                writable: region.writable,
                executable: region.executable,
                dont_fork: region.dont_fork,
                wipe_on_fork: region.wipe_on_fork,
            });
        }
        if region.end > end {
            updated.push(UserRegion {
                start: end,
                end: region.end,
                readable: region.readable,
                writable: region.writable,
                executable: region.executable,
                dont_fork: region.dont_fork,
                wipe_on_fork: region.wipe_on_fork,
            });
        }
    }
    if let Some((readable, writable, executable, dont_fork, wipe_on_fork)) = replacement {
        updated.push(UserRegion {
            start,
            end,
            readable,
            writable,
            executable,
            dont_fork,
            wipe_on_fork,
        });
    }
    updated.sort_by_key(|region| (region.start, region.end));
    for region in updated {
        if region.start >= region.end {
            continue;
        }
        if let Some(last) = regions.last_mut()
            && last.readable == region.readable
            && last.writable == region.writable
            && last.executable == region.executable
            && last.dont_fork == region.dont_fork
            && last.wipe_on_fork == region.wipe_on_fork
            && last.end >= region.start
        {
            last.end = last.end.max(region.end);
            continue;
        }
        regions.push(region);
    }
}

fn has_duplicate_user_page_mapping(mappings: &[UserPageMapping]) -> bool {
    for (index, mapping) in mappings.iter().enumerate() {
        if mappings[index + 1..].iter().any(|other| other.va == mapping.va) {
            return true;
        }
    }
    false
}

fn subranges_total_len(ranges: &[(u64, u64)]) -> u64 {
    ranges.iter().map(|(start, end)| end.saturating_sub(*start)).sum()
}

fn ranges_overlap_for_mremap(
    left_start: u64,
    left_end: u64,
    right_start: u64,
    right_end: u64,
) -> bool {
    left_start < right_end && right_start < left_end
}

fn validate_reserved_user_page_range(ptr: u64, len: u64) -> Result<(), i32> {
    if len == 0 {
        return Ok(());
    }
    let end = ptr.checked_add(len).ok_or(ERR_EFAULT)?;
    if ptr & 4095 != 0 || end & 4095 != 0 {
        return Err(ERR_EINVAL);
    }
    if ptr < USER_BRK_BASE || end > USER_MMAP_END {
        return Err(ERR_EFAULT);
    }
    Ok(())
}

fn validate_user_range_access(ptr: u64, len: u64, access: UserRangeAccess) -> Result<(), i32> {
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
        match access {
            UserRangeAccess::Mapped => {}
            UserRangeAccess::Read if !region.readable => return Err(ERR_EFAULT),
            UserRangeAccess::Write if !region.writable => return Err(ERR_EFAULT),
            UserRangeAccess::Read | UserRangeAccess::Write => {}
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

fn validate_lower_user_address_range(ptr: u64, len: u64) -> Result<(), i32> {
    if len == 0 {
        return Ok(());
    }
    let end = ptr.checked_add(len).ok_or(ERR_EINVAL)?;
    if ptr >= X86_64_USER_CANONICAL_LIMIT || end > X86_64_USER_CANONICAL_LIMIT {
        return Err(ERR_EINVAL);
    }
    Ok(())
}

fn protect_active_user_page_range(start: u64, len: u64, prot: u64) -> Result<(), i32> {
    let context = active_context();
    let cow_pages = if prot & PROT_WRITE != 0 {
        let end = start.checked_add(len).ok_or(ERR_EFAULT)?;
        context
            .page_mappings
            .iter()
            .filter(|mapping| mapping.cow && mapping.va >= start && mapping.va < end)
            .map(|mapping| mapping.va)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    protect_user_page_range(
        context.physical_memory_offset(),
        &mut context.page_mappings,
        &mut context.frame_allocator,
        start,
        len,
        prot,
    )
    .map_err(|_| ERR_EFAULT)?;

    for page in cow_pages {
        if context.page_mappings.iter().any(|mapping| mapping.va == page && !mapping.cow) {
            context.supervisor.record_guest_memory_cow_break(page);
        }
    }
    Ok(())
}

fn unmap_active_user_page_range(start: u64, len: u64) -> Result<(), i32> {
    let file_shared = active_file_shared_page_mappings_in_range(start, len);
    sync_file_shared_page_mappings(&file_shared)?;
    let context = active_context();
    unmap_user_page_range(
        context.physical_memory_offset(),
        &mut context.page_mappings,
        &mut context.frame_allocator,
        start,
        len,
    )
    .map_err(|_| ERR_EFAULT)?;
    release_file_shared_page_refs(&file_shared);
    Ok(())
}

fn discard_active_user_page_range(start: u64, len: u64) -> Result<(), i32> {
    let context = active_context();
    discard_user_page_range(
        context.physical_memory_offset(),
        &mut context.page_mappings,
        &mut context.frame_allocator,
        start,
        len,
    )
    .map_err(|err| {
        if err == "user page range has non-discardable backing" {
            vmos_abi::ERR_EOPNOTSUPP
        } else {
            ERR_EFAULT
        }
    })
}

fn discard_active_zero_user_page_range(start: u64, len: u64) -> Result<(), i32> {
    let context = active_context();
    discard_zero_user_page_range(
        context.physical_memory_offset(),
        &mut context.page_mappings,
        &mut context.frame_allocator,
        start,
        len,
    )
    .map_err(|err| {
        if err == "user page range has non-zero-fill backing" { ERR_EINVAL } else { ERR_EFAULT }
    })
}

fn set_active_user_region_dofork(start: u64, len: u64) {
    let Some(end) = start.checked_add(len) else {
        return;
    };
    for (range_start, range_end, wipe_on_fork) in active_context()
        .regions
        .iter()
        .filter_map(|region| {
            let range_start = region.start.max(start);
            let range_end = region.end.min(end);
            (range_start < range_end).then_some((range_start, range_end, region.wipe_on_fork))
        })
        .collect::<Vec<_>>()
    {
        active_context().set_user_region_fork_advice(
            range_start,
            range_end - range_start,
            false,
            wipe_on_fork,
        );
    }
}

fn set_active_user_region_keeponfork(start: u64, len: u64) {
    let Some(end) = start.checked_add(len) else {
        return;
    };
    for (range_start, range_end, dont_fork) in active_context()
        .regions
        .iter()
        .filter_map(|region| {
            let range_start = region.start.max(start);
            let range_end = region.end.min(end);
            (range_start < range_end).then_some((range_start, range_end, region.dont_fork))
        })
        .collect::<Vec<_>>()
    {
        active_context().set_user_region_fork_advice(
            range_start,
            range_end - range_start,
            dont_fork,
            false,
        );
    }
}

fn validate_active_user_page_range_zero_backing(start: u64, len: u64) -> Result<(), i32> {
    let end = start.checked_add(len).ok_or(ERR_EFAULT)?;
    for mapping in active_context()
        .page_mappings
        .iter()
        .filter(|mapping| mapping.va >= start && mapping.va < end)
    {
        if !matches!(&mapping.backing, UserPageBacking::ZeroFill) {
            return Err(ERR_EINVAL);
        }
    }
    Ok(())
}

fn validate_active_user_page_range_dontunmap_backing(start: u64, len: u64) -> Result<(), i32> {
    let end = start.checked_add(len).ok_or(ERR_EFAULT)?;
    for mapping in active_context()
        .page_mappings
        .iter()
        .filter(|mapping| mapping.va >= start && mapping.va < end)
    {
        if !matches!(&mapping.backing, UserPageBacking::ZeroFill | UserPageBacking::FilePrivate(_))
        {
            return Err(ERR_EINVAL);
        }
    }
    Ok(())
}

fn validate_active_user_page_range_file_shared(start: u64, len: u64) -> Result<(), i32> {
    let end = start.checked_add(len).ok_or(ERR_EFAULT)?;
    let mut page = start;
    while page < end {
        let mapping = active_context()
            .page_mappings
            .iter()
            .find(|mapping| mapping.va == page)
            .ok_or(ERR_EINVAL)?;
        if !matches!(&mapping.backing, UserPageBacking::FileShared { .. }) {
            return Err(ERR_EINVAL);
        }
        page = page.checked_add(4096).ok_or(ERR_EFAULT)?;
    }
    Ok(())
}

fn prefault_active_user_page_range(start: u64, len: u64, write: bool) -> Result<(), i32> {
    let raw_end = start.checked_add(len).ok_or(ERR_EFAULT)?;
    let end = align_page(raw_end).ok_or(ERR_EFAULT)?;
    let mut page = start;
    while page < end {
        let prot = user_page_region_prot(page).ok_or(ERR_EFAULT)?;
        prefault_active_user_page(page, prot, write)?;
        page = page.checked_add(4096).ok_or(ERR_EFAULT)?;
    }
    Ok(())
}

fn prefault_active_user_page(page: u64, prot: u64, write: bool) -> Result<(), i32> {
    let context = active_context();
    let cow_pages = if write {
        context
            .page_mappings
            .iter()
            .filter(|mapping| mapping.cow && mapping.va == page)
            .map(|mapping| mapping.va)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    prefault_user_page_range(
        context.physical_memory_offset(),
        &mut context.page_mappings,
        &mut context.frame_allocator,
        page,
        4096,
        prot,
        write,
    )
    .map_err(|_| ERR_EFAULT)?;

    for page in cow_pages {
        if context.page_mappings.iter().any(|mapping| mapping.va == page && !mapping.cow) {
            context.supervisor.record_guest_memory_cow_break(page);
        }
    }
    Ok(())
}

fn populate_active_user_page_range(start: u64, bytes: &[u8]) -> Result<(), i32> {
    let context = active_context();
    populate_user_page_range(context.physical_memory_offset(), &context.page_mappings, start, bytes)
        .map_err(|_| ERR_EFAULT)
}

fn mark_active_user_page_range_file_private(start: u64, len: u64, bytes: &[u8]) {
    let Some(end) = start.checked_add(len) else {
        return;
    };
    for mapping in &mut active_context().page_mappings {
        if mapping.va >= start && mapping.va < end {
            let copied = (mapping.va - start) as usize;
            let mut page_bytes = vec![0u8; 4096];
            if copied < bytes.len() {
                let copy_len = core::cmp::min(4096, bytes.len() - copied);
                page_bytes[..copy_len].copy_from_slice(&bytes[copied..copied + copy_len]);
            }
            mapping.backing = UserPageBacking::FilePrivate(page_bytes);
        }
    }
}

fn mark_active_user_page_range_file_shared(
    start: u64,
    len: u64,
    bytes: &[u8],
    vfs_node_id: u64,
    path: &[u8],
    file_offset: usize,
) {
    let Some(end) = start.checked_add(len) else {
        return;
    };
    for mapping in &mut active_context().page_mappings {
        if mapping.va >= start && mapping.va < end {
            let copied = (mapping.va - start) as usize;
            let mut page_bytes = vec![0u8; 4096];
            if copied < bytes.len() {
                let copy_len = core::cmp::min(4096, bytes.len() - copied);
                page_bytes[..copy_len].copy_from_slice(&bytes[copied..copied + copy_len]);
            }
            mapping.backing = UserPageBacking::FileShared {
                vfs_node_id,
                path: path.to_vec(),
                offset: file_offset.saturating_add(copied),
                bytes: page_bytes,
            };
        }
    }
}

fn active_file_shared_page_mappings_in_range(start: u64, len: u64) -> Vec<UserPageMapping> {
    let Some(end) = start.checked_add(len) else {
        return Vec::new();
    };
    active_context()
        .page_mappings
        .iter()
        .filter(|mapping| mapping.va >= start && mapping.va < end)
        .filter(|mapping| matches!(mapping.backing, UserPageBacking::FileShared { .. }))
        .cloned()
        .collect()
}

fn retain_active_file_shared_page_refs(start: u64, len: u64) {
    let mappings = active_file_shared_page_mappings_in_range(start, len);
    retain_file_shared_page_refs(&mappings);
}

fn retain_file_shared_page_refs(mappings: &[UserPageMapping]) {
    for mapping in mappings {
        if let UserPageBacking::FileShared { vfs_node_id, .. } = &mapping.backing {
            active_context().supervisor.retain_shared_mmap_inode(*vfs_node_id);
        }
    }
}

fn release_file_shared_page_refs(mappings: &[UserPageMapping]) {
    for mapping in mappings {
        if let UserPageBacking::FileShared { vfs_node_id, .. } = &mapping.backing {
            active_context().supervisor.release_shared_mmap_inode(*vfs_node_id);
        }
    }
}

fn sync_active_file_shared_page_range(start: u64, len: u64) -> Result<(), i32> {
    let mappings = active_file_shared_page_mappings_in_range(start, len);
    sync_file_shared_page_mappings(&mappings)?;
    let mut synced_pages = Vec::new();
    for mapping in mappings {
        if let Some(bytes) = file_shared_page_bytes(&mapping)? {
            synced_pages.push((mapping.va, bytes));
        }
    }
    for (va, bytes) in synced_pages {
        if let Some(mapping) = active_context().page_mappings.iter_mut().find(|mapping| {
            mapping.va == va && matches!(mapping.backing, UserPageBacking::FileShared { .. })
        }) && let UserPageBacking::FileShared { bytes: backing_bytes, .. } = &mut mapping.backing
        {
            *backing_bytes = bytes;
        }
    }
    Ok(())
}

fn sync_file_shared_page_mappings(mappings: &[UserPageMapping]) -> Result<(), i32> {
    for mapping in mappings {
        let UserPageBacking::FileShared { vfs_node_id, path, offset, .. } = &mapping.backing else {
            continue;
        };
        let Some(bytes) = file_shared_page_bytes(mapping)? else {
            continue;
        };
        active_context().supervisor.write_shared_mmap_vfs_page(
            *vfs_node_id,
            path,
            *offset,
            &bytes,
        )?;
    }
    Ok(())
}

struct FileSharedPageTarget {
    va: u64,
    frame_start: u64,
    vfs_node_id: u64,
    path: Vec<u8>,
    offset: usize,
}

fn remove_active_file_shared_page_range(start: u64, len: u64) -> Result<(), i32> {
    validate_user_range_access(start, len, UserRangeAccess::Write)?;
    let end = start.checked_add(len).ok_or(ERR_EINVAL)?;
    let mut targets = Vec::new();
    for page in (start..end).step_by(4096) {
        let mapping = active_context()
            .page_mappings
            .iter()
            .find(|mapping| mapping.va == page)
            .ok_or(ERR_EINVAL)?;
        let UserPageBacking::FileShared { vfs_node_id, path, offset, .. } = &mapping.backing else {
            return Err(ERR_EINVAL);
        };
        targets.push(FileSharedPageTarget {
            va: mapping.va,
            frame_start: mapping.frame_start,
            vfs_node_id: *vfs_node_id,
            path: path.clone(),
            offset: *offset,
        });
    }

    for target in &targets {
        active_context().supervisor.remove_shared_mmap_vfs_range(
            target.vfs_node_id,
            &target.path,
            target.offset,
            4096,
        )?;
    }

    let physical_memory_offset = active_context().physical_memory_offset();
    for target in targets {
        fill_user_page_frame(physical_memory_offset, target.frame_start, 0)
            .map_err(|_| ERR_EFAULT)?;
        if let Some(mapping) =
            active_context().page_mappings.iter_mut().find(|mapping| mapping.va == target.va)
            && let UserPageBacking::FileShared { bytes, .. } = &mut mapping.backing
        {
            bytes.clear();
            bytes.resize(4096, 0);
        }
    }
    Ok(())
}

fn file_shared_page_bytes(mapping: &UserPageMapping) -> Result<Option<Vec<u8>>, i32> {
    let UserPageBacking::FileShared { bytes, .. } = &mapping.backing else {
        return Ok(None);
    };
    let mut page_bytes = bytes.clone();
    if page_bytes.len() < 4096 {
        page_bytes.resize(4096, 0);
    }
    if mapping.frame_start != 0 {
        copy_user_page_bytes(active_context().physical_memory_offset(), mapping, &mut page_bytes)
            .map_err(|_| ERR_EFAULT)?;
    }
    Ok(Some(page_bytes))
}

fn clone_active_user_address_space() -> Result<UserAddressSpaceState, i32> {
    let context = active_context();
    let child_allocator = context.frame_allocator.fork_child_allocator();
    let regions =
        context.regions.iter().copied().filter(|region| !region.dont_fork).collect::<Vec<_>>();
    let forked_source_mappings = context
        .page_mappings
        .iter()
        .filter(|mapping| {
            child_region_for_page(&regions, mapping.va).is_some_and(|region| !region.wipe_on_fork)
        })
        .cloned()
        .collect::<Vec<_>>();
    let page_mappings =
        clone_user_page_mappings(&forked_source_mappings).map_err(|_| ERR_ENOMEM)?;
    Ok(UserAddressSpaceState { regions, page_mappings, frame_allocator: child_allocator })
}

fn child_region_for_page(regions: &[UserRegion], page: u64) -> Option<&UserRegion> {
    regions.iter().rev().find(|region| {
        page >= region.start
            && page < region.end
            && (region.readable || region.writable || region.executable)
    })
}

fn switch_active_user_address_space_to_child(
    child_address_space: &mut UserAddressSpaceState,
) -> Result<(), i32> {
    let context = active_context();
    let current_mappings = context.page_mappings.clone();
    let current_regions = context.regions.clone();
    switch_user_page_mappings(
        context.physical_memory_offset(),
        &current_mappings,
        &current_regions,
        &child_address_space.page_mappings,
        &child_address_space.regions,
        &mut child_address_space.frame_allocator,
        false,
    )
    .map_err(|_| ERR_EFAULT)
}

fn restore_independent_clone_parent_address_space(
    parent: &mut crate::frontends::linux_elf::context::SuspendedCloneParent,
) -> Result<(), i32> {
    let Some(parent_address_space) = parent.address_space.as_mut() else {
        return Ok(());
    };
    let context = active_context();
    let child_mappings = context.page_mappings.clone();
    let child_regions = context.regions.clone();
    sync_file_shared_page_mappings(&child_mappings)?;
    switch_user_page_mappings(
        context.physical_memory_offset(),
        &child_mappings,
        &child_regions,
        &parent_address_space.page_mappings,
        &parent_address_space.regions,
        &mut context.frame_allocator,
        true,
    )
    .map_err(|_| ERR_EFAULT)?;
    release_file_shared_page_refs(&child_mappings);
    Ok(())
}

fn cow_break_active_user_page(page: u64, prot: u64) -> Result<(), i32> {
    let context = active_context();
    cow_break_user_page(
        context.physical_memory_offset(),
        &mut context.page_mappings,
        &mut context.frame_allocator,
        page,
        prot,
    )
    .map_err(|_| ERR_EFAULT)?;
    context.supervisor.record_guest_memory_cow_break(page);
    Ok(())
}

fn ensure_active_user_pages_present(ptr: u64, len: u64) -> Result<(), i32> {
    if len == 0 {
        return Ok(());
    }
    let raw_end = ptr.checked_add(len).ok_or(ERR_EFAULT)?;
    let start = ptr & !4095;
    let end = align_page(raw_end).ok_or(ERR_EFAULT)?;
    let mut page = start;
    while page < end {
        let prot = user_page_region_prot(page).ok_or(ERR_EFAULT)?;
        protect_active_user_page_range(page, 4096, prot)?;
        page = page.checked_add(4096).ok_or(ERR_EFAULT)?;
    }
    Ok(())
}

fn user_page_region_prot(page: u64) -> Option<u64> {
    let region = active_context().regions.iter().rev().find(|region| {
        page >= region.start
            && page < region.end
            && (region.readable || region.writable || region.executable)
    })?;
    let mut prot = 0;
    if region.readable || region.writable {
        prot |= PROT_READ;
    }
    if region.writable {
        prot |= PROT_WRITE;
    }
    if region.executable {
        prot |= PROT_EXEC;
    }
    Some(prot)
}

pub(crate) fn try_handle_user_page_fault(
    fault_va: u64,
    write: bool,
    instruction_fetch: bool,
    protection: bool,
) -> bool {
    let Some(context) = try_active_context() else {
        return false;
    };
    let page = fault_va & !4095;
    let Some(region) = context.regions.iter().rev().find(|region| {
        fault_va >= region.start
            && fault_va < region.end
            && (region.readable || region.writable || region.executable)
    }) else {
        return false;
    };
    if instruction_fetch && !region.executable {
        return false;
    }
    if write && !region.writable {
        return false;
    }
    if !write && !instruction_fetch && !region.readable {
        return false;
    }
    let mut prot = 0;
    if region.readable || region.writable {
        prot |= PROT_READ;
    }
    if region.writable {
        prot |= PROT_WRITE;
    }
    if region.executable {
        prot |= PROT_EXEC;
    }
    if protection {
        if !write || instruction_fetch {
            return false;
        }
        return cow_break_active_user_page(page, prot).is_ok();
    }
    protect_active_user_page_range(page, 4096, prot).is_ok()
}

fn prot_user_region_permissions(prot: u64) -> (bool, bool, bool) {
    let writable = prot & PROT_WRITE != 0;
    let readable = writable || prot & PROT_READ != 0;
    let executable = prot & PROT_EXEC != 0;
    (readable, writable, executable)
}

fn align_page(value: u64) -> Option<u64> {
    value.checked_add(4095).map(|value| value & !4095)
}

fn resolve_path(dirfd: i64, path: &[u8]) -> Result<Vec<u8>, i32> {
    if path.starts_with(b"/") {
        return Ok(resolve_absolute_path(path));
    }

    let base = if dirfd == AT_FDCWD {
        active_context().cwd().to_vec()
    } else if dirfd >= 0 {
        let base = active_context().supervisor.fd_path(dirfd as u32).map_err(|_| ERR_EBADF)?;
        if !path.is_empty()
            && active_context().supervisor.path_kind(&base)? != vmos_abi::NodeKind::Directory
        {
            return Err(ERR_ENOTDIR);
        }
        base
    } else {
        return Err(ERR_EBADF);
    };

    let mut resolved = base;
    if !resolved.ends_with(b"/") {
        resolved.push(b'/');
    }
    resolved.extend_from_slice(path);
    restrict_path_to_chroot(normalize_user_path(&resolved))
}

fn resolve_final_symlink_for_stat(path: Vec<u8>, follow: bool) -> Result<Vec<u8>, i32> {
    if !follow {
        return Ok(path);
    }
    if active_context().supervisor.path_kind(&path)? != vmos_abi::NodeKind::Symlink {
        return Ok(path);
    }
    let target = active_context().supervisor.read_link_path_bytes(&path)?;
    if target.starts_with(b"/") {
        return Ok(resolve_absolute_path(&target));
    }
    let mut base = parent_user_path(&path).unwrap_or_else(|| b"/".to_vec());
    if !base.ends_with(b"/") {
        base.push(b'/');
    }
    base.extend_from_slice(&target);
    restrict_path_to_chroot(normalize_user_path(&base))
}

fn resolve_absolute_path(path: &[u8]) -> Vec<u8> {
    let normalized = normalize_user_path(path);
    let root = active_context().root().to_vec();
    if root == b"/" {
        return normalized;
    }
    if normalized == b"/" {
        return root;
    }

    let mut resolved = root;
    if !resolved.ends_with(b"/") {
        resolved.push(b'/');
    }
    if let Some(rest) = normalized.strip_prefix(b"/") {
        resolved.extend_from_slice(rest);
    } else {
        resolved.extend_from_slice(&normalized);
    }
    normalize_user_path(&resolved)
}

fn restrict_path_to_chroot(path: Vec<u8>) -> Result<Vec<u8>, i32> {
    let root = active_context().root();
    if path_is_inside_root(&path, root) { Ok(path) } else { Err(ERR_EACCES) }
}

fn path_is_inside_root(path: &[u8], root: &[u8]) -> bool {
    root == b"/"
        || path == root
        || (path.len() > root.len() && path.starts_with(root) && path[root.len()] == b'/')
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

fn parent_user_path(path: &[u8]) -> Option<Vec<u8>> {
    if path == b"/" {
        return None;
    }
    let trimmed =
        if path.len() > 1 && path.ends_with(b"/") { &path[..path.len() - 1] } else { path };
    let slash = trimmed.iter().rposition(|byte| *byte == b'/')?;
    if slash == 0 { Some(b"/".to_vec()) } else { Some(trimmed[..slash].to_vec()) }
}

fn linux_fd_arg(raw: u64) -> i64 {
    (raw as i32) as i64
}

fn linux_pid_arg(raw: u64) -> Result<i32, i32> {
    let value = raw as i32;
    if raw == value as i64 as u64 { Ok(value) } else { Err(ERR_EINVAL) }
}

fn linux_owner_arg(raw: u64) -> Result<Option<u32>, i32> {
    if raw == u64::MAX || raw as u32 == u32::MAX { Ok(None) } else { linux_id_arg(raw).map(Some) }
}

fn linux_id_arg(raw: u64) -> Result<u32, i32> {
    u32::try_from(raw).map_err(|_| ERR_EINVAL)
}

fn optional_linux_id_arg(raw: u64) -> Result<Option<u32>, i32> {
    if raw == u64::MAX || raw as u32 == u32::MAX { Ok(None) } else { linux_id_arg(raw).map(Some) }
}

/// Called from the page fault handler when a user-space memory access
/// cannot be resolved. Exits the current process with the given signal.
pub(crate) fn handle_user_fault(signal: u8) -> ! {
    crate::kdebug!("user fault signal={signal}, exiting process");
    handle_exit(128 + signal as i32)
}

fn display_path(path: &[u8]) -> &str {
    core::str::from_utf8(path).unwrap_or("<non-utf8>")
}
