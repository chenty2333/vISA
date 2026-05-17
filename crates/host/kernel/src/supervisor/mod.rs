mod artifacts;
mod authority;
mod authority_rebind;
mod boundary;
mod demos;
mod engine;
mod events;
mod fault;
mod guest_memory;
mod linux;
mod linux_bpf;
mod linux_clock_dispatch;
mod linux_dispatch;
mod linux_epoll_dispatch;
mod linux_eventfd_dispatch;
mod linux_fd;
mod linux_fs_dispatch;
mod linux_memory_dispatch;
mod linux_pipe_dispatch;
mod linux_resource_dispatch;
mod linux_robust_dispatch;
mod linux_seccomp_dispatch;
mod linux_socket_dispatch;
mod linux_socketpair_dispatch;
mod linux_timerfd_dispatch;
mod linux_wait_dispatch;
mod net;
mod process;
mod pulse;
mod recovery;
mod runtime;
mod scheduler;
mod semantic;
mod services;
mod signal;
mod store;
mod store_manager;
pub(crate) mod types;
mod wait;

pub(crate) use linux::LinuxCallResult;
pub(crate) use runtime::{PrototypeRuntime, runtime};
pub(crate) use services::linux_user_resource_bytes_for_path;
pub(crate) use types::TaskId;

pub(crate) fn run() -> Result<(), &'static str> {
    runtime()?.run_prototype_demos()
}
