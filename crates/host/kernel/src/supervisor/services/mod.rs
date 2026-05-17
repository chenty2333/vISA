#[cfg(any(target_os = "none", test))]
mod native;

#[cfg(any(target_os = "none", test))]
pub(crate) use native::{
    ConsoleService, DevfsService, DriverNetEventKind, DriverVirtioNetService, EpollService,
    FutexService, LinuxSocketService, NetCoreService, ProcfsService, ReplaySnapshotService,
    VfsService, WasmApp, linux_user_resource_bytes_for_path,
};

#[cfg(not(any(target_os = "none", test)))]
mod console;
#[cfg(not(any(target_os = "none", test)))]
mod devfs;
#[cfg(not(any(target_os = "none", test)))]
mod driver_virtio_net;
#[cfg(not(any(target_os = "none", test)))]
mod epoll;
#[cfg(not(any(target_os = "none", test)))]
mod futex;
#[cfg(not(any(target_os = "none", test)))]
mod linux_socket;
#[cfg(not(any(target_os = "none", test)))]
mod net_core;
#[cfg(not(any(target_os = "none", test)))]
mod procfs;
#[cfg(not(any(target_os = "none", test)))]
mod replay_snapshot;
#[cfg(not(any(target_os = "none", test)))]
mod vfs;
#[cfg(not(any(target_os = "none", test)))]
mod wasm_app;

#[cfg(not(any(target_os = "none", test)))]
pub(crate) use console::ConsoleService;
#[cfg(not(any(target_os = "none", test)))]
pub(crate) use devfs::DevfsService;
#[cfg(not(any(target_os = "none", test)))]
pub(crate) use driver_virtio_net::{DriverNetEventKind, DriverVirtioNetService};
#[cfg(not(any(target_os = "none", test)))]
pub(crate) use epoll::EpollService;
#[cfg(not(any(target_os = "none", test)))]
pub(crate) use futex::FutexService;
#[cfg(not(any(target_os = "none", test)))]
pub(crate) use linux_socket::LinuxSocketService;
#[cfg(not(any(target_os = "none", test)))]
pub(crate) use net_core::NetCoreService;
#[cfg(not(any(target_os = "none", test)))]
pub(crate) use procfs::ProcfsService;
#[cfg(not(any(target_os = "none", test)))]
pub(crate) use replay_snapshot::ReplaySnapshotService;
#[cfg(not(any(target_os = "none", test)))]
pub(crate) use vfs::VfsService;
#[cfg(not(any(target_os = "none", test)))]
pub(crate) use wasm_app::WasmApp;
