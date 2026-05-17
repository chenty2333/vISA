#[cfg(target_os = "none")]
mod native;

#[cfg(target_os = "none")]
pub(crate) use native::{
    ConsoleService, DevfsService, DriverNetEventKind, DriverVirtioNetService, EpollService,
    FutexService, LinuxSocketService, NetCoreService, ProcfsService, ReplaySnapshotService,
    VfsService, WasmApp, linux_user_resource_bytes_for_path,
};

#[cfg(not(target_os = "none"))]
mod console;
#[cfg(not(target_os = "none"))]
mod devfs;
#[cfg(not(target_os = "none"))]
mod driver_virtio_net;
#[cfg(not(target_os = "none"))]
mod epoll;
#[cfg(not(target_os = "none"))]
mod futex;
#[cfg(not(target_os = "none"))]
mod linux_socket;
#[cfg(not(target_os = "none"))]
mod net_core;
#[cfg(not(target_os = "none"))]
mod procfs;
#[cfg(not(target_os = "none"))]
mod replay_snapshot;
#[cfg(not(target_os = "none"))]
mod vfs;
#[cfg(not(target_os = "none"))]
mod wasm_app;

#[cfg(not(target_os = "none"))]
pub(crate) use console::ConsoleService;
#[cfg(not(target_os = "none"))]
pub(crate) use devfs::DevfsService;
#[cfg(not(target_os = "none"))]
pub(crate) use driver_virtio_net::{DriverNetEventKind, DriverVirtioNetService};
#[cfg(not(target_os = "none"))]
pub(crate) use epoll::EpollService;
#[cfg(not(target_os = "none"))]
pub(crate) use futex::FutexService;
#[cfg(not(target_os = "none"))]
pub(crate) use linux_socket::LinuxSocketService;
#[cfg(not(target_os = "none"))]
pub(crate) use net_core::NetCoreService;
#[cfg(not(target_os = "none"))]
pub(crate) use procfs::ProcfsService;
#[cfg(not(target_os = "none"))]
pub(crate) use replay_snapshot::ReplaySnapshotService;
#[cfg(not(target_os = "none"))]
pub(crate) use vfs::VfsService;
#[cfg(not(target_os = "none"))]
pub(crate) use wasm_app::WasmApp;
