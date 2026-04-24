use alloc::vec::Vec;

use crate::serial;
use vmos_abi::{
    EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLLIN, EPOLLOUT, ERR_EAGAIN, ERR_EBADF, ERR_EINVAL, ERR_EISDIR,
    ERR_ENOENT, ERR_ENOTDIR, ERR_EOPNOTSUPP, NodeKind, PackedStep, ServiceRoute,
};

use super::super::engine::SupervisorEngine;
use super::super::types::{LookupInfo, ServiceCallError};

const HELLO_TXT: &[u8] = b"sandbox file: supervisor world says hello\n";
const ROOT_DIR: &[u8] = b"sandbox\nproc\ndev\n";
const SANDBOX_DIR: &[u8] = b"hello.txt\nreadme.link\n";
const README_LINK: &[u8] = b"/sandbox/hello.txt";

const PROC_DIR: &[u8] = b"self\nmeminfo\n";
const PROC_SELF_DIR: &[u8] = b"status\ncwd\n";
const PROC_STATUS: &[u8] = b"Name:\tvmos-demo\nState:\tR (running)\nSupervisor:\tPrototype2\n";
const PROC_MEMINFO: &[u8] = b"MemTotal:\t8192 kB\nMemFree:\t4096 kB\n";
const PROC_CWD: &[u8] = b"/sandbox";

const DEV_DIR: &[u8] = b"null\nzero\npulse\n";
const PULSE_BYTES: &[u8] = b"pulse\n";

const NET_READY_KEY_BASE: u64 = 0x6e65_7473_6f63_0000;
const DRIVER_FIRST_RX_DELAY_TICKS: u64 = 7;
const DRIVER_NEXT_RX_DELAY_TICKS: u64 = 20;
const DRIVER_PACKET: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nhello vmos\n";
const WASM_APP_PTR: u32 = 0x2000;
const WASM_APP_MESSAGE: &[u8] = b"wasm frontend: hello from wasm_app\n";

pub(crate) struct ConsoleService;

impl ConsoleService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self)
    }

    pub(crate) fn write_bytes(
        &mut self,
        bytes: &[u8],
        inject_fault: bool,
    ) -> Result<(), &'static str> {
        if inject_fault {
            return Err("console_service trapped");
        }
        serial::write_bytes(bytes);
        Ok(())
    }
}

pub(crate) struct VfsService;

impl VfsService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self)
    }

    pub(crate) fn lookup(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<LookupInfo, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("vfs_service trapped"));
        }
        match path {
            b"/" => lookup(ServiceRoute::Vfs, NodeKind::Directory),
            b"/sandbox" => lookup(ServiceRoute::Vfs, NodeKind::Directory),
            b"/sandbox/hello.txt" => lookup(ServiceRoute::Vfs, NodeKind::File),
            b"/sandbox/readme.link" => lookup(ServiceRoute::Vfs, NodeKind::Symlink),
            b"/proc" | b"/proc/self" => lookup(ServiceRoute::Procfs, NodeKind::Directory),
            b"/proc/self/status" | b"/proc/meminfo" => lookup(ServiceRoute::Procfs, NodeKind::File),
            b"/proc/self/cwd" => lookup(ServiceRoute::Procfs, NodeKind::Symlink),
            b"/dev" => lookup(ServiceRoute::Devfs, NodeKind::Directory),
            b"/dev/null" | b"/dev/zero" | b"/dev/pulse" => {
                lookup(ServiceRoute::Devfs, NodeKind::CharDevice)
            }
            _ => errno(ERR_ENOENT),
        }
    }

    pub(crate) fn read_file(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("vfs_service trapped"));
        }
        match path {
            b"/sandbox/hello.txt" => Ok(HELLO_TXT.to_vec()),
            b"/" | b"/sandbox" => errno(ERR_EISDIR),
            _ => errno(ERR_ENOENT),
        }
    }

    pub(crate) fn list_dir(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("vfs_service trapped"));
        }
        match path {
            b"/" => Ok(ROOT_DIR.to_vec()),
            b"/sandbox" => Ok(SANDBOX_DIR.to_vec()),
            b"/sandbox/hello.txt" | b"/sandbox/readme.link" => errno(ERR_ENOTDIR),
            _ => errno(ERR_ENOENT),
        }
    }

    pub(crate) fn read_link(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("vfs_service trapped"));
        }
        match path {
            b"/sandbox/readme.link" => Ok(README_LINK.to_vec()),
            b"/" | b"/sandbox" | b"/sandbox/hello.txt" => errno(ERR_EINVAL),
            _ => errno(ERR_ENOENT),
        }
    }
}

pub(crate) struct ProcfsService;

impl ProcfsService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self)
    }

    pub(crate) fn lookup(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<NodeKind, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("procfs_service trapped"));
        }
        match path {
            b"/proc" | b"/proc/self" => Ok(NodeKind::Directory),
            b"/proc/self/status" | b"/proc/meminfo" => Ok(NodeKind::File),
            b"/proc/self/cwd" => Ok(NodeKind::Symlink),
            _ => errno(ERR_ENOENT),
        }
    }

    pub(crate) fn read_file(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("procfs_service trapped"));
        }
        match path {
            b"/proc/self/status" => Ok(PROC_STATUS.to_vec()),
            b"/proc/meminfo" => Ok(PROC_MEMINFO.to_vec()),
            b"/proc" | b"/proc/self" => errno(ERR_EISDIR),
            _ => errno(ERR_ENOENT),
        }
    }

    pub(crate) fn list_dir(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("procfs_service trapped"));
        }
        match path {
            b"/proc" => Ok(PROC_DIR.to_vec()),
            b"/proc/self" => Ok(PROC_SELF_DIR.to_vec()),
            b"/proc/self/status" | b"/proc/self/cwd" | b"/proc/meminfo" => errno(ERR_ENOTDIR),
            _ => errno(ERR_ENOENT),
        }
    }

    pub(crate) fn read_link(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("procfs_service trapped"));
        }
        match path {
            b"/proc/self/cwd" => Ok(PROC_CWD.to_vec()),
            b"/proc" | b"/proc/self" | b"/proc/self/status" | b"/proc/meminfo" => errno(ERR_EINVAL),
            _ => errno(ERR_ENOENT),
        }
    }
}

pub(crate) struct DevfsService;

impl DevfsService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self)
    }

    pub(crate) fn lookup(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<NodeKind, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("devfs_service trapped"));
        }
        match path {
            b"/dev" => Ok(NodeKind::Directory),
            b"/dev/null" | b"/dev/zero" | b"/dev/pulse" => Ok(NodeKind::CharDevice),
            _ => errno(ERR_ENOENT),
        }
    }

    pub(crate) fn list_dir(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("devfs_service trapped"));
        }
        match path {
            b"/dev" => Ok(DEV_DIR.to_vec()),
            b"/dev/null" | b"/dev/zero" | b"/dev/pulse" => errno(ERR_ENOTDIR),
            _ => errno(ERR_ENOENT),
        }
    }

    pub(crate) fn read_device(
        &mut self,
        path: &[u8],
        count: u32,
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("devfs_service trapped"));
        }
        match path {
            b"/dev/null" => Ok(Vec::new()),
            b"/dev/zero" => Ok(alloc::vec![0; count as usize]),
            b"/dev/pulse" => {
                Ok(PULSE_BYTES[..core::cmp::min(count as usize, PULSE_BYTES.len())].to_vec())
            }
            _ => errno(ERR_ENOENT),
        }
    }

    pub(crate) fn write_device(
        &mut self,
        path: &[u8],
        data_len: u32,
        inject_fault: bool,
    ) -> Result<u32, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("devfs_service trapped"));
        }
        match path {
            b"/dev/null" => Ok(data_len),
            b"/dev/zero" | b"/dev/pulse" => errno(ERR_EINVAL),
            _ => errno(ERR_ENOENT),
        }
    }
}

#[derive(Clone, Copy)]
struct EpollWatcher {
    epoll_id: u32,
    ready_key: u64,
    events: u32,
    data: u64,
    ready: bool,
}

#[derive(Clone, Copy)]
struct EpollWaiter {
    epoll_id: u32,
    wait_id: u64,
}

pub(crate) struct EpollService {
    next_id: u32,
    instances: Vec<u32>,
    watchers: Vec<EpollWatcher>,
    waiters: Vec<EpollWaiter>,
}

impl EpollService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self {
            next_id: 1,
            instances: Vec::new(),
            watchers: Vec::new(),
            waiters: Vec::new(),
        })
    }

    pub(crate) fn create(&mut self, flags: u32) -> Result<u32, ServiceCallError> {
        if flags != 0 {
            return errno(ERR_EINVAL);
        }
        let epoll_id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.instances.push(epoll_id);
        Ok(epoll_id)
    }

    pub(crate) fn ctl(
        &mut self,
        epoll_id: u32,
        op: u32,
        ready_key: u64,
        events: u32,
        data: u64,
    ) -> Result<(), ServiceCallError> {
        self.require_instance(epoll_id)?;
        match op {
            EPOLL_CTL_ADD => {
                if self
                    .watchers
                    .iter()
                    .any(|watcher| watcher.epoll_id == epoll_id && watcher.ready_key == ready_key)
                {
                    return errno(ERR_EINVAL);
                }
                self.watchers.push(EpollWatcher {
                    epoll_id,
                    ready_key,
                    events,
                    data,
                    ready: false,
                });
                Ok(())
            }
            EPOLL_CTL_DEL => {
                let old_len = self.watchers.len();
                self.watchers.retain(|watcher| {
                    !(watcher.epoll_id == epoll_id && watcher.ready_key == ready_key)
                });
                if self.watchers.len() == old_len {
                    errno(ERR_ENOENT)
                } else {
                    Ok(())
                }
            }
            _ => errno(ERR_EINVAL),
        }
    }

    pub(crate) fn collect_ready(
        &mut self,
        epoll_id: u32,
        max_events: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        self.require_instance(epoll_id)?;
        let mut out = Vec::new();
        let mut count = 0usize;
        let limit = max_events.max(1) as usize;
        for watcher in &mut self.watchers {
            if watcher.epoll_id != epoll_id || !watcher.ready || count == limit {
                continue;
            }
            out.extend_from_slice(&watcher.events.to_le_bytes());
            out.extend_from_slice(&watcher.data.to_le_bytes());
            watcher.ready = false;
            count += 1;
        }
        Ok(out)
    }

    pub(crate) fn arm_wait(&mut self, epoll_id: u32, wait_id: u64) -> Result<(), ServiceCallError> {
        self.require_instance(epoll_id)?;
        self.waiters.push(EpollWaiter { epoll_id, wait_id });
        Ok(())
    }

    pub(crate) fn notify_ready(&mut self, ready_key: u64) -> Result<Vec<u64>, ServiceCallError> {
        self.signal_waiters(ready_key, false)
    }

    pub(crate) fn restart_key(&mut self, ready_key: u64) -> Result<Vec<u64>, ServiceCallError> {
        self.signal_waiters(ready_key, true)
    }

    pub(crate) fn cancel_wait(&mut self, wait_id: u64) -> Result<(), ServiceCallError> {
        let old_len = self.waiters.len();
        self.waiters.retain(|waiter| waiter.wait_id != wait_id);
        if self.waiters.len() == old_len {
            errno(ERR_EINVAL)
        } else {
            Ok(())
        }
    }

    fn require_instance(&self, epoll_id: u32) -> Result<(), ServiceCallError> {
        if self.instances.iter().any(|id| *id == epoll_id) {
            Ok(())
        } else {
            errno(ERR_ENOENT)
        }
    }

    fn signal_waiters(
        &mut self,
        ready_key: u64,
        restart: bool,
    ) -> Result<Vec<u64>, ServiceCallError> {
        if !restart {
            for watcher in &mut self.watchers {
                if watcher.ready_key == ready_key {
                    watcher.ready = true;
                }
            }
        }

        let mut ready_epolls = Vec::new();
        for watcher in &self.watchers {
            if watcher.ready_key == ready_key {
                ready_epolls.push(watcher.epoll_id);
            }
        }

        let mut wait_ids = Vec::new();
        self.waiters.retain(|waiter| {
            if ready_epolls
                .iter()
                .any(|epoll_id| *epoll_id == waiter.epoll_id)
            {
                wait_ids.push(waiter.wait_id);
                false
            } else {
                true
            }
        });
        Ok(wait_ids)
    }
}

#[derive(Clone, Copy)]
struct FutexWaiter {
    key: u64,
    wait_id: u64,
}

pub(crate) struct FutexService {
    waiters: Vec<FutexWaiter>,
}

impl FutexService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self {
            waiters: Vec::new(),
        })
    }

    pub(crate) fn register_wait(&mut self, key: u64, wait_id: u64) -> Result<(), ServiceCallError> {
        self.waiters.push(FutexWaiter { key, wait_id });
        Ok(())
    }

    pub(crate) fn wake(&mut self, key: u64, max_count: u32) -> Result<Vec<u64>, ServiceCallError> {
        let mut remaining = max_count.max(1) as usize;
        let mut wait_ids = Vec::new();
        self.waiters.retain(|waiter| {
            if waiter.key == key && remaining > 0 {
                wait_ids.push(waiter.wait_id);
                remaining -= 1;
                false
            } else {
                true
            }
        });
        Ok(wait_ids)
    }

    pub(crate) fn cancel_wait(&mut self, wait_id: u64) -> Result<(), ServiceCallError> {
        let old_len = self.waiters.len();
        self.waiters.retain(|waiter| waiter.wait_id != wait_id);
        if self.waiters.len() == old_len {
            errno(ERR_EINVAL)
        } else {
            Ok(())
        }
    }
}

#[allow(dead_code)]
struct NetSocket {
    id: u32,
    domain: u32,
    ty: u32,
    protocol: u32,
    ready_key: u64,
    state: u32,
    rx: Vec<u8>,
    tx: Vec<u8>,
}

pub(crate) struct NetCoreService {
    next_socket_id: u32,
    sockets: Vec<NetSocket>,
}

impl NetCoreService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self {
            next_socket_id: 1,
            sockets: Vec::new(),
        })
    }

    pub(crate) fn create_socket(
        &mut self,
        domain: u32,
        ty: u32,
        protocol: u32,
    ) -> Result<u32, ServiceCallError> {
        let id = self.next_socket_id;
        self.next_socket_id = self.next_socket_id.saturating_add(1);
        self.sockets.push(NetSocket {
            id,
            domain,
            ty,
            protocol,
            ready_key: NET_READY_KEY_BASE | id as u64,
            state: 1,
            rx: Vec::new(),
            tx: Vec::new(),
        });
        Ok(id)
    }

    pub(crate) fn close_socket(&mut self, socket_id: u32) -> Result<(), ServiceCallError> {
        let old_len = self.sockets.len();
        self.sockets.retain(|socket| socket.id != socket_id);
        if self.sockets.len() == old_len {
            errno(ERR_EBADF)
        } else {
            Ok(())
        }
    }

    pub(crate) fn ready_key(&mut self, socket_id: u32) -> Result<u64, ServiceCallError> {
        self.socket(socket_id).map(|socket| socket.ready_key)
    }

    pub(crate) fn poll_socket(&mut self, socket_id: u32) -> Result<u32, ServiceCallError> {
        let socket = self.socket(socket_id)?;
        let mut events = EPOLLOUT;
        if !socket.rx.is_empty() {
            events |= EPOLLIN;
        }
        Ok(events)
    }

    pub(crate) fn send_socket(
        &mut self,
        socket_id: u32,
        bytes: &[u8],
    ) -> Result<u32, ServiceCallError> {
        let socket = self.socket_mut(socket_id)?;
        socket.tx.clear();
        socket.tx.extend_from_slice(bytes);
        socket.state = 2;
        Ok(bytes.len() as u32)
    }

    pub(crate) fn recv_socket(
        &mut self,
        socket_id: u32,
        count: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let socket = self.socket_mut(socket_id)?;
        if socket.rx.is_empty() {
            return errno(ERR_EAGAIN);
        }
        let len = core::cmp::min(count as usize, socket.rx.len());
        let bytes = socket.rx[..len].to_vec();
        socket.rx.drain(..len);
        Ok(bytes)
    }

    pub(crate) fn inject_packet(&mut self, bytes: &[u8]) -> Result<Option<u64>, ServiceCallError> {
        let Some(socket) = self.sockets.first_mut() else {
            return Ok(None);
        };
        socket.rx.clear();
        socket.rx.extend_from_slice(bytes);
        socket.state = 3;
        Ok(Some(socket.ready_key))
    }

    pub(crate) fn socket_count(&mut self) -> Result<u32, ServiceCallError> {
        Ok(self.sockets.len() as u32)
    }

    pub(crate) fn queued_rx_bytes(&mut self) -> Result<u32, ServiceCallError> {
        Ok(self.sockets.iter().fold(0u32, |acc, socket| {
            acc.saturating_add(socket.rx.len() as u32)
        }))
    }

    fn socket(&self, socket_id: u32) -> Result<&NetSocket, ServiceCallError> {
        self.sockets
            .iter()
            .find(|socket| socket.id == socket_id)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))
    }

    fn socket_mut(&mut self, socket_id: u32) -> Result<&mut NetSocket, ServiceCallError> {
        self.sockets
            .iter_mut()
            .find(|socket| socket.id == socket_id)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))
    }
}

#[allow(dead_code)]
struct LinuxSocket {
    socket_id: u32,
    domain: u32,
    ty: u32,
    protocol: u32,
    ready_key: u64,
    state: u32,
}

pub(crate) struct LinuxSocketService {
    sockets: Vec<LinuxSocket>,
}

impl LinuxSocketService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self {
            sockets: Vec::new(),
        })
    }

    pub(crate) fn register_socket(
        &mut self,
        socket_id: u32,
        domain: u32,
        ty: u32,
        protocol: u32,
        ready_key: u64,
    ) -> Result<(), ServiceCallError> {
        self.sockets.push(LinuxSocket {
            socket_id,
            domain,
            ty,
            protocol,
            ready_key,
            state: 1,
        });
        Ok(())
    }

    pub(crate) fn close_socket(&mut self, socket_id: u32) -> Result<(), ServiceCallError> {
        let old_len = self.sockets.len();
        self.sockets.retain(|socket| socket.socket_id != socket_id);
        if self.sockets.len() == old_len {
            errno(ERR_EBADF)
        } else {
            Ok(())
        }
    }

    pub(crate) fn bind_socket(
        &mut self,
        socket_id: u32,
        _addr_len: u32,
    ) -> Result<(), ServiceCallError> {
        self.set_state(socket_id, 2)
    }

    pub(crate) fn connect_socket(
        &mut self,
        socket_id: u32,
        _addr_len: u32,
    ) -> Result<(), ServiceCallError> {
        self.set_state(socket_id, 3)
    }

    pub(crate) fn listen_socket(
        &mut self,
        socket_id: u32,
        _backlog: u32,
    ) -> Result<(), ServiceCallError> {
        self.set_state(socket_id, 4)
    }

    pub(crate) fn accept_socket(&mut self, _socket_id: u32) -> Result<u32, ServiceCallError> {
        errno(ERR_EOPNOTSUPP)
    }

    pub(crate) fn send_socket(
        &mut self,
        socket_id: u32,
        len: u32,
    ) -> Result<u32, ServiceCallError> {
        self.socket(socket_id)?;
        Ok(len)
    }

    pub(crate) fn recv_socket(
        &mut self,
        socket_id: u32,
        len: u32,
    ) -> Result<u32, ServiceCallError> {
        self.socket(socket_id)?;
        Ok(len)
    }

    pub(crate) fn setsockopt(
        &mut self,
        socket_id: u32,
        _level: u32,
        _optname: u32,
        _optlen: u32,
    ) -> Result<(), ServiceCallError> {
        self.socket(socket_id)?;
        Ok(())
    }

    pub(crate) fn getsockopt(
        &mut self,
        socket_id: u32,
        _level: u32,
        _optname: u32,
    ) -> Result<u32, ServiceCallError> {
        self.socket(socket_id)?;
        Ok(0)
    }

    pub(crate) fn fcntl(
        &mut self,
        socket_id: u32,
        _cmd: u32,
        _arg: u64,
    ) -> Result<u32, ServiceCallError> {
        self.socket(socket_id)?;
        Ok(0)
    }

    pub(crate) fn socket_count(&mut self) -> Result<u32, ServiceCallError> {
        Ok(self.sockets.len() as u32)
    }

    fn set_state(&mut self, socket_id: u32, state: u32) -> Result<(), ServiceCallError> {
        let socket = self
            .sockets
            .iter_mut()
            .find(|socket| socket.socket_id == socket_id)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        socket.state = state;
        Ok(())
    }

    fn socket(&self, socket_id: u32) -> Result<&LinuxSocket, ServiceCallError> {
        self.sockets
            .iter()
            .find(|socket| socket.socket_id == socket_id)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DriverNetEventKind {
    None,
    Irq,
    DmaSubmitted,
    DmaCompleted,
    DriverCompletion,
    PacketRx,
}

pub(crate) struct DriverNetEvent {
    pub(crate) kind: DriverNetEventKind,
    pub(crate) len: u32,
    pub(crate) packet: Vec<u8>,
}

pub(crate) struct DriverVirtioNetService {
    next_tick: u64,
    phase: DriverNetEventKind,
}

impl DriverVirtioNetService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self {
            next_tick: DRIVER_FIRST_RX_DELAY_TICKS,
            phase: DriverNetEventKind::None,
        })
    }

    pub(crate) fn reset_sequence(&mut self, now_ticks: u64) -> Result<(), ServiceCallError> {
        self.next_tick = now_ticks.saturating_add(DRIVER_FIRST_RX_DELAY_TICKS);
        self.phase = DriverNetEventKind::None;
        Ok(())
    }

    pub(crate) fn poll_device(
        &mut self,
        now_ticks: u64,
    ) -> Result<DriverNetEvent, ServiceCallError> {
        if now_ticks < self.next_tick {
            return Ok(DriverNetEvent {
                kind: DriverNetEventKind::None,
                len: 0,
                packet: Vec::new(),
            });
        }

        self.phase = match self.phase {
            DriverNetEventKind::None => DriverNetEventKind::Irq,
            DriverNetEventKind::Irq => DriverNetEventKind::DmaSubmitted,
            DriverNetEventKind::DmaSubmitted => DriverNetEventKind::DmaCompleted,
            DriverNetEventKind::DmaCompleted => DriverNetEventKind::DriverCompletion,
            DriverNetEventKind::DriverCompletion | DriverNetEventKind::PacketRx => {
                DriverNetEventKind::PacketRx
            }
        };

        if self.phase == DriverNetEventKind::PacketRx {
            self.phase = DriverNetEventKind::None;
            self.next_tick = now_ticks.saturating_add(DRIVER_NEXT_RX_DELAY_TICKS);
            Ok(DriverNetEvent {
                kind: DriverNetEventKind::PacketRx,
                len: DRIVER_PACKET.len() as u32,
                packet: DRIVER_PACKET.to_vec(),
            })
        } else {
            Ok(DriverNetEvent {
                kind: self.phase,
                len: 64,
                packet: Vec::new(),
            })
        }
    }
}

pub(crate) struct ReplaySnapshotService {
    last_cursor: u64,
}

impl ReplaySnapshotService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { last_cursor: 0 })
    }

    pub(crate) fn validate_barrier(
        &mut self,
        _pending_waits: u32,
        active_transactions: u32,
        active_dmw_leases: u32,
        pending_dma: u32,
    ) -> Result<(), ServiceCallError> {
        if active_dmw_leases != 0 || pending_dma != 0 {
            return errno(vmos_abi::ERR_EFAULT);
        }
        if active_transactions != 0 {
            return errno(ERR_EAGAIN);
        }
        Ok(())
    }

    pub(crate) fn replay_until(&mut self, cursor: u64) -> Result<u64, ServiceCallError> {
        self.last_cursor = cursor;
        Ok(self.last_cursor)
    }

    pub(crate) fn last_replay_cursor(&mut self) -> Result<u64, ServiceCallError> {
        Ok(self.last_cursor)
    }
}

pub(crate) struct WasmApp {
    message: Vec<u8>,
}

impl WasmApp {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self {
            message: WASM_APP_MESSAGE.to_vec(),
        })
    }

    pub(crate) fn run(&mut self) -> Result<u64, &'static str> {
        Ok(PackedStep::console_write(WASM_APP_PTR, self.message.len() as u32).raw())
    }

    pub(crate) fn read_bytes(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, &'static str> {
        if ptr != WASM_APP_PTR || len as usize > self.message.len() {
            return Err("wasm_app native pointer was invalid");
        }
        Ok(self.message[..len as usize].to_vec())
    }
}

fn lookup(route: ServiceRoute, node: NodeKind) -> Result<LookupInfo, ServiceCallError> {
    Ok(LookupInfo { route, node })
}

fn errno<T>(errno: i32) -> Result<T, ServiceCallError> {
    Err(ServiceCallError::Errno(errno))
}
