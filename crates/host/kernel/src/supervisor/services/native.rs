use alloc::vec::Vec;

use vmos_abi::{
    EPOLL_CTL_ADD, EPOLL_CTL_DEL, ERR_EINVAL, ERR_EISDIR, ERR_ENOENT, ERR_ENOTDIR, NodeKind,
    PackedStep, ServiceRoute,
};

use super::super::{
    engine::SupervisorEngine,
    types::{LookupInfo, ServiceCallError},
};
use crate::serial;

#[path = "native_network.rs"]
mod native_network;

pub(crate) use native_network::{
    DriverNetEventKind, DriverVirtioNetService, LinuxSocketService, NetCoreService,
    ReplaySnapshotService,
};

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
        Ok(Self { next_id: 1, instances: Vec::new(), watchers: Vec::new(), waiters: Vec::new() })
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
                if self.watchers.len() == old_len { errno(ERR_ENOENT) } else { Ok(()) }
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
        if self.waiters.len() == old_len { errno(ERR_EINVAL) } else { Ok(()) }
    }

    fn require_instance(&self, epoll_id: u32) -> Result<(), ServiceCallError> {
        if self.instances.contains(&epoll_id) { Ok(()) } else { errno(ERR_ENOENT) }
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
            if ready_epolls.contains(&waiter.epoll_id) {
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
        Ok(Self { waiters: Vec::new() })
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
        if self.waiters.len() == old_len { errno(ERR_EINVAL) } else { Ok(()) }
    }
}

pub(crate) struct WasmApp {
    message: Vec<u8>,
}

impl WasmApp {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { message: WASM_APP_MESSAGE.to_vec() })
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
