use alloc::vec::Vec;

use vmos_abi::{
    EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD, ERR_EEXIST, ERR_EINVAL, ERR_EISDIR, ERR_ELOOP,
    ERR_ENOENT, ERR_ENOTDIR, ERR_ENOTEMPTY, ERR_EPERM, NodeKind, PackedStep, ServiceRoute,
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
const ROOT_DIR: &[u8] = b"sandbox\nproc\ndev\ntmp\nboot\nlib\n";
const SANDBOX_DIR: &[u8] = b"hello.txt\nreadme.link\n";
const README_LINK: &[u8] = b"/sandbox/hello.txt";
const BOOT_DIR: &[u8] = b"config-prototype2\n";
const LIB_DIR: &[u8] = b"modules\nkernel\n";
const LIB_MODULES_DIR: &[u8] = b"prototype2\n";
const LIB_MODULES_PROTOTYPE2_DIR: &[u8] = b"build\nconfig\n";
const LIB_MODULES_BUILD_DIR: &[u8] = b".config\n";
const LIB_KERNEL_DIR: &[u8] = b"config-prototype2\n";
const BOOT_CONFIG: &[u8] = b"CONFIG_EVENTFD=y\n\
CONFIG_MODULES=n\n\
CONFIG_MODULE_UNLOAD=n\n\
CONFIG_MODULE_SIG=n\n\
CONFIG_SECURITY_LOCKDOWN_LSM=n\n\
CONFIG_EFI_SECURE_BOOT_LOCK_DOWN=n\n\
CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=n\n";

const PROC_DIR: &[u8] = b"self\nmeminfo\ncpuinfo\nsys\ncmdline\nmounts\n";
const PROC_SELF_DIR: &[u8] = b"status\nstat\ncwd\n";
const PROC_SYS_DIR: &[u8] = b"kernel\n";
const PROC_SYS_KERNEL_DIR: &[u8] = b"pid_max\ntainted\n";
const PROC_STATUS: &[u8] = b"Name:\tvmos-ltp\n\
State:\tR (running)\n\
Tgid:\t4\n\
Pid:\t4\n\
PPid:\t2\n\
Uid:\t0\t0\t0\t0\n\
Gid:\t0\t0\t0\t0\n\
Supervisor:\tPrototype2\n";
const PROC_STAT: &[u8] = b"4 (vmos-ltp) R 2 4 4 0 -1 0 0 0 0 0 1 0 0 20 0 1 0 1 0 0\n";
const PROC_CPUINFO: &[u8] = b"processor\t: 0\n\
vendor_id\t: VMOS\n\
cpu family\t: 6\n\
model\t\t: 1\n\
model name\t: VMOS Virtual CPU\n\
cpu MHz\t\t: 1000.000\n\
flags\t\t: fpu tsc cx8 cmov sse sse2 syscall nx lm constant_tsc\n";
const PROC_PID_MAX: &[u8] = b"4194304\n";
const PROC_TAINTED: &[u8] = b"0\n";
const PROC_CMDLINE: &[u8] = b"root=/dev/vmos module.sig_enforce=0\n";
const PROC_MOUNTS: &[u8] = b"tmpfs / tmpfs rw,relatime 0 0\n\
tmpfs /tmp tmpfs rw,relatime 0 0\n";
const PROC_MEMINFO: &[u8] = b"MemTotal:      1048576 kB\n\
MemFree:        524288 kB\n\
MemAvailable:   786432 kB\n\
Buffers:             0 kB\n\
Cached:         262144 kB\n\
SwapCached:          0 kB\n\
Active:              0 kB\n\
Inactive:            0 kB\n\
SwapTotal:           0 kB\n\
SwapFree:            0 kB\n\
HugePages_Total:     0\n\
HugePages_Free:      0\n\
HugePages_Rsvd:      0\n\
HugePages_Surp:      0\n\
Hugepagesize:     2048 kB\n";
const PROC_CWD: &[u8] = b"/sandbox";

const DEV_DIR: &[u8] = b"null\nzero\npulse\nloop0\nloop-control\n";
const PULSE_BYTES: &[u8] = b"pulse\n";

const WASM_APP_PTR: u32 = 0x2000;
const WASM_APP_MESSAGE: &[u8] = b"wasm frontend: hello from wasm_app\n";
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;
const RENAME_SUPPORTED_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;

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

struct VfsChunk {
    start: usize,
    len: usize,
    fill: Option<u8>,
    data: Vec<u8>,
}

struct VfsNode {
    path: Vec<u8>,
    kind: NodeKind,
    mode: u32,
    uid: u32,
    gid: u32,
    len: usize,
    chunks: Vec<VfsChunk>,
}

pub(crate) struct LinuxUserResourceFile {
    pub(crate) path: &'static [u8],
    pub(crate) mode: u32,
    pub(crate) bytes: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/linux_user_resources.rs"));

#[derive(Clone)]
struct FileLock {
    path: Vec<u8>,
    owner_pid: u32,
    write: bool,
    start: i64,
    len: i64,
}

pub(crate) struct VfsService {
    nodes: Vec<VfsNode>,
    locks: Vec<FileLock>,
}

impl VfsService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let mut service = Self { nodes: Vec::new(), locks: Vec::new() };
        service.install_linux_user_resources();
        Ok(service)
    }

    pub(crate) fn lookup(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<LookupInfo, ServiceCallError> {
        if inject_fault {
            return Err(ServiceCallError::Trap("vfs_service trapped"));
        }
        if let Some(node) = self.dynamic_node(path) {
            return lookup(ServiceRoute::Vfs, node.kind);
        }
        if linux_user_resource_for_path(path).is_some() {
            return lookup(ServiceRoute::Vfs, NodeKind::File);
        }
        match path {
            b"/" => lookup(ServiceRoute::Vfs, NodeKind::Directory),
            b"/tmp" => lookup(ServiceRoute::Vfs, NodeKind::Directory),
            b"/boot" => lookup(ServiceRoute::Vfs, NodeKind::Directory),
            b"/lib"
            | b"/lib/modules"
            | b"/lib/modules/prototype2"
            | b"/lib/modules/prototype2/build"
            | b"/lib/kernel" => lookup(ServiceRoute::Vfs, NodeKind::Directory),
            b"/boot/config-prototype2"
            | b"/lib/modules/prototype2/build/.config"
            | b"/lib/modules/prototype2/config"
            | b"/lib/kernel/config-prototype2" => lookup(ServiceRoute::Vfs, NodeKind::File),
            b"/sandbox" => lookup(ServiceRoute::Vfs, NodeKind::Directory),
            b"/sandbox/hello.txt" => lookup(ServiceRoute::Vfs, NodeKind::File),
            b"/sandbox/readme.link" => lookup(ServiceRoute::Vfs, NodeKind::Symlink),
            b"/proc" | b"/proc/self" | b"/proc/sys" | b"/proc/sys/kernel" => {
                lookup(ServiceRoute::Procfs, NodeKind::Directory)
            }
            b"/proc/self/status"
            | b"/proc/self/stat"
            | b"/proc/cmdline"
            | b"/proc/mounts"
            | b"/proc/meminfo"
            | b"/proc/cpuinfo"
            | b"/proc/sys/kernel/tainted"
            | b"/proc/sys/kernel/pid_max" => lookup(ServiceRoute::Procfs, NodeKind::File),
            b"/proc/self/cwd" => lookup(ServiceRoute::Procfs, NodeKind::Symlink),
            b"/dev" => lookup(ServiceRoute::Devfs, NodeKind::Directory),
            b"/dev/null" | b"/dev/zero" | b"/dev/pulse" | b"/dev/loop0" | b"/dev/loop-control" => {
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
        if let Some(node) = self.dynamic_node(path) {
            return match node.kind {
                NodeKind::File => Ok(node.read_range(0, node.len)),
                NodeKind::Directory => errno(ERR_EISDIR),
                _ => errno(ERR_EINVAL),
            };
        }
        if let Some(resource) = linux_user_resource_for_path(path) {
            return Ok(resource.bytes.to_vec());
        }
        match path {
            b"/sandbox/hello.txt" => Ok(HELLO_TXT.to_vec()),
            b"/boot/config-prototype2"
            | b"/lib/modules/prototype2/build/.config"
            | b"/lib/modules/prototype2/config"
            | b"/lib/kernel/config-prototype2" => Ok(BOOT_CONFIG.to_vec()),
            b"/"
            | b"/sandbox"
            | b"/boot"
            | b"/lib"
            | b"/lib/modules"
            | b"/lib/modules/prototype2"
            | b"/lib/modules/prototype2/build"
            | b"/lib/kernel" => errno(ERR_EISDIR),
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
        if path == b"/tmp"
            || self.dynamic_node(path).is_some_and(|node| node.kind == NodeKind::Directory)
        {
            return Ok(self.dynamic_listing(path));
        }
        match path {
            b"/" => Ok(ROOT_DIR.to_vec()),
            b"/sandbox" => Ok(SANDBOX_DIR.to_vec()),
            b"/boot" => Ok(BOOT_DIR.to_vec()),
            b"/lib" => Ok(LIB_DIR.to_vec()),
            b"/lib/modules" => Ok(LIB_MODULES_DIR.to_vec()),
            b"/lib/modules/prototype2" => Ok(LIB_MODULES_PROTOTYPE2_DIR.to_vec()),
            b"/lib/modules/prototype2/build" => Ok(LIB_MODULES_BUILD_DIR.to_vec()),
            b"/lib/kernel" => Ok(LIB_KERNEL_DIR.to_vec()),
            b"/sandbox/hello.txt"
            | b"/sandbox/readme.link"
            | b"/boot/config-prototype2"
            | b"/lib/modules/prototype2/build/.config"
            | b"/lib/modules/prototype2/config"
            | b"/lib/kernel/config-prototype2" => errno(ERR_ENOTDIR),
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
        if let Some(node) = self.dynamic_node(path) {
            return match node.kind {
                NodeKind::Symlink => Ok(node.read_range(0, node.len)),
                _ => errno(ERR_EINVAL),
            };
        }
        match path {
            b"/sandbox/readme.link" => Ok(README_LINK.to_vec()),
            b"/" | b"/sandbox" | b"/sandbox/hello.txt" => errno(ERR_EINVAL),
            _ => errno(ERR_ENOENT),
        }
    }

    pub(crate) fn mkdir(
        &mut self,
        path: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(), ServiceCallError> {
        if self.lookup(path, false).is_ok() {
            return errno(ERR_EEXIST);
        }
        self.require_parent_dir(path)?;
        self.nodes.push(VfsNode {
            path: normalize_path(path),
            kind: NodeKind::Directory,
            mode: 0o040000 | (mode & 0o7777),
            uid,
            gid,
            len: 0,
            chunks: Vec::new(),
        });
        Ok(())
    }

    pub(crate) fn create_file(
        &mut self,
        path: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(), ServiceCallError> {
        if self.lookup(path, false).is_ok() {
            return Ok(());
        }
        self.require_parent_dir(path)?;
        let normalized = normalize_path(path);
        let (mode, gid) = self.create_file_mode_and_gid(&normalized, mode, gid);
        self.nodes.push(VfsNode {
            path: normalized,
            kind: NodeKind::File,
            mode: 0o100000 | mode,
            uid,
            gid,
            len: 0,
            chunks: Vec::new(),
        });
        Ok(())
    }

    pub(crate) fn symlink(&mut self, path: &[u8], target: &[u8]) -> Result<(), ServiceCallError> {
        if self.lookup(path, false).is_ok() {
            return errno(ERR_EEXIST);
        }
        self.require_parent_dir(path)?;
        self.nodes.push(VfsNode::from_bytes(
            normalize_path(path),
            NodeKind::Symlink,
            0o120777,
            0,
            0,
            target,
        ));
        Ok(())
    }

    pub(crate) fn unlink(&mut self, path: &[u8]) -> Result<(), ServiceCallError> {
        let Some(index) = self.nodes.iter().position(|node| node.path.as_slice() == path) else {
            return errno(ERR_ENOENT);
        };
        if self.nodes[index].kind == NodeKind::Directory {
            return errno(ERR_EISDIR);
        }
        self.nodes.remove(index);
        Ok(())
    }

    pub(crate) fn rmdir(&mut self, path: &[u8]) -> Result<(), ServiceCallError> {
        let normalized = normalize_path(path);
        let Some(index) = self.nodes.iter().position(|node| {
            node.path.as_slice() == normalized.as_slice() && node.kind == NodeKind::Directory
        }) else {
            return errno(ERR_ENOENT);
        };
        if self.nodes.iter().any(|node| child_name(&normalized, &node.path).is_some()) {
            return errno(ERR_ENOTEMPTY);
        }
        self.nodes.remove(index);
        Ok(())
    }

    pub(crate) fn rename(
        &mut self,
        old_path: &[u8],
        new_path: &[u8],
        flags: u32,
    ) -> Result<(), ServiceCallError> {
        if flags & !RENAME_SUPPORTED_FLAGS != 0
            || flags & (RENAME_NOREPLACE | RENAME_EXCHANGE) == RENAME_NOREPLACE | RENAME_EXCHANGE
        {
            return errno(ERR_EINVAL);
        }

        let old_path = normalize_path(old_path);
        let new_path = normalize_path(new_path);
        if old_path == new_path {
            self.lookup(&old_path, false)?;
            return Ok(());
        }

        self.require_parent_dir(&new_path)?;
        let Some(old_index) = self.nodes.iter().position(|node| node.path == old_path) else {
            self.lookup(&old_path, false)?;
            return errno(ERR_EPERM);
        };
        let old_kind = self.nodes[old_index].kind;
        if old_kind == NodeKind::Directory && is_descendant_path(&new_path, &old_path) {
            return errno(ERR_EINVAL);
        }

        let target_index = self.nodes.iter().position(|node| node.path == new_path);
        let target_kind = if let Some(index) = target_index {
            Some(self.nodes[index].kind)
        } else {
            match self.lookup(&new_path, false) {
                Ok(info) => Some(info.node),
                Err(ServiceCallError::Errno(ERR_ENOENT)) => None,
                Err(err) => return Err(err),
            }
        };

        if flags & RENAME_NOREPLACE != 0 && target_kind.is_some() {
            return errno(ERR_EEXIST);
        }

        if flags & RENAME_EXCHANGE != 0 {
            let Some(target_index) = target_index else {
                return if target_kind.is_some() { errno(ERR_EPERM) } else { errno(ERR_ENOENT) };
            };
            if self.nodes[target_index].kind == NodeKind::Directory
                && is_descendant_path(&old_path, &new_path)
            {
                return errno(ERR_EINVAL);
            }
            self.swap_subtree_prefixes(&old_path, &new_path);
            return Ok(());
        }

        match target_index {
            Some(index) => {
                let target_kind = self.nodes[index].kind;
                match (old_kind == NodeKind::Directory, target_kind == NodeKind::Directory) {
                    (true, false) => return errno(ERR_ENOTDIR),
                    (false, true) => return errno(ERR_EISDIR),
                    _ => {}
                }
                if target_kind == NodeKind::Directory
                    && self.nodes.iter().any(|node| child_name(&new_path, &node.path).is_some())
                {
                    return errno(ERR_ENOTEMPTY);
                }
                self.nodes.remove(index);
            }
            None if target_kind.is_some() => return errno(ERR_EPERM),
            None => {}
        }

        self.rename_subtree_prefix(&old_path, &new_path);
        Ok(())
    }

    pub(crate) fn chmod(&mut self, path: &[u8], mode: u32) -> Result<(), ServiceCallError> {
        let Some(node) = self.dynamic_node_mut(path) else {
            return if matches!(
                path,
                b"/" | b"/tmp" | b"/sandbox" | b"/sandbox/hello.txt" | b"/sandbox/readme.link"
            ) {
                Ok(())
            } else {
                errno(ERR_ENOENT)
            };
        };
        let kind_bits = node.mode & 0o170000;
        node.mode = kind_bits | (mode & 0o7777);
        Ok(())
    }

    pub(crate) fn chown(
        &mut self,
        path: &[u8],
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), ServiceCallError> {
        let Some(node) = self.dynamic_node_mut(path) else {
            return self.lookup(path, false).map(|_| ());
        };
        if let Some(uid) = uid {
            node.uid = uid;
        }
        if let Some(gid) = gid {
            node.gid = gid;
        }
        Ok(())
    }

    pub(crate) fn write_file(
        &mut self,
        path: &[u8],
        cursor: usize,
        bytes: &[u8],
    ) -> Result<usize, ServiceCallError> {
        let Some(node) = self.dynamic_node_mut(path) else {
            return errno(ERR_ENOENT);
        };
        if node.kind != NodeKind::File {
            return errno(ERR_EISDIR);
        }
        let end = cursor.checked_add(bytes.len()).ok_or(ServiceCallError::Errno(ERR_EINVAL))?;
        if end > node.len {
            node.len = end;
        }
        node.chunks.push(VfsChunk::from_write(cursor, bytes));
        Ok(bytes.len())
    }

    pub(crate) fn read_file_range(
        &mut self,
        path: &[u8],
        cursor: usize,
        count: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let Some(node) = self.dynamic_node(path) else {
            return self.read_file(path, false).map(|bytes| {
                let start = cursor.min(bytes.len());
                let end = start.saturating_add(count as usize).min(bytes.len());
                bytes[start..end].to_vec()
            });
        };
        if node.kind != NodeKind::File {
            return errno(ERR_EISDIR);
        }
        let start = cursor.min(node.len);
        let end = start.saturating_add(count as usize).min(node.len);
        Ok(node.read_range(start, end))
    }

    pub(crate) fn truncate_file(
        &mut self,
        path: &[u8],
        len: usize,
    ) -> Result<(), ServiceCallError> {
        let Some(node) = self.dynamic_node_mut(path) else {
            return errno(ERR_ENOENT);
        };
        if node.kind != NodeKind::File {
            return errno(ERR_EISDIR);
        }
        node.truncate(len);
        Ok(())
    }

    pub(crate) fn mode_for_path(&self, path: &[u8], kind: NodeKind) -> u32 {
        if let Some(node) = self.dynamic_node(path) {
            return node.mode;
        }
        if path == b"/tmp" {
            return 0o041777;
        }
        if let Some(resource) = linux_user_resource_for_path(path) {
            return 0o100000 | (resource.mode & 0o7777);
        }
        match kind {
            NodeKind::Directory => 0o040755,
            NodeKind::File => 0o100444,
            NodeKind::Symlink => 0o120777,
            NodeKind::CharDevice => 0o020666,
        }
    }

    pub(crate) fn owner_for_path(&self, path: &[u8]) -> (u32, u32) {
        self.dynamic_node(path).map(|node| (node.uid, node.gid)).unwrap_or((0, 0))
    }

    pub(crate) fn len_for_path(&self, path: &[u8]) -> u64 {
        self.dynamic_node(path)
            .map(|node| node.len as u64)
            .or_else(|| {
                linux_user_resource_for_path(path).map(|resource| resource.bytes.len() as u64)
            })
            .unwrap_or(0)
    }

    fn install_linux_user_resources(&mut self) {
        if LINUX_USER_RESOURCE_FILES.is_empty() {
            return;
        }
        for path in [b"/tmp/datafiles".as_slice(), b"/sandbox/datafiles", b"/datafiles"] {
            self.install_dynamic_dir(path);
        }
        for resource in LINUX_USER_RESOURCE_FILES {
            let Some(name) = file_name(resource.path) else { continue };
            for root in [
                b"/tmp/datafiles".as_slice(),
                b"/sandbox/datafiles",
                b"/datafiles",
                b"/tmp",
                b"/sandbox",
                b"",
            ] {
                self.install_resource_file(root, name, resource.mode, resource.bytes);
            }
        }
    }

    fn install_dynamic_dir(&mut self, path: &[u8]) {
        let normalized = normalize_path(path);
        if self.nodes.iter().any(|node| node.path == normalized) {
            return;
        }
        self.nodes.push(VfsNode {
            path: normalized,
            kind: NodeKind::Directory,
            mode: 0o040755,
            uid: 0,
            gid: 0,
            len: 0,
            chunks: Vec::new(),
        });
    }

    fn install_resource_file(&mut self, root: &[u8], name: &[u8], mode: u32, bytes: &[u8]) {
        let path = join_resource_path(root, name);
        if self.nodes.iter().any(|node| node.path == path) {
            return;
        }
        self.nodes.push(VfsNode::from_bytes(
            path,
            NodeKind::File,
            0o100000 | (mode & 0o7777),
            0,
            0,
            bytes,
        ));
    }

    fn dynamic_node(&self, path: &[u8]) -> Option<&VfsNode> {
        self.nodes.iter().find(|node| node.path.as_slice() == path)
    }

    fn dynamic_node_mut(&mut self, path: &[u8]) -> Option<&mut VfsNode> {
        self.nodes.iter_mut().find(|node| node.path.as_slice() == path)
    }

    fn create_file_mode_and_gid(&self, path: &[u8], mode: u32, gid: u32) -> (u32, u32) {
        let mut mode = mode & 0o7777;
        let Some(parent) = parent_path(path) else {
            return (mode, gid);
        };
        let Some(parent) = self.dynamic_node(&parent) else {
            return (mode, gid);
        };
        if parent.mode & 0o2000 != 0 {
            mode &= !0o2000;
            return (mode, parent.gid);
        }
        (mode, gid)
    }

    fn require_parent_dir(&mut self, path: &[u8]) -> Result<(), ServiceCallError> {
        let Some(parent) = parent_path(path) else {
            return errno(ERR_EPERM);
        };
        match self.lookup(&parent, false) {
            Ok(info) if info.node == NodeKind::Directory => Ok(()),
            Ok(_) => errno(ERR_ENOTDIR),
            Err(err) => Err(err),
        }
    }

    fn dynamic_listing(&self, dir: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for node in &self.nodes {
            let Some(name) = child_name(dir, &node.path) else {
                continue;
            };
            out.extend_from_slice(name);
            out.push(b'\n');
        }
        out
    }

    fn rename_subtree_prefix(&mut self, old_prefix: &[u8], new_prefix: &[u8]) {
        for node in &mut self.nodes {
            if let Some(path) = replace_path_prefix(&node.path, old_prefix, new_prefix) {
                node.path = path;
            }
        }
        for lock in &mut self.locks {
            if let Some(path) = replace_path_prefix(&lock.path, old_prefix, new_prefix) {
                lock.path = path;
            }
        }
    }

    fn swap_subtree_prefixes(&mut self, left: &[u8], right: &[u8]) {
        for node in &mut self.nodes {
            if let Some(path) = replace_path_prefix(&node.path, left, right) {
                node.path = path;
            } else if let Some(path) = replace_path_prefix(&node.path, right, left) {
                node.path = path;
            }
        }
        for lock in &mut self.locks {
            if let Some(path) = replace_path_prefix(&lock.path, left, right) {
                lock.path = path;
            } else if let Some(path) = replace_path_prefix(&lock.path, right, left) {
                lock.path = path;
            }
        }
    }

    pub(crate) fn fcntl_setlk(
        &mut self,
        path: &[u8],
        owner: u32,
        write: bool,
        s: i64,
        l: i64,
    ) -> Result<(), i32> {
        for lock in &self.locks {
            if lock.path != path || lock.owner_pid == owner {
                continue;
            }
            if ranges_overlap(s, l, lock.start, lock.len) && (write || lock.write) {
                return Err(vmos_abi::ERR_EAGAIN);
            }
        }
        self.remove_owner_locks(path, owner, s, l);
        self.locks.push(FileLock {
            path: path.to_vec(),
            owner_pid: owner,
            write,
            start: s,
            len: l,
        });
        Ok(())
    }

    pub(crate) fn fcntl_unlock(&mut self, path: &[u8], owner: u32, s: i64, l: i64) {
        self.remove_owner_locks(path, owner, s, l);
    }

    pub(crate) fn fcntl_getlk(
        &self,
        path: &[u8],
        owner: u32,
        want_write: bool,
        s: i64,
        l: i64,
    ) -> Option<(bool, u32, i64, i64)> {
        for lock in &self.locks {
            if lock.path != path || lock.owner_pid == owner {
                continue;
            }
            if ranges_overlap(s, l, lock.start, lock.len) && (want_write || lock.write) {
                return Some((lock.write, lock.owner_pid, lock.start, lock.len));
            }
        }
        None
    }

    fn remove_owner_locks(&mut self, path: &[u8], owner: u32, s: i64, l: i64) {
        let remove_start = s;
        let remove_end = lock_end(s, l);
        let mut next = Vec::new();
        for lock in core::mem::take(&mut self.locks) {
            if lock.path != path
                || lock.owner_pid != owner
                || !ranges_overlap(s, l, lock.start, lock.len)
            {
                next.push(lock);
                continue;
            }

            let lock_start = lock.start;
            let stored_end = lock_end(lock.start, lock.len);
            if lock_start < remove_start {
                let mut left = lock.clone();
                left.len = remove_start.saturating_sub(lock_start);
                next.push(left);
            }
            if remove_end < stored_end {
                let mut right = lock;
                right.start = remove_end;
                right.len =
                    if stored_end == i64::MAX { 0 } else { stored_end.saturating_sub(remove_end) };
                next.push(right);
            }
        }
        self.locks = next;
    }
}

fn ranges_overlap(left_start: i64, left_len: i64, right_start: i64, right_len: i64) -> bool {
    let left_end = lock_end(left_start, left_len);
    let right_end = lock_end(right_start, right_len);
    left_start < right_end && left_end > right_start
}

fn lock_end(start: i64, len: i64) -> i64 {
    if len == 0 { i64::MAX } else { start.saturating_add(len) }
}

impl VfsChunk {
    fn from_write(start: usize, bytes: &[u8]) -> Self {
        let fill = uniform_byte(bytes);
        let data = if fill.is_some() { Vec::new() } else { bytes.to_vec() };
        Self { start, len: bytes.len(), fill, data }
    }

    fn end(&self) -> usize {
        self.start.saturating_add(self.len)
    }
}

impl VfsNode {
    fn from_bytes(
        path: Vec<u8>,
        kind: NodeKind,
        mode: u32,
        uid: u32,
        gid: u32,
        bytes: &[u8],
    ) -> Self {
        Self {
            path,
            kind,
            mode,
            uid,
            gid,
            len: bytes.len(),
            chunks: alloc::vec![VfsChunk::from_write(0, bytes)],
        }
    }

    fn read_range(&self, start: usize, end: usize) -> Vec<u8> {
        if start >= end {
            return Vec::new();
        }
        let mut out = alloc::vec![0; end - start];
        for chunk in &self.chunks {
            let overlap_start = core::cmp::max(start, chunk.start);
            let overlap_end = core::cmp::min(end, chunk.end());
            if overlap_start >= overlap_end {
                continue;
            }
            let dst_start = overlap_start - start;
            let dst_end = overlap_end - start;
            if let Some(fill) = chunk.fill {
                out[dst_start..dst_end].fill(fill);
            } else {
                let src_start = overlap_start - chunk.start;
                let src_end = overlap_end - chunk.start;
                out[dst_start..dst_end].copy_from_slice(&chunk.data[src_start..src_end]);
            }
        }
        out
    }

    fn truncate(&mut self, len: usize) {
        self.len = len;
        self.chunks.retain_mut(|chunk| {
            if chunk.start >= len {
                return false;
            }
            if chunk.end() > len {
                chunk.len = len - chunk.start;
                if chunk.fill.is_none() {
                    chunk.data.truncate(chunk.len);
                }
            }
            true
        });
    }
}

fn uniform_byte(bytes: &[u8]) -> Option<u8> {
    let first = *bytes.first()?;
    if bytes.iter().all(|byte| *byte == first) { Some(first) } else { None }
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
            b"/proc" | b"/proc/self" | b"/proc/sys" | b"/proc/sys/kernel" => {
                Ok(NodeKind::Directory)
            }
            b"/proc/self/status"
            | b"/proc/self/stat"
            | b"/proc/cmdline"
            | b"/proc/mounts"
            | b"/proc/meminfo"
            | b"/proc/cpuinfo"
            | b"/proc/sys/kernel/tainted"
            | b"/proc/sys/kernel/pid_max" => Ok(NodeKind::File),
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
            b"/proc/self/stat" => Ok(PROC_STAT.to_vec()),
            b"/proc/cmdline" => Ok(PROC_CMDLINE.to_vec()),
            b"/proc/mounts" => Ok(PROC_MOUNTS.to_vec()),
            b"/proc/meminfo" => Ok(PROC_MEMINFO.to_vec()),
            b"/proc/cpuinfo" => Ok(PROC_CPUINFO.to_vec()),
            b"/proc/sys/kernel/tainted" => Ok(PROC_TAINTED.to_vec()),
            b"/proc/sys/kernel/pid_max" => Ok(PROC_PID_MAX.to_vec()),
            b"/proc" | b"/proc/self" | b"/proc/sys" | b"/proc/sys/kernel" => errno(ERR_EISDIR),
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
            b"/proc/sys" => Ok(PROC_SYS_DIR.to_vec()),
            b"/proc/sys/kernel" => Ok(PROC_SYS_KERNEL_DIR.to_vec()),
            b"/proc/self/status"
            | b"/proc/self/stat"
            | b"/proc/self/cwd"
            | b"/proc/cmdline"
            | b"/proc/mounts"
            | b"/proc/meminfo"
            | b"/proc/cpuinfo"
            | b"/proc/sys/kernel/tainted"
            | b"/proc/sys/kernel/pid_max" => errno(ERR_ENOTDIR),
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
            b"/proc"
            | b"/proc/self"
            | b"/proc/self/status"
            | b"/proc/self/stat"
            | b"/proc/cmdline"
            | b"/proc/mounts"
            | b"/proc/meminfo"
            | b"/proc/cpuinfo"
            | b"/proc/sys"
            | b"/proc/sys/kernel"
            | b"/proc/sys/kernel/tainted"
            | b"/proc/sys/kernel/pid_max" => errno(ERR_EINVAL),
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
            b"/dev/null" | b"/dev/zero" | b"/dev/pulse" | b"/dev/loop0" | b"/dev/loop-control" => {
                Ok(NodeKind::CharDevice)
            }
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
            b"/dev/null" | b"/dev/zero" | b"/dev/pulse" | b"/dev/loop0" | b"/dev/loop-control" => {
                errno(ERR_ENOTDIR)
            }
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
            b"/dev/loop0" => Ok(alloc::vec![0; count as usize]),
            b"/dev/loop-control" => Ok(Vec::new()),
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
            b"/dev/null" | b"/dev/loop0" => Ok(data_len),
            b"/dev/zero" | b"/dev/pulse" | b"/dev/loop-control" => errno(ERR_EINVAL),
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
    disabled: bool,
}

#[derive(Clone, Copy)]
struct EpollWaiter {
    epoll_id: u32,
    wait_id: u64,
}

const EPOLL_READY_TAG: u64 = 0x6000_0000_0000_0000;
const READY_TAG_MASK: u64 = 0xf000_0000_0000_0000;
const MAX_EPOLL_NESTING_DEPTH: u32 = 5;
const EPOLLONESHOT: u32 = 0x4000_0000;

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
                if let Some(target_epoll_id) = epoll_id_from_ready_key(ready_key) {
                    if target_epoll_id == epoll_id {
                        return errno(ERR_EINVAL);
                    }
                    if self.epoll_reaches(target_epoll_id, epoll_id)? {
                        return errno(ERR_ELOOP);
                    }
                    if 1 + self.epoll_nesting_depth(target_epoll_id)? >= MAX_EPOLL_NESTING_DEPTH {
                        return errno(ERR_EINVAL);
                    }
                }
                if self
                    .watchers
                    .iter()
                    .any(|watcher| watcher.epoll_id == epoll_id && watcher.ready_key == ready_key)
                {
                    return errno(ERR_EEXIST);
                }
                self.watchers.push(EpollWatcher {
                    epoll_id,
                    ready_key,
                    events,
                    data,
                    ready: false,
                    disabled: false,
                });
                Ok(())
            }
            EPOLL_CTL_MOD => {
                if let Some(watcher) = self
                    .watchers
                    .iter_mut()
                    .find(|watcher| watcher.epoll_id == epoll_id && watcher.ready_key == ready_key)
                {
                    watcher.events = events;
                    watcher.data = data;
                    watcher.disabled = false;
                    Ok(())
                } else {
                    errno(ERR_ENOENT)
                }
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
            if watcher.epoll_id != epoll_id || watcher.disabled || !watcher.ready || count == limit
            {
                continue;
            }
            out.extend_from_slice(&watcher.events.to_le_bytes());
            out.extend_from_slice(&watcher.data.to_le_bytes());
            if watcher.events & EPOLLONESHOT != 0 {
                watcher.disabled = true;
            }
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

    fn epoll_nesting_depth(&self, epoll_id: u32) -> Result<u32, ServiceCallError> {
        self.epoll_nesting_depth_inner(epoll_id, &mut Vec::new())
    }

    fn epoll_reaches(
        &self,
        start_epoll_id: u32,
        target_epoll_id: u32,
    ) -> Result<bool, ServiceCallError> {
        self.epoll_reaches_inner(start_epoll_id, target_epoll_id, &mut Vec::new())
    }

    fn epoll_reaches_inner(
        &self,
        start_epoll_id: u32,
        target_epoll_id: u32,
        seen: &mut Vec<u32>,
    ) -> Result<bool, ServiceCallError> {
        if start_epoll_id == target_epoll_id {
            return Ok(true);
        }
        if seen.contains(&start_epoll_id) {
            return errno(ERR_ELOOP);
        }
        seen.push(start_epoll_id);
        for watcher in self.watchers.iter().filter(|watcher| watcher.epoll_id == start_epoll_id) {
            if let Some(next_epoll_id) = epoll_id_from_ready_key(watcher.ready_key)
                && self.epoll_reaches_inner(next_epoll_id, target_epoll_id, seen)?
            {
                seen.pop();
                return Ok(true);
            }
        }
        seen.pop();
        Ok(false)
    }

    fn epoll_nesting_depth_inner(
        &self,
        epoll_id: u32,
        seen: &mut Vec<u32>,
    ) -> Result<u32, ServiceCallError> {
        if seen.contains(&epoll_id) {
            return errno(ERR_EINVAL);
        }
        seen.push(epoll_id);
        let mut depth = 0;
        for watcher in self.watchers.iter().filter(|watcher| watcher.epoll_id == epoll_id) {
            if let Some(target_epoll_id) = epoll_id_from_ready_key(watcher.ready_key) {
                let child_depth = 1 + self.epoll_nesting_depth_inner(target_epoll_id, seen)?;
                depth = depth.max(child_depth);
            }
        }
        seen.pop();
        Ok(depth)
    }

    fn signal_waiters(
        &mut self,
        ready_key: u64,
        restart: bool,
    ) -> Result<Vec<u64>, ServiceCallError> {
        if !restart {
            for watcher in &mut self.watchers {
                if watcher.ready_key == ready_key && !watcher.disabled {
                    watcher.ready = true;
                }
            }
        }

        let mut ready_epolls = Vec::new();
        for watcher in &self.watchers {
            if watcher.ready_key == ready_key && !watcher.disabled {
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

fn epoll_id_from_ready_key(ready_key: u64) -> Option<u32> {
    if ready_key & READY_TAG_MASK == EPOLL_READY_TAG {
        u32::try_from(ready_key & !READY_TAG_MASK).ok()
    } else {
        None
    }
}

#[derive(Clone, Copy)]
struct FutexWaiter {
    key: u64,
    wait_id: u64,
    bitset: u32,
}

pub(crate) struct FutexService {
    waiters: Vec<FutexWaiter>,
}

impl FutexService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { waiters: Vec::new() })
    }

    pub(crate) fn register_wait(&mut self, key: u64, wait_id: u64) -> Result<(), ServiceCallError> {
        self.register_wait_bitset(key, wait_id, u32::MAX)
    }

    pub(crate) fn register_wait_bitset(
        &mut self,
        key: u64,
        wait_id: u64,
        bitset: u32,
    ) -> Result<(), ServiceCallError> {
        self.waiters.push(FutexWaiter { key, wait_id, bitset });
        Ok(())
    }

    pub(crate) fn wake(&mut self, key: u64, max_count: u32) -> Result<Vec<u64>, ServiceCallError> {
        self.wake_bitset(key, max_count, u32::MAX)
    }

    pub(crate) fn wake_bitset(
        &mut self,
        key: u64,
        max_count: u32,
        bitset: u32,
    ) -> Result<Vec<u64>, ServiceCallError> {
        let mut remaining = max_count as usize;
        let mut wait_ids = Vec::new();
        self.waiters.retain(|waiter| {
            if waiter.key == key && waiter.bitset & bitset != 0 && remaining > 0 {
                wait_ids.push(waiter.wait_id);
                remaining -= 1;
                false
            } else {
                true
            }
        });
        Ok(wait_ids)
    }

    pub(crate) fn requeue(
        &mut self,
        src_key: u64,
        requeue_count: u32,
        dst_key: u64,
        wake_count: u32,
    ) -> Result<(u32, Vec<u64>), ServiceCallError> {
        let mut wake_remaining = wake_count as usize;
        let mut requeue_remaining = requeue_count as usize;
        let mut wait_ids = Vec::new();
        let mut total = 0u32;

        self.waiters.retain(|waiter| {
            if waiter.key == src_key && wake_remaining > 0 {
                wait_ids.push(waiter.wait_id);
                wake_remaining -= 1;
                total = total.saturating_add(1);
                false
            } else {
                true
            }
        });

        for waiter in &mut self.waiters {
            if waiter.key != src_key || requeue_remaining == 0 {
                continue;
            }
            waiter.key = dst_key;
            requeue_remaining -= 1;
            total = total.saturating_add(1);
        }

        Ok((total, wait_ids))
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

fn normalize_path(path: &[u8]) -> Vec<u8> {
    if path.len() > 1 && path.ends_with(b"/") {
        path[..path.len() - 1].to_vec()
    } else {
        path.to_vec()
    }
}

fn file_name(path: &[u8]) -> Option<&[u8]> {
    path.rsplit(|byte| *byte == b'/').find(|part| !part.is_empty())
}

fn join_resource_path(root: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = Vec::new();
    if root.is_empty() {
        path.push(b'/');
    } else {
        path.extend_from_slice(root);
        if !root.ends_with(b"/") {
            path.push(b'/');
        }
    }
    path.extend_from_slice(name);
    normalize_path(&path)
}

fn linux_user_resource_for_path(path: &[u8]) -> Option<&'static LinuxUserResourceFile> {
    let name = file_name(path)?;
    if !looks_like_ltp_resource_path(path, name) {
        return None;
    }
    LINUX_USER_RESOURCE_FILES.iter().find(|resource| file_name(resource.path) == Some(name))
}

fn looks_like_ltp_resource_path(path: &[u8], name: &[u8]) -> bool {
    let Some(parent) = parent_path(path) else {
        return false;
    };
    if parent == b"/tmp"
        || parent == b"/sandbox"
        || parent == b"/"
        || parent == b"/datafiles"
        || parent == b"/tmp/datafiles"
        || parent == b"/sandbox/datafiles"
    {
        return true;
    }
    if path.windows(b"/datafiles/".len()).any(|window| window == b"/datafiles/") {
        return true;
    }
    parent.starts_with(b"/tmp/LTP_") && !name.is_empty()
}

fn parent_path(path: &[u8]) -> Option<Vec<u8>> {
    if path == b"/" {
        return None;
    }
    let trimmed =
        if path.len() > 1 && path.ends_with(b"/") { &path[..path.len() - 1] } else { path };
    let slash = trimmed.iter().rposition(|byte| *byte == b'/')?;
    if slash == 0 { Some(b"/".to_vec()) } else { Some(trimmed[..slash].to_vec()) }
}

fn child_name<'a>(dir: &[u8], path: &'a [u8]) -> Option<&'a [u8]> {
    let rest = if dir == b"/" {
        path.strip_prefix(b"/")?
    } else {
        path.strip_prefix(dir)?.strip_prefix(b"/")?
    };
    if rest.is_empty() || rest.contains(&b'/') { None } else { Some(rest) }
}

fn is_descendant_path(path: &[u8], prefix: &[u8]) -> bool {
    path != prefix && subtree_suffix(path, prefix).is_some()
}

fn replace_path_prefix(path: &[u8], old_prefix: &[u8], new_prefix: &[u8]) -> Option<Vec<u8>> {
    let suffix = subtree_suffix(path, old_prefix)?;
    let mut out = Vec::with_capacity(new_prefix.len() + suffix.len());
    out.extend_from_slice(new_prefix);
    out.extend_from_slice(suffix);
    Some(normalize_path(&out))
}

fn subtree_suffix<'a>(path: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() || rest.starts_with(b"/") { Some(rest) } else { None }
}
