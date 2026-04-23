use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;

use wasmi::{Engine, Error, Extern, Instance, Linker, Memory, Module, Store, TypedFunc};

use crate::interrupts;
use crate::serial;
use crate::serial_println;
use vmos_abi::{
    ERR_EBADF, ERR_EINVAL, FD_STDOUT, NodeKind, PackedStep, PlanKind, SYS_CLOSE, SYS_GETCWD,
    SYS_GETDENTS64, SYS_NANOSLEEP, SYS_OPENAT, SYS_READ, SYS_READLINKAT, SYS_UNAME, SYS_WRITE,
    ServiceRoute, StepTag, SyscallContext,
};

const CONSOLE_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_CONSOLE_SERVICE_WASM"));
const DEVFS_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_DEVFS_SERVICE_WASM"));
const LINUX_SYSCALL_WASM: &[u8] = include_bytes!(env!("VMOS_LINUX_SYSCALL_WASM"));
const PROCFS_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_PROCFS_SERVICE_WASM"));
const VFS_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_VFS_SERVICE_WASM"));
const WASM_APP_WASM: &[u8] = include_bytes!(env!("VMOS_WASM_APP_WASM"));

const CURRENT_CWD: &[u8] = b"/sandbox";
const UNAME_BYTES: &[u8] = b"VmOS Prototype2 x86_64 supervisor";

pub fn run() -> Result<(), &'static str> {
    let engine = Engine::default();
    crate::kdebug!("wasmi engine ready");
    let mut runtime = PrototypeRuntime::new(&engine)?;
    crate::kdebug!("prototype2 runtime ready");

    runtime.run_wasm_frontend()?;
    runtime.run_linux_stdio_demo()?;
    runtime.run_linux_vfs_demo()?;
    runtime.run_linux_procfs_demo()?;
    runtime.run_linux_devfs_demo()?;
    runtime.run_linux_metadata_demo()?;
    runtime.run_sleep_demo()?;
    runtime.run_procfs_recovery_demo()?;

    Ok(())
}

struct PrototypeRuntime<'engine> {
    console: ConsoleService,
    vfs: VfsService,
    procfs: ProcfsService<'engine>,
    devfs: DevfsService,
    linux: LinuxFrontend<'engine>,
    app: WasmApp<'engine>,
    fd_table: Vec<Option<FdEntry>>,
    fault: Option<InjectedFault>,
}

impl<'engine> PrototypeRuntime<'engine> {
    fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        Ok(Self {
            console: ConsoleService::new(engine)?,
            vfs: VfsService::new(engine)?,
            procfs: ProcfsService::new(engine)?,
            devfs: DevfsService::new(engine)?,
            linux: LinuxFrontend::new(engine)?,
            app: WasmApp::new(engine)?,
            fd_table: vec![None, None, None],
            fault: None,
        })
    }

    fn run_wasm_frontend(&mut self) -> Result<(), &'static str> {
        serial_println!("== wasm frontend demo ==");
        let step = self.app.run()?;
        self.handle_wasm_step("wasm_app", step)?;
        Ok(())
    }

    fn run_linux_stdio_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== linux stdio demo ==");
        let message = b"linux frontend: hello via syscall planner\n";
        let result = self.sys_write(FD_STDOUT, message)?;
        serial_println!("linux write returned {}", result);
        Ok(())
    }

    fn run_linux_vfs_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== linux vfs demo ==");
        let fd = self.open_path(b"/sandbox/hello.txt")?;
        serial_println!("openat('/sandbox/hello.txt') -> fd {}", fd);
        let bytes = self.read_fd(fd, 128)?;
        serial::write_bytes(&bytes);
        if !bytes.ends_with(b"\n") {
            serial_println!();
        }
        let rc = self.close_fd(fd)?;
        serial_println!("close(fd={}) -> {}", fd, rc);
        Ok(())
    }

    fn run_linux_procfs_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== linux procfs demo ==");
        let fd = self.open_path(b"/proc/self/status")?;
        serial_println!("openat('/proc/self/status') -> fd {}", fd);
        let bytes = self.read_fd(fd, 256)?;
        serial::write_bytes(&bytes);
        if !bytes.ends_with(b"\n") {
            serial_println!();
        }
        self.close_fd(fd)?;
        Ok(())
    }

    fn run_linux_devfs_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== linux devfs demo ==");
        let fd = self.open_path(b"/dev/zero")?;
        serial_println!("openat('/dev/zero') -> fd {}", fd);
        let bytes = self.read_fd(fd, 8)?;
        serial_println!("read(fd={}) -> {}", fd, format_hex(&bytes));
        self.close_fd(fd)?;
        Ok(())
    }

    fn run_linux_metadata_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== linux metadata demo ==");

        let root_fd = self.open_path(b"/")?;
        let dents = self.getdents(root_fd, 256)?;
        serial_println!("getdents64('/'):");
        serial::write_bytes(&dents);
        if !dents.ends_with(b"\n") {
            serial_println!();
        }
        self.close_fd(root_fd)?;

        let cwd = self.getcwd()?;
        serial_println!(
            "getcwd() -> {}",
            core::str::from_utf8(&cwd).unwrap_or("<invalid utf8>")
        );

        let link = self.readlinkat(b"/sandbox/readme.link")?;
        serial_println!(
            "readlinkat('/sandbox/readme.link') -> {}",
            core::str::from_utf8(&link).unwrap_or("<invalid utf8>")
        );

        let uname = self.uname()?;
        serial_println!(
            "uname() -> {}",
            core::str::from_utf8(&uname).unwrap_or("<invalid utf8>")
        );

        Ok(())
    }

    fn run_sleep_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== explicit suspend/resume demo ==");
        let pending = self.dispatch_linux_call(
            "linux_sleep",
            SyscallContext::new(SYS_NANOSLEEP, [25, 0, 0, 0, 0, 0]),
        )?;
        let (token, delay_ms) = match pending {
            LinuxCallResult::Pending { token, delay_ms } => (token, delay_ms),
            _ => return Err("sleep path did not enter pending state"),
        };

        crate::kinfo!(
            "linux_syscall returned Pending(token={}, delay_hint={}ms)",
            token,
            delay_ms
        );
        crate::kinfo!("waiting for timer wakeup");
        interrupts::sleep_ms(delay_ms);

        let resumed = self.linux.resume_wait(token)?;
        match self.execute_linux_step("linux_resume", resumed)? {
            LinuxCallResult::Ret(count) => {
                crate::kinfo!("nanosleep completed with explicit resume");
                serial_println!("resume path returned {}", count);
                Ok(())
            }
            _ => Err("resume path returned an unexpected result"),
        }
    }

    fn run_procfs_recovery_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== service recovery demo ==");
        let fd = self.open_path(b"/proc/self/status")?;
        self.fault = Some(InjectedFault::ProcfsRead);
        let bytes = self.read_fd(fd, 128)?;
        self.close_fd(fd)?;
        serial_println!("procfs recovered after injected fault");
        serial::write_bytes(&bytes);
        if !bytes.ends_with(b"\n") {
            serial_println!();
        }
        Ok(())
    }

    fn handle_wasm_step(&mut self, label: &str, step: u64) -> Result<(), &'static str> {
        let decoded = PackedStep::decode(step);
        match decoded.tag {
            StepTag::ConsoleWrite => {
                let len = u32::try_from(decoded.value)
                    .map_err(|_| "wasm console write length was negative")?;
                crate::kdebug!(
                    "{}: ConsoleWrite(ptr=0x{:x}, len={})",
                    label,
                    decoded.aux,
                    len
                );
                let bytes = self.app.read_bytes(decoded.aux, len)?;
                self.console.write_bytes(&bytes, false)
            }
            StepTag::Ready => Ok(()),
            _ => Err("wasm frontend returned an unexpected step"),
        }
    }

    fn sys_write(&mut self, fd: u32, bytes: &[u8]) -> Result<i64, &'static str> {
        let (ptr, len) = self.linux.write_arg_bytes(bytes)?;
        let result = self.dispatch_linux_call(
            "linux_write",
            SyscallContext::new(SYS_WRITE, [fd as u64, ptr as u64, len as u64, 0, 0, 0]),
        )?;
        self.expect_ret("write", result)
    }

    fn open_path(&mut self, path: &[u8]) -> Result<u32, &'static str> {
        let (ptr, len) = self.linux.write_arg_bytes(path)?;
        let result = self.dispatch_linux_call(
            "openat",
            SyscallContext::new(SYS_OPENAT, [0, ptr as u64, len as u64, 0, 0, 0]),
        )?;
        let fd = self.expect_ret("openat", result)?;
        if fd >= 0 {
            Ok(fd as u32)
        } else {
            Err(if fd == -(ERR_EBADF as i64) {
                "openat returned EBADF"
            } else {
                "openat returned an error"
            })
        }
    }

    fn read_fd(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, &'static str> {
        let result = self.dispatch_linux_call(
            "read",
            SyscallContext::new(SYS_READ, [fd as u64, 0, count as u64, 0, 0, 0]),
        )?;
        match result {
            LinuxCallResult::Bytes(bytes) => Ok(bytes),
            LinuxCallResult::Ret(0) => Ok(Vec::new()),
            LinuxCallResult::Ret(_) => Err("read returned a numeric error"),
            LinuxCallResult::Pending { token, delay_ms } => {
                crate::kwarn!(
                    "read unexpectedly returned Pending(token={}, delay_ms={})",
                    token,
                    delay_ms
                );
                Err("read returned an unexpected pending result")
            }
            LinuxCallResult::Exit(code) => {
                crate::kwarn!("read unexpectedly returned Exit({})", code);
                Err("read returned an unexpected exit result")
            }
        }
    }

    fn getdents(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, &'static str> {
        let result = self.dispatch_linux_call(
            "getdents64",
            SyscallContext::new(SYS_GETDENTS64, [fd as u64, 0, count as u64, 0, 0, 0]),
        )?;
        self.expect_bytes("getdents64", result)
    }

    fn readlinkat(&mut self, path: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (ptr, len) = self.linux.write_arg_bytes(path)?;
        let result = self.dispatch_linux_call(
            "readlinkat",
            SyscallContext::new(SYS_READLINKAT, [0, ptr as u64, len as u64, 0, 0, 0]),
        )?;
        self.expect_bytes("readlinkat", result)
    }

    fn getcwd(&mut self) -> Result<Vec<u8>, &'static str> {
        let result = self.dispatch_linux_call(
            "getcwd",
            SyscallContext::new(SYS_GETCWD, [0, 256, 0, 0, 0, 0]),
        )?;
        self.expect_bytes("getcwd", result)
    }

    fn uname(&mut self) -> Result<Vec<u8>, &'static str> {
        let result =
            self.dispatch_linux_call("uname", SyscallContext::new(SYS_UNAME, [0, 0, 0, 0, 0, 0]))?;
        self.expect_bytes("uname", result)
    }

    fn close_fd(&mut self, fd: u32) -> Result<i64, &'static str> {
        let result = self.dispatch_linux_call(
            "close",
            SyscallContext::new(SYS_CLOSE, [fd as u64, 0, 0, 0, 0, 0]),
        )?;
        self.expect_ret("close", result)
    }

    fn dispatch_linux_call(
        &mut self,
        label: &str,
        ctx: SyscallContext,
    ) -> Result<LinuxCallResult, &'static str> {
        let step = self.linux.dispatch(ctx)?;
        self.execute_linux_step(label, step)
    }

    fn expect_ret(
        &self,
        context: &'static str,
        result: LinuxCallResult,
    ) -> Result<i64, &'static str> {
        match result {
            LinuxCallResult::Ret(ret) => Ok(ret),
            LinuxCallResult::Bytes(_) => Err("linux call returned bytes instead of an integer"),
            LinuxCallResult::Pending { token, delay_ms } => {
                crate::kwarn!(
                    "{} unexpectedly returned Pending(token={}, delay_ms={})",
                    context,
                    token,
                    delay_ms
                );
                Err("linux call returned an unexpected pending result")
            }
            LinuxCallResult::Exit(code) => {
                crate::kwarn!("{} unexpectedly returned Exit({})", context, code);
                Err("linux call returned an unexpected exit result")
            }
        }
    }

    fn expect_bytes(
        &self,
        context: &'static str,
        result: LinuxCallResult,
    ) -> Result<Vec<u8>, &'static str> {
        match result {
            LinuxCallResult::Bytes(bytes) => Ok(bytes),
            LinuxCallResult::Ret(ret) => {
                crate::kwarn!("{} unexpectedly returned Ret({})", context, ret);
                Err("linux call returned an integer instead of bytes")
            }
            LinuxCallResult::Pending { token, delay_ms } => {
                crate::kwarn!(
                    "{} unexpectedly returned Pending(token={}, delay_ms={})",
                    context,
                    token,
                    delay_ms
                );
                Err("linux call returned an unexpected pending result")
            }
            LinuxCallResult::Exit(code) => {
                crate::kwarn!("{} unexpectedly returned Exit({})", context, code);
                Err("linux call returned an unexpected exit result")
            }
        }
    }

    fn execute_linux_step(
        &mut self,
        label: &str,
        step: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        let decoded = PackedStep::decode(step);
        match decoded.tag {
            StepTag::Ready => {
                crate::kdebug!("{}: Ready({})", label, decoded.value);
                Ok(LinuxCallResult::Ret(decoded.value as i64))
            }
            StepTag::Pending => Ok(LinuxCallResult::Pending {
                token: decoded.aux,
                delay_ms: decoded.value as u32,
            }),
            StepTag::Plan => {
                let kind = PlanKind::from_raw(decoded.aux).ok_or("linux plan kind was invalid")?;
                let plan = self.linux.current_plan(kind)?;
                self.execute_linux_plan(label, plan)
            }
            StepTag::ConsoleWrite => {
                let len = u32::try_from(decoded.value)
                    .map_err(|_| "linux console write length was negative")?;
                let bytes = self.linux.read_bytes(decoded.aux, len)?;
                self.console.write_bytes(&bytes, false)?;
                Ok(LinuxCallResult::Ret(len as i64))
            }
            StepTag::Exit => Ok(LinuxCallResult::Exit(decoded.value)),
            StepTag::Error => Ok(LinuxCallResult::Ret(decoded.value as i64)),
        }
    }

    fn execute_linux_plan(
        &mut self,
        label: &str,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        crate::kdebug!("{}: {:?}", label, plan.kind);
        match plan.kind {
            PlanKind::Write => self.plan_write(plan),
            PlanKind::OpenAt => self.plan_openat(plan),
            PlanKind::Read => self.plan_read(plan),
            PlanKind::Close => self.plan_close(plan),
            PlanKind::GetDents64 => self.plan_getdents(plan),
            PlanKind::ReadLinkAt => self.plan_readlinkat(plan),
            PlanKind::GetCwd => Ok(LinuxCallResult::Bytes(CURRENT_CWD.to_vec())),
            PlanKind::Uname => Ok(LinuxCallResult::Bytes(UNAME_BYTES.to_vec())),
        }
    }

    fn plan_write(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "write plan fd overflowed")?;
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "write plan ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "write plan len overflowed")?;
        let bytes = self.linux.read_bytes(ptr, len)?;

        if fd == FD_STDOUT || fd == vmos_abi::FD_STDERR {
            self.console.write_bytes(&bytes, false)?;
            return Ok(LinuxCallResult::Ret(bytes.len() as i64));
        }

        let (route, _node, _cursor, path) = self
            .fd_snapshot(fd)
            .map_err(|_| "write targeted an unknown file descriptor")?;
        match route {
            ServiceRoute::Devfs => {
                match self.devfs.write_device(&path, bytes.len() as u32, false) {
                    Ok(count) => Ok(LinuxCallResult::Ret(count as i64)),
                    Err(ServiceCallError::Errno(errno)) => {
                        Ok(LinuxCallResult::Ret(-(errno as i64)))
                    }
                    Err(ServiceCallError::Trap(_)) => Err("devfs_service trapped during write"),
                    Err(ServiceCallError::Invalid(err)) => Err(err),
                }
            }
            _ => Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64))),
        }
    }

    fn plan_openat(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "openat ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "openat len overflowed")?;
        let path = self.linux.read_bytes(ptr, len)?;

        match self.lookup_path(&path) {
            Ok(info) => {
                let fd = self.alloc_fd(FdEntry {
                    route: info.route,
                    node: info.node,
                    path,
                    cursor: 0,
                });
                Ok(LinuxCallResult::Ret(fd as i64))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("openat: {}", reason);
                Err("a service trapped during openat")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_read(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "read plan fd overflowed")?;
        let count = u32::try_from(plan.args[1]).map_err(|_| "read plan count overflowed")?;
        match self.read_from_fd(fd, count) {
            Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("read: {}", reason);
                Err("a service trapped during read")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_close(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "close plan fd overflowed")?;
        if fd < 3 {
            return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64)));
        }

        let slot = self
            .fd_table
            .get_mut(fd as usize)
            .ok_or("close targeted an out-of-range file descriptor")?;
        if slot.take().is_none() {
            return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64)));
        }

        Ok(LinuxCallResult::Ret(0))
    }

    fn plan_getdents(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "getdents fd overflowed")?;
        let count = u32::try_from(plan.args[1]).map_err(|_| "getdents count overflowed")?;
        match self.read_dir_entries(fd, count) {
            Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("getdents64: {}", reason);
                Err("a service trapped during getdents")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_readlinkat(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "readlink ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "readlink len overflowed")?;
        let path = self.linux.read_bytes(ptr, len)?;

        match self.read_link_path(&path) {
            Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("readlinkat: {}", reason);
                Err("a service trapped during readlink")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn lookup_path(&mut self, path: &[u8]) -> Result<LookupInfo, ServiceCallError> {
        let info = self.vfs.lookup(path, false)?;
        match info.route {
            ServiceRoute::Vfs => Ok(info),
            ServiceRoute::Procfs => {
                let node = self.procfs.lookup(path, false)?;
                Ok(LookupInfo {
                    route: ServiceRoute::Procfs,
                    node,
                })
            }
            ServiceRoute::Devfs => {
                let node = self.devfs.lookup(path, false)?;
                Ok(LookupInfo {
                    route: ServiceRoute::Devfs,
                    node,
                })
            }
        }
    }

    fn read_from_fd(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, ServiceCallError> {
        let (route, node, cursor, path) = self.fd_snapshot(fd)?;
        if node == NodeKind::Directory {
            return Err(ServiceCallError::Errno(vmos_abi::ERR_EISDIR));
        }

        let bytes = match route {
            ServiceRoute::Vfs => self.vfs.read_file(&path, false)?,
            ServiceRoute::Procfs => self.procfs_read_with_recovery(&path)?,
            ServiceRoute::Devfs => self.devfs.read_device(&path, count, false)?,
        };

        let start = cursor.min(bytes.len());
        let end = start.saturating_add(count as usize).min(bytes.len());
        let chunk = bytes[start..end].to_vec();
        self.set_fd_cursor(fd, end)?;
        Ok(chunk)
    }

    fn read_dir_entries(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, ServiceCallError> {
        let (route, node, cursor, path) = self.fd_snapshot(fd)?;
        if node != NodeKind::Directory {
            return Err(ServiceCallError::Errno(vmos_abi::ERR_ENOTDIR));
        }

        let bytes = match route {
            ServiceRoute::Vfs => self.vfs.list_dir(&path, false)?,
            ServiceRoute::Procfs => self.procfs.list_dir(&path, false)?,
            ServiceRoute::Devfs => self.devfs.list_dir(&path, false)?,
        };

        let start = cursor.min(bytes.len());
        let end = start.saturating_add(count as usize).min(bytes.len());
        let chunk = bytes[start..end].to_vec();
        self.set_fd_cursor(fd, end)?;
        Ok(chunk)
    }

    fn read_link_path(&mut self, path: &[u8]) -> Result<Vec<u8>, ServiceCallError> {
        let info = self.lookup_path(path)?;
        if info.node != NodeKind::Symlink {
            return Err(ServiceCallError::Errno(ERR_EINVAL));
        }

        match info.route {
            ServiceRoute::Vfs => self.vfs.read_link(path, false),
            ServiceRoute::Procfs => self.procfs.read_link(path, false),
            ServiceRoute::Devfs => Err(ServiceCallError::Errno(ERR_EINVAL)),
        }
    }

    fn procfs_read_with_recovery(&mut self, path: &[u8]) -> Result<Vec<u8>, ServiceCallError> {
        let inject_fault = self.take_fault(InjectedFault::ProcfsRead);
        match self.procfs.read_file(path, inject_fault) {
            Ok(bytes) => Ok(bytes),
            Err(ServiceCallError::Trap(_)) if inject_fault => {
                crate::kinfo!("procfs_service trapped; recreating service store");
                let engine = self.procfs.engine;
                self.procfs = ProcfsService::new(engine).map_err(ServiceCallError::Invalid)?;
                self.procfs.read_file(path, false)
            }
            Err(err) => Err(err),
        }
    }

    fn take_fault(&mut self, target: InjectedFault) -> bool {
        match self.fault {
            Some(current) if current == target => {
                self.fault = None;
                true
            }
            _ => false,
        }
    }

    fn alloc_fd(&mut self, entry: FdEntry) -> u32 {
        for (fd, slot) in self.fd_table.iter_mut().enumerate().skip(3) {
            if slot.is_none() {
                *slot = Some(entry);
                return fd as u32;
            }
        }

        self.fd_table.push(Some(entry));
        (self.fd_table.len() - 1) as u32
    }

    fn fd_entry(&self, fd: u32) -> Option<&FdEntry> {
        self.fd_table.get(fd as usize)?.as_ref()
    }

    fn fd_snapshot(
        &self,
        fd: u32,
    ) -> Result<(ServiceRoute, NodeKind, usize, Vec<u8>), ServiceCallError> {
        let entry = self
            .fd_entry(fd)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        Ok((entry.route, entry.node, entry.cursor, entry.path.clone()))
    }

    fn set_fd_cursor(&mut self, fd: u32, cursor: usize) -> Result<(), ServiceCallError> {
        let entry = self
            .fd_table
            .get_mut(fd as usize)
            .and_then(Option::as_mut)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        entry.cursor = cursor;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InjectedFault {
    ProcfsRead,
}

#[derive(Debug)]
enum LinuxCallResult {
    Ret(i64),
    Bytes(Vec<u8>),
    Pending { token: u32, delay_ms: u32 },
    Exit(i32),
}

#[derive(Clone, Copy, Debug)]
struct LinuxPlan {
    kind: PlanKind,
    args: [u64; 6],
}

#[derive(Clone, Debug)]
struct FdEntry {
    route: ServiceRoute,
    node: NodeKind,
    path: Vec<u8>,
    cursor: usize,
}

#[derive(Clone, Copy, Debug)]
struct LookupInfo {
    route: ServiceRoute,
    node: NodeKind,
}

#[derive(Debug)]
enum ServiceCallError {
    Trap(&'static str),
    Errno(i32),
    Invalid(&'static str),
}

struct ConsoleService {
    store: Store<()>,
    memory: Memory,
    buffer_ptr: u32,
    buffer_capacity: u32,
    commit_write: TypedFunc<(u32, u32), i32>,
}

impl ConsoleService {
    fn new(engine: &Engine) -> Result<Self, &'static str> {
        let module = load_module(engine, CONSOLE_SERVICE_WASM)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| "failed to instantiate console_service")?;
        let memory = get_memory(&mut store, &instance)?;
        let buffer_ptr = instance
            .get_typed_func::<(), u32>(&store, "buffer_ptr")
            .map_err(|_| "missing console buffer_ptr export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch console buffer ptr")?;
        let buffer_capacity = instance
            .get_typed_func::<(), u32>(&store, "buffer_capacity")
            .map_err(|_| "missing console buffer_capacity export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch console buffer capacity")?;
        let commit_write = instance
            .get_typed_func::<(u32, u32), i32>(&store, "commit_write")
            .map_err(|_| "missing console commit_write export")?;

        Ok(Self {
            store,
            memory,
            buffer_ptr,
            buffer_capacity,
            commit_write,
        })
    }

    fn write_bytes(&mut self, bytes: &[u8], inject_fault: bool) -> Result<(), &'static str> {
        if bytes.len() > self.buffer_capacity as usize {
            return Err("console_service buffer was too small");
        }

        self.memory
            .write(&mut self.store, self.buffer_ptr as usize, bytes)
            .map_err(|_| "failed to write console_service buffer")?;
        let inject = if inject_fault { 1 } else { 0 };
        let rc = self
            .commit_write
            .call(&mut self.store, (bytes.len() as u32, inject))
            .map_err(|_| "console_service trapped")?;
        if rc != 0 {
            return Err("console_service rejected the write");
        }

        let echoed = read_memory(
            &self.memory,
            &self.store,
            self.buffer_ptr,
            bytes.len() as u32,
        )?;
        serial::write_bytes(&echoed);
        Ok(())
    }
}

struct BufferedStore {
    store: Store<()>,
    memory: Memory,
    request_ptr: u32,
    request_capacity: u32,
    response_ptr: u32,
    response_capacity: u32,
}

impl BufferedStore {
    fn new(
        engine: &Engine,
        bytes: &[u8],
        module_name: &'static str,
    ) -> Result<(Self, Instance), &'static str> {
        let module = load_module(engine, bytes)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| module_name)?;
        let memory = get_memory(&mut store, &instance)?;
        let request_ptr = instance
            .get_typed_func::<(), u32>(&store, "request_ptr")
            .map_err(|_| "missing service request_ptr export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch service request_ptr")?;
        let request_capacity = instance
            .get_typed_func::<(), u32>(&store, "request_capacity")
            .map_err(|_| "missing service request_capacity export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch service request_capacity")?;
        let response_ptr = instance
            .get_typed_func::<(), u32>(&store, "response_ptr")
            .map_err(|_| "missing service response_ptr export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch service response_ptr")?;
        let response_capacity = instance
            .get_typed_func::<(), u32>(&store, "response_capacity")
            .map_err(|_| "missing service response_capacity export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch service response_capacity")?;

        Ok((
            Self {
                store,
                memory,
                request_ptr,
                request_capacity,
                response_ptr,
                response_capacity,
            },
            instance,
        ))
    }

    fn write_request(&mut self, bytes: &[u8]) -> Result<u32, &'static str> {
        if bytes.len() > self.request_capacity as usize {
            return Err("service request buffer overflowed");
        }
        self.memory
            .write(&mut self.store, self.request_ptr as usize, bytes)
            .map_err(|_| "failed to write service request buffer")?;
        Ok(bytes.len() as u32)
    }

    fn read_response(&mut self, len: u32) -> Result<Vec<u8>, &'static str> {
        if len > self.response_capacity {
            return Err("service response exceeded capacity");
        }
        read_memory(&self.memory, &self.store, self.response_ptr, len)
    }
}

struct VfsService {
    io: BufferedStore,
    lookup: TypedFunc<(u32, u32), i32>,
    route_kind: TypedFunc<(), u32>,
    node_kind: TypedFunc<(), u32>,
    read_file: TypedFunc<(u32, u32), i32>,
    list_dir: TypedFunc<(u32, u32), i32>,
    read_link: TypedFunc<(u32, u32), i32>,
}

impl VfsService {
    fn new(engine: &Engine) -> Result<Self, &'static str> {
        let (io, instance) = BufferedStore::new(
            engine,
            VFS_SERVICE_WASM,
            "failed to instantiate vfs_service",
        )?;
        let lookup = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "lookup")
            .map_err(|_| "missing vfs lookup export")?;
        let route_kind = instance
            .get_typed_func::<(), u32>(&io.store, "route_kind")
            .map_err(|_| "missing vfs route_kind export")?;
        let node_kind = instance
            .get_typed_func::<(), u32>(&io.store, "node_kind")
            .map_err(|_| "missing vfs node_kind export")?;
        let read_file = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "read_file")
            .map_err(|_| "missing vfs read_file export")?;
        let list_dir = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "list_dir")
            .map_err(|_| "missing vfs list_dir export")?;
        let read_link = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "read_link")
            .map_err(|_| "missing vfs read_link export")?;

        Ok(Self {
            io,
            lookup,
            route_kind,
            node_kind,
            read_file,
            list_dir,
            read_link,
        })
    }

    fn lookup(&mut self, path: &[u8], inject_fault: bool) -> Result<LookupInfo, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        expect_ok(
            self.lookup
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )?;
        let route = ServiceRoute::from_raw(
            self.route_kind
                .call(&mut self.io.store, ())
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )
        .ok_or(ServiceCallError::Invalid(
            "vfs_service returned an invalid route",
        ))?;
        let node = NodeKind::from_raw(
            self.node_kind
                .call(&mut self.io.store, ())
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )
        .ok_or(ServiceCallError::Invalid(
            "vfs_service returned an invalid node kind",
        ))?;

        Ok(LookupInfo { route, node })
    }

    fn read_file(&mut self, path: &[u8], inject_fault: bool) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.read_file
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }

    fn list_dir(&mut self, path: &[u8], inject_fault: bool) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.list_dir
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }

    fn read_link(&mut self, path: &[u8], inject_fault: bool) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.read_link
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }
}

struct ProcfsService<'engine> {
    engine: &'engine Engine,
    io: BufferedStore,
    lookup: TypedFunc<(u32, u32), i32>,
    node_kind: TypedFunc<(), u32>,
    read_file: TypedFunc<(u32, u32), i32>,
    list_dir: TypedFunc<(u32, u32), i32>,
    read_link: TypedFunc<(u32, u32), i32>,
}

impl<'engine> ProcfsService<'engine> {
    fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        let (io, instance) = BufferedStore::new(
            engine,
            PROCFS_SERVICE_WASM,
            "failed to instantiate procfs_service",
        )?;
        let lookup = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "lookup")
            .map_err(|_| "missing procfs lookup export")?;
        let node_kind = instance
            .get_typed_func::<(), u32>(&io.store, "node_kind")
            .map_err(|_| "missing procfs node_kind export")?;
        let read_file = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "read_file")
            .map_err(|_| "missing procfs read_file export")?;
        let list_dir = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "list_dir")
            .map_err(|_| "missing procfs list_dir export")?;
        let read_link = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "read_link")
            .map_err(|_| "missing procfs read_link export")?;

        Ok(Self {
            engine,
            io,
            lookup,
            node_kind,
            read_file,
            list_dir,
            read_link,
        })
    }

    fn lookup(&mut self, path: &[u8], inject_fault: bool) -> Result<NodeKind, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        expect_ok(
            self.lookup
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("procfs_service trapped"))?,
        )?;
        NodeKind::from_raw(
            self.node_kind
                .call(&mut self.io.store, ())
                .map_err(|_| ServiceCallError::Trap("procfs_service trapped"))?,
        )
        .ok_or(ServiceCallError::Invalid(
            "procfs_service returned an invalid node kind",
        ))
    }

    fn read_file(&mut self, path: &[u8], inject_fault: bool) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.read_file
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("procfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }

    fn list_dir(&mut self, path: &[u8], inject_fault: bool) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.list_dir
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("procfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }

    fn read_link(&mut self, path: &[u8], inject_fault: bool) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.read_link
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("procfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }
}

struct DevfsService {
    io: BufferedStore,
    lookup: TypedFunc<(u32, u32), i32>,
    node_kind: TypedFunc<(), u32>,
    list_dir: TypedFunc<(u32, u32), i32>,
    read_device: TypedFunc<(u32, u32, u32), i32>,
    write_device: TypedFunc<(u32, u32, u32), i32>,
}

impl DevfsService {
    fn new(engine: &Engine) -> Result<Self, &'static str> {
        let (io, instance) = BufferedStore::new(
            engine,
            DEVFS_SERVICE_WASM,
            "failed to instantiate devfs_service",
        )?;
        let lookup = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "lookup")
            .map_err(|_| "missing devfs lookup export")?;
        let node_kind = instance
            .get_typed_func::<(), u32>(&io.store, "node_kind")
            .map_err(|_| "missing devfs node_kind export")?;
        let list_dir = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "list_dir")
            .map_err(|_| "missing devfs list_dir export")?;
        let read_device = instance
            .get_typed_func::<(u32, u32, u32), i32>(&io.store, "read_device")
            .map_err(|_| "missing devfs read_device export")?;
        let write_device = instance
            .get_typed_func::<(u32, u32, u32), i32>(&io.store, "write_device")
            .map_err(|_| "missing devfs write_device export")?;

        Ok(Self {
            io,
            lookup,
            node_kind,
            list_dir,
            read_device,
            write_device,
        })
    }

    fn lookup(&mut self, path: &[u8], inject_fault: bool) -> Result<NodeKind, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        expect_ok(
            self.lookup
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("devfs_service trapped"))?,
        )?;
        NodeKind::from_raw(
            self.node_kind
                .call(&mut self.io.store, ())
                .map_err(|_| ServiceCallError::Trap("devfs_service trapped"))?,
        )
        .ok_or(ServiceCallError::Invalid(
            "devfs_service returned an invalid node kind",
        ))
    }

    fn list_dir(&mut self, path: &[u8], inject_fault: bool) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.list_dir
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("devfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }

    fn read_device(
        &mut self,
        path: &[u8],
        count: u32,
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.read_device
                .call(&mut self.io.store, (path_len, count, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("devfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }

    fn write_device(
        &mut self,
        path: &[u8],
        data_len: u32,
        inject_fault: bool,
    ) -> Result<u32, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        expect_len(
            self.write_device
                .call(
                    &mut self.io.store,
                    (path_len, data_len, inject_fault as u32),
                )
                .map_err(|_| ServiceCallError::Trap("devfs_service trapped"))?,
        )
    }
}

struct LinuxFrontend<'engine> {
    store: Store<()>,
    memory: Memory,
    arg_buffer_ptr: u32,
    arg_buffer_capacity: u32,
    dispatch: TypedFunc<(u64, u64, u64, u64, u64, u64, u64), u64>,
    resume_wait: TypedFunc<u32, u64>,
    plan_arg: TypedFunc<u32, u64>,
    _engine: &'engine Engine,
}

impl<'engine> LinuxFrontend<'engine> {
    fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        let module = load_module(engine, LINUX_SYSCALL_WASM)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| "failed to instantiate linux_syscall")?;
        let memory = get_memory(&mut store, &instance)?;
        let arg_buffer_ptr = instance
            .get_typed_func::<(), u32>(&store, "arg_buffer_ptr")
            .map_err(|_| "missing linux arg_buffer_ptr export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch linux arg buffer ptr")?;
        let arg_buffer_capacity = instance
            .get_typed_func::<(), u32>(&store, "arg_buffer_capacity")
            .map_err(|_| "missing linux arg_buffer_capacity export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch linux arg buffer capacity")?;
        let dispatch = instance
            .get_typed_func::<(u64, u64, u64, u64, u64, u64, u64), u64>(&store, "dispatch")
            .map_err(|_| "missing linux dispatch export")?;
        let resume_wait = instance
            .get_typed_func::<u32, u64>(&store, "resume_wait")
            .map_err(|_| "missing linux resume_wait export")?;
        let plan_arg = instance
            .get_typed_func::<u32, u64>(&store, "plan_arg")
            .map_err(|_| "missing linux plan_arg export")?;

        Ok(Self {
            store,
            memory,
            arg_buffer_ptr,
            arg_buffer_capacity,
            dispatch,
            resume_wait,
            plan_arg,
            _engine: engine,
        })
    }

    fn dispatch(&mut self, ctx: SyscallContext) -> Result<u64, &'static str> {
        self.dispatch
            .call(
                &mut self.store,
                (
                    ctx.nr,
                    ctx.args[0],
                    ctx.args[1],
                    ctx.args[2],
                    ctx.args[3],
                    ctx.args[4],
                    ctx.args[5],
                ),
            )
            .map_err(|_| "linux_syscall dispatch trapped")
    }

    fn resume_wait(&mut self, token: u32) -> Result<u64, &'static str> {
        self.resume_wait
            .call(&mut self.store, token)
            .map_err(|_| "linux_syscall resume trapped")
    }

    fn write_arg_bytes(&mut self, bytes: &[u8]) -> Result<(u32, u32), &'static str> {
        if bytes.len() > self.arg_buffer_capacity as usize {
            return Err("linux arg buffer overflowed");
        }

        self.memory
            .write(&mut self.store, self.arg_buffer_ptr as usize, bytes)
            .map_err(|_| "failed to write linux arg buffer")?;
        Ok((self.arg_buffer_ptr, bytes.len() as u32))
    }

    fn read_bytes(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, &'static str> {
        read_memory(&self.memory, &self.store, ptr, len)
    }

    fn current_plan(&mut self, kind: PlanKind) -> Result<LinuxPlan, &'static str> {
        let mut args = [0u64; 6];
        for (idx, slot) in args.iter_mut().enumerate() {
            *slot = self
                .plan_arg
                .call(&mut self.store, idx as u32)
                .map_err(|_| "failed to read linux plan arg")?;
        }

        Ok(LinuxPlan { kind, args })
    }
}

struct WasmApp<'engine> {
    store: Store<()>,
    memory: Memory,
    run: TypedFunc<(), u64>,
    _engine: &'engine Engine,
}

impl<'engine> WasmApp<'engine> {
    fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        let module = load_module(engine, WASM_APP_WASM)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| "failed to instantiate wasm_app")?;
        let memory = get_memory(&mut store, &instance)?;
        let run = instance
            .get_typed_func::<(), u64>(&store, "run")
            .map_err(|_| "missing wasm_app run export")?;

        Ok(Self {
            store,
            memory,
            run,
            _engine: engine,
        })
    }

    fn run(&mut self) -> Result<u64, &'static str> {
        self.run
            .call(&mut self.store, ())
            .map_err(|_| "wasm_app trapped")
    }

    fn read_bytes(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, &'static str> {
        read_memory(&self.memory, &self.store, ptr, len)
    }
}

fn expect_ok(rc: i32) -> Result<(), ServiceCallError> {
    if rc == 0 {
        Ok(())
    } else if rc < 0 {
        Err(ServiceCallError::Errno(-rc))
    } else {
        Err(ServiceCallError::Invalid(
            "service returned an unexpected positive status",
        ))
    }
}

fn expect_len(rc: i32) -> Result<u32, ServiceCallError> {
    if rc < 0 {
        Err(ServiceCallError::Errno(-rc))
    } else {
        Ok(rc as u32)
    }
}

fn format_hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            out.push(' ');
        }
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn load_module(engine: &Engine, bytes: &[u8]) -> Result<Module, &'static str> {
    Module::new(engine, bytes).map_err(map_wasmi_error)
}

fn get_memory(store: &mut Store<()>, instance: &Instance) -> Result<Memory, &'static str> {
    match instance.get_export(store, "memory") {
        Some(Extern::Memory(memory)) => Ok(memory),
        _ => Err("wasm module did not export linear memory"),
    }
}

fn read_memory(
    memory: &Memory,
    store: &Store<()>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, &'static str> {
    let mut buffer = vec![0_u8; len as usize];
    memory
        .read(store, ptr as usize, &mut buffer)
        .map_err(|_| "failed to read wasm linear memory")?;
    Ok(buffer)
}

fn map_wasmi_error(error: Error) -> &'static str {
    let _ = error;
    "wasmi returned an error"
}
