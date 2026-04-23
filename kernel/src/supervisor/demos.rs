use alloc::string::String;
use core::fmt::Write;

use crate::serial;
use crate::serial_println;
use vmos_abi::{
    EPOLL_CTL_ADD, EPOLLIN, ERR_EPERM, FD_STDOUT, FUTEX_WAIT, FUTEX_WAKE, PackedStep,
    SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT, SYS_FUTEX, StepTag, SyscallContext,
};

use super::linux::LinuxCallResult;
use super::runtime::PrototypeRuntime;
use super::types::{InjectedFault, WaitRestartClass, WaitToken};

impl<'engine> PrototypeRuntime<'engine> {
    pub(crate) fn run_prototype_demos(&mut self) -> Result<(), &'static str> {
        self.run_wasm_frontend()?;
        self.run_linux_stdio_demo()?;
        self.run_linux_vfs_demo()?;
        self.run_linux_procfs_demo()?;
        self.run_linux_devfs_demo()?;
        self.run_linux_metadata_demo()?;
        self.run_sleep_demo()?;
        self.run_futex_demo()?;
        self.run_epoll_demo()?;
        self.run_procfs_recovery_demo()?;
        self.run_capability_enforcement_demo()?;
        self.run_generation_plane_demo()?;
        self.run_snapshot_migration_demo()?;
        self.run_semantic_debug_demo()?;
        Ok(())
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
        let pending = self.dispatch_linux_sleep_ms_raw("linux_sleep", 25)?;
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            _ => return Err("sleep path did not enter pending state"),
        };

        crate::kinfo!("linux_syscall returned Pending({:?})", token);
        match self.block_on_wait("linux_sleep", token)? {
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

    fn run_semantic_debug_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== semantic object graph demo ==");
        for line in self.semantic_debug_lines() {
            serial_println!("{}", line);
        }
        Ok(())
    }

    fn run_snapshot_migration_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== snapshot migration package demo ==");
        let package = self.create_migration_package()?;
        for line in package.summary_lines() {
            serial_println!("{}", line);
        }
        Ok(())
    }

    fn run_capability_enforcement_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== capability enforcement demo ==");
        let old_generation = self
            .capability_generation("linux_syscall", "timer.sleep")
            .ok_or("timer.sleep capability generation was missing")?;
        self.revoke_capability_for_demo("linux_syscall", "timer.sleep")?;

        match self.dispatch_linux_sleep_ms_raw("capability_denied_sleep", 1)? {
            LinuxCallResult::Ret(ret) if ret == -(ERR_EPERM as i64) => {
                serial_println!("revoked timer.sleep denied nanosleep");
            }
            _ => return Err("revoked timer.sleep did not deny nanosleep"),
        }

        self.grant_capability_for_demo(
            "linux_syscall",
            "timer.sleep",
            &["arm", "cancel"],
            "wait-token",
        );
        if self
            .require_capability_generation("linux_syscall", "timer.sleep", "arm", old_generation)
            .is_ok()
        {
            return Err("stale timer.sleep generation was accepted");
        }
        self.require_capability("linux_syscall", "timer.sleep", "arm")
            .map_err(|_| "restored timer.sleep capability was denied")?;
        serial_println!("stale timer.sleep generation rejected after regrant");
        Ok(())
    }

    fn run_generation_plane_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== resource/wait/dmw generation demo ==");

        let fd = self.open_path(b"/sandbox/hello.txt")?;
        let fd_handle = self
            .fd_handle_for_demo(fd)
            .ok_or("opened fd did not publish a resource handle")?;
        self.validate_resource_handle(fd_handle)
            .map_err(|_| "fresh fd resource handle was rejected")?;
        self.close_fd(fd)?;
        if self.validate_resource_handle(fd_handle).is_ok() {
            return Err("stale fd resource handle was accepted after close");
        }
        serial_println!("closed fd handle rejected after generation change");

        let pending = self.dispatch_linux_sleep_ms_raw("generation_wait", 1)?;
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            _ => return Err("generation wait did not enter pending state"),
        };
        let stale_token = WaitToken {
            generation: token.generation.saturating_add(1),
            ..token
        };
        if self.validate_wait_token(stale_token).is_ok() {
            return Err("stale wait token generation was accepted");
        }
        match self.block_on_wait("generation_wait", token)? {
            LinuxCallResult::Ret(_) => {
                serial_println!("stale wait token rejected before resume");
            }
            _ => return Err("generation wait resumed with an unexpected result"),
        }

        if !crate::substrate::dmw::quarantine_reuse_self_check() {
            return Err("DMW slot quarantine did not block same-activation reuse");
        }
        serial_println!("dmw slot reuse blocked within one activation");
        Ok(())
    }

    fn run_futex_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== futex service demo ==");
        let bootstrap = self.bootstrap_task();
        let waiter = self.allocate_task();
        let waker = self.allocate_task();

        self.set_current_task(waiter);
        let pending =
            self.dispatch_linux_futex_raw("futex_wait", 0x2000, FUTEX_WAIT as u64, 1, u64::MAX, 1)?;
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            _ => return Err("futex wait did not enter pending state"),
        };

        self.set_current_task(waker);
        let woke = self.dispatch_linux_syscall(
            "futex_wake",
            SyscallContext::new(SYS_FUTEX, [0x2000, FUTEX_WAKE as u64, 1, 0, 0, 0]),
        )?;
        let woke = match woke {
            LinuxCallResult::Ret(value) => value,
            _ => {
                self.set_current_task(bootstrap);
                return Err("futex wake returned an unexpected result");
            }
        };
        serial_println!("futex_wake(...) -> {}", woke);

        self.set_current_task(waiter);
        match self.block_on_wait("futex_wait", token)? {
            LinuxCallResult::Ret(0) => {
                serial_println!("futex waiter resumed");
                self.set_current_task(bootstrap);
                Ok(())
            }
            _ => {
                self.set_current_task(bootstrap);
                Err("futex waiter resumed with an unexpected result")
            }
        }
    }

    fn run_epoll_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== epoll demo ==");
        self.pulse.reset_sequence(crate::interrupts::tick_count());
        let pulse_fd = self.open_path(b"/dev/pulse")?;
        let created = self.dispatch_linux_syscall(
            "epoll_create1",
            SyscallContext::new(SYS_EPOLL_CREATE1, [0, 0, 0, 0, 0, 0]),
        )?;
        let epfd = self.expect_ret("epoll_create1", created)? as u32;
        let ctl = self.dispatch_linux_syscall(
            "epoll_ctl",
            SyscallContext::new(
                SYS_EPOLL_CTL,
                [
                    epfd as u64,
                    EPOLL_CTL_ADD as u64,
                    pulse_fd as u64,
                    EPOLLIN as u64,
                    0x33,
                    0,
                ],
            ),
        )?;
        let added = self.expect_ret("epoll_ctl", ctl)?;
        serial_println!("epoll_ctl(add /dev/pulse) -> {}", added);

        let before = self.restart_count();
        let waited = match self.dispatch_linux_syscall_raw(
            "epoll_wait",
            SyscallContext::new(SYS_EPOLL_WAIT, [epfd as u64, 1, 40, 0, 0, 0]),
        )? {
            LinuxCallResult::Pending(token) => {
                self.inject_wait_restart(token, WaitRestartClass::DriverRestart);
                self.block_on_wait("epoll_wait", token)?
            }
            ready => ready,
        };
        let events = self.expect_bytes("epoll_wait", waited)?;
        if self.restart_count() > before {
            serial_println!("epoll_wait restarted after pulse source restart");
        }
        serial_println!("epoll_wait(...) -> {}", events.len() / 12);

        let pulse = self.read_fd(pulse_fd, 16)?;
        serial_println!(
            "pulse fd read -> {}",
            core::str::from_utf8(&pulse).unwrap_or("<invalid utf8>")
        );

        self.close_fd(pulse_fd)?;
        self.close_fd(epfd)?;
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
                self.require_capability("wasm_app", "console.write", "write")
                    .map_err(|_| "wasm_app console.write capability denied")?;
                let bytes = self.app.read_bytes(decoded.aux, len)?;
                self.console.write_bytes(&bytes, false)
            }
            StepTag::Ready => Ok(()),
            _ => Err("wasm frontend returned an unexpected step"),
        }
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
