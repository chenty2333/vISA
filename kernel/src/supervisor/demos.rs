use alloc::string::String;
use core::fmt::Write;

use crate::serial;
use crate::serial_println;
use vmos_abi::{FD_STDOUT, PackedStep, SYS_NANOSLEEP, StepTag, SyscallContext};

use super::linux::LinuxCallResult;
use super::runtime::PrototypeRuntime;
use super::types::InjectedFault;

impl<'engine> PrototypeRuntime<'engine> {
    pub(crate) fn run_prototype_demos(&mut self) -> Result<(), &'static str> {
        self.run_wasm_frontend()?;
        self.run_linux_stdio_demo()?;
        self.run_linux_vfs_demo()?;
        self.run_linux_procfs_demo()?;
        self.run_linux_devfs_demo()?;
        self.run_linux_metadata_demo()?;
        self.run_sleep_demo()?;
        self.run_procfs_recovery_demo()?;
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
        let pending = self.dispatch_linux_syscall(
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
        crate::interrupts::sleep_ms(delay_ms);

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
