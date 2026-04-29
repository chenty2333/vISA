use x86_64::instructions::port::Port;

#[derive(Clone, Copy)]
#[repr(u32)]
enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_success() {
    exit(QemuExitCode::Success);
}

pub fn exit_failed() {
    exit(QemuExitCode::Failed);
}

fn exit(code: QemuExitCode) {
    unsafe {
        let mut port = Port::<u32>::new(0xF4);
        port.write(code as u32);
    }
}
