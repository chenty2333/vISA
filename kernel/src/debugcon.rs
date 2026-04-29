use core::fmt::{self, Write};

use x86_64::instructions::port::Port;

pub fn write_str(message: &str) {
    for byte in message.bytes() {
        write_byte(byte);
    }
}

pub fn _print(args: fmt::Arguments<'_>) {
    let mut writer = DebugCon;
    writer.write_fmt(args).expect("debugcon output should not fail");
}

struct DebugCon;

impl Write for DebugCon {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}

fn write_byte(byte: u8) {
    unsafe {
        let mut port = Port::<u8>::new(0xE9);
        port.write(byte);
    }
}
