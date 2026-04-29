use core::fmt::{self, Write};

use spin::{Lazy, Mutex};
use uart_16550::SerialPort;
use x86_64::instructions::interrupts;

static SERIAL1: Lazy<Mutex<SerialPort>> = Lazy::new(|| {
    let mut serial_port = unsafe { SerialPort::new(0x3F8) };
    serial_port.init();
    Mutex::new(serial_port)
});

pub fn init() {
    interrupts::without_interrupts(|| {
        let _guard = SERIAL1.lock();
    });
}

pub fn write_bytes(bytes: &[u8]) {
    interrupts::without_interrupts(|| {
        let mut serial = SERIAL1.lock();
        for byte in bytes {
            serial.send(*byte);
        }
    });
}

pub fn _print(args: fmt::Arguments<'_>) {
    interrupts::without_interrupts(|| {
        let mut serial = SERIAL1.lock();
        serial.write_fmt(args).expect("serial output should not fail");
    });
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! serial_println {
    () => {
        $crate::serial_print!("\n")
    };
    ($fmt:expr) => {
        $crate::serial_print!(concat!($fmt, "\n"))
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::serial_print!(concat!($fmt, "\n"), $($arg)*)
    };
}
