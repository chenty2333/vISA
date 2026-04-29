use core::fmt;

use crate::{debugcon, serial};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

const SERIAL_LEVEL: Level = Level::Warn;
const DEBUGCON_LEVEL: Level = Level::Trace;

pub fn log(level: Level, args: fmt::Arguments<'_>) {
    if level <= DEBUGCON_LEVEL {
        debugcon::_print(format_args!("[{}] ", level.as_str()));
        debugcon::_print(args);
        debugcon::_print(format_args!("\n"));
    }

    if level <= SERIAL_LEVEL {
        serial::_print(format_args!("[{}] ", level.as_str()));
        serial::_print(args);
        serial::_print(format_args!("\n"));
    }
}

impl Level {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

#[macro_export]
macro_rules! kerror {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::Level::Error, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! kwarn {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::Level::Warn, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! kinfo {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::Level::Info, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! kdebug {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::Level::Debug, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! ktrace {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::Level::Trace, format_args!($($arg)*))
    };
}
