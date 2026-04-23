mod demos;
mod linux;
mod runtime;
mod services;
mod types;
mod wasm;

pub(crate) use linux::LinuxCallResult;
pub(crate) use runtime::{PrototypeRuntime, runtime};

pub(crate) fn run() -> Result<(), &'static str> {
    runtime()?.run_prototype_demos()
}
