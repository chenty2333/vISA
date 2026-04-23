mod demos;
mod engine;
mod events;
mod linux;
mod pulse;
mod runtime;
mod scheduler;
mod services;
mod types;
mod wait;

pub(crate) use linux::LinuxCallResult;
pub(crate) use runtime::{PrototypeRuntime, runtime};
pub(crate) use types::TaskId;

pub(crate) fn run() -> Result<(), &'static str> {
    runtime()?.run_prototype_demos()
}
