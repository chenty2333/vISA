mod artifacts;
mod authority;
mod boundary;
mod demos;
mod engine;
mod events;
mod fault;
mod linux;
mod net;
mod pulse;
mod recovery;
mod runtime;
mod scheduler;
mod semantic;
mod services;
mod store;
mod store_manager;
mod types;
mod wait;

pub(crate) use linux::LinuxCallResult;
pub(crate) use runtime::{PrototypeRuntime, runtime};
pub(crate) use types::TaskId;

pub(crate) fn run() -> Result<(), &'static str> {
    runtime()?.run_prototype_demos()
}
