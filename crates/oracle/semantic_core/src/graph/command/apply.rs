use alloc::boxed::Box;

use super::*;

mod block_fs;
mod device_io;
mod integrated;
mod lifecycle;
mod network;
mod scheduler;
mod simd_display;

pub(super) enum ApplyDispatch {
    Applied(bool),
    Next(Box<SemanticCommand>),
}

impl SemanticGraph {
    pub(super) fn apply_prechecked_command(&mut self, command: SemanticCommand) -> bool {
        let command = match scheduler::apply_scheduler_command(self, command) {
            ApplyDispatch::Applied(applied) => return applied,
            ApplyDispatch::Next(command) => *command,
        };
        let command = match integrated::apply_integrated_command(self, command) {
            ApplyDispatch::Applied(applied) => return applied,
            ApplyDispatch::Next(command) => *command,
        };
        let command = match network::apply_network_command(self, command) {
            ApplyDispatch::Applied(applied) => return applied,
            ApplyDispatch::Next(command) => *command,
        };
        let command = match block_fs::apply_block_fs_command(self, command) {
            ApplyDispatch::Applied(applied) => return applied,
            ApplyDispatch::Next(command) => *command,
        };
        let command = match simd_display::apply_simd_display_command(self, command) {
            ApplyDispatch::Applied(applied) => return applied,
            ApplyDispatch::Next(command) => *command,
        };
        let command = match device_io::apply_device_io_command(self, command) {
            ApplyDispatch::Applied(applied) => return applied,
            ApplyDispatch::Next(command) => *command,
        };
        match lifecycle::apply_lifecycle_command(self, command) {
            ApplyDispatch::Applied(applied) => applied,
            ApplyDispatch::Next(_) => unreachable!("prechecked command dispatch missed a variant"),
        }
    }
}
