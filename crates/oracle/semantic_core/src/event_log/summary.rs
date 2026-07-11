use alloc::string::String;

use super::kind::EventKind;

mod block_fs;
mod device_io;
mod integrated;
mod network;
mod runtime;
mod scheduler;
mod simd_display;

impl EventKind {
    pub fn summary(&self) -> String {
        if let Some(summary) = scheduler::summary(self) {
            return summary;
        }
        if let Some(summary) = integrated::summary(self) {
            return summary;
        }
        if let Some(summary) = device_io::summary(self) {
            return summary;
        }
        if let Some(summary) = network::summary(self) {
            return summary;
        }
        if let Some(summary) = block_fs::summary(self) {
            return summary;
        }
        if let Some(summary) = simd_display::summary(self) {
            return summary;
        }
        if let Some(summary) = runtime::summary(self) {
            return summary;
        }
        unreachable!("event summary dispatch missed a variant")
    }
}
