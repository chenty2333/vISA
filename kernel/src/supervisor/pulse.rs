use alloc::vec::Vec;

use crate::interrupts;

const PULSE_READY_KEY: u64 = 0x_7075_6c73_65;
const PULSE_READ_BYTES: &[u8] = b"pulse\n";
const FIRST_RESTART_DELAY_MS: u32 = 15;
const READY_DELAY_MS: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PulseEvent {
    Ready(u64),
    Restart(u64),
}

pub(crate) struct PulseDevice {
    next_tick: u64,
    ready: bool,
    injected_restart: bool,
}

impl PulseDevice {
    pub(crate) fn new(now_ticks: u64) -> Self {
        Self {
            next_tick: now_ticks + ms_to_ticks(FIRST_RESTART_DELAY_MS),
            ready: false,
            injected_restart: false,
        }
    }

    pub(crate) fn reset_sequence(&mut self, now_ticks: u64) {
        self.next_tick = now_ticks + ms_to_ticks(FIRST_RESTART_DELAY_MS);
        self.ready = false;
        self.injected_restart = false;
    }

    pub(crate) fn ready_key_for_path(path: &[u8]) -> Option<u64> {
        if path == b"/dev/pulse" {
            Some(PULSE_READY_KEY)
        } else {
            None
        }
    }

    pub(crate) fn collect_events(&mut self, now_ticks: u64, out: &mut Vec<PulseEvent>) {
        if self.ready || now_ticks < self.next_tick {
            return;
        }

        if !self.injected_restart {
            self.injected_restart = true;
            self.next_tick = now_ticks + ms_to_ticks(READY_DELAY_MS);
            out.push(PulseEvent::Restart(PULSE_READY_KEY));
            return;
        }

        self.ready = true;
        out.push(PulseEvent::Ready(PULSE_READY_KEY));
    }

    pub(crate) fn is_ready_key(&self, ready_key: u64) -> bool {
        self.ready && ready_key == PULSE_READY_KEY
    }

    pub(crate) fn read(&mut self, path: &[u8], count: u32, now_ticks: u64) -> Option<&[u8]> {
        if path != b"/dev/pulse" || !self.ready {
            return None;
        }

        self.ready = false;
        self.next_tick = now_ticks + ms_to_ticks(READY_DELAY_MS);
        let count = core::cmp::min(count as usize, PULSE_READ_BYTES.len());
        Some(&PULSE_READ_BYTES[..count])
    }
}

fn ms_to_ticks(delay_ms: u32) -> u64 {
    let scaled = delay_ms as u64 * interrupts::TIMER_HZ as u64;
    scaled.div_ceil(1_000).max(1)
}
