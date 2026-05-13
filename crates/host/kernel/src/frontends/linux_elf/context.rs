use alloc::vec::Vec;
use core::ptr::null_mut;

use crate::supervisor::{PrototypeRuntime, TaskId};

#[derive(Clone, Copy)]
pub(crate) struct UserRegion {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) writable: bool,
}

pub(crate) struct LoadedUserImage {
    pub(crate) entry: u64,
    pub(crate) stack_top: u64,
    pub(crate) regions: Vec<UserRegion>,
}

pub(crate) struct ActiveUserContext {
    pub(crate) supervisor: &'static mut PrototypeRuntime<'static>,
    pub(crate) regions: Vec<UserRegion>,
    pub(crate) task_id: TaskId,
    pub(crate) activation_id: u64,
    cwd: Vec<u8>,
    brk_base: u64,
    brk_current: u64,
    brk_end: u64,
    mmap_cursor: u64,
    mmap_end: u64,
    next_activation_id: u64,
    alarm_seconds: u64,
    realtime_epoch_ns: u64,
    realtime_epoch_tick: u64,
    fake_child_pending: bool,
    fake_child_pid: u64,
    fake_child_wait_status: i32,
    fake_executable_busy_paths: Vec<Vec<u8>>,
    fake_signal_pending: bool,
}

static mut ACTIVE_CONTEXT: *mut ActiveUserContext = null_mut();

impl ActiveUserContext {
    pub(crate) fn new(
        supervisor: &'static mut PrototypeRuntime<'static>,
        regions: Vec<UserRegion>,
        task_id: TaskId,
        brk_base: u64,
        brk_end: u64,
        mmap_base: u64,
        mmap_end: u64,
    ) -> Self {
        Self {
            supervisor,
            regions,
            task_id,
            activation_id: 0,
            cwd: b"/tmp".to_vec(),
            brk_base,
            brk_current: brk_base,
            brk_end,
            mmap_cursor: mmap_base,
            mmap_end,
            next_activation_id: (task_id as u64) << 32 | 1,
            alarm_seconds: 0,
            realtime_epoch_ns: 1_000_000_000,
            realtime_epoch_tick: 0,
            fake_child_pending: false,
            fake_child_pid: task_id as u64 + 1,
            fake_child_wait_status: 0,
            fake_executable_busy_paths: Vec::new(),
            fake_signal_pending: false,
        }
    }

    pub(crate) fn begin_activation(&mut self) -> u64 {
        let activation_id = self.next_activation_id;
        self.next_activation_id += 1;
        self.activation_id = activation_id;
        activation_id
    }

    pub(crate) fn finish_activation(&mut self, activation_id: u64) {
        if self.activation_id == activation_id {
            self.activation_id = 0;
        }
    }

    pub(crate) fn allocate_mmap(&mut self, len: u64, align: u64) -> Option<u64> {
        let align = align.max(1);
        let start = align_up(self.mmap_cursor, align)?;
        let end = start.checked_add(align_up(len, align)?)?;
        if end > self.mmap_end {
            return None;
        }
        self.mmap_cursor = end;
        Some(start)
    }

    pub(crate) fn record_user_region(&mut self, start: u64, len: u64, writable: bool) {
        if let Some(end) = start.checked_add(len) {
            self.regions.push(UserRegion { start, end, writable });
        }
    }

    pub(crate) fn set_program_break(&mut self, requested: u64) -> u64 {
        if requested == 0 {
            return self.brk_current;
        }
        if requested < self.brk_base || requested > self.brk_end {
            return self.brk_current;
        }
        self.brk_current = requested;
        self.brk_current
    }

    pub(crate) fn cwd(&self) -> &[u8] {
        &self.cwd
    }

    pub(crate) fn set_cwd(&mut self, path: Vec<u8>) {
        self.cwd = path;
    }

    pub(crate) fn replace_alarm(&mut self, seconds: u64) -> u64 {
        let previous = self.alarm_seconds;
        self.alarm_seconds = seconds;
        previous
    }

    pub(crate) fn realtime_now_ns(&self, tick_count: u64, timer_hz: u64) -> u64 {
        let elapsed_ticks = tick_count.saturating_sub(self.realtime_epoch_tick);
        self.realtime_epoch_ns
            .saturating_add(elapsed_ticks.saturating_mul(1_000_000_000) / timer_hz.max(1))
    }

    pub(crate) fn set_realtime_ns(&mut self, now_ns: u64, tick_count: u64) {
        self.realtime_epoch_ns = now_ns;
        self.realtime_epoch_tick = tick_count;
    }

    pub(crate) fn spawn_fake_child(&mut self, wait_status: i32) -> u64 {
        self.fake_child_pending = true;
        self.fake_child_wait_status = wait_status;
        self.fake_signal_pending = true;
        self.fake_child_pid
    }

    pub(crate) fn reap_fake_child(&mut self) -> Option<(u64, i32)> {
        if !self.fake_child_pending {
            return None;
        }
        self.fake_child_pending = false;
        self.fake_executable_busy_paths.clear();
        Some((self.fake_child_pid, self.fake_child_wait_status))
    }

    pub(crate) fn mark_fake_executable_busy(&mut self, path: Vec<u8>) {
        if !self.fake_executable_busy_paths.iter().any(|busy| busy == &path) {
            self.fake_executable_busy_paths.push(path);
        }
    }

    pub(crate) fn is_fake_executable_busy(&self, path: &[u8]) -> bool {
        self.fake_executable_busy_paths.iter().any(|busy| busy.as_slice() == path)
    }

    pub(crate) fn clear_fake_executable_busy(&mut self) {
        self.fake_executable_busy_paths.clear();
    }

    pub(crate) fn consume_fake_signal(&mut self) -> bool {
        let pending = self.fake_signal_pending;
        self.fake_signal_pending = false;
        pending
    }
}

fn align_up(value: u64, align: u64) -> Option<u64> {
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|value| value & !mask)
}

pub(crate) fn install_active_context(context: &mut ActiveUserContext) {
    unsafe {
        ACTIVE_CONTEXT = context as *mut _;
    }
}

pub(crate) fn active_context() -> &'static mut ActiveUserContext {
    unsafe {
        if ACTIVE_CONTEXT.is_null() {
            panic!("ring3 context was not installed");
        }
        &mut *ACTIVE_CONTEXT
    }
}
