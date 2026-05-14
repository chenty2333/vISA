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
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    pub(crate) activation_id: u64,
    cwd: Vec<u8>,
    brk_base: u64,
    brk_current: u64,
    brk_end: u64,
    mmap_cursor: u64,
    mmap_end: u64,
    uid: u32,
    gid: u32,
    euid: u32,
    egid: u32,
    io_owner: i64,
    io_owner_ex_type: u32,
    io_owner_ex_pid: i32,
    io_signal: u32,
    pending_io_signal: Option<u32>,
    next_activation_id: u64,
    alarm_seconds: u64,
    realtime_epoch_ns: u64,
    realtime_epoch_tick: u64,
}

static mut ACTIVE_CONTEXT: *mut ActiveUserContext = null_mut();

impl ActiveUserContext {
    pub(crate) fn new(
        supervisor: &'static mut PrototypeRuntime<'static>,
        regions: Vec<UserRegion>,
        task_id: TaskId,
        pid: u32,
        tid: u32,
        brk_base: u64,
        brk_end: u64,
        mmap_base: u64,
        mmap_end: u64,
    ) -> Self {
        Self {
            supervisor,
            regions,
            task_id,
            pid,
            tid,
            activation_id: 0,
            cwd: b"/tmp".to_vec(),
            brk_base,
            brk_current: brk_base,
            brk_end,
            mmap_cursor: mmap_base,
            mmap_end,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            io_owner: 0,
            io_owner_ex_type: 0,
            io_owner_ex_pid: 0,
            io_signal: 0,
            pending_io_signal: None,
            next_activation_id: (task_id as u64) << 32 | 1,
            alarm_seconds: 0,
            realtime_epoch_ns: 1_000_000_000,
            realtime_epoch_tick: 0,
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

    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    pub(crate) fn gid(&self) -> u32 {
        self.gid
    }

    pub(crate) fn euid(&self) -> u32 {
        self.euid
    }

    pub(crate) fn egid(&self) -> u32 {
        self.egid
    }

    pub(crate) fn set_uid(&mut self, uid: u32) {
        self.uid = uid;
        self.euid = uid;
    }

    pub(crate) fn set_gid(&mut self, gid: u32) {
        self.gid = gid;
        self.egid = gid;
    }

    pub(crate) fn set_reuid(&mut self, ruid: Option<u32>, euid: Option<u32>) {
        if let Some(uid) = ruid {
            self.uid = uid;
        }
        if let Some(uid) = euid {
            self.euid = uid;
        }
    }

    pub(crate) fn set_regid(&mut self, rgid: Option<u32>, egid: Option<u32>) {
        if let Some(gid) = rgid {
            self.gid = gid;
        }
        if let Some(gid) = egid {
            self.egid = gid;
        }
    }

    pub(crate) fn open_owner_ids(&self) -> u64 {
        ((self.euid as u64) << 32) | self.egid as u64
    }

    pub(crate) fn io_owner(&self) -> i64 {
        self.io_owner
    }

    pub(crate) fn set_io_owner(&mut self, owner: i64) {
        self.io_owner = owner;
        if owner < 0 {
            self.io_owner_ex_type = 2;
            self.io_owner_ex_pid = owner.saturating_abs().min(i32::MAX as i64) as i32;
        } else {
            self.io_owner_ex_type = 1;
            self.io_owner_ex_pid = owner.min(i32::MAX as i64) as i32;
        }
    }

    pub(crate) fn io_owner_ex(&self) -> (u32, i32) {
        (self.io_owner_ex_type, self.io_owner_ex_pid)
    }

    pub(crate) fn set_io_owner_ex(&mut self, owner_type: u32, pid: i32) {
        self.io_owner_ex_type = owner_type;
        self.io_owner_ex_pid = pid;
        self.io_owner = match owner_type {
            2 => -(pid as i64),
            _ => pid as i64,
        };
    }

    pub(crate) fn io_signal(&self) -> u32 {
        self.io_signal
    }

    pub(crate) fn set_io_signal(&mut self, signal: u32) {
        self.io_signal = signal;
    }

    pub(crate) fn queue_io_signal(&mut self) {
        if self.io_owner == 0 && self.io_owner_ex_pid == 0 {
            return;
        }
        if self.io_signal != 0 {
            self.pending_io_signal = Some(self.io_signal);
        }
    }

    pub(crate) fn consume_io_signal(&mut self) -> Option<u32> {
        self.pending_io_signal.take()
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
