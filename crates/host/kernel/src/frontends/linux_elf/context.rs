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
