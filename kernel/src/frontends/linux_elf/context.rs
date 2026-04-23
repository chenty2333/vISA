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
}

static mut ACTIVE_CONTEXT: *mut ActiveUserContext = null_mut();

impl ActiveUserContext {
    pub(crate) fn new(
        supervisor: &'static mut PrototypeRuntime<'static>,
        regions: Vec<UserRegion>,
        task_id: TaskId,
    ) -> Self {
        Self {
            supervisor,
            regions,
            task_id,
            activation_id: task_id as u64,
        }
    }
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
