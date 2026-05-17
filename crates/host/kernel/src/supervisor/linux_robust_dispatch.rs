use vmos_abi::{ERR_EFAULT, ERR_EINVAL, ERR_ESRCH};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{RobustListRegistration, Tid},
};

const ROBUST_LIST_HEAD_SIZE: u64 = 24;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_set_robust_list(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let head = plan.args[0];
        let len = plan.args[1];
        if len != ROBUST_LIST_HEAD_SIZE {
            return Ok(errno_ret(ERR_EINVAL));
        }
        let registration =
            if head == 0 { None } else { Some(RobustListRegistration { head, len }) };
        match self.set_thread_robust_list(self.current_tid(), registration) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    pub(super) fn plan_get_robust_list(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let head_ptr = match checked_user_ptr(plan.args[1]) {
            Ok(ptr) => ptr,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        let len_ptr = match checked_user_ptr(plan.args[2]) {
            Ok(ptr) => ptr,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        let target_tid = match decode_target_tid(plan.args[0], self.current_tid()) {
            Ok(tid) => tid,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        let registration = match self.get_thread_robust_list_for_caller(
            self.current_pid(),
            self.current_tid(),
            target_tid,
        ) {
            Ok(registration) => registration,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        let (head, len) = registration
            .map(|registration| (registration.head, registration.len))
            .unwrap_or((0, ROBUST_LIST_HEAD_SIZE));
        if self.linux.write_bytes(head_ptr, &head.to_le_bytes()).is_err() {
            return Ok(errno_ret(ERR_EFAULT));
        }
        if self.linux.write_bytes(len_ptr, &len.to_le_bytes()).is_err() {
            return Ok(errno_ret(ERR_EFAULT));
        }
        Ok(LinuxCallResult::Ret(0))
    }
}

fn checked_user_ptr(value: u64) -> Result<u32, i32> {
    match u32::try_from(value) {
        Ok(ptr) if ptr != 0 => Ok(ptr),
        _ => Err(ERR_EFAULT),
    }
}

fn decode_target_tid(raw_tid: u64, current_tid: Tid) -> Result<Tid, i32> {
    if raw_tid == 0 {
        return Ok(current_tid);
    }
    if (raw_tid as i64) < 0 || raw_tid > i32::MAX as u64 {
        return Err(ERR_ESRCH);
    }
    Ok(raw_tid as Tid)
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
