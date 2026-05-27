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

    pub(super) fn plan_set_tid_address(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let clear_child_tid = if plan.args[0] == 0 { None } else { Some(plan.args[0]) };
        let tid = self.current_tid();
        match self.set_thread_clear_child_tid(tid, clear_child_tid) {
            Ok(()) => Ok(LinuxCallResult::Ret(tid as i64)),
            Err(errno) => Ok(errno_ret(errno)),
        }
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

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use vmos_abi::{SYS_SET_TID_ADDRESS, SyscallContext};

    use super::*;
    use crate::supervisor::{engine::RuntimeOnlyExecutor, runtime::PrototypeRuntime};

    fn test_runtime() -> PrototypeRuntime<'static> {
        let engine = Box::leak(Box::new(RuntimeOnlyExecutor::default()));
        PrototypeRuntime::new(engine).expect("test runtime")
    }

    fn expect_ret(result: LinuxCallResult) -> i64 {
        match result {
            LinuxCallResult::Ret(ret) => ret,
            other => panic!("expected Ret, got {other:?}"),
        }
    }

    #[test]
    fn generic_set_tid_address_updates_clear_child_tid_and_returns_tid() {
        let mut runtime = test_runtime();
        let tid = runtime.current_tid();

        let set = runtime
            .dispatch_linux_syscall_raw(
                "test_set_tid_address",
                SyscallContext::new(SYS_SET_TID_ADDRESS, [0x7000, 0, 0, 0, 0, 0]),
            )
            .expect("set_tid_address dispatch");
        assert_eq!(expect_ret(set), tid as i64);
        assert_eq!(
            runtime.query_thread(tid).expect("current thread").clear_child_tid,
            Some(0x7000)
        );

        let clear = runtime
            .dispatch_linux_syscall_raw(
                "test_clear_tid_address",
                SyscallContext::new(SYS_SET_TID_ADDRESS, [0, 0, 0, 0, 0, 0]),
            )
            .expect("clear set_tid_address dispatch");
        assert_eq!(expect_ret(clear), tid as i64);
        assert_eq!(runtime.query_thread(tid).expect("current thread").clear_child_tid, None);
    }
}
