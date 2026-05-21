use vmos_abi::{ERR_EINVAL, ERR_EPERM, ERR_ESRCH};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{CAP_SYS_RESOURCE, Pid, Rlimit},
};

const RLIMIT_COUNT: usize = 16;
const RLIMIT64_SIZE: usize = 16;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_prlimit64(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let pid = match decode_pid(plan.args[0], self.current_pid()) {
            Ok(pid) => pid,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        self.apply_rlimit_plan(pid, plan.args[1], plan.args[2], plan.args[3])
    }

    pub(super) fn plan_getrlimit(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let resource = plan.args[0];
        let old_ptr = plan.args[1];
        self.apply_rlimit_plan(self.current_pid(), resource, 0, old_ptr)
    }

    pub(super) fn plan_setrlimit(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let resource = plan.args[0];
        let new_ptr = plan.args[1];
        if new_ptr == 0 {
            return Ok(errno_ret(ERR_EINVAL));
        }
        self.apply_rlimit_plan(self.current_pid(), resource, new_ptr, 0)
    }

    fn apply_rlimit_plan(
        &mut self,
        pid: Pid,
        resource_raw: u64,
        new_ptr_raw: u64,
        old_ptr_raw: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.query_process(pid).is_none() {
            return Ok(errno_ret(ERR_ESRCH));
        }

        let resource = match usize::try_from(resource_raw) {
            Ok(resource) if resource < RLIMIT_COUNT => resource,
            _ => return Ok(errno_ret(ERR_EINVAL)),
        };
        let new_ptr = match u32::try_from(new_ptr_raw) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        let old_ptr = match u32::try_from(old_ptr_raw) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };

        self.apply_rlimit_ptrs(pid, resource, new_ptr, old_ptr)
    }

    fn apply_rlimit_ptrs(
        &mut self,
        pid: Pid,
        resource: usize,
        new_ptr: u32,
        old_ptr: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        let old_limit = self.get_rlimit(pid, resource);
        let new_limit = if new_ptr != 0 {
            let bytes = match self.linux.read_bytes(new_ptr, RLIMIT64_SIZE as u32) {
                Ok(bytes) => bytes,
                Err(_) => return Ok(errno_ret(ERR_EINVAL)),
            };
            let new_limit = match decode_rlimit(&bytes) {
                Ok(limit) => limit,
                Err(errno) => return Ok(errno_ret(errno)),
            };
            if new_limit.max > old_limit.max
                && self.current_access_state().cap_effective & CAP_SYS_RESOURCE == 0
            {
                return Ok(errno_ret(ERR_EPERM));
            }
            Some(new_limit)
        } else {
            None
        };

        if old_ptr != 0 {
            let encoded = encode_rlimit(old_limit);
            if self.linux.write_bytes(old_ptr, &encoded).is_err() {
                return Ok(errno_ret(ERR_EINVAL));
            }
        }

        if let Some(new_limit) = new_limit {
            if !self.set_rlimit(pid, resource, new_limit) {
                return Ok(errno_ret(ERR_ESRCH));
            }
        }

        Ok(LinuxCallResult::Ret(0))
    }
}

fn decode_pid(raw_pid: u64, current_pid: Pid) -> Result<Pid, i32> {
    if raw_pid == 0 { Ok(current_pid) } else { u32::try_from(raw_pid).map_err(|_| ERR_EINVAL) }
}

fn encode_rlimit(limit: Rlimit) -> [u8; RLIMIT64_SIZE] {
    let mut out = [0u8; RLIMIT64_SIZE];
    out[..8].copy_from_slice(&limit.cur.to_le_bytes());
    out[8..].copy_from_slice(&limit.max.to_le_bytes());
    out
}

fn decode_rlimit(bytes: &[u8]) -> Result<Rlimit, i32> {
    if bytes.len() != RLIMIT64_SIZE {
        return Err(ERR_EINVAL);
    }
    let cur = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| ERR_EINVAL)?);
    let max = u64::from_le_bytes(bytes[8..].try_into().map_err(|_| ERR_EINVAL)?);
    if cur > max {
        return Err(ERR_EINVAL);
    }
    Ok(Rlimit { cur, max })
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use vmos_abi::{ERR_EPERM, SYS_PRLIMIT64, SyscallContext};

    use super::{
        super::{
            engine::RuntimeOnlyExecutor,
            types::{DEFAULT_RLIMIT_STACK_BYTES, RLIMIT_NOFILE, RLIMIT_STACK},
        },
        *,
    };

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
    fn default_runtime_stack_rlimit_matches_linux_elf_stack_ceiling() {
        let runtime = test_runtime();
        let pid = runtime.current_pid();
        assert_eq!(
            runtime.get_rlimit(pid, RLIMIT_STACK),
            Rlimit { cur: DEFAULT_RLIMIT_STACK_BYTES, max: DEFAULT_RLIMIT_STACK_BYTES }
        );
    }

    #[test]
    fn generic_prlimit64_max_raise_requires_resource_capability() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let process = runtime
            .processes
            .iter_mut()
            .find(|process| process.pid == pid)
            .expect("current process");
        process.access.cap_permitted = 0;
        process.access.cap_effective = 0;

        let raised = encode_rlimit(Rlimit { cur: 2048, max: 2048 });
        let (limit_ptr, _) = runtime.linux.write_arg_bytes(&raised).expect("rlimit input");
        let denied = runtime
            .dispatch_linux_syscall_raw(
                "test_prlimit_raise_denied",
                SyscallContext::new(
                    SYS_PRLIMIT64,
                    [0, RLIMIT_NOFILE as u64, limit_ptr as u64, 0, 0, 0],
                ),
            )
            .expect("prlimit dispatch");
        assert_eq!(expect_ret(denied), -(ERR_EPERM as i64));
        assert_eq!(runtime.get_rlimit(pid, RLIMIT_NOFILE).max, 1024);

        let process = runtime
            .processes
            .iter_mut()
            .find(|process| process.pid == pid)
            .expect("current process");
        process.access.cap_permitted = CAP_SYS_RESOURCE;
        process.access.cap_effective = CAP_SYS_RESOURCE;
        let raised = encode_rlimit(Rlimit { cur: 2048, max: 2048 });
        let (limit_ptr, _) = runtime.linux.write_arg_bytes(&raised).expect("rlimit input");
        let allowed = runtime
            .dispatch_linux_syscall_raw(
                "test_prlimit_raise_allowed",
                SyscallContext::new(
                    SYS_PRLIMIT64,
                    [0, RLIMIT_NOFILE as u64, limit_ptr as u64, 0, 0, 0],
                ),
            )
            .expect("prlimit dispatch");
        assert_eq!(expect_ret(allowed), 0);
        assert_eq!(runtime.get_rlimit(pid, RLIMIT_NOFILE), Rlimit { cur: 2048, max: 2048 });
    }
}
