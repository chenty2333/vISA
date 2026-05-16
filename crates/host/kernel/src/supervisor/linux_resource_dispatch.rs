use vmos_abi::{ERR_EINVAL, ERR_EPERM, ERR_ESRCH};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{Pid, Rlimit},
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
        if self.query_process(pid).is_none() {
            return Ok(errno_ret(ERR_ESRCH));
        }

        let resource = match usize::try_from(plan.args[1]) {
            Ok(resource) if resource < RLIMIT_COUNT => resource,
            _ => return Ok(errno_ret(ERR_EINVAL)),
        };
        let new_ptr = match u32::try_from(plan.args[2]) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        let old_ptr = match u32::try_from(plan.args[3]) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };

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
            if new_limit.max > old_limit.max {
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
